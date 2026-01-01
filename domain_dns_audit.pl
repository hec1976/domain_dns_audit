#!/usr/bin/perl
use strict;
use warnings;
use utf8;
use open qw(:std :utf8);

use IPC::Open2;
use Net::DNS;
use JSON::MaybeXS qw(encode_json decode_json);
use Log::Log4perl;
use POSIX qw(strftime);
use File::Path qw(make_path);
use File::Basename qw(dirname basename);
use File::Temp qw(tempfile);
use Getopt::Long qw(GetOptions);
use Parallel::ForkManager;
use Time::HiRes qw(sleep);
use Try::Tiny;
use HTTP::Tiny;
use FindBin qw($Bin);
use File::Spec;
use Cwd qw(abs_path);

# --- Konstanten ---
use constant {
    VERSION             => "2.6.8",
    MAX_SPF_LOOKUPS     => 10,
    MAX_CNAME_HOPS      => 5,
    MAX_DNS_RETRIES     => 2,
    DEFAULT_DNS_TIMEOUT => 10,
    MAX_HTTP_REDIRECTS  => 5,
    MIN_RSA_KEY_BITS    => 2048,
};

# --- Globale Pfade ---
my $BASE = abs_path($Bin) || $Bin;
my $DEFAULT_CONFIG = File::Spec->catfile($BASE, "config", "domain_dns_audit.json");

# --- CLI-Optionen ---
my ($opt_domain, $opt_config, $opt_debug, $opt_dry_run, $opt_version, $opt_help, $opt_max_procs, $opt_fast);
GetOptions(
    'domain=s'    => \$opt_domain,
    'config=s'    => \$opt_config,
    'debug'       => \$opt_debug,
    'dry-run'     => \$opt_dry_run,
    'max-procs=i' => \$opt_max_procs,
    'fast'        => \$opt_fast,
    'version'     => \$opt_version,
    'help'        => \$opt_help,
) or die "Ungültige Parameter. Nutze --help\n";

# --- Hilfe & Version ---
if ($opt_help) {
    print <<"USAGE";
domain_dns_audit.pl v@{[VERSION]} (HEC Edition)

Optionen:
  --domain <domain>     Nur diese Domain prüfen
  --config <file>       Pfad zur JSON-Konfiguration (default: $DEFAULT_CONFIG)
  --debug               Debug-Logging aktivieren
  --dry-run             Kein Report schreiben (nur Prüfung)
  --max-procs <n>       Parallelität (default: runtime.max_procs)
  --fast                Schnellmodus: DANE/MTA-STS nur wenn im Profil 'require=true'
  --version             Version anzeigen
  --help                Diese Hilfe anzeigen

USAGE
    exit 0;
}

if ($opt_version) {
    print "domain_dns_audit Version @{[VERSION]}\n";
    exit 0;
}

# --- Globale Variablen ---
my ($log, $conf, $PROFILE_CONF, $DNS_CONF, $DOMAINS_CONF, $OUT_CONF, $RUNTIME_CONF);
my ($MAX_PROCS, %DNS_CACHE, $PSL_REF);

# DNS Cache LRU Meta
my %DNS_CACHE_LRU;
my $DNS_CACHE_TICK = 0;

use constant {
    DNS_CACHE_MAX      => 1000,
    DNS_CACHE_PURGE_TO => 800,
};

# --- Helferfunktionen ---
sub _trim {
    my ($s) = @_;
    $s //= "";
    $s =~ s/^\s+|\s+$//g;
    return $s;
}

sub _as_list {
    my ($v) = @_;
    return () unless defined $v;
    return ref($v) eq 'ARRAY' ? @$v : ($v);
}

sub _lcset {
    my %h;
    for my $v (@_) {
        next unless defined $v;
        my $x = lc($v);
        $x =~ s/\.$//;
        next unless $x ne "";
        $h{$x} = 1;
    }
    return \%h;
}

sub is_valid_domain {
    my ($domain) = @_;
    return 0 unless $domain;
    $domain = lc $domain;
    return 0 if $domain =~ /\s/;
    return 0 if $domain !~ /^[a-z0-9.-]+\.[a-z]{2,}$/;
    return 0 if $domain =~ /\.\./;
    return 1;
}

sub load_config {
    my ($file) = @_;
    die "Konfigurationsdatei fehlt: $file\n" unless $file && -f $file;

    open my $fh, '<:encoding(UTF-8)', $file or die "Kann Konfiguration nicht öffnen: $file: $!";
    local $/;
    my $raw = <$fh>;
    close $fh;

    my $data = eval { decode_json($raw) };
    die "JSON-Fehler in $file: $@\n" if $@;
    return $data;
}

sub atomic_write_json {
    my ($target_file, $data) = @_;
    die "atomic_write_json: target_file fehlt\n" unless defined $target_file && $target_file ne "";

    my $dir = dirname($target_file);
    make_path($dir) unless -d $dir;

    # Tempfile im gleichen Verzeichnis, damit rename wirklich atomar ist
    my ($fh, $tmp) = tempfile(
        "domain_dns_audit_XXXX",
        DIR    => $dir,
        SUFFIX => ".tmp",
        UNLINK => 0,    # wir loeschen selber, sicherer bei rename
    );

    eval {
        binmode($fh, ":encoding(UTF-8)") or die "binmode fehlgeschlagen: $!";

        my $json = encode_json($data);
        print $fh $json or die "Write fehlgeschlagen: $!";

        # Wichtig: Daten wirklich raus auf Disk, damit es nicht nur im Buffer ist
        close($fh) or die "Kann temporäre Datei nicht schließen: $!";

        rename($tmp, $target_file) or die "Kann $tmp nach $target_file nicht umbenennen: $!";

        1;
    } or do {
        my $err = $@ || "unbekannter Fehler";
        # best effort cleanup
        eval { close($fh) if $fh; 1 };
        eval { unlink($tmp) if $tmp && -e $tmp; 1 };
        die $err;
    };

    return 1;
}

sub dated_output_path {
    my ($path, $date) = @_;
    $date //= strftime("%Y%m%d", localtime);

    return File::Spec->catfile($BASE, "json", "domain_dns_audit_$date.json") unless $path;

    if ($path =~ /%Y%m%d/) {
        $path =~ s/%Y%m%d/$date/g;
        return $path;
    }
    elsif ($path =~ /\.json$/i) {
        my ($base, $suffix) = basename($path) =~ /^(.*?)(\.json)$/i;
        return File::Spec->catfile(dirname($path), $base . "_" . $date . $suffix);
    }
    else {
        return File::Spec->catfile($path, "domain_dns_audit_$date.json");
    }
}

sub worst_status {
    my @statuses = @_;
    my $worst = "ok";
    for my $s (@statuses) {
        next unless $s;
        $worst = "warn" if $s eq "warn" && $worst eq "ok";
        $worst = "fail" if $s eq "fail";
    }
    return $worst;
}

# --- DNS-Funktionen ---
sub build_resolver {
    my ($dns_conf) = @_;
    $dns_conf //= {};

    my $res = Net::DNS::Resolver->new;

    my $use_dnssec = exists $dns_conf->{dnssec} ? $dns_conf->{dnssec} : 1;
    $res->dnssec($use_dnssec);

    # EDNS0 UDP Size klein halten (hilft gegen Fragment-Drops)
    my $udp_size = $dns_conf->{edns_udp_size} // 1232;
    eval { $res->udppacketsize($udp_size); 1 } or do {};
    eval { $res->edns_size($udp_size); 1 } or do {};

    my $ns = $dns_conf->{nameservers} // $dns_conf->{servers};
    if (ref($ns) eq 'ARRAY' && @$ns) {
        $res->nameservers(@$ns);
    }

    $res->udp_timeout($dns_conf->{udp_timeout} // DEFAULT_DNS_TIMEOUT);
    $res->tcp_timeout($dns_conf->{tcp_timeout} // 20);
    $res->retrans($dns_conf->{retrans} // 2);
    $res->retry($dns_conf->{retry} // 2);

    return $res;
}

sub _dns_cache_key {
    my ($name, $type) = @_;
    $name = lc(_trim($name // ""));
    $name =~ s/\.$//;
    $type = uc(_trim($type // ""));
    return "$type|$name";
}


sub _dns_cache_purge_if_needed {
    my $size = scalar(keys %DNS_CACHE);
    return if $size <= DNS_CACHE_MAX;

    my $target = DNS_CACHE_PURGE_TO;
    $target = int(DNS_CACHE_MAX * 0.8) if $target >= DNS_CACHE_MAX;

    my @keys_by_oldest = sort {
        ($DNS_CACHE_LRU{$a} // 0) <=> ($DNS_CACHE_LRU{$b} // 0)
    } keys %DNS_CACHE;

    my $to_remove = $size - $target;
    $to_remove = 0 if $to_remove < 0;

    for my $i (0 .. $to_remove - 1) {
        my $k = $keys_by_oldest[$i];
        delete $DNS_CACHE{$k};
        delete $DNS_CACHE_LRU{$k};
    }

	if ($log && eval { $log->can('debug') }) {
		$log->debug("[DNS] Cache bereinigt: $size -> " . scalar(keys %DNS_CACHE));
	}
}



sub safe_dns_query {
    my ($resolver, $name, $type, $max_retries, $timeout) = @_;
    $type       //= 'A';
    $max_retries //= MAX_DNS_RETRIES;
    $timeout    //= DEFAULT_DNS_TIMEOUT;

    my $key = _dns_cache_key($name, $type);
    if (exists $DNS_CACHE{$key}) {
        $DNS_CACHE_LRU{$key} = ++$DNS_CACHE_TICK;
        return $DNS_CACHE{$key};
    }

    my $retry_delay = 1;
    for my $attempt (1 .. $max_retries) {
        my ($pkt, $timed_out);

        eval {
            local $SIG{ALRM} = sub { $timed_out = 1; die "TIMEOUT\n" };
            alarm $timeout;
            $pkt = $resolver->query($name, $type);
            alarm 0;
        };
        alarm 0;

        if ($@) {
            my $err = $@;
            if ($err =~ /TIMEOUT/ || $timed_out) {
                $log->debug("[DNS] Timeout bei $name ($type), Versuch $attempt/$max_retries");
            } else {
                $log->debug("[DNS] Fehler bei $name ($type): $err");
            }
            sleep $retry_delay if $attempt < $max_retries;
            $retry_delay *= 1.5;
            next;
        }

		if ($pkt) {
			$DNS_CACHE{$key} = $pkt;
			$DNS_CACHE_LRU{$key} = ++$DNS_CACHE_TICK;

			_dns_cache_purge_if_needed();

			return $pkt;
		}

        sleep $retry_delay if $attempt < $max_retries;
    }

	$DNS_CACHE{$key} = undef;
	$DNS_CACHE_LRU{$key} = ++$DNS_CACHE_TICK;

	_dns_cache_purge_if_needed();

	return;

}

sub get_txt_records {
    my ($resolver, $name, $timeout) = @_;
    my $pkt = safe_dns_query($resolver, $name, 'TXT', MAX_DNS_RETRIES, $timeout);
    return () unless $pkt;

    my @txt;
    for my $rr ($pkt->answer) {
        next unless $rr->type eq "TXT";
        my $t = $rr->txtdata;
        if (ref($t) eq 'ARRAY') {
            push @txt, join("", @$t);
        } elsif (defined $t) {
            push @txt, $t;
        }
    }
    return @txt;
}

sub resolve_cname_target {
    my ($resolver, $name, $max_hops, $timeout) = @_;
    $max_hops //= MAX_CNAME_HOPS;

    my %seen;
    my $cur = lc($name // "");
    $cur =~ s/\.$//;

    for (my $i = 0; $i < $max_hops; $i++) {
        if ($seen{$cur}++) {
            $log->warn("CNAME-Schleife erkannt: $name → $cur");
            return "";
        }

        my $pkt = safe_dns_query($resolver, $cur, 'CNAME', MAX_DNS_RETRIES, $timeout);
        return "" unless $pkt;

        my ($cname_rr) = grep { $_->type eq 'CNAME' } $pkt->answer;
        return "" unless $cname_rr;

        my $target = lc($cname_rr->cname // "");
        $target =~ s/\.$//;
        return "" if !$target || $target eq $cur;
        $cur = $target;
    }

    return "";
}


sub get_txt_records_follow_cname {
    my ($resolver, $name, $timeout) = @_;
    my @txt = get_txt_records($resolver, $name, $timeout);
    return (\@txt, "") if @txt;

    my $target = resolve_cname_target($resolver, $name, MAX_CNAME_HOPS, $timeout);
    return ([], "") unless $target;

    my @txt2 = get_txt_records($resolver, $target, $timeout);
    return (\@txt2, $target);
}

sub get_mx_records {
    my ($resolver, $domain, $timeout) = @_;
    my $pkt = safe_dns_query($resolver, $domain, 'MX', MAX_DNS_RETRIES, $timeout);
    return () unless $pkt;

    my @mx = map {
        { preference => $_->preference, exchange => lc($_->exchange) }
    } grep { $_->type eq "MX" } $pkt->answer;

    @mx = sort { $a->{preference} <=> $b->{preference} } @mx;
    return @mx;
}

# --- Public Suffix / Organizational Domain Logik ---

sub load_public_suffix_list {
    my ($custom_path) = @_;
    my $psl_file = $custom_path || File::Spec->catfile($BASE, "public_suffix_list.dat");

    # Kein Download – nur laden, wenn die Datei existiert
    unless (-f $psl_file) {
        $log->warn("PSL Datei nicht gefunden unter $psl_file. Nutze verbesserte Heuristik.");
        return undef;
    }

    my %psl;
    if (open my $fh, '<:encoding(UTF-8)', $psl_file) {
        while (my $line = <$fh>) {
            $line =~ s/^\s+|\s+$//g;
            next if !$line || $line =~ m|^//|;
            $line =~ s/^[\*\!]//; # Wildcards/Exceptions vereinfachen
            $psl{lc($line)} = 1;
        }
        close $fh;
        $log->debug("PSL geladen (" . scalar(keys %psl) . " Einträge).");
        return \%psl;
    }
    return undef;
}

sub get_organizational_domain {
    my ($domain) = @_;
    $domain = lc(_trim($domain));
    return "" unless $domain;

    my @parts = split(/\./, $domain);
    return $domain if @parts <= 1;

    # 1) Wenn PSL geladen wurde, nutze sie (Präzision geht vor)
    if ($PSL_REF) {
        for (my $i = 0; $i < @parts; $i++) {
            my $current_suffix = join('.', @parts[$i .. $#parts]);
            if (exists $PSL_REF->{$current_suffix}) {
                return ($i > 0) ? join('.', @parts[$i-1 .. $#parts]) : $domain;
            }
        }
    }

    # 2) Erweiterte Heuristik ohne PSL
    my $tld = $parts[-1];
    my $sld = $parts[-2] // "";
    my $t3  = $parts[-3] // "";   # third-level label (von rechts)

    # A) Sehr haeufige "funktionale" Second-Level-Labels bei ccTLDs
    my %functional_sld = map { $_ => 1 } qw(
        com co net org gov edu ac ad nom mil
        info biz name pro
    );

    # B) ccTLDs mit gut bekannten Registry-Strukturen (2nd-level Registry)
    my $is_cc = (length($tld) == 2) ? 1 : 0;

    if ($is_cc && $functional_sld{$sld}) {
        return join('.', @parts[-3 .. -1]) if @parts >= 3;
        return join('.', @parts[-2 .. -1]);
    }

    # C) Japan Sonderfaelle (ohne PSL) schlank:
    # typische Registry-Labels + "city"
    if ($tld eq "jp" && @parts >= 4) {
        my %jp_registry = map { $_ => 1 } qw(ac ed go gr lg ne or);

        if ($jp_registry{$sld} || $jp_registry{$t3} || $sld eq "city" || $t3 eq "city") {
            # Beispiel: host.example.city.kawasaki.jp -> example.city.kawasaki.jp
            return join('.', @parts[-4 .. -1]);
        }
    }

    # D) USA K12 Sonderfaelle (ohne PSL) korrekt:
    # school.k12.ca.us -> org domain oft auf 4th level
    if ($tld eq "us" && @parts >= 4) {
        if ($parts[-3] eq "k12" && $parts[-2] =~ /^[a-z]{2}$/) {
            return join('.', @parts[-4 .. -1]);  # example.k12.ca.us
        }
    }

    # E) Multipart-TLDs die keine ccTLD sind, z.B. uk.com, eu.com
    if ($tld =~ /^(com|org|net)$/ && $sld =~ /^(uk|eu|de|jp|us|gb|co)$/) {
        return join('.', @parts[-3 .. -1]) if @parts >= 3;
        return join('.', @parts[-2 .. -1]);
    }

    # F) fallback: 2 Labels (Standard)
    return join('.', @parts[-2 .. -1]);
}


sub is_same_organizational_domain {
    my ($dom1, $dom2) = @_;
    return 1 if lc(_trim($dom1 // "")) eq lc(_trim($dom2 // ""));

    my $base1 = get_organizational_domain($dom1);
    my $base2 = get_organizational_domain($dom2);

    return ($base1 ne "" && $base1 eq $base2) ? 1 : 0;
}



# --- DKIM/ARC-Funktionen ---
sub parse_dkim_txt_kv {
    my ($rec) = @_;
    $rec = _trim($rec // "");
    return {} unless $rec;

    my %kv;
    for my $part (split /\s*;\s*/, $rec) {
        $part = _trim($part);
        next unless $part;

        my ($k, $v) = split(/\s*=\s*/, $part, 2);
        $k = lc(_trim($k // ""));
        next unless $k;

        $v = _trim($v // "");
        if (defined $v) {
            if ($k eq 'p') {
                $v =~ s/\s+//g;
            }
            elsif ($k eq 'v' || $k eq 'k') {
                $v = lc($v);
            }
            $kv{$k} = $v;
        }
    }

    # Standardwerte für fehlende Schlüssel setzen
    $kv{v} //= "";
    $kv{k} //= "rsa";
    $kv{p} //= "";

    return \%kv;
}

sub dkim_expected_match {
    my ($actual_rec, $expected_rec) = @_;
    $actual_rec   //= "";
    $expected_rec //= "";
    return 1 if _trim($expected_rec) eq "";

    my $a = parse_dkim_txt_kv($actual_rec);
    my $e = parse_dkim_txt_kv($expected_rec);

    for my $k (keys %$e) {
        return 0 unless exists $a->{$k};
        return 0 unless defined $a->{$k} && defined $e->{$k};
        return 0 unless $a->{$k} eq $e->{$k};
    }
    return 1;
}

my $_openssl_path_cache;
sub _openssl_present {
    return $_openssl_path_cache if defined $_openssl_path_cache;
    my $p = `command -v openssl 2>/dev/null`;
    chomp($p);
    $_openssl_path_cache = $p ? 1 : 0;
    return $_openssl_path_cache;
}

sub dkim_key_bits_rsa {
    my ($rec) = @_;
    my $kv = parse_dkim_txt_kv($rec);

    return (0, "invalid: p-tag fehlt") unless exists $kv->{p};
    if (defined $kv->{p} && $kv->{p} eq "") {
        return (0, "revoked");
    }

    my $p = $kv->{p};
    $p =~ s/\s+//g; 

    return (0, "openssl nicht vorhanden") unless _openssl_present();

    my $pem = "-----BEGIN PUBLIC KEY-----\n" .
              join("\n", ($p =~ /.{1,64}/g)) .
              "\n-----END PUBLIC KEY-----\n";

    my $output = "";
    my ($child_out, $child_in);
    my $pid;

    # Try-Block für die Ausführung
    try {
        # Lokaler Alarm-Handler für diesen Block (max 3 Sekunden für OpenSSL)
        local $SIG{ALRM} = sub { die "OPENSSL_TIMEOUT\n" };
        alarm 3;

        # Prozess starten (STDERR wird nach STDOUT umgeleitet via 2>&1)
        $pid = open2($child_out, $child_in, 'openssl pkey -pubin -text -noout 2>&1');
        
        # Daten schreiben
        print $child_in $pem;
        close($child_in); # Wichtig: Signalisiert OpenSSL das Ende der Eingabe
        
        # Ergebnis lesen
        $output = do { local $/; <$child_out> };
        
        # Prozess ordnungsgemäß beenden
        waitpid($pid, 0);
        alarm 0; # Alarm deaktivieren
    } 
    catch {
        alarm 0;
        # Im Fehlerfall (Timeout oder Crash): Prozess aufräumen
        if ($pid) {
            kill('KILL', $pid);
            waitpid($pid, 0); # Zombie-Vermeidung
        }
        $log->error("Fehler beim OpenSSL-Aufruf: $_");
        return (0, "openssl_error: $_");
    };

    # Auswertung
    if ($output =~ /ED25519 Public-Key/i) {
        return (256, "ed25519");
    }
    elsif ($output =~ /Public-Key:\s*\((\d+)\s*bit\)/i) {
        return (int($1), "rsa");
    }
    else {
        return (0, "invalid_key_format");
    }
}

# --- Profil-Matching ---
sub profile_matches_domain {
    my ($profile, $domain) = @_;
    return 1 unless ref($profile) eq 'HASH';

    my $match = $profile->{match};
    return 1 unless ref($match) eq 'HASH';

    if (my $domains = $match->{domains}) {
        return 0 unless grep { defined && lc($_) eq lc($domain) } @$domains;
    }

    if (my $suffixes = $match->{suffixes}) {
        for my $s (@$suffixes) {
            next unless $s;
            my $suf = lc($s);
            $suf =~ s/^\*\.//;
            return 1 if lc($domain) =~ /\Q$suf\E$/;
        }
        return 0;
    }

    return 1;
}

# --- Checks: MX ---
sub check_mx {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "MX nicht gefordert", rfc => "RFC 5321" }
        unless $profile->{require_mx};

    my @mx = get_mx_records($resolver, $domain, $timeout);
    if (!@mx) {
        return {
            status  => "fail",
            message => "Keine MX Records gefunden",
            rfc     => "RFC 5321",
            mx      => [],
        };
    }

    my @ex = map { lc($_->{exchange} // "") } @mx;
    my $status = "ok";
    my @notes;

    # --- NEU: MX-Target Validierung ---
    for my $mxh (@ex) {
        my $target = $mxh;
        $target =~ s/\.$//; # Punkt am Ende entfernen für die Abfrage
        next unless $target;

        # Prüfe, ob der Host mindestens eine IPv4 (A) oder IPv6 (AAAA) Adresse hat
        my $pkt_a    = safe_dns_query($resolver, $target, 'A', 1, 2);
        my $pkt_aaaa = safe_dns_query($resolver, $target, 'AAAA', 1, 2);

        my $has_ip = 0;
		$has_ip = 1 if ($pkt_a    && grep { $_->type eq 'A'    } $pkt_a->answer);
		$has_ip = 1 if ($pkt_aaaa && grep { $_->type eq 'AAAA' } $pkt_aaaa->answer);

        unless ($has_ip) {
            $status = "fail";
            push @notes, "Kritisch: MX-Host '$target' hat keine IP-Adresse (A oder AAAA Record fehlt).";
        }
    }
    # ----------------------------------

    # Bestehende Policy-Prüfung (groups)
    if (my $groups = $profile->{mx_policy}{groups}) {
        # ... (dein restlicher Code für mx_policy) ...
        # Wichtig: Falls die Policy-Prüfung scheitert, bleibt status auf 'fail'
    }

    return {
        status  => $status,
        message => $status eq 'ok' ? "MX vorhanden und erreichbar" : "MX Konfigurationsfehler",
        rfc     => "RFC 5321",
        mx      => \@ex,
        notes   => \@notes,
    };
}

# --- Checks: SPF ---
sub count_spf_lookups_recursive {
    my ($resolver, $domain, $seen, $depth) = @_;
    $seen  //= {};
    $depth //= 0;

    $domain = lc(_trim($domain // ""));
    return 0 if $domain eq "";
    return 0 if $depth >= MAX_SPF_LOOKUPS;
    return 0 if $seen->{$domain}++;

    my @txt = get_txt_records($resolver, $domain, DEFAULT_DNS_TIMEOUT);
    my ($spf) = grep { /^v=spf1(\s|$)/i } @txt;
    return 0 unless $spf;

    my $count = 0;

    my @tokens = split(/\s+/, lc($spf));
    shift @tokens if @tokens && $tokens[0] =~ /^v=spf1$/;

    for my $t (@tokens) {
        $t = _trim($t);
        next if $t eq "";

        if ($t =~ /^[-+~?]?include:(.+)$/i) {
            my $target = lc(_trim($1));
            next if $target eq "";
            $count++;
            $count += count_spf_lookups_recursive($resolver, $target, $seen, $depth + 1);
            next;
        }

        if ($t =~ /^redirect=(.+)$/i) {
            my $target = lc(_trim($1));
            next if $target eq "";
            $count++;
            $count += count_spf_lookups_recursive($resolver, $target, $seen, $depth + 1);
            next;
        }

        if ($t =~ /^[-+~?]?(a|mx|ptr|exists)(?::[^ ]+)?$/i) {
            $count++;
            next;
        }
    }

    return $count;
}


sub check_spf {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "SPF nicht gefordert", rfc => "RFC 7208" }
        unless $profile->{require_spf};

    my @txt = get_txt_records($resolver, $domain, $timeout);

    # --- 1. PRÜFUNG: Mehrfach-SPF-Records (RFC 7208 §4.5) ---
    my @spf_candidates = grep { /^v=spf1(\s|$)/i } @txt;
    if (@spf_candidates > 1) {
        return {
            status  => "fail",
            message => "Mehrere SPF Records gefunden (RFC 7208 §4.5)",
            rfc     => "RFC 7208",
            record  => join(" | ", @spf_candidates),
            notes   => [
                "Gefunden: " . scalar(@spf_candidates) . " SPF-Records.",
                "Empfänger-Server geben 'PermError' zurück und ignorieren SPF.",
                "Lösung: Behalte nur einen SPF-Record und entferne die anderen."
            ],
        };
    }

    my $spf = $spf_candidates[0];
    unless ($spf) {
        return {
            status  => "fail",
            message => "Kein SPF Record gefunden (RFC 7208 §3.1)",
            rfc     => "RFC 7208",
            record  => "",
            notes   => ["Ohne SPF können Empfänger die Authentizität von HEC-E-Mails nicht prüfen."]
        };
    }

    # --- Initialisierung ---
    my $status = "ok";
    my @notes;
    my %seen_mechanisms;          # Für exakte Duplikate (z. B. doppelte "include:_spf.hec.ch")
    my %seen_mechanism_types;     # Für redundante Mechanismen (z. B. doppeltes "mx")
    my $has_redirect = 0;

    # Token parsen (ohne 'v=spf1')
    my @tokens = split /\s+/, $spf;
    shift @tokens;  # Entferne 'v=spf1'

    # --- 2. PRÜFUNG: Mechanismen-Logik ---
    for (my $i = 0; $i < @tokens; $i++) {
        my $t = $tokens[$i];

        # A) Veralteter 'ptr'-Mechanismus (RFC 7208 §5.5)
        if ($t =~ /^[-+~?]?ptr[:=]?/i) {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: 'ptr'-Mechanismus ist veraltet (RFC 7208 §5.5) und unsicher. " .
                         "Ersetze ihn durch 'ip4'/'ip6' oder 'a'/mx' (HEC-Standard).";
        }

        # B) 'all'-Mechanismus: Position und Typ (RFC 7208 §5.1)
        if ($t =~ /all$/i) {
            # Position prüfen
            if ($i < $#tokens) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: '$t' steht nicht am Ende (RFC 7208 §6.1). " .
                             "Regeln danach werden ignoriert: " . join(" ", @tokens[$i+1 .. $#tokens]);
            }

            # Typ prüfen
            if ($t =~ /^\+?all$/i) {  # +all oder implizites all
                $status = worst_status($status, "fail");
                push @notes, "KRITISCH: '$t' erlaubt jedem den Versand! " .
                             "HEC-Richtlinie: Nutze '-all' (HardFail) oder '~all' (SoftFail).";
            }
            elsif ($t =~ /^~all$/i) {
                $status = worst_status($status, "warn");
                push @notes, "Hinweis: '~all' (SoftFail) ist weniger sicher als '-all' (HardFail, HEC-Empfehlung).";
            }
            elsif ($t =~ /^-all$/i) {
                push @notes, "Info: '-all' (HardFail) ist korrekt nach HEC-Richtlinien konfiguriert.";
            }
        }

        # C) 'redirect'-Modifikator (RFC 7208 §6.1)
        if ($t =~ /^redirect=/i) {
            if ($has_redirect) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Mehrere 'redirect=' gefunden (RFC 7208 §6.1). Nur einer erlaubt!";
            }
            if ($i < $#tokens) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: 'redirect=' muss am Ende stehen (RFC 7208 §6.1).";
            }
            $has_redirect = 1;
        }

        # D) Exakte Duplikate (z. B. doppelte "include:_spf.hec.ch")
        if ($seen_mechanisms{$t}++) {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: Der Eintrag '$t' ist doppelt vorhanden. " .
                         "HEC-Empfehlung: Entferne Duplikate, um Lookups zu sparen.";
        }

        # E) Redundante Mechanismus-Typen (z. B. doppeltes "mx" oder "a")
        my ($mechanism_type) = $t =~ /^([^\s:]+)/;
        if ($mechanism_type && $mechanism_type !~ /all$/i && $seen_mechanism_types{$mechanism_type}++) {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: Mechanismus-Typ '$mechanism_type' ist mehrfach definiert. " .
                         "Prüfe, ob alle Einträge (z. B. verschiedene 'include'-Domains) benötigt werden.";
        }
    }

    # --- 3. HEC-SPEZIFISCHE PRÜFUNG: Erforderliche Mechanismen ---
    if (my $groups = $profile->{spf_policy}{groups}) {
        my %token_set = map { _trim($_) =~ s/^\+//r => 1 }
                        grep { _trim($_) ne "" }
                        @tokens;

        for my $g (@$groups) {
            next unless ref($g) eq 'HASH';
            my @required = _as_list($g->{required_contains_any});
            next unless @required;

            my $ok = 0;
            for my $req (@required) {
                $req = _trim($req);
                $req =~ s/^\+//;
                $ok = 1 if $token_set{$req};
            }

            unless ($ok) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: SPF enthält keinen der HEC-Pflicht-Mechanismen: " .
                             join(", ", @required) .
                             (($g->{name}) ? " (Gruppe: $g->{name})" : "") .
                             ". Füge diese gemäß HEC-Richtlinie hinzu.";
            }
        }
    }

    # --- 4. DNS-LOOKUP-LIMIT (RFC 7208 §4.6.4) ---
    my $lookup_count = count_spf_lookups_recursive($resolver, $domain);
    if ($lookup_count > MAX_SPF_LOOKUPS) {
        $status = worst_status($status, "fail");
        push @notes, "FEHLER: SPF Lookup-Limit überschritten ($lookup_count/" . MAX_SPF_LOOKUPS . "). " .
                     "HEC-Richtlinie: Maximal 10 Lookups (RFC 7208 §4.6.4). " .
                     "Verringere die Anzahl der 'include:'-Mechanismen.";
    } else {
        push @notes, "Info: SPF Lookups: $lookup_count/" . MAX_SPF_LOOKUPS . " (OK).";
    }

    # --- ERGEBNIS ---
    my $message = {
        fail => "SPF-Policy verletzt HEC-Richtlinien (RFC 7208)",
        warn => "SPF vorhanden mit Warnungen (HEC-Prüfung)",
        ok   => "SPF Record ist valide und HEC-konform"
    }->{$status};

    return {
        status       => $status,
        message      => $message,
        rfc          => "RFC 7208",
        record       => $spf,
        notes        => \@notes,
        lookup_count => $lookup_count,
    };
}


# --- Checks: DMARC ---
sub check_dmarc {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "DMARC nicht gefordert", rfc => "RFC 7489" }
        unless $profile->{require_dmarc};

    my $name = "_dmarc.$domain";
    my @txt = get_txt_records($resolver, $name, $timeout);

    # --- 1. PRÜFUNG: Mehrfach-Records (RFC 7489 §6.6.3) ---
    my @dmarc_candidates = grep { /^v=DMARC1(\s|;|$)/i } @txt;
    if (@dmarc_candidates > 1) {
        return {
            status  => "fail",
            message => "Mehrere DMARC Records gefunden (RFC 7489 §6.6.3)",
            rfc     => "RFC 7489",
            record  => join(" | ", @dmarc_candidates),
            notes   => [
                "Gefunden: " . scalar(@dmarc_candidates) . " DMARC-Records.",
                "Empfänger-Server ignorieren DMARC komplett, wenn mehr als ein Record existiert.",
                "Lösung: Behalte nur einen validen DMARC-Record."
            ],
        };
    }

    my $rec = $dmarc_candidates[0];
    unless ($rec) {
        return {
            status  => "fail",
            message => "Kein DMARC Record gefunden (RFC 7489 §6.1)",
            rfc     => "RFC 7489",
            record  => "",
            notes   => ["Ohne DMARC erhalten Empfänger keine Anweisung für nicht authentifizierte Mails."]
        };
    }

    # --- Initialisierung & Parsing ---
    my $status = "ok";
    my @notes;
    my %tags;

    for my $part (split /\s*;\s*/, $rec) {
        next unless $part =~ /=/;
        my ($k, $v) = split(/\s*=\s*/, $part, 2);
        $k = lc(_trim($k // ""));
        $v = _trim($v // "");
        $tags{$k} = $v if $k;
    }

    # --- 2. PRÜFUNG: Unbekannte/Fehlerhafte Tags (RFC 7489 §6.3) ---
    my %valid_tags = map { $_ => 1 } qw(v p rua ruf pct adkim aspf sp fo ri rf);
    for my $tag (keys %tags) {
        unless ($valid_tags{$tag}) {
            push @notes, "Hinweis: Unbekanntes DMARC-Tag '$tag=' gefunden. Tippfehler? (RFC 7489 §6.3).";
            $status = worst_status($status, "warn");
        }
    }

    # --- 3. PRÜFUNG: Policy (p=) (RFC 7489 §6.1) ---
    my $p = $tags{p} // "";
    if (!$p) {
        $status = worst_status($status, "fail");
        push @notes, "FEHLER: 'p=' Tag (Policy) fehlt (RFC 7489 §6.1).";
    } else {
        if (my @okp = _as_list($profile->{dmarc_ok_policies})) {
            unless (grep { $_ eq $p } @okp) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Policy 'p=$p' entspricht nicht den Sicherheitsvorgaben.";
            }
        }
        if ($p eq "none") {
            $status = worst_status($status, "warn");
            push @notes, "Hinweis: 'p=none' ist nur Monitoring. Ziel: 'p=quarantine' oder 'p=reject'.";
        }
    }

    # --- 4. PRÜFUNG: Reporting URIs (rua & ruf) & External Authorization (RFC 7489 §7.1) ---
    for my $tag_name (qw(rua ruf)) {
        if ($tags{$tag_name}) {
            my @uris = split(/\s*,\s*/, $tags{$tag_name});
            for my $uri (@uris) {
                if ($uri =~ /mailto:.*\@([a-z0-9.-]+)/i) {
                    my $report_domain = lc($1);
                    if (!is_same_organizational_domain($domain, $report_domain)) {
                        # Prüfe External Reporting Authorization (ERA)
                        my $verify_name = "$domain._report._dmarc.$report_domain";
                        my @v_txt = get_txt_records($resolver, $verify_name, $timeout);
                        my ($v_rec) = grep { /^v=DMARC1(\s|;|$)/i } @v_txt;
                        unless ($v_rec) {
                            $status = worst_status($status, "fail");
                            push @notes, "KRITISCH: Externe $tag_name-Domain '$report_domain' hat keine Berechtigung erteilt ($verify_name fehlt).";
                        }
                    }
                } else {
                    $status = worst_status($status, "fail");
                    push @notes, "FEHLER: Ungültiges '$tag_name=' Format: '$uri'.";
                }
            }
        } elsif ($tag_name eq 'rua') {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: Kein 'rua=' Tag (Reporting) gefunden.";
        }
    }

    # --- 5. PRÜFUNG: Alignment & Subdomain Policy ---
    for my $tag (qw(adkim aspf)) {
        if (exists $tags{$tag}) {
            unless ($tags{$tag} =~ /^(r|s)$/) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Ungültiger Wert für '$tag=': '$tags{$tag}'.";
            }
        }
    }
    if (exists $tags{sp}) {
        unless ($tags{sp} =~ /^(none|quarantine|reject)$/) {
            $status = worst_status($status, "fail");
            push @notes, "FEHLER: Ungültige Subdomain-Policy 'sp=$tags{sp}'.";
        }
    }

    # --- 6. PRÜFUNG: fo, ri, rf (Expert Tags) ---
    if (exists $tags{fo}) {
        my %valid_fo = map { $_ => 1 } qw(0 1 d s);
        for (split(/:/, $tags{fo})) {
            ($status = worst_status($status, "fail"), push @notes, "FEHLER: Ungültiger fo-Wert '$_'") unless $valid_fo{$_};
        }
    }
    if (exists $tags{ri}) {
        unless ($tags{ri} =~ /^\d+$/ && $tags{ri} >= 1) {
            $status = worst_status($status, "fail");
            push @notes, "FEHLER: Ungültiger 'ri=' Wert (muss positive Zahl sein).";
        }
    }
    if (exists $tags{rf}) {
        my %valid_rf = map { $_ => 1 } qw(afrf iodef);
        for (split(/:/, $tags{rf})) {
            ($status = worst_status($status, "fail"), push @notes, "FEHLER: Ungültiger rf-Wert '$_'") unless $valid_rf{$_};
        }
    }

    # --- ERGEBNIS ---
    my $message = { fail => "DMARC-Policy verletzt RFC 7489", warn => "DMARC mit Warnungen", ok => "DMARC ist valide" }->{$status};

    return {
        status  => $status,
        message => $message,
        rfc     => "RFC 7489",
        record  => $rec,
        policy  => $p,
        notes   => \@notes,
        tags    => \%tags,
    };
}

# --- Checks: DKIM ---
sub check_dkim {
    my ($resolver, $domain, $profile, $timeout) = @_;
    
    # Initialer Skip-Check
    return { status => "skip", message => "DKIM nicht gefordert", rfc => "RFC 6376", found => [] }
        unless $profile->{require_dkim};

    my @selectors = _as_list($profile->{dkim_selectors});
    unless (@selectors) {
        return {
            status  => "fail",
            message => "Keine dkim_selectors im Profil definiert",
            rfc     => "RFC 6376",
            found   => [],
        };
    }

    my $pol = $profile->{dkim_policy} || {};
    my $expected = $pol->{expected_txt} || {};
    my $eval_mode = lc($pol->{evaluation_mode} || "any_ok");

    my (@found, @notes);
    for my $sel (@selectors) {
        my $name = "$sel._domainkey.$domain";
        my ($txt_ref, $cname_target) = get_txt_records_follow_cname($resolver, $name, $timeout);
        my @txt = @$txt_ref;

        if ($cname_target) {
            push @notes, "DKIM $sel: Verweist via CNAME auf $cname_target";
        }

        # DKIM Record identifizieren (v=DKIM1 muss nicht zwingend am Anfang stehen, ist aber üblich)
        my ($rec) = grep { /v=DKIM1/i } @txt;
        # Falls kein v=DKIM1 da ist, aber TXT Records existieren, 
        # besagt RFC 6376, dass es trotzdem DKIM sein kann (v ist optional).
        ($rec) = @txt if !defined $rec && @txt;

        next unless $rec;

        my $kv = parse_dkim_txt_kv($rec);
        my $v_tag = lc($kv->{v} // "");
        my $k_tag = lc($kv->{k} // "rsa");

        # Prüfung der Tags
        my $ok_contains = ($v_tag eq "" || $v_tag eq "dkim1") && ($k_tag eq "rsa" || $k_tag eq "ed25519");
        
        # Abgleich mit Erwartungswert aus Profil
        my $ok_expected = 1;
        if (ref($expected) eq 'HASH' && exists $expected->{$sel}) {
            my $want = $expected->{$sel} // "";
            if (_trim($want) ne "") {
                $ok_expected = dkim_expected_match($rec, $want) ? 1 : 0;
                push @notes, "DKIM $sel: Record-Inhalt entspricht nicht der Vorgabe" unless $ok_expected;
            }
        }

        # Key-Stärke und Revocation prüfen
        my ($bits, $type_or_err) = dkim_key_bits_rsa($rec);
        my $strength = "unknown";
        my $is_revoked = 0;

        if ($type_or_err eq "revoked") {
            $is_revoked = 1;
            $strength = "revoked";
            push @notes, "DKIM $sel: Schlüssel wurde widerrufen (p= leer)";
        }
        elsif ($type_or_err eq "ed25519") {
            $strength = "ok";
        }
        elsif ($bits) {
            if ($bits < MIN_RSA_KEY_BITS) {
                $strength = "weak";
                push @notes, "DKIM $sel: RSA Schlüssel ist zu schwach ($bits Bit)";
            } else {
                $strength = "ok";
            }
        } else {
            push @notes, "DKIM $sel: Schlüsselprüfung fehlgeschlagen ($type_or_err)";
        }

        push @found, {
            selector     => $sel,
            record       => $rec,
            cname_target => ($cname_target // ""),
            ok_contains  => $ok_contains ? 1 : 0,
            ok_expected  => $ok_expected ? 1 : 0,
            key_bits     => $bits,
            key_strength => $strength,
            is_revoked   => $is_revoked,
        };
    }

    # Wenn gar kein Selektor gefunden wurde
    unless (@found) {
        return {
            status  => "fail",
            message => "Kein DKIM Record für die Selektoren gefunden: " . join(", ", @selectors),
            rfc     => "RFC 6376",
            found   => [],
            notes   => \@notes,
        };
    }

    # Ergebnis-Auswertung (Evaluation)
    my @individual_results;
    for my $f (@found) {
        if ($f->{is_revoked}) {
            push @individual_results, "warn"; # Revoked ist kein Fail, aber ein Achtung-Signal
        } elsif ($f->{ok_contains} && $f->{ok_expected} && $f->{key_strength} eq "ok") {
            push @individual_results, "ok";
        } elsif ($f->{key_strength} eq "weak") {
            push @individual_results, "warn";
        } else {
            push @individual_results, "fail";
        }
    }

    my $status = "fail";
    if ($eval_mode eq "all_ok") {
        $status = (grep { $_ ne "ok" } @individual_results) ? "fail" : "ok";
        # Wenn alles "ok" oder "warn" ist, stufen wir auf warn zurück statt fail
        if ($status eq "fail" && !(grep { $_ eq "fail" } @individual_results)) {
            $status = "warn";
        }
    } else {
        # default: any_ok
        $status = (grep { $_ eq "ok" } @individual_results) ? "ok" : 
                  (grep { $_ eq "warn" } @individual_results) ? "warn" : "fail";
    }

    return {
        status  => $status,
        message => $status eq "ok" ? "DKIM Prüfung erfolgreich" : 
                   $status eq "warn" ? "DKIM vorhanden mit Warnungen" : "DKIM Policy verletzt",
        rfc     => "RFC 6376",
        found   => \@found,
        notes   => \@notes,
    };
}

# --- Checks: ARC ---
sub check_arc {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "ARC nicht gefordert", rfc => "RFC 8617", found => [] }
        unless $profile->{require_arc};

    my @selectors = _as_list($profile->{arc_selectors});
    unless (@selectors) {
        return {
            status  => "fail",
            message => "Keine ARC Selektoren definiert",
            rfc     => "RFC 8617",
            found   => [],
        };
    }

    my @found;
    for my $sel (@selectors) {
        my $name = "$sel._domainkey.$domain";
        my ($txt_ref, $cname_target) = get_txt_records_follow_cname($resolver, $name, $timeout);
        my @txt = @$txt_ref;

        my ($rec) = grep { /^v=(DKIM1|ARC1)(\s|;|$)/i } @txt;
        next unless $rec;

        my ($bits, $type_or_err) = dkim_key_bits_rsa($rec);
        my $strength = "unknown";
        my $is_revoked = 0;

        if ($type_or_err eq "revoked") {
            $is_revoked = 1;
            $strength = "revoked";
        }
        elsif ($type_or_err eq "ed25519") {
            $strength = "ok";
        }
        elsif ($bits) {
            $strength = $bits < MIN_RSA_KEY_BITS ? "weak" : "ok";
        }

        push @found, {
            selector     => $sel,
            record       => $rec,
            cname_target => ($cname_target // ""),
            key_bits     => $bits,
            key_strength => $strength,
            is_revoked   => $is_revoked,
            key_error    => ($bits || $is_revoked ? "" : $type_or_err),
        };
    }

    unless (@found) {
        return {
            status  => "fail",
            message => "Kein ARC Key gefunden",
            rfc     => "RFC 8617",
            found   => [],
        };
    }

    my $status = "ok";
    # Warnung wenn ein Key schwach oder widerrufen ist
    if (grep { $_->{key_strength} eq 'weak' || $_->{is_revoked} } @found) {
        $status = "warn";
    }

    return {
        status  => $status,
        message => $status eq "ok" ? "ARC Keys vorhanden" : "ARC Keys vorhanden mit Warnungen",
        rfc     => "RFC 8617",
        found   => \@found,
    };
}

# --- Checks: MTA-STS ---
sub fetch_mta_sts_policy {
    my ($domain, $timeout) = @_;
    $timeout //= 6;
    my $url = "https://mta-sts.$domain/.well-known/mta-sts.txt";
    my $http = HTTP::Tiny->new(
        timeout     => $timeout,
        verify_SSL  => 1,
        agent       => "domain_dns_audit/@{[VERSION]}",
    );

    my $cur = $url;
    for (my $i = 0; $i <= MAX_HTTP_REDIRECTS; $i++) {
        my $res = $http->get($cur);
        unless ($res) {
            return (0, "HTTP request fehlgeschlagen", "", $cur);
        }

        # Handling von Redirects
        if ($res->{status} =~ /^(301|302|303|307|308)$/) {
            my $loc = _trim($res->{headers}{location} // "");
            unless ($loc) {
                return (0, "Redirect ohne Location Header", "", $cur);
            }
            unless ($loc =~ m/^https:\/\//i) {
                return (0, "Redirect nicht https: $loc", "", $cur);
            }
            $cur = $loc;
            next;
        }

        # Prüfung, ob der Status-Code 200-299 ist
        unless ($res->{success}) {
            return (0, "HTTP status $res->{status}", "", $cur);
        }

        # --- NEU: RFC 8461 Content-Type Check ---
        # HTTP::Tiny speichert Header-Keys immer in Kleinschreibung
        my $ct = $res->{headers}{'content-type'} // "";
        unless ($ct =~ m|^text/plain|i) {
            return (0, "Falscher Content-Type: $ct (erwartet text/plain)", "", $cur);
        }
        # ----------------------------------------

        my $body = $res->{content} // "";
        unless (length($body) > 0) {
            return (0, "Empty policy body", "", $cur);
        }

        return (1, "OK", $body, $cur);
    }

    return (0, "Zu viele Redirects", "", $cur);
}

sub parse_mta_sts_policy {
    my ($body) = @_;
    my %kv;
    for my $line (split /\n/, $body) {
        $line =~ s/\r$//;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq "" || $line =~ /^\s*#/;
        if ($line =~ /^([a-zA-Z_]+)\s*:\s*(.+)$/) {
            $kv{lc($1)} = $2;
        }
    }
    return \%kv;
}

sub check_mta_sts {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "MTA-STS nicht gefordert", rfc => "RFC 8461" }
        unless $profile->{require_mta_sts};

    my $name = "_mta-sts.$domain";
    my @txt = get_txt_records($resolver, $name, $timeout);
    my ($sts) = grep { /^v=STSv1(\s|;|$)/i } @txt;

    unless ($sts) {
        return {
            status  => "fail",
            message => "Kein MTA-STS TXT Record gefunden",
            rfc     => "RFC 8461",
            record  => "",
        };
    }

    my ($ok, $msg, $body, $url) = fetch_mta_sts_policy($domain, 6);
    unless ($ok) {
        return {
            status   => "fail",
            message  => "MTA-STS Policy nicht abrufbar",
            rfc      => "RFC 8461",
            record   => $sts,
            policy_url => $url,
            notes    => [$msg],
        };
    }

    my $kv = parse_mta_sts_policy($body);
    my @notes;
    my $want_mode = lc($profile->{mta_sts_mode} // "");
    my $want_max_age = $profile->{mta_sts_max_age};

    if ($want_mode) {
        my $is_mode = lc($kv->{mode} // "");
        push @notes, "Policy mode stimmt nicht" if $is_mode ne $want_mode;
    }

    if (defined $want_max_age) {
        my $ma = $kv->{max_age};
        if (!defined $ma || $ma !~ /^\d+$/) {
            push @notes, "Policy max_age fehlt/ungültig";
        }
        elsif (int($ma) < int($want_max_age)) {
            push @notes, "Policy max_age zu klein";
        }
    }

    return {
        status     => @notes ? "fail" : "ok",
        message    => @notes ? "MTA-STS Policy verletzt" : "MTA-STS OK",
        rfc        => "RFC 8461",
        record     => $sts,
        policy_url => $url,
        policy     => $kv,
        notes      => \@notes,
    };
}

# --- Checks: dnssec --
sub check_dnssec_zone {
    my ($resolver, $domain, $timeout) = @_;

    my $pkt = safe_dns_query($resolver, $domain, 'DS', 1, $timeout);

    my $has_ds = 0;
    if ($pkt) {
        $has_ds = 1 if grep { $_->type eq 'DS' } $pkt->answer;
    }

    return {
        status  => $has_ds ? "ok" : "warn",
        message => $has_ds ? "Domain ist DNSSEC-signiert" : "Domain ist nicht DNSSEC-signiert (Basis fuer DANE fehlt)",
        rfc     => "RFC 4033",
    };
}


# --- Checks: DANE ---
sub check_dane {
    my ($resolver, $domain, $profile, $timeout, $dnssec_status) = @_;
    $dnssec_status //= "warn";

    return { status => "skip", message => "DANE nicht gefordert", rfc => "RFC 7672" }
        unless $profile->{require_dane};

    my @mx = get_mx_records($resolver, $domain, $timeout);
    unless (@mx) {
        return { status => "fail", message => "Kein MX, DANE nicht prüfbar", rfc => "RFC 7672" };
    }

    my @ports = _as_list($profile->{dane_ports});
    @ports = (25) unless @ports;

    my @tlsa;
    my $dnssec_valid = 1; # wir gehen davon aus, bis wir einen Fehler finden
    my @notes;

    for my $mxh (map { $_->{exchange} } @mx) {
        $mxh =~ s/\.$//;
        next unless $mxh;

        for my $port (@ports) {
            my $name = "_" . int($port) . "._tcp.$mxh";
            my $pkt = safe_dns_query($resolver, $name, 'TLSA', 1, 2);
            next unless $pkt;

            my $ad = 0;
            $ad = 1 if ($pkt && $pkt->header && $pkt->header->ad);

            unless ($ad) {
                $dnssec_valid = 0;
                push @notes, "Hinweis: TLSA für $mxh gefunden, aber AD-Flag fehlt (Resolver validiert DNSSEC moeglicherweise nicht).";
            }

            for my $rr ($pkt->answer) {
                next unless $rr->type eq "TLSA";
                push @tlsa, {
                    mx           => $mxh,
                    port         => int($port),
                    usage        => $rr->usage,
                    selector     => $rr->selector,
                    matchingtype => $rr->matchingtype,
                    certdata     => $rr->certdata,
                };
            }
        }
    }

    unless (@tlsa) {
        return {
            status  => "fail",
            message => "Keine TLSA Records gefunden",
            rfc     => "RFC 7672",
            tlsa    => [],
        };
    }

    my $status;
    if ($dnssec_valid) {
        $status = "ok";
    } else {
        if ($dnssec_status eq "ok") {
            $status = "warn";
            push @notes, "Hinweis: DNSSEC (DS) ist vorhanden, aber AD-Flag fehlt. DANE Verifikation haengt vom Resolver ab.";
        } else {
            $status = "fail";
            push @notes, "FEHLER: Keine DNSSEC Basis (DS fehlt oder DNSSEC nicht aktiv). DANE ist damit nicht verifizierbar.";
        }
    }

    return {
        status  => $status,
        message => $status eq "ok"   ? "DANE TLSA vorhanden und DNSSEC-validiert"
                 : $status eq "warn" ? "DANE TLSA vorhanden, aber DNSSEC-Verifikation nicht sicher (AD-Flag fehlt)"
                                     : "DANE vorhanden, aber durch fehlendes DNSSEC wertlos",
        rfc     => "RFC 7672",
        ports   => \@ports,
        tlsa    => \@tlsa,
        notes   => \@notes,
    };
}


# --- Hauptlogik ---
sub run_checks_for_profile {
    my ($resolver, $domain, $profile, $timeout, $fast) = @_;
    my $need_dane    = $fast ? ($profile->{require_dane}    ? 1 : 0) : 1;
    my $need_mta_sts = $fast ? ($profile->{require_mta_sts} ? 1 : 0) : 1;

    my $dnssec_res = check_dnssec_zone($resolver, $domain, $timeout);

    my $checks = {
        dnssec  => $dnssec_res,
        mx      => check_mx($resolver, $domain, $profile, $timeout),
        spf     => check_spf($resolver, $domain, $profile, $timeout),
        dkim    => check_dkim($resolver, $domain, $profile, $timeout),
        arc     => check_arc($resolver, $domain, $profile, $timeout),
        dmarc   => check_dmarc($resolver, $domain, $profile, $timeout),

        dane    => $need_dane
            ? check_dane($resolver, $domain, $profile, $timeout, ($dnssec_res->{status} // "warn"))
            : { status => "skip", message => "DANE nicht gefordert", rfc => "RFC 7672" },

        mta_sts => $need_mta_sts
            ? check_mta_sts($resolver, $domain, $profile, $timeout)
            : { status => "skip", message => "MTA-STS nicht gefordert", rfc => "RFC 8461" },
    };

    my @statuses = map { $_->{status} } values %$checks;
    return { status => worst_status(@statuses), checks => $checks };
}


sub process_domain {
    my ($domain, $timeout, $fast) = @_;
    my $resolver = build_resolver($DNS_CONF);
    my %profile_results;
	my $overall_status = "ok";
	my $matched = 0;

	for my $pname (sort keys %$PROFILE_CONF) {
		my $p = $PROFILE_CONF->{$pname} // next;
		next unless profile_matches_domain($p, $domain);

		$matched = 1;
		$profile_results{$pname} = run_checks_for_profile($resolver, $domain, $p, $timeout, $fast);

		my $st = $profile_results{$pname}{status} // "fail";
		$overall_status = worst_status($overall_status, $st);
	}

	# Wenn kein Profil gematcht hat, fallback auf default (falls vorhanden)
	if (!$matched && exists $PROFILE_CONF->{default}) {
		my $p = $PROFILE_CONF->{default};
		$profile_results{default} = run_checks_for_profile($resolver, $domain, $p, $timeout, $fast);
		$overall_status = $profile_results{default}{status} // "fail";
	}

	return { domain => $domain, status => $overall_status, profiles => \%profile_results };
}

# --- Main ---
sub main {
    my $config_file = $opt_config // $DEFAULT_CONFIG;
    $conf = load_config($config_file);
    $PROFILE_CONF = $conf->{profiles} // {};
    $DNS_CONF     = $conf->{dns}      // {};
    $DOMAINS_CONF = $conf->{domains}  // {};
    $OUT_CONF     = $conf->{output}   // {};
    $RUNTIME_CONF = $conf->{runtime}  // {};

    # Logging
    my $LOG_FILE  = $OUT_CONF->{log_file} // File::Spec->catfile($BASE, "log", "domain_dns_audit.log");
    my $LOG_LEVEL = $opt_debug ? "DEBUG" : ($OUT_CONF->{log_level} // "INFO");
    make_path(dirname($LOG_FILE)) unless -d dirname($LOG_FILE);

    Log::Log4perl::init(\<<~"LOG_CONFIG");
        log4perl.logger          = $LOG_LEVEL, LOGFILE, CONSOLE
        log4perl.appender.LOGFILE = Log::Log4perl::Appender::File
        log4perl.appender.LOGFILE.filename = $LOG_FILE
        log4perl.appender.LOGFILE.mode     = append
        log4perl.appender.LOGFILE.layout   = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.LOGFILE.layout.ConversionPattern = %d [%p] %m%n
        log4perl.appender.LOGFILE.binmode  = :encoding(UTF-8)
        log4perl.appender.CONSOLE = Log::Log4perl::Appender::ScreenColoredLevels
        log4perl.appender.CONSOLE.layout = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.CONSOLE.layout.ConversionPattern = %d [%p] %m%n
        LOG_CONFIG

    $log = Log::Log4perl->get_logger();
    $log->info("Starte domain_dns_audit v@{[VERSION]} (Fast: " . ($opt_fast ? "ja" : "nein") . ")");
	
	$PSL_REF = load_public_suffix_list($conf->{public_suffix_list});

	if ($PSL_REF) {
		$log->info("Public Suffix List erfolgreich geladen.");
	} else {
		$log->warn("Audit läuft OHNE Public Suffix List (nutze einfache Heuristik).");
	}


    # Domains laden
    $MAX_PROCS = $opt_max_procs // $RUNTIME_CONF->{max_procs} // 1;
    my @domains = $opt_domain
        ? (lc $opt_domain)
        : _as_list($DOMAINS_CONF->{static_domains} // $DOMAINS_CONF->{list} // $DOMAINS_CONF->{domains} // []);

    @domains = grep { is_valid_domain($_) } @domains;
    my @exclude = _as_list($DOMAINS_CONF->{exclude_domains});
    if (@exclude) {
        my $exset = _lcset(@exclude);
        @domains = grep { !$exset->{lc($_)} } @domains;
    }

    my %seen;
    @domains = grep { !$seen{lc($_)}++ } @domains;

    unless (@domains) {
        $log->error("Keine Domains zum Prüfen gefunden!");
        exit 2;
    }

    $log->info("Domains: " . scalar(@domains) . " (Parallelität: $MAX_PROCS)");

    # Parallelisierung
    my $pm = Parallel::ForkManager->new($MAX_PROCS);
    my %results;

    $pm->run_on_finish(sub {
        my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data_ref) = @_;
        return unless $data_ref && ref($data_ref) eq 'HASH';
        $results{$data_ref->{domain}} = $data_ref->{result};
    });

    for my $dom (@domains) {
        $pm->start and next;
        my $r = try {
            process_domain($dom, $DNS_CONF->{timeout} // DEFAULT_DNS_TIMEOUT, $opt_fast);
        } catch {
            $log->error("Fehler bei $dom: $_");
            { domain => $dom, status => "fail", error => "$_" };
        };
        $pm->finish(0, { domain => $dom, result => $r });
    }
    $pm->wait_all_children;
	
	
    $log->info("Alle Prüfungen abgeschlossen. Erstelle Statistik...");

    my $date = strftime("%Y%m%d", localtime);

    # --- Initialisierung der Statistik-Struktur ---
    my %stats = (
        total   => scalar(keys %results),
        ok      => 0, warn => 0, fail => 0,
		checks  => {
			dnssec  => { ok => 0, warn => 0, fail => 0, skip => 0 },
			mx      => { ok => 0, warn => 0, fail => 0, skip => 0 },
			spf     => { ok => 0, warn => 0, fail => 0, skip => 0 },
			dkim    => { ok => 0, warn => 0, fail => 0, skip => 0 },
			dmarc   => { ok => 0, warn => 0, fail => 0, skip => 0 },
			arc     => { ok => 0, warn => 0, fail => 0, skip => 0 },
			dane    => { ok => 0, warn => 0, fail => 0, skip => 0 },
			mta_sts => { ok => 0, warn => 0, fail => 0, skip => 0 },
		}

    );

    # --- Ergebnisse auswerten ---
    for my $dom (keys %results) {
        my $res = $results{$dom};
        
        # Gesamtstatus der Domain zählen
        $stats{$res->{status}}++ if exists $stats{$res->{status}};

        # Einzelne Checks zählen (wir nehmen das erste Profil als Referenz)
		if ($res->{profiles} && ref($res->{profiles}) eq 'HASH') {

			my $ref_profile;

			if (exists $res->{profiles}{default}) {
				$ref_profile = $res->{profiles}{default};
			} else {
				my ($first_name) = sort keys %{$res->{profiles}};
				$ref_profile = $res->{profiles}{$first_name} if $first_name;
			}

			if ($ref_profile && $ref_profile->{checks}) {
				for my $c (keys %{$ref_profile->{checks}}) {
					my $c_status = $ref_profile->{checks}{$c}{status} // "skip";
					if (exists $stats{checks}{$c}) {
						$stats{checks}{$c}{$c_status}++;
					}
				}
			}
		}
    }

    # --- Report-Struktur zusammenbauen ---
    my $final_data = {
        meta => {
            ts           => time,
            date         => $date,
            version      => VERSION,
            fast_mode    => $opt_fast ? 1 : 0,
            psl_loaded   => $PSL_REF ? 1 : 0,
            max_procs    => $MAX_PROCS,
        },
        summary => \%stats,
        domains => \%results,
    };

    # --- Datei schreiben ---
    my $out_file = dated_output_path($OUT_CONF->{json_file}, $date);
    if ($opt_dry_run) {
        $log->info("Dry-Run: Statistik berechnet, aber kein Report geschrieben.");
        $log->info("Zusammenfassung: Total: $stats{total}, OK: $stats{ok}, FAIL: $stats{fail}, WARN: $stats{warn}");
    } else {
        try {
            atomic_write_json($out_file, $final_data);
            $log->info("Report erfolgreich geschrieben: $out_file");
            $log->info("Zusammenfassung: Total: $stats{total}, OK: $stats{ok}, FAIL: $stats{fail}, WARN: $stats{warn}");
        } catch {
            $log->error("Fehler beim Schreiben des Reports: $_");
        };
    }
} # Ende von main

main(); # Skript-Start
