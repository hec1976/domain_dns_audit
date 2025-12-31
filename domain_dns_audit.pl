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
    VERSION             => "2.6.7",
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
    my $dir = dirname($target_file);
    make_path($dir) unless -d $dir;

    my ($fh, $tmp) = tempfile(
        "domain_dns_audit_XXXX",
        DIR    => $dir,
        SUFFIX => ".tmp",
        UNLINK => 1,
    );
    binmode($fh, ":encoding(UTF-8)") or die "binmode fehlgeschlagen: $!";
    print $fh encode_json($data);
    close $fh or die "Kann temporäre Datei nicht schließen: $!";

    rename $tmp, $target_file or die "Kann $tmp nach $target_file nicht umbenennen: $!";
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
    $name = lc($name // "");
    $name =~ s/\.$//;
    $type = uc($type // "");
    return "$type|$name";
}

sub safe_dns_query {
    my ($resolver, $name, $type, $max_retries, $timeout) = @_;
    $type       //= 'A';
    $max_retries //= MAX_DNS_RETRIES;
    $timeout    //= DEFAULT_DNS_TIMEOUT;

    my $key = _dns_cache_key($name, $type);
    return $DNS_CACHE{$key} if exists $DNS_CACHE{$key};

    my $retry_delay = 1;
    for my $attempt (1 .. $max_retries) {
        my ($pkt, $timed_out);

        # Wir nutzen einen harten Watchdog-Timer
        local $SIG{ALRM} = sub { $timed_out = 1; die "TIMEOUT\n" };
        eval {
            alarm $timeout;
            $pkt = $resolver->query($name, $type);
            alarm 0;
        };
        alarm 0; # Sicherstellen, dass der Alarm aus ist

        if ($@) {
            my $err = $@;
            if ($err =~ /TIMEOUT/ || $timed_out) {
                $log->warn("[DNS] Timeout bei $name ($type), Versuch $attempt/$max_retries");
            } else {
                $log->debug("[DNS] Fehler bei $name ($type): $err");
            }
            sleep $retry_delay if $attempt < $max_retries;
            $retry_delay *= 1.5;
            next;
        }

        if ($pkt) {
            $DNS_CACHE{$key} = $pkt;
            return $pkt;
        }

        sleep $retry_delay if $attempt < $max_retries;
    }

    $DNS_CACHE{$key} = undef;
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
        push @txt, join("", $t) if defined $t;
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
        return "" if $seen{$cur}++;

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
    
    # Priorität: 1. Pfad aus Config, 2. Standardpfad im Script-Verzeichnis
    my $psl_file = $custom_path || File::Spec->catfile($BASE, "public_suffix_list.dat");

    unless (-f $psl_file) {
        $log->warn("PSL Datei nicht gefunden unter $psl_file - nutze einfache Heuristik.");
        return undef;
    }

    my %psl;
    if (open my $fh, '<:encoding(UTF-8)', $psl_file) {
        while (my $line = <$fh>) {
            $line =~ s/^\s+|\s+$//g;
            next if !$line || $line =~ m|^//| || $line =~ m|^\*|;
            $psl{lc($line)} = 1;
        }
        close $fh;
        $log->debug("PSL geladen von $psl_file (" . scalar(keys %psl) . " Einträge).");
        return \%psl;
    }
    return undef;
}

sub get_organizational_domain {
    my ($domain) = @_;
    $domain = lc(_trim($domain));
    return "" unless $domain;

    my @parts = split(/\./, $domain);
    
    # Fallback: Wenn keine PSL da ist, nimm die letzten zwei Teile (Heuristik)
    unless ($PSL_REF) {
        return @parts <= 2 ? $domain : join('.', @parts[-2, -1]);
    }

    # Wir suchen den längsten passenden Suffix in der Liste
    # Beispiel: "sub.mail.example.co.uk"
    # Prüfe: "sub.mail.example.co.uk", "mail.example.co.uk", "example.co.uk", "co.uk", "uk"
    for (my $i = 0; $i < @parts; $i++) {
        my $current_suffix = join('.', @parts[$i .. $#parts]);
        if (exists $PSL_REF->{$current_suffix}) {
            # Wenn der Suffix gefunden wurde (z.B. "co.uk"), 
            # ist die Org-Domain dieser Suffix + ein Label davor.
            if ($i > 0) {
                return join('.', @parts[$i-1 .. $#parts]);
            } else {
                # Der Treffer ist selbst der Suffix (sollte bei validen Domains nicht passieren)
                return $domain;
            }
        }
    }

    # Wenn gar nichts in der PSL gefunden wurde (neue TLD?), nimm letzte zwei Teile
    return join('.', @parts[-2, -1]) if @parts >= 2;
    return $domain;
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

    if (my $groups = $profile->{mx_policy}{groups}) {
        my $ex_set = _lcset(@ex);
        for my $g (@$groups) {
            next unless ref($g) eq 'HASH';
            my @required = _as_list($g->{mx_required});
            @required = map { lc($_) } @required;
            my $allow_others = $g->{mx_allow_others} // 0;

            my @missing = grep { !$ex_set->{$_} } @required;
            if (@missing) {
                $status = "fail";
                push @notes, "MX fehlen: " . join(", ", @missing);
                next;
            }

            if (!$allow_others) {
                my $req_set = _lcset(@required);
                my @extra = grep { !$req_set->{$_} } @ex;
                if (@extra) {
                    $status = "fail";
                    push @notes, "Unerwartete MX: " . join(", ", @extra);
                }
            }
        }
    }

    return {
        status  => $status,
        message => $status eq 'ok' ? "MX vorhanden" : "MX Policy verletzt",
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
    return 0 if $depth > MAX_SPF_LOOKUPS || $seen->{lc($domain)}++;

    my @txt = get_txt_records($resolver, $domain, DEFAULT_DNS_TIMEOUT);
    my ($spf) = grep { /^v=spf1(\s|$)/i } @txt;
    return 0 unless $spf;

    my $count = 0;
    for my $t (split /\s+/, lc($spf)) {
		# Erlaube optionale Qualifier am Anfang (+, -, ~, ?)
		if ($t =~ /^[-+~?]?include:(.*)/i || $t =~ /^redirect=(.*)/i) {
			my $target = $1 // $2;
			$count++;
			$count += count_spf_lookups_recursive($resolver, $target, $seen, $depth + 1);
		}
		elsif ($t =~ /^[-+~?]?(a|mx|ptr|exists)/i) {
			$count++;
		}
    }
    return $count;
}

sub check_spf {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "SPF nicht gefordert", rfc => "RFC 7208" }
        unless $profile->{require_spf};

    my @txt = get_txt_records($resolver, $domain, $timeout);
    my ($spf) = grep { /^v=spf1(\s|$)/i } @txt;

    unless ($spf) {
        return {
            status  => "fail",
            message => "Kein SPF Record gefunden",
            rfc     => "RFC 7208",
            record  => "",
        };
    }

    my $status = "ok";
    my @notes;
	
	if ($spf =~ /\+all$/i || $spf =~ /\ball$/i) { # \b statt \s
		$status = "fail";
		push @notes, "Kritisch: SPF endet auf 'all' (deaktiviert Schutz komplett).";
	}
	
    my %token_set = map { _trim($_) =~ s/^\+//r => 1 }
                    grep { _trim($_) ne "" }
                    split /\s+/, $spf;

    if (my $groups = $profile->{spf_policy}{groups}) {
        for my $g (@$groups) {
            next unless ref($g) eq 'HASH';
            my @any = _as_list($g->{required_contains_any});
            next unless @any;

            my $ok = 0;
            for my $a (@any) {
                $a = _trim($a);
                $a =~ s/^\+//;
                $ok = 1 if $token_set{$a};
            }

            unless ($ok) {
                $status = "fail";
                push @notes, "SPF enthält keines von required_contains_any (Gruppe: " . ($g->{name} // "") . ")";
            }
        }
    }

    my $lookup_count = count_spf_lookups_recursive($resolver, $domain);
    if ($lookup_count > MAX_SPF_LOOKUPS) {
        $status = "fail";
        push @notes, "SPF Lookup Limit überschritten: $lookup_count (maximal " . MAX_SPF_LOOKUPS . ")";
    }
    else {
        push @notes, "SPF DNS Lookups: $lookup_count/" . MAX_SPF_LOOKUPS;
    }

    return {
        status       => $status,
        message      => $status eq "ok" ? "SPF vorhanden und valide" : "SPF Policy verletzt",
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
    my ($rec) = grep { /^v=DMARC1(\s|;|$)/i } @txt;

    unless ($rec) {
        return {
            status  => "fail",
            message => "Kein DMARC Record gefunden",
            rfc     => "RFC 7489",
            record  => "",
        };
    }

    my $status = "ok";
    my @notes;
    my $p = "";
    if ($rec =~ /\bp\s*=\s*([a-z]+)\b/i) { $p = lc($1); }

    # 1. Policy Prüfung (p=)
    if (my @okp = _as_list($profile->{dmarc_ok_policies})) {
        unless (grep { defined && lc($_) eq $p } @okp) {
            $status = "fail";
            push @notes, "DMARC p=$p nicht erlaubt.";
        }
    }

    # 2. RUA Prüfung & Organisational Domain Check (RFC 7489)
    if (my $dmarc_policy_cfg = $profile->{dmarc_policy}) {
        my @allowed_rua_domains = _as_list($dmarc_policy_cfg->{allow_external_rua_domains});
        my $allowed_rua_set = _lcset(@allowed_rua_domains);

        if ($rec =~ /\brua\s*=\s*([^;]+)/i) {
            my $rua_val = $1;
            my @uris = split(/\s*,\s*/, $rua_val);

            for my $uri (@uris) {
                if ($uri =~ /mailto:.*\@([a-z0-9.-]+)/i) {
                    my $rua_domain = lc($1);
                    $rua_domain =~ s/\.$//;

                    # NEU: Robuste Prüfung auf organisatorische Verwandtschaft
                    my $is_internal = is_same_organizational_domain($domain, $rua_domain);

                    if (!$is_internal) {
                        # Nur wenn es wirklich EXTERN ist, prüfen wir Whitelist und DNS-Record
                        if (!$allowed_rua_set->{$rua_domain}) {
                            $status = "fail";
                            push @notes, "Externe RUA Domain '$rua_domain' nicht in Whitelist erlaubt.";
                        }
                        else {
                            # DNS Counter-Check (RFC 7489, 7.1) - External Reporting Authorization
                            my $verify_name = "$domain._report._dmarc.$rua_domain";
                            my @v_txt = get_txt_records($resolver, $verify_name, $timeout);
                            my ($v_rec) = grep { /^v=DMARC1(\s|;|$)/i } @v_txt;

                            unless ($v_rec) {
                                $status = "fail";
                                push @notes, "External Verification fehlt: Kein Record unter $verify_name.";
                            }
                            else {
                                push @notes, "External Verification OK: $verify_name gefunden.";
                            }
                        }
                    } else {
                        $log->debug("RUA Ziel '$rua_domain' ist organisatorisch verwandt mit '$domain' (Intern).");
                    }
                }
            }
        }
    }

    return {
        status  => $status,
        message => $status eq "ok" ? "DMARC OK" : "DMARC Verifizierung fehlgeschlagen",
        rfc     => "RFC 7489",
        record  => $rec,
        policy  => $p,
        notes   => \@notes,
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

# --- Checks: DANE ---
sub check_dane {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "DANE nicht gefordert", rfc => "RFC 7672" }
        unless $profile->{require_dane};

    my @mx = get_mx_records($resolver, $domain, $timeout);
    unless (@mx) {
        return { status => "fail", message => "Kein MX, DANE nicht prüfbar", rfc => "RFC 7672" };
    }

    my @ports = _as_list($profile->{dane_ports});
    @ports = (25) unless @ports;

    my @tlsa;
    my $dnssec_valid = 1; # Wir gehen davon aus, bis wir einen Fehler finden
    my @notes;

    for my $mxh (map { $_->{exchange} } @mx) {
        $mxh =~ s/\.$//;
        next unless $mxh;

        for my $port (@ports) {
            my $name = "_" . int($port) . "._tcp.$mxh";
            my $pkt = safe_dns_query($resolver, $name, 'TLSA', 1, 2);
            next unless $pkt;

            # --- NEU: DNSSEC Authenticated Data (AD) Flag prüfen ---
            unless ($pkt->header->ad) {
                $dnssec_valid = 0;
                push @notes, "DANE Record für $mxh gefunden, aber NICHT per DNSSEC verifiziert (AD-Flag fehlt).";
            }
            # -------------------------------------------------------

            for my $rr ($pkt->answer) {
                next unless $rr->type eq "TLSA";
                push @tlsa, {
                    mx          => $mxh,
                    port        => int($port),
                    usage       => $rr->usage,
                    selector    => $rr->selector,
                    matchingtype => $rr->matchingtype,
                    certdata    => $rr->certdata,
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

    # DANE ist nur OK, wenn Records da sind UND DNSSEC sie schützt
    my $status = $dnssec_valid ? "ok" : "fail";

    return {
        status  => $status,
        message => $status eq "ok" ? "DANE TLSA vorhanden und DNSSEC-validiert" 
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

    my $checks = {
        mx      => check_mx($resolver, $domain, $profile, $timeout),
        spf     => check_spf($resolver, $domain, $profile, $timeout),
        dkim    => check_dkim($resolver, $domain, $profile, $timeout),
        arc     => check_arc($resolver, $domain, $profile, $timeout),
        dmarc   => check_dmarc($resolver, $domain, $profile, $timeout),
        dane    => $need_dane    ? check_dane($resolver, $domain, $profile, $timeout) : { status => "skip", message => "DANE nicht gefordert", rfc => "RFC 7672" },
        mta_sts => $need_mta_sts ? check_mta_sts($resolver, $domain, $profile, $timeout) : { status => "skip", message => "MTA-STS nicht gefordert", rfc => "RFC 8461" },
    };

    my @statuses = map { $_->{status} } values %$checks;
    return { status => worst_status(@statuses), checks => $checks };
}

sub process_domain {
    my ($domain, $timeout, $fast) = @_;
    my $resolver = build_resolver($DNS_CONF);
    my %profile_results;
    my $best_status = "fail";

    for my $pname (sort keys %$PROFILE_CONF) {
        my $p = $PROFILE_CONF->{$pname} // next;
        next unless profile_matches_domain($p, $domain);
        $profile_results{$pname} = run_checks_for_profile($resolver, $domain, $p, $timeout, $fast);
        my $st = $profile_results{$pname}{status};
        $best_status = $st if $st eq "ok" ||
                       ($st eq "warn" && $best_status ne "ok") ||
                       ($best_status eq "fail");
    }

    if (!%profile_results && exists $PROFILE_CONF->{default}) {
        my $p = $PROFILE_CONF->{default};
        $profile_results{default} = run_checks_for_profile($resolver, $domain, $p, $timeout, $fast);
        $best_status = $profile_results{default}{status};
    }

    return { domain => $domain, status => $best_status, profiles => \%profile_results };
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

    # Report schreiben
    my $date = strftime("%Y%m%d", localtime);
    my $final_data = {
        ts      => time,
        date    => $date,
        version => VERSION,
        fast    => $opt_fast ? 1 : 0,
        domains => \%results,
    };

    my $out_file = dated_output_path($OUT_CONF->{json_file}, $date);
    if ($opt_dry_run) {
        $log->info("Dry-Run: Kein Report geschrieben.");
    } else {
        atomic_write_json($out_file, $final_data);
        $log->info("Report geschrieben: $out_file");
    }
}

main();
