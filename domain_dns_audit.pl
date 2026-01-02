#!/usr/bin/perl
use strict;
use warnings;
use utf8;
use open qw(:std :utf8);

# ============================================================
# HIERARCHIE UEBERSICHT
# Zweck:
#   Dieses Script prueft DNS Mail-Sicherheits- und Mail-Infrastruktur-Records pro Domain.
#   Die Logik ist in Schichten aufgebaut: Utilities -> DNS Layer -> Domain Logic -> Crypto/SPF -> Checks -> Orchestration.
#   Kommentare sind nur zur Orientierung, der Code darunter ist unveraendert.
# Inputs:
#   CLI Parameter (--domain, --config, --debug, --dry-run, --max-procs, --fast, --dnssec)
#   JSON Konfiguration (Profiles, Domains, Output, Runtime, DNS Settings)
# Output:
#   JSON Report pro Lauf/Datum (atomic write)
#   Log Output via Log4perl
# Haupt-Subs:
#   load_config(), build_resolver(), safe_dns_query(), check_*(), process_domain(), main()
# ============================================================

# ============================================================
# 0) DEPENDENCIES / MODULE
# Zweck:
#   Laedt alle Perl Module, die fuer DNS, Crypto, JSON, Parallelisierung und HTTP gebraucht werden.
# Inputs:
#   Perl runtime
#   Installierte Module
# Output:
#   Funktionen in spaeteren Bloecken koennen die Module direkt nutzen.
# Haupt-Subs:
#   use Net::DNS, Crypt::OpenSSL::RSA, JSON::MaybeXS, Log::Log4perl, HTTP::Tiny, ...
# ============================================================

# --- Module ---
use IPC::Open2;
use Net::DNS;
use Crypt::OpenSSL::RSA;
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
use Cache::Memcached;

# ============================================================
# 1) KONSTANTEN / LIMITS
# Zweck:
#   Zentrale Limits und Defaults (Timeouts, SPF Lookup Limits, DNS Cache Limits, RSA Mindestbits).
# Inputs:
#   Keine (compile time)
# Output:
#   Konstanten via use constant
# Haupt-Subs:
#   VERSION, MAX_SPF_LOOKUPS, DEFAULT_DNS_TIMEOUT, MIN_RSA_KEY_BITS, ...
# ============================================================

# --- Constants ---
use constant {
    VERSION             => "2.7.0",
    MAX_SPF_LOOKUPS     => 10,
    MAX_CNAME_HOPS      => 5,
    MAX_DNS_RETRIES     => 2,
    DEFAULT_DNS_TIMEOUT => 10,
    MAX_HTTP_REDIRECTS  => 5,
    MIN_RSA_KEY_BITS    => 2048,
    DNS_CACHE_MAX       => 1000,
    DNS_CACHE_PURGE_TO   => 800,
};

# ============================================================
# 2) PFADE / DEFAULTS
# Zweck:
#   Leitet BASE Pfad aus Script-Location ab und setzt Default-Konfig Pfade.
# Inputs:
#   FindBin / abs_path($Bin)
# Output:
#   $BASE und $DEFAULT_CONFIG
# Haupt-Subs:
#   abs_path(), File::Spec->catfile()
# ============================================================

# --- Global Paths ---
my $BASE = abs_path($Bin) || $Bin;
my $DEFAULT_CONFIG = File::Spec->catfile($BASE, "config", "domain_dns_audit.json");

# ============================================================
# 3) CLI / ARGUMENTE
# Zweck:
#   Parsed die Kommandozeile und setzt Options-Variablen.
# Inputs:
#   ARGV
# Output:
#   Option-Variablen (opt_*)
# Haupt-Subs:
#   GetOptions(...)
# ============================================================

# --- CLI Options ---
my ($opt_domain, $opt_config, $opt_debug, $opt_dry_run, $opt_version, $opt_help, $opt_max_procs, $opt_fast, $opt_dnssec);
GetOptions(
    'domain=s'    => \$opt_domain,
    'config=s'    => \$opt_config,
    'debug'       => \$opt_debug,
    'dry-run'     => \$opt_dry_run,
    'max-procs=i' => \$opt_max_procs,
    'fast'        => \$opt_fast,
    'dnssec!'     => \$opt_dnssec,
    'version'     => \$opt_version,
    'help'        => \$opt_help,
) or die "Ungültige Parameter. Nutze --help\n";

# ============================================================
# 4) HELP / VERSION OUTPUT
# Zweck:
#   Gibt Hilfe oder Version aus und beendet das Script fruehzeitig.
# Inputs:
#   --help, --version
# Output:
#   STDOUT Text
#   exit
# Haupt-Subs:
#   print <<USAGE, exit
# ============================================================

# --- Help & Version ---
if ($opt_help) {
    print <<"USAGE";
domain_dns_audit.pl v@{[VERSION]}

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

# ============================================================
# 5) GLOBALE VARIABLEN
# Zweck:
#   Definiert zentrale globale Handles und Config-Referenzen, die spaeter gefuellt werden.
# Inputs:
#   Keine
# Output:
#   $log, $conf, $PROFILE_CONF, $DNS_CONF, $DOMAINS_CONF, $OUT_CONF, $RUNTIME_CONF, $PSL_REF
# Haupt-Subs:
#   (nur Deklaration)
# ============================================================

# --- Global Variables ---
my ($log, $conf, $PROFILE_CONF, $DNS_CONF, $DOMAINS_CONF, $OUT_CONF, $RUNTIME_CONF);
my ($MAX_PROCS, %DNS_CACHE, $PSL_REF);

use constant {
    MEMCACHED_SERVERS => ['127.0.0.1:11211'], # Deine Memcached IP:Port
    DNS_CACHE_TTL     => 3600,                # 1 Stunde Gültigkeit
};

# ============================================================
# 6) DNS CACHE (MEMCACHED)
# Zweck:
#   Initialisiert Memcached fuer DNS Query Caching.
# Inputs:
#   MEMCACHED_SERVERS, DNS_CACHE_TTL
# Output:
#   $dns_cache Objekt
# Haupt-Subs:
#   Cache::Memcached->new(...)
# ============================================================

# Globales Memcached Objekt
my $dns_cache = eval { Cache::Memcached->new({
    servers => MEMCACHED_SERVERS,
    debug   => 0,
    compress_threshold => 10_000,
}) };
if ($@ || !$dns_cache) {
    $log->warn("Memcached nicht verfügbar: $@. Cache wird deaktiviert.") if $log;
    $dns_cache = undef;
}

# =============================================
# HILFSFUNKTIONEN (Utilities)
# =============================================
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

    my ($fh, $tmp) = tempfile(
        "domain_dns_audit_XXXX",
        DIR    => $dir,
        SUFFIX => ".tmp",
        UNLINK => 0,
    );

    eval {
        binmode($fh, ":encoding(UTF-8)") or die "binmode fehlgeschlagen: $!";
        my $json = encode_json($data);
        print $fh $json or die "Write fehlgeschlagen: $!";
        close($fh) or die "Kann temporäre Datei nicht schließen: $!";
        rename($tmp, $target_file) or die "Kann $tmp nach $target_file nicht umbenennen: $!";
        chmod(0644, $target_file) or warn "Konnte Berechtigungen für $target_file nicht auf 644 setzen: $!";
        1;
    } or do {
        my $err = $@ || "unbekannter Fehler";
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
    my @in = @_;
    @in = map { lc($_ // "") } @in;
    @in = grep { $_ ne "" } @in;

    return "info" unless @in;

    my @real = grep { $_ ne "skip" && $_ ne "info" } @in;
    my @use  = @real ? @real : @in;

    my %rank = (
        fail => 3,
        warn => 2,
        ok   => 1,
        info => 0,
        skip => 0,
    );

    my ($worst, $worst_r) = ("info", -1);
    for my $s (@use) {
        my $r = defined $rank{$s} ? $rank{$s} : 0;
        if ($r > $worst_r) {
            $worst_r = $r;
            $worst   = $s;
        }
    }

    if (!@real) {
        return "skip" if grep { $_ eq "skip" } @in;
        return "info";
    }

    return $worst;
}

# =============================================
# DNS-FUNKTIONEN
# =============================================
sub build_resolver {
    my ($dns_conf) = @_;
    $dns_conf //= {};

    my $res = Net::DNS::Resolver->new;
    my $use_dnssec = exists $dns_conf->{dnssec} ? $dns_conf->{dnssec} : 1;
    $res->dnssec($use_dnssec);

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
    return unless $dns_cache;
    my $stats = eval { $dns_cache->stats() } || {};
    my $bytes = 0;
    for my $srv (keys %$stats) {
        $bytes += ($stats->{$srv}{bytes} // 0);
    }
    if ($bytes > DNS_CACHE_MAX * 1024) {
        eval { $dns_cache->flush_all() };
        $log->warn("DNS-Cache geleert (Größe: $bytes Bytes)") if $log;
    }
}

sub safe_dns_query {
    my ($resolver, $name, $type, $max_retries, $timeout) = @_;
    $type        //= 'A';
    $max_retries //= MAX_DNS_RETRIES;
    $timeout     //= DEFAULT_DNS_TIMEOUT;

    $name = lc(_trim($name // ""));
    $type = uc(_trim($type // "A"));
    return undef unless $name;

    my $key = "dns:" . lc($type) . "|" . $name;
    $key =~ s/\s+/_/g;
    $key =~ s/\.$//;

    # Cache lesen (wenn Memcached nicht da ist, soll das Script nicht sterben)
	_dns_cache_purge_if_needed();
    my $cached_val;
    eval { $cached_val = $dns_cache->get($key) if $dns_cache; 1; };

    if (defined $cached_val) {
        # Negative/Transient Marker
        return undef if $cached_val eq "NXDOMAIN";
        return undef if $cached_val eq "NODATA";
        return undef if $cached_val eq "SERVFAIL";
        return undef if $cached_val eq "TIMEOUT";

        # Positiv: Packet aus serialisierten Daten
        my $pkt = eval { Net::DNS::Packet->new(\$cached_val) };
        return $pkt if $pkt;

        # Cache-Wert war kaputt: ignorieren und neu anfragen
        $log->debug("DNS cache value ungueltig, ignoriere ($type $name)") if $log;
    }

    my $retry_delay = 1;
    my $last_err    = "";
    my $pkt;

    for my $attempt (1 .. $max_retries) {
        # pro Versuch Timeouts setzen
        $resolver->udp_timeout($timeout);
        $resolver->tcp_timeout($timeout);

        $pkt = undef;
        my $ok = eval { $pkt = $resolver->query($name, $type); 1; };
        if (!$ok) {
            $last_err = $@ || "query exception";
        }

        if ($pkt) {
            my $rcode = uc($pkt->header->rcode // "");

            # NOERROR kann trotzdem "keine Antwortdaten" bedeuten (NODATA)
            if ($rcode eq "NOERROR") {
                my @ans = $pkt->answer;
                if (!@ans) {
                    # NODATA: Name existiert, aber kein RRset fuer diesen Typ
                    eval { $dns_cache->set($key, "NODATA", 60) if $dns_cache; 1; };
                    $log->debug("DNS NODATA gecacht (NOERROR, keine Answer) ($type $name)") if $log;
                    return undef;
                }

                # Positiver Cache
                eval { $dns_cache->set($key, $pkt->data, DNS_CACHE_TTL) if $dns_cache; 1; };
                return $pkt;
            }

            if ($rcode eq "NXDOMAIN") {
                eval { $dns_cache->set($key, "NXDOMAIN", 120) if $dns_cache; 1; };
                $log->debug("DNS NXDOMAIN gecacht ($type $name)") if $log;
                return undef;
            }

            if ($rcode eq "SERVFAIL") {
                # Transient: sehr kurz cachen oder gar nicht
                eval { $dns_cache->set($key, "SERVFAIL", 3) if $dns_cache; 1; };
                $log->debug("DNS SERVFAIL (kurz) gecacht ($type $name)") if $log;
                $last_err = "SERVFAIL";
            }
            else {
                # Andere rcodes: REFUSED, FORMERR, NOTIMP, etc.
                $last_err = $rcode || ($resolver->errorstring // "DNS error");
            }
        }
        else {
            # Kein Packet: errorstring aus Resolver
            my $err = $resolver->errorstring // "";
            $last_err = $err if $err ne "";

            # TIMEOUT erkennen und sehr kurz cachen
            if ($err =~ /TIMEOUT/i) {
                eval { $dns_cache->set($key, "TIMEOUT", 3) if $dns_cache; 1; };
                $log->debug("DNS TIMEOUT (kurz) gecacht ($type $name)") if $log;
            }

            # NXDOMAIN ohne Packet (manche Resolver): kurz cachen
            if ($err =~ /NXDOMAIN/i) {
                eval { $dns_cache->set($key, "NXDOMAIN", 120) if $dns_cache; 1; };
                $log->debug("DNS NXDOMAIN gecacht (errorstring) ($type $name)") if $log;
                return undef;
            }

            # SERVFAIL ohne Packet: nicht als NXDOMAIN labeln
            if ($err =~ /SERVFAIL/i) {
                eval { $dns_cache->set($key, "SERVFAIL", 3) if $dns_cache; 1; };
                $log->debug("DNS SERVFAIL (kurz) gecacht (errorstring) ($type $name)") if $log;
            }
        }

        # Retry nur wenn noch Versuche uebrig sind
        if ($attempt < $max_retries) {
            sleep $retry_delay if $retry_delay > 0;
            $retry_delay = int($retry_delay * 1.5 + 0.5);
            $retry_delay = 8 if $retry_delay > 8;  # Deckel, sonst wird es zu lahm
        }
    }

    $log->debug("DNS query fehlgeschlagen ($type $name): $last_err") if $log;
    return undef;
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

    my $pkt = safe_dns_query($resolver, $name, 'TXT', MAX_DNS_RETRIES, $timeout);
    return ([], "") unless $pkt;

    my @txt;
    my $cname_target = "";

    for my $rr ($pkt->answer) {
        if ($rr->type eq 'CNAME') {
            $cname_target = lc($rr->cname);
            $cname_target =~ s/\.$//;
        }
        elsif ($rr->type eq 'TXT') {
            my $t = $rr->txtdata;
            if (ref($t) eq 'ARRAY') {
                push @txt, join("", @$t);
            } elsif (defined $t) {
                push @txt, $t;
            }
        }
    }
    if (!@txt && $cname_target) {
        my @txt_from_target = get_txt_records($resolver, $cname_target, $timeout);
        return (\@txt_from_target, $cname_target);
    }

    return (\@txt, $cname_target);
}

sub get_mx_records {
    my ($resolver, $domain, $timeout) = @_;
    my $pkt = safe_dns_query($resolver, $domain, 'MX', MAX_DNS_RETRIES, $timeout);
    return () unless $pkt;

    my @mx = map { { preference => $_->preference, exchange => lc($_->exchange) } } grep { $_->type eq "MX" } $pkt->answer;

    @mx = sort { $a->{preference} <=> $b->{preference} } @mx;
    return @mx;
}

# =============================================
# PUBLIC SUFFIX / ORGANIZATIONAL DOMAIN LOGIC
# =============================================
sub load_public_suffix_list {
    my ($custom_path) = @_;
    my $psl_file = $custom_path || File::Spec->catfile($BASE, "public_suffix_list.dat");

    unless (-f $psl_file) {
        $log->warn("PSL Datei nicht gefunden unter $psl_file. Nutze verbesserte Heuristik.");
        return undef;
    }

    my %psl;
    if (open my $fh, '<:encoding(UTF-8)', $psl_file) {
        while (my $line = <$fh>) {
            $line =~ s/^\s+|\s+$//g;
            next if !$line || $line =~ m|^//|;
            $line =~ s/^[\*\!]//;
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

    if ($PSL_REF) {
        for (my $i = 0; $i < @parts; $i++) {
            my $current_suffix = join('.', @parts[$i .. $#parts]);
            if (exists $PSL_REF->{$current_suffix}) {
                return ($i > 0) ? join('.', @parts[$i-1 .. $#parts]) : $domain;
            }
        }
    }

    my $tld = $parts[-1];
    my $sld = $parts[-2] // "";
    my $t3  = $parts[-3] // "";

    my %functional_sld = map { $_ => 1 } qw(com co net org gov edu ac ad nom mil info biz name pro);

    my $is_cc = (length($tld) == 2) ? 1 : 0;

    if ($is_cc && $functional_sld{$sld}) {
        return join('.', @parts[-3 .. -1]) if @parts >= 3;
        return join('.', @parts[-2 .. -1]);
    }

    if ($tld eq "jp" && @parts >= 4) {
        my %jp_registry = map { $_ => 1 } qw(ac ed go gr lg ne or);
        if ($jp_registry{$sld} || $jp_registry{$t3} || $sld eq "city" || $t3 eq "city") {
            return join('.', @parts[-4 .. -1]);
        }
    }

    if ($tld eq "us" && @parts >= 4) {
        if ($parts[-3] eq "k12" && $parts[-2] =~ /^[a-z]{2}$/) {
            return join('.', @parts[-4 .. -1]);
        }
    }

    if ($tld =~ /^(com|org|net)$/ && $sld =~ /^(uk|eu|de|jp|us|gb|co)$/) {
        return join('.', @parts[-3 .. -1]) if @parts >= 3;
        return join('.', @parts[-2 .. -1]);
    }

    return join('.', @parts[-2 .. -1]);
}

sub is_same_organizational_domain {
    my ($dom1, $dom2) = @_;
    return 1 if lc(_trim($dom1 // "")) eq lc(_trim($dom2 // ""));

    my $base1 = get_organizational_domain($dom1);
    my $base2 = get_organizational_domain($dom2);

    return ($base1 ne "" && $base1 eq $base2) ? 1 : 0;
}

# =============================================
# DKIM/ARC-FUNKTIONEN
# =============================================
sub parse_dkim_txt_kv {
    my ($txt) = @_;
    $txt //= "";
    $txt = _trim($txt);

    my %kv;

    # split on semicolons, tolerate whitespace/newlines
    for my $part (split /\s*;\s*/, $txt) {
        $part = _trim($part);
        next unless length $part;

        my ($k, $v) = split /\s*=\s*/, $part, 2;
        $k = lc(_trim($k // ""));
        next unless length $k;

        $v = _trim($v // "");

        # DKIM: p= darf im TXT umbrochen sein, Whitespace ist irrelevant
        if ($k eq "p") {
            $v =~ s/\s+//g;
        }

        # v= und k= sind case-insensitive, stabilisieren
        if ($k eq "v" || $k eq "k") {
            $v = lc($v);
        }

        $kv{$k} = $v;  # last wins
    }

    return \%kv;
}


sub dkim_expected_match {
    my ($actual_rec, $expected_rec) = @_;
    $actual_rec   //= "";
    $expected_rec //= "";

    # keine Vorgabe => ok
    return 1 if _trim($expected_rec) eq "";

    my $a = parse_dkim_txt_kv($actual_rec);
    my $e = parse_dkim_txt_kv($expected_rec);

    # Safety: wenn parse mal nichts liefert
    $a = {} unless $a && ref($a) eq "HASH";
    $e = {} unless $e && ref($e) eq "HASH";

    for my $k (keys %$e) {
        my $kk = lc(_trim($k // ""));
        next if $kk eq "";  # ignore kaputte keys

        return 0 unless exists $a->{$kk};

        my $av = $a->{$kk};
        my $ev = $e->{$kk};

        return 0 unless defined $av && defined $ev;

        $av = _trim($av);
        $ev = _trim($ev);

        # p= darf Whitespace enthalten (TXT Umbruch), fuer Vergleich raus
        if ($kk eq "p") {
            $av =~ s/\s+//g;
            $ev =~ s/\s+//g;
        }

        # v= und k= sind case-insensitive, sauber vergleichen
        if ($kk eq "v" || $kk eq "k") {
            $av = lc($av);
            $ev = lc($ev);
        }

        return 0 unless $av eq $ev;
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
    return (0, "revoked") if defined $kv->{p} && $kv->{p} eq "";

    if ($kv->{k} && lc($kv->{k}) eq 'ed25519') {
        return (256, "ed25519");
    }

    my $p = $kv->{p};
    $p =~ s/\s+//g;
    my $pem = "-----BEGIN PUBLIC KEY-----\n" .
              join("\n", ($p =~ /.{1,64}/g)) .
              "\n-----END PUBLIC KEY-----\n";

    my $rsa;
    my $bits = 0;
    try {
        $rsa = Crypt::OpenSSL::RSA->new_public_key($pem);
        if ($rsa) {
            $bits = $rsa->size() * 8;
        }
    } catch {
        return (0, "invalid_key_format: $_");
    };

    return (0, "invalid_rsa_objekt") unless $bits;
    return ($bits, $bits < MIN_RSA_KEY_BITS ? "weak" : "ok");
}

# =============================================
# SPF-HILFSFUNKTIONEN
# =============================================
sub spf_normalize_token {
    my ($t) = @_;
    $t = _trim($t // "");
    return "" if $t eq "";

    $t =~ s/^[\+\-\~\?]//;

    $t =~ s/^(include:)([a-z0-9.-]+)\.$/$1$2/i;
    $t =~ s/^(redirect=)([a-z0-9.-]+)\.$/$1$2/i;
    $t =~ s/^(exists:)([a-z0-9.-]+)\.$/$1$2/i;
    $t =~ s/^(a:)([a-z0-9.-]+)\.$/$1$2/i;
    $t =~ s/^(mx:)([a-z0-9.-]+)\.$/$1$2/i;

    return lc($t);
}

sub spf_mechanism_type {
    my ($t) = @_;
    $t = spf_normalize_token($t);
    return "" if $t eq "";

    return "all"      if $t eq "all";
    return "redirect" if $t =~ /^redirect=/;
    return "include"  if $t =~ /^include:/;
    return "a"        if $t =~ /^a(?::|\/|$)/;
    return "mx"       if $t =~ /^mx(?::|\/|$)/;
    return "ptr"      if $t =~ /^ptr(?::|$)/;
    return "exists"   if $t =~ /^exists:/;
    return "ip4"      if $t =~ /^ip4:/;
    return "ip6"      if $t =~ /^ip6:/;

    my ($x) = $t =~ /^([^:=\s]+)/;
    return $x // "";
}

sub spf_is_void_lookup {
    my ($pkt) = @_;
    return 0 unless $pkt;

    my $rcode = $pkt->header->rcode // "";
    return 1 if $rcode eq "NXDOMAIN";

    return 0 unless $rcode eq "NOERROR";

    return 0 if (($pkt->header->ancount // 0) > 0);

    my @auth = $pkt->authority;
    for my $rr (@auth) {
        next unless $rr;
        return 1 if (($rr->type // "") eq "SOA");
    }

    return 0;
}

sub count_spf_lookups_recursive {
    my ($resolver, $domain, $timeout, $seen, $depth, $stats) = @_;
    $timeout //= DEFAULT_DNS_TIMEOUT;
    $seen    //= {};
    $depth   //= 0;
    $stats   //= { lookups => 0, void => 0, truncated => 0, dns_error => 0 };

    $domain = lc(_trim($domain // ""));
	if ($domain eq "" || $depth >= 10) {
		$stats->{truncated} = 1;  
		return;  # SOFORTIGER ABBRUCH (RFC 7208 §4.6.4)
	}

    return if $seen->{$domain}++;
    return if ($stats->{lookups} >= MAX_SPF_LOOKUPS);  # RFC 7208: 10 DNS-Lookups
    return if ($stats->{void}    >= 2);                # RFC 7208: Void-Limit 2

    my @txt = get_txt_records($resolver, $domain, $timeout);
    my ($spf) = grep { /^v=spf1(\s|$)/i } @txt;

    unless ($spf) {
        # "void lookup" (keine SPF TXT Antwort) zaehlt als void, wenn ein Lookup stattfand.
        $stats->{void}++;
        return;
    }

    my @tokens = split(/\s+/, $spf);
    for my $t (@tokens) {
        next if $t =~ /^v=spf1$/i;
        my $orig = $t;
        $t = spf_normalize_token($t);
        next unless $t;

        my $mtype = spf_mechanism_type($t);

        # DNS-Lookup Mechanismen/Modifier (RFC 7208 4.6.4)
        if ($mtype eq "include") {
            $stats->{lookups}++;
            last if $stats->{lookups} >= MAX_SPF_LOOKUPS;
            my ($inc) = $t =~ /include:([^\s]+)/i;
            next unless $inc;
            count_spf_lookups_recursive($resolver, $inc, $timeout, $seen, $depth + 1, $stats);
        }
        elsif ($mtype eq "redirect") {
            $stats->{lookups}++;
            last if $stats->{lookups} >= MAX_SPF_LOOKUPS;
            my ($rd) = $t =~ /redirect=([^\s]+)/i;
            next unless $rd;
            count_spf_lookups_recursive($resolver, $rd, $timeout, $seen, $depth + 1, $stats);
        }
		elsif ($mtype eq "a" || $mtype eq "mx" || $mtype eq "ptr" || $mtype eq "exists") {
			$stats->{lookups}++;
			last if $stats->{lookups} >= MAX_SPF_LOOKUPS;

			my $qname = $domain;

			if ($mtype eq "a" || $mtype eq "mx" || $mtype eq "ptr") {
				if ($t =~ /^(?:a|mx|ptr):([^\/\s]+)(?:\/\d+)?$/i) {
					$qname = lc(_trim($1));
				}
			}
			elsif ($mtype eq "exists") {
				if ($t =~ /^exists:([^\s]+)$/i) {
					$qname = lc(_trim($1));
				}
			}

			my $qtype = uc($mtype);
			$qtype = "A" if $mtype eq "exists";

			# PTR fuer Domain macht wenig Sinn, deshalb optional: nicht querien
			if ($mtype eq "ptr") {
				next;
			}

			my $sub_pkt = safe_dns_query($resolver, $qname, $qtype, 1, $timeout);

			if (spf_is_void_lookup($sub_pkt)) {
				$stats->{void}++;
				last if $stats->{void} >= 2;
			}
		}


        # Bei DNS Fehlern nicht zu aggressiv abbrechen, aber merken
        # (spf_is_void_lookup setzt stats->{dns_error} nicht, das passiert an anderer Stelle)
    }
}

sub spf_valid_ip4_cidr {
    my ($s) = @_;
    return 0 unless defined $s && $s ne "";
    my ($ip, $mask) = split(/\//, $s, 2);

    my @o = split(/\./, $ip);
    return 0 unless @o == 4;
    for my $x (@o) {
        return 0 unless $x =~ /^\d+$/ && $x >= 0 && $x <= 255;
    }
    if (defined $mask) {
        return 0 unless $mask =~ /^\d+$/ && $mask >= 0 && $mask <= 32;
    }
    return 1;
}

sub spf_valid_ip6_cidr_basic {
    my ($s) = @_;
    return 0 unless defined $s && $s ne "";
    my ($ip, $mask) = split(/\//, $s, 2);

    return 0 unless $ip =~ /^[0-9a-fA-F:\.]+$/;
    return 0 unless $ip =~ /:/;

    if (defined $mask) {
        return 0 unless $mask =~ /^\d+$/ && $mask >= 0 && $mask <= 128;
    }
    return 1;
}

# =============================================
# HAUPT-CHECKS (Alphabetisch)
# =============================================

sub check_bimi {
    my ($resolver, $domain, $profile, $timeout) = @_;

    return { status => "skip", message => "BIMI nicht gefordert" }
        unless $profile->{require_bimi};

    my $name = "default._bimi.$domain";
    my @txt  = get_txt_records($resolver, $name, $timeout);
    my ($bimi) = grep { /^v=BIMI1/i } @txt;

    unless ($bimi) {
        return {
            status  => "fail",
            message => "Kein BIMI-Record gefunden",
            spec    => "IETF Internet Draft (BIMI)",
            record  => "",
        };
    }

    my %tags;
    my @notes;
    my $status = "ok";

    # Parse BIMI Record
    for my $part (split /\s*;\s*/, $bimi) {
        my ($k, $v) = split(/\s*=\s*/, $part, 2);
        $k = lc(_trim($k // ""));
        $v = _trim($v // "");
        $tags{$k} = $v if $k ne "";
    }

    # Pflicht-Tags
    unless (exists $tags{v} && lc($tags{v}) eq "bimi1") {
        $status = "fail";
        push @notes, "FEHLER: 'v=' Tag fehlt oder ist ungueltig (erwartet: 'v=BIMI1').";
    }

    unless (exists $tags{l} && $tags{l} ne "") {
        $status = "fail";
        push @notes, "FEHLER: 'l=' Tag (Logo-URL) fehlt.";
    } else {
        # Logo-URL Checks
        unless ($tags{l} =~ /^https:\/\//i) {
            $status = ($status eq "fail") ? "fail" : "warn";
            push @notes, "Warnung: 'l=' Tag sollte eine HTTPS-URL sein (gefunden: $tags{l}).";
        }
        unless ($tags{l} =~ /\.svg(\?.*)?$/i) {
            $status = ($status eq "fail") ? "fail" : "warn";
            push @notes, "Hinweis: Logo-URL sollte auf '.svg' enden (gefunden: $tags{l}).";
        }

        # --- NEU: Prüfe Logo-Domain gegen Whitelist ---
        if ($tags{l} =~ /^https:\/\/(.+?)\//) {
            my $logo_domain = lc($1);
            my @allowed_logo_domains = @{$profile->{bimi_policy}{allowed_logo_domains} // []};
            unless (grep { $logo_domain eq lc($_) } @allowed_logo_domains) {
                push @notes, "FEHLER: Logo-URL stammt von unzulässiger Domain: $logo_domain (erlaubt: " . join(", ", @allowed_logo_domains) . ")";
                $status = "fail";
            }
        }
    }

    # Optionales 'a=' Tag (Zertifikat)
    if (exists $tags{a} && $tags{a} ne "") {
        unless ($tags{a} =~ /^https:\/\//i) {
            $status = ($status eq "fail") ? "fail" : "warn";
            push @notes, "Warnung: 'a=' Tag (VMC-Zertifikat-URL) sollte eine HTTPS-URL sein (gefunden: $tags{a}).";
        }
    }

    # HTTP-Client für Logo- und VMC-Prüfungen
    my $http = HTTP::Tiny->new(
        timeout    => ($timeout // 10),
        verify_SSL => 1,
        agent      => "domain_dns_audit/@{[VERSION]}",
    );

    # Optional: Erreichbarkeit Logo prüfen (nur wenn nicht bereits fail)
    if ($status ne "fail" && exists $tags{l} && $tags{l} ne "") {
        # --- NEU: Content-Type prüfen ---
        my $head_res = $http->head($tags{l});
        if ($head_res->{success}) {
            my $content_type = $head_res->{headers}{'content-type'} // "";
            unless ($content_type =~ /image\/svg\+xml/i) {
                push @notes, "FEHLER: Logo-URL hat ungültigen Content-Type: $content_type (erwartet: image/svg+xml).";
                $status = "fail";
            }
        } else {
            my $code = $head_res->{status} // "n/a";
            push @notes, "FEHLER: Logo-URL '$tags{l}' ist nicht erreichbar (HTTP-Status: $code).";
            $status = "fail";
        }
    }

    # --- NEU: VMC-Zertifikat prüfen ---
    if (exists $tags{a} && $tags{a} ne "") {
        my $vmc_url = $tags{a};
        my $vmc_res = $http->head($vmc_url);
        unless ($vmc_res->{success}) {
            my $code = $vmc_res->{status} // "n/a";
            push @notes, "FEHLER: VMC-Zertifikat-URL '$vmc_url' ist nicht erreichbar (HTTP-Status: $code).";
            $status = "fail";
        }
    }

    return {
        status  => $status,
        message => $status eq "ok"  ? "BIMI-Record ist valide"
                 : $status eq "warn" ? "BIMI-Record mit Warnungen"
                 : "BIMI-Record fehlerhaft",
        spec    => "IETF Internet Draft (BIMI)",
        record  => $bimi,
        notes   => \@notes,
        tags    => \%tags,
    };
}



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
    my @notes;
    my $status = "ok";

    my $saw_tlsa       = 0;
    my $saw_ad_missing = 0;
    my $saw_ad_ok      = 0;

    for my $mxh (map { $_->{exchange} } @mx) {
        $mxh =~ s/\.$//;
        next unless $mxh;

        for my $port (@ports) {
            my $name = "_" . int($port) . "._tcp.$mxh";
            my $pkt  = safe_dns_query($resolver, $name, 'TLSA', 1, 2);
            next unless $pkt;

            my $ad = 0;
            $ad = 1 if ($pkt && $pkt->header && $pkt->header->ad);

            for my $rr ($pkt->answer) {
                next unless $rr->type eq "TLSA";

                $saw_tlsa = 1;
                $ad ? ($saw_ad_ok = 1) : ($saw_ad_missing = 1);

                my $usage        = $rr->usage;
                my $selector     = $rr->selector;
                my $matchingtype = $rr->matchingtype;
                my $certdata     = $rr->certdata;

                unless ($usage =~ /^[0-3]$/) {
                    push @notes, "FEHLER: Ungültiger TLSA 'usage' Wert '$usage' (erlaubt: 0-3).";
                    $status = worst_status($status, "fail");
                }

                unless ($selector =~ /^[01]$/) {
                    push @notes, "FEHLER: Ungültiger TLSA 'selector' Wert '$selector' (erlaubt: 0-1).";
                    $status = worst_status($status, "fail");
                }

                my $data_len = length($certdata);

                if ($matchingtype == 0) {
                    if ($data_len < 128) {
                        push @notes, "Warnung: Matching Type 0 (Full), aber Daten auffällig kurz ($data_len Bytes).";
                        $status = worst_status($status, "warn");
                    }
                }
                elsif ($matchingtype == 1) {
                    if ($data_len != 32) {
                        push @notes, "FEHLER: TLSA SHA-256 Digest hat falsche Länge ($data_len statt 32 Bytes).";
                        $status = worst_status($status, "fail");
                    }
                }
                elsif ($matchingtype == 2) {
                    if ($data_len != 64) {
                        push @notes, "FEHLER: TLSA SHA-512 Digest hat falsche Länge ($data_len statt 64 Bytes).";
                        $status = worst_status($status, "fail");
                    }
                }
                else {
                    push @notes, "FEHLER: Ungültiger 'matchingtype' Wert '$matchingtype' (erlaubt: 0-2).";
                    $status = worst_status($status, "fail");
                }

                push @tlsa, {
                    mx           => $mxh,
                    port         => int($port),
                    usage        => $usage,
                    selector     => $selector,
                    matchingtype => $matchingtype,
                    certdata_len => $data_len,
                    ad_flag      => $ad,
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
            notes   => \@notes,
        };
    }

    if ($saw_ad_missing) {
        $status = worst_status($status, "fail");
        push @notes, "KRITISCH: TLSA vorhanden, aber keine DNSSEC-validierte Antwort (AD-Flag fehlt). RFC 7672 setzt DNSSEC-Validierung voraus.";
    }

    my $final_msg = ($status eq "ok")   ? "DANE TLSA korrekt konfiguriert und DNSSEC-validiert"
                  : ($status eq "warn") ? "DANE vorhanden, aber DNSSEC-Verifikation unsicher"
                  : "DANE Konfigurationsfehler oder fehlende DNSSEC-Basis";

    return {
        status  => $status,
        message => $final_msg,
        rfc     => "RFC 7672",
        ports   => \@ports,
        tlsa    => \@tlsa,
        notes   => \@notes,
    };
}

sub check_dkim {
    my ($resolver, $domain, $profile, $timeout) = @_;

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
    my $found_count = 0;
    my $status = "ok";

    for my $sel (@selectors) {
        my $name = "$sel._domainkey.$domain";
        my ($txt_ref, $cname_target) = get_txt_records_follow_cname($resolver, $name, $timeout);
        my @txt = @$txt_ref;

        if ($cname_target) {
            push @notes, "DKIM $sel: Verweist via CNAME auf $cname_target";
        }

        my ($rec) = grep { /v=DKIM1/i } @txt;
        ($rec) = @txt if !defined $rec && @txt;

        if (!defined $rec) {
            push @notes, "DKIM $sel: Record nicht im DNS gefunden";
            next;
        }

        $found_count++;

        my $kv = parse_dkim_txt_kv($rec);
        my $v_tag = lc($kv->{v} // "");
        my $k_tag = lc($kv->{k} // "rsa");

        my $ok_contains = ($v_tag eq "" || $v_tag eq "dkim1") && ($k_tag eq "rsa" || $k_tag eq "ed25519");

        my $ok_expected = 1;
        if (ref($expected) eq 'HASH' && exists $expected->{$sel}) {
            my $want = $expected->{$sel} // "";
            if (_trim($want) ne "") {
                $ok_expected = dkim_expected_match($rec, $want) ? 1 : 0;
                push @notes, "DKIM $sel: Record-Inhalt entspricht nicht der Vorgabe" unless $ok_expected;
            }
        }

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

        if (exists $kv->{h}) {
            my %valid_hash_algos = map { $_ => 1 } qw(sha1 sha256);
            my @hash_algos = split(/:/, lc($kv->{h}));
            for my $algo (@hash_algos) {
                unless ($valid_hash_algos{$algo}) {
                    push @notes, "FEHLER: Ungültiger Hash-Algorithmus '$algo' im 'h=' Tag (RFC 6376 §3.3).";
                    $ok_contains = 0;
                }
                if ($algo eq "sha1") {
                    push @notes, "Warnung: 'h=sha1' ist veraltet und unsicher (RFC 6376 §3.3). Verwende 'sha256'.";
                    $status = worst_status($status, "warn");
                }
            }
        }

		if (exists $kv->{t}) {
            my %flags = map { $_ => 1 } split(/:/, lc($kv->{t}));
            if ($flags{y}) {
                push @notes, "Hinweis: DKIM Selektor $sel ist im Testmodus (t=y).";
                $status = worst_status($status, "info");
            }
            if ($flags{s}) {
                push @notes, "Hinweis: Selektor $sel ist auf die Hauptdomain beschränkt (t=s), keine Subdomains.";
            }
            for my $f (keys %flags) {
                unless ($f eq 'y' || $f eq 's') {
                    push @notes, "Warnung: Unbekanntes Flag '$f' im t= Tag.";
                }
            }
        }

        if (exists $kv->{s}) {
            my @services = split(/:/, lc($kv->{s}));
            unless (grep { $_ eq '*' || $_ eq 'email' } @services) {
                push @notes, "FEHLER: Selektor $sel ist nicht für E-Mail-Dienste freigegeben (s=$kv->{s}).";
                $ok_contains = 0;
            }
        }

        if (scalar(grep { /v=DKIM1/i } @txt) > 1) {
            push @notes, "KRITISCH: Mehrere DKIM-Records für Selektor $sel gefunden. Dies führt zu Validierungsfehlern.";
            $status = "fail";
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

    unless (@found) {
        return {
            status  => "fail",
            message => "Keiner der geforderten Selektoren wurde im DNS gefunden",
            rfc     => "RFC 6376",
            found   => [],
            notes   => \@notes,
        };
    }

    my @individual_results;
    for my $f (@found) {
        if ($f->{is_revoked}) {
            push @individual_results, "warn";
        } elsif ($f->{ok_contains} && $f->{ok_expected} && $f->{key_strength} eq "ok") {
            push @individual_results, "ok";
        } elsif ($f->{key_strength} eq "weak") {
            push @individual_results, "warn";
        } else {
            push @individual_results, "fail";
        }
    }

    if ($eval_mode eq "all_ok") {
        if ($found_count < scalar(@selectors)) {
            $status = "fail";
            push @notes, "FEHLER: Modus 'all_ok' aktiv, aber es wurden nur $found_count von " . scalar(@selectors) . " Selektoren gefunden.";
        } else {
            $status = (grep { $_ ne "ok" } @individual_results) ? "fail" : "ok";
            if ($status eq "fail" && !(grep { $_ eq "fail" } @individual_results)) {
                $status = "warn";
            }
        }
    } else {
        $status = (grep { $_ eq "ok" } @individual_results) ? "ok" :
                  (grep { $_ eq "warn" } @individual_results) ? "warn" : "fail";
    }

    return {
        status  => $status,
        message => $status eq "ok" ? "DKIM Prüfung erfolgreich" :
                   $status eq "warn" ? "DKIM vorhanden mit Warnungen" : "DKIM Policy verletzt (mind. ein Selektor fehlt oder ist fehlerhaft)",
        rfc     => "RFC 6376",
        found   => \@found,
        notes   => \@notes,
    };
}

sub check_dmarc {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "DMARC nicht gefordert", rfc => "RFC 7489" }
        unless $profile->{require_dmarc};

    my $org_domain = get_organizational_domain($domain);
    my $is_subdomain = (lc($domain) ne lc($org_domain)) ? 1 : 0;
    my $used_fallback = 0;

    my $name = "_dmarc.$domain";
    my @txt = get_txt_records($resolver, $name, $timeout);
    my @dmarc_candidates = grep { /^v=DMARC1(\s|;|$)/i } @txt;

    if (!@dmarc_candidates && $is_subdomain) {
        my $fallback_name = "_dmarc.$org_domain";
        my @fallback_txt = get_txt_records($resolver, $fallback_name, $timeout);
        my @fallback_candidates = grep { /^v=DMARC1(\s|;|$)/i } @fallback_txt;

        if (@fallback_candidates) {
            @dmarc_candidates = @fallback_candidates;
            $name = $fallback_name;
            $used_fallback = 1;
        }
    }

    if (@dmarc_candidates > 1) {
        return {
            status  => "fail",
            message => "Mehrere DMARC-Records gefunden (RFC 7489 §6.6.3)",
            rfc     => "RFC 7489",
            record  => join(" | ", @dmarc_candidates),
            notes   => [
                "Gefunden: " . scalar(@dmarc_candidates) . " DMARC-Records.",
                "Empfänger ignorieren DMARC, wenn mehr als ein Record existiert.",
                "Lösung: Nur einen DMARC-Record behalten."
            ],
        };
    }

    my $rec = $dmarc_candidates[0];
    unless ($rec) {
        return {
            status  => "fail",
            message => "Kein DMARC-Record gefunden (RFC 7489 §6.1)",
            rfc     => "RFC 7489",
            record  => "",
            notes   => ["Ohne DMARC erhalten Empfänger keine Anweisungen für nicht authentifizierte E-Mails."],
        };
    }

    my $status = "ok";
    my @notes;
    my %tags;
    my @external_auth;

    if ($used_fallback) {
        push @notes, "Info: Kein Record auf Subdomain gefunden. Nutze Fallback von Hauptdomain ($org_domain).";
    }

    for my $part (split /\s*;\s*/, $rec) {
        next unless $part =~ /=/;
        my ($k, $v) = split(/\s*=\s*/, $part, 2);
        $k = lc(_trim($k // ""));
        $v = _trim($v // "");
        $tags{$k} = $v if $k;
    }

    my %valid_tags = map { $_ => 1 } qw(v p rua ruf pct adkim aspf sp fo ri rf);
    for my $tag (keys %tags) {
        unless ($valid_tags{$tag}) {
            push @notes, "Hinweis: Unbekanntes DMARC-Tag '$tag=' (RFC 7489 §6.3).";
            $status = worst_status($status, "warn");
        }
    }

    my $p = $tags{p} // "";
    if (!$p) {
        $status = worst_status($status, "fail");
        push @notes, "FEHLER: 'p=' fehlt (RFC 7489 §6.1).";
    } else {
        my $effective_p = ($used_fallback && exists $tags{sp}) ? $tags{sp} : $p;

        if (my @okp = _as_list($profile->{dmarc_ok_policies})) {
            unless (grep { $_ eq $effective_p } @okp) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Effektive Policy '" . ($used_fallback ? "sp=" : "p=") . "$effective_p' entspricht nicht den Vorgaben.";
            }
        }
        if ($effective_p eq "none") {
            $status = worst_status($status, "warn");
            push @notes, "Hinweis: '$effective_p' ist nur für Monitoring (RFC 7489 §6.1).";
        }
    }

    for my $tag_name (qw(rua ruf)) {
        if (my $uris = $tags{$tag_name}) {
            my @uris = split(/\s*,\s*/, $uris);
            for my $uri (@uris) {
                unless ($uri =~ /^(mailto|https):/i) {
                    $status = worst_status($status, "fail");
                    push @notes, "FEHLER: Ungültiges '$tag_name=' Format: '$uri' (nur mailto: oder https: erlaubt).";
                    next;
                }

                my $report_domain;
                if ($uri =~ /^mailto:.*\@([a-z0-9.-]+)/i) {
                    $report_domain = lc($1);
                } elsif ($uri =~ /^https:\/\/([a-z0-9.-]+)/i) {
                    $report_domain = lc($1);
                } else {
                    next;
                }

                my $dmarc_check_name = "_dmarc.$report_domain";
                my @dmarc_check_txt = get_txt_records($resolver, $dmarc_check_name, $timeout);
                my ($dmarc_check_rec) = grep { /^v=DMARC1(\s|;|$)/i } @dmarc_check_txt;

                my $verify_name;
                my $verify_exists = 1;
                if (!is_same_organizational_domain($domain, $report_domain)) {
                    $verify_name = "$domain._report._dmarc.$report_domain";
                    my @v_txt = get_txt_records($resolver, $verify_name, $timeout);
                    my ($v_rec) = grep { /^v=DMARC1(\s|;|$)/i } @v_txt;
                    $verify_exists = $v_rec ? 1 : 0;
                }

                push @external_auth, {
                    tag                 => $tag_name,
                    uri                 => $uri,
                    report_domain       => $report_domain,
                    dmarc_check_name    => $dmarc_check_name,
                    dmarc_check_exists  => $dmarc_check_rec ? 1 : 0,
                    verify_name         => $verify_name // "N/A (eigene Domain)",
                    verify_exists       => $verify_exists,
                };

                unless ($dmarc_check_rec) {
                    $status = worst_status($status, "fail");
                    push @notes, "FEHLER: $tag_name-Domain '$report_domain' hat keine gültige DMARC-Policy ($dmarc_check_name).";
                }

                if (!is_same_organizational_domain($domain, $report_domain) && !$verify_exists) {
                    $status = worst_status($status, "fail");
                    push @notes, "FEHLER: $tag_name-Domain '$report_domain' hat keine Berechtigung ($verify_name fehlt).";
                }

                unless (is_same_organizational_domain($domain, $report_domain)) {
                    push @notes, "Hinweis: $tag_name-Domain '$report_domain' ist extern (RFC 7489 §6.3).";
                }
            }
        } elsif ($tag_name eq 'rua') {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: Kein 'rua=' für Berichte definiert.";
        }
    }

    for my $tag (qw(adkim aspf)) {
        if (exists $tags{$tag} && $tags{$tag} !~ /^(r|s)$/) {
            $status = worst_status($status, "fail");
            push @notes, "FEHLER: Ungültiger '$tag=' Wert: '$tags{$tag}' (nur 'r' oder 's' erlaubt).";
        }
    }

    if (exists $tags{sp} && $tags{sp} !~ /^(none|quarantine|reject)$/) {
        $status = worst_status($status, "fail");
        push @notes, "FEHLER: Ungültige Subdomain-Policy 'sp=$tags{sp}'.";
    }

    if (exists $tags{fo}) {
        my %valid_fo = map { $_ => 1 } qw(0 1 d s);
        for my $fo (split(/:/, $tags{fo})) {
            unless ($valid_fo{$fo}) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Ungültiger 'fo=' Wert: '$fo' (RFC 7489 §6.1).";
            }
        }
    }

    if (exists $tags{rf}) {
        my %valid_rf = map { $_ => 1 } qw(afrf iodef);
        for my $rf (split(/:/, $tags{rf})) {
            unless ($valid_rf{$rf}) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Ungültiger 'rf=' Wert: '$rf' (RFC 7489 §6.1).";
            }
        }
    }

    if (exists $tags{pct}) {
        unless ($tags{pct} =~ /^\d+$/ && $tags{pct} >= 0 && $tags{pct} <= 100) {
            $status = worst_status($status, "fail");
            push @notes, "FEHLER: 'pct=' muss zwischen 0 und 100 liegen.";
        } elsif ($tags{pct} < 100) {
            $status = worst_status($status, "warn");
            push @notes, "Hinweis: 'pct=$tags{pct}' < 100% (RFC 7489 §6.1).";
        }
    }

    if (exists $tags{ri}) {
        unless ($tags{ri} =~ /^\d+$/ && $tags{ri} >= 1) {
            $status = worst_status($status, "fail");
            push @notes, "FEHLER: 'ri=' muss eine positive Zahl sein.";
        } elsif ($tags{ri} < 86400) {
            $status = worst_status($status, "warn");
            push @notes, "Hinweis: 'ri=$tags{ri}' < 86400s (1 Tag).";
        }
    }

    my $message = {
        fail => "DMARC-Policy verletzt RFC 7489",
        warn => "DMARC mit Warnungen",
        ok   => "DMARC ist valide",
    }->{$status};

    return {
        status        => $status,
        message       => $message,
        rfc           => "RFC 7489",
        record        => $rec,
        policy        => $p,
        used_fallback => $used_fallback,
        notes         => \@notes,
        tags          => \%tags,
        external_auth => \@external_auth,
    };
}

sub check_dnssec_zone {
    my ($resolver, $domain, $timeout) = @_;

    $timeout //= DEFAULT_DNS_TIMEOUT;

    my $d = normalize_for_dnssec($domain);
    return {
        status  => "fail",
        message => "DNSSEC: ungültige Domain",
        rfc     => "RFC 4033/4034/4035",
        details => { input => ($domain // ""), normalized_domain => ($d // "") },
    } unless $d;

    $resolver->dnssec(1);

    my $parent_domain = get_parent_domain($d);

    if (!$parent_domain) {
        my $key_pkt = safe_dns_query($resolver, $d, "DNSKEY", MAX_DNS_RETRIES, $timeout);

        my @keys   = $key_pkt ? grep { $_->type eq "DNSKEY" } $key_pkt->answer : ();
        my @rrsigs = $key_pkt ? grep { $_->type eq "RRSIG"  } $key_pkt->answer : ();

        my $ad = 0;
        $ad = ($key_pkt && $key_pkt->header && $key_pkt->header->ad) ? 1 : 0;

        if (@keys && (@rrsigs || $ad)) {
            return {
                status  => "warn",
                message => "DNSSEC sichtbar (DNSKEY vorhanden), aber Parent-Zone nicht bestimmbar, DS-Prüfung nicht möglich",
                rfc     => "RFC 4033/4034/4035",
                details => {
                    normalized_domain => $d,
                    parent_domain     => "",
                    ds_count          => 0,
                    parent_ds_count   => 0,
                    dnskey_count      => scalar(@keys),
                    rrsig_count       => scalar(@rrsigs),
                    ad_flag           => $ad,
                },
            };
        }

        return {
            status  => "fail",
            message => "DNSSEC nicht nachweisbar (Parent-Zone nicht bestimmbar, keine DNSKEY Daten)",
            rfc     => "RFC 4033/4034/4035",
            details => {
                normalized_domain => $d,
                parent_domain     => "",
                ds_count          => 0,
                parent_ds_count   => 0,
                dnskey_count      => scalar(@keys),
                rrsig_count       => scalar(@rrsigs),
                ad_flag           => $ad,
            },
        };
    }

    my $ds_pkt = safe_dns_query($resolver, $d, "DS", MAX_DNS_RETRIES, $timeout);
    my @ds = $ds_pkt ? grep { $_->type eq "DS" } $ds_pkt->answer : ();

    my $parent_ds_pkt = safe_dns_query($resolver, $parent_domain, "DS", MAX_DNS_RETRIES, $timeout);
    my @parent_ds = $parent_ds_pkt ? grep { $_->type eq "DS" } $parent_ds_pkt->answer : ();

    my $key_pkt = safe_dns_query($resolver, $d, "DNSKEY", MAX_DNS_RETRIES, $timeout);
    my @keys   = $key_pkt ? grep { $_->type eq "DNSKEY" } $key_pkt->answer : ();
    my @rrsigs = $key_pkt ? grep { $_->type eq "RRSIG"  } $key_pkt->answer : ();

    my $ad = 0;
    if ($key_pkt && $key_pkt->header) {
        $ad = $key_pkt->header->ad ? 1 : 0;
    }

    if (@keys && @rrsigs) {
        if (@parent_ds) {
            return {
                status  => "ok",
                message => "DNSSEC validiert (DNSKEY, RRSIG und DS in Parent-Zone vorhanden)",
                rfc     => "RFC 4033/4034/4035",
                details => {
                    normalized_domain => $d,
                    parent_domain     => $parent_domain,
                    ds_count          => scalar(@ds),
                    parent_ds_count   => scalar(@parent_ds),
                    dnskey_count      => scalar(@keys),
                    rrsig_count       => scalar(@rrsigs),
                    ad_flag           => $ad,
                },
            };
        }

        return {
            status  => "warn",
            message => "DNSSEC sichtbar (DNSKEY und RRSIG vorhanden), aber kein DS in Parent-Zone gefunden",
            rfc     => "RFC 4033/4034/4035",
            details => {
                normalized_domain => $d,
                parent_domain     => $parent_domain,
                ds_count          => scalar(@ds),
                parent_ds_count   => scalar(@parent_ds),
                dnskey_count      => scalar(@keys),
                rrsig_count       => scalar(@rrsigs),
                ad_flag           => $ad,
            },
        };
    }

    if (@keys && !@rrsigs && $ad) {
        if (@parent_ds) {
            return {
                status  => "ok",
                message => "DNSSEC vermutlich validiert (DNSKEY vorhanden, AD gesetzt, RRSIG evtl. gefiltert, DS in Parent-Zone vorhanden)",
                rfc     => "RFC 4033/4034/4035",
                details => {
                    normalized_domain => $d,
                    parent_domain     => $parent_domain,
                    ds_count          => scalar(@ds),
                    parent_ds_count   => scalar(@parent_ds),
                    dnskey_count      => scalar(@keys),
                    rrsig_count       => scalar(@rrsigs),
                    ad_flag           => $ad,
                },
            };
        }

        return {
            status  => "warn",
            message => "DNSSEC teilweise sichtbar (DNSKEY vorhanden, AD gesetzt, RRSIG evtl. gefiltert), aber kein DS in Parent-Zone gefunden",
            rfc     => "RFC 4033/4034/4035",
            details => {
                normalized_domain => $d,
                parent_domain     => $parent_domain,
                ds_count          => scalar(@ds),
                parent_ds_count   => scalar(@parent_ds),
                dnskey_count      => scalar(@keys),
                rrsig_count       => scalar(@rrsigs),
                ad_flag           => $ad,
            },
        };
    }

    if (@keys && !@rrsigs) {
        return {
            status  => "warn",
            message => "DNSSEC teilweise sichtbar (DNSKEY vorhanden, aber keine RRSIG Records oder AD Flag nicht gesetzt)",
            rfc     => "RFC 4033/4034/4035",
            details => {
                normalized_domain => $d,
                parent_domain     => $parent_domain,
                ds_count          => scalar(@ds),
                parent_ds_count   => scalar(@parent_ds),
                dnskey_count      => scalar(@keys),
                rrsig_count       => scalar(@rrsigs),
                ad_flag           => $ad,
            },
        };
    }

    if (@ds && !@keys) {
        return {
            status  => "warn",
            message => "DNSSEC inkonsistent (DS vorhanden, aber keine DNSKEY Antwort)",
            rfc     => "RFC 4033/4034/4035",
            details => {
                normalized_domain => $d,
                parent_domain     => $parent_domain,
                ds_count          => scalar(@ds),
                parent_ds_count   => scalar(@parent_ds),
                dnskey_count      => scalar(@keys),
                rrsig_count       => scalar(@rrsigs),
                ad_flag           => $ad,
            },
        };
    }

    return {
        status  => "fail",
        message => "DNSSEC nicht nachweisbar (kein DS in Parent-Zone, keine DNSKEY oder keine validierten Antworten)",
        rfc     => "RFC 4033/4034/4035",
        details => {
            normalized_domain => $d,
            parent_domain     => $parent_domain,
            ds_count          => scalar(@ds),
            parent_ds_count   => scalar(@parent_ds),
            dnskey_count      => scalar(@keys),
            rrsig_count       => scalar(@rrsigs),
            ad_flag           => $ad,
        },
    };
}

sub normalize_for_dnssec {
    my ($d) = @_;
    $d = lc(_trim($d // ""));
    return "" unless $d;

    my $org = get_organizational_domain($d);
    return $org if $org;

    return $d;
}

sub get_parent_domain {
    my ($domain) = @_;
    my @parts = split(/\./, $domain);
    return unless @parts > 1;
    my $parent = join('.', @parts[1..$#parts]);
    return $PSL_REF->{lc($parent)} ? $parent : undef;
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

    my %dns_kv;
    for my $part (split /\s*;\s*/, $sts) {
        my ($k, $v) = split(/\s*=\s*/, $part, 2);
        $dns_kv{lc(_trim($k // ""))} = _trim($v // "") if $k;
    }
    my $dns_id = $dns_kv{id} // "";

    my ($ok, $msg, $body, $url) = fetch_mta_sts_policy($domain, $timeout);
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
    my $status = "ok";

    my $pol_id = $kv->{id} // "";
    if ($dns_id ne "" && $pol_id ne "") {
        if ($dns_id ne $pol_id) {
            push @notes, "Abweichung: DNS id ($dns_id) passt nicht zu Policy id ($pol_id). Änderungen an der Policy werden von Sendern evtl. ignoriert.";
            $status = worst_status($status, "warn");
        }
    }

    my $want_mode = lc($profile->{mta_sts_mode} // "");
    if ($want_mode) {
        my $is_mode = lc($kv->{mode} // "");
        if ($is_mode ne $want_mode) {
            push @notes, "Policy mode stimmt nicht (erwartet: $want_mode, gefunden: $is_mode)";
            $status = "fail";
        }
    }

    my $ma = $kv->{max_age};
    if (!defined $ma || $ma !~ /^\d+$/) {
        push @notes, "FEHLER: Policy max_age fehlt oder ist keine Zahl";
        $status = "fail";
    } else {
        my $want_max_age = $profile->{mta_sts_max_age};
        if (defined $want_max_age && int($ma) < int($want_max_age)) {
            push @notes, "Policy max_age ($ma) ist kleiner als gefordert ($want_max_age)";
            $status = "fail";
        }
        if (int($ma) < 86400) {
            push @notes, "Warnung: max_age ist sehr kurz ($ma s). Empfohlen wird mindestens 1 Tag (86400s).";
            $status = worst_status($status, "warn");
        }
    }

    return {
        status     => $status,
        message    => ($status eq "ok") ? "MTA-STS OK" : "MTA-STS Prüfung fehlerhaft oder mit Warnungen",
        rfc        => "RFC 8461",
        record     => $sts,
        policy_url => $url,
        policy     => $kv,
        dns_id     => $dns_id,
        notes      => \@notes,
    };
}

sub fetch_mta_sts_policy {
    my ($domain, $timeout) = @_;
    $timeout //= DEFAULT_DNS_TIMEOUT;
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

        if ($res->{status} =~ /^(301|302|303|307|308)$/) {
            my $loc = _trim($res->{headers}{location} // "");
            unless ($loc) {
                return (0, "Redirect ohne Location Header", "", $cur);
            }
			# 1. Prüfe, ob der Redirect HTTPS verwendet
			unless ($loc =~ m/^https:\/\//i) {
				return (0, "Redirect nicht HTTPS: $loc", "", $cur);
			}

			# 2. Extrahiere die Domain aus der Redirect-URL
			my $redirect_domain;
			if ($loc =~ m|^https://([a-z0-9.-]+)|i) {
				$redirect_domain = lc($1);
			} else {
				return (0, "Konnte Domain aus Redirect-URL nicht extrahieren: $loc", "", $cur);
			}

			# 3. Prüfe, ob die Redirect-Domain zur ursprünglichen Domain gehört
			#    Erlaubt sind:
			#    - Exakte Übereinstimmung: mta-sts.example.com
			#    - Subdomain der ursprünglichen Domain: mta-sts.sub.example.com
			unless ($redirect_domain eq "mta-sts.$domain" ||
				   $redirect_domain =~ /\.mta-sts\.$domain$/i ||
				   $redirect_domain =~ /^mta-sts\.[a-z0-9.-]+\.\Q$domain\E$/i) {
				return (0, "Redirect zu unzulässiger Domain: $loc (erwartet: mta-sts.$domain oder Subdomain davon)", "", $cur);
			}
            $cur = $loc;
            next;
        }

        unless ($res->{success}) {
            return (0, "HTTP status $res->{status}", "", $cur);
        }

        my $ct = $res->{headers}{'content-type'} // "";
        unless ($ct =~ m|^text/plain|i) {
            return (0, "Falscher Content-Type: $ct (erwartet text/plain)", "", $cur);
        }

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

    # --- NEU: Prüfe erwartete MX-Server aus dem Profil ---
    if (exists $profile->{mx_policy}{groups} && ref($profile->{mx_policy}{groups}) eq 'ARRAY') {
        my @expected_mx = map { lc($_) }
            @{ $profile->{mx_policy}{groups}[0]{mx_required} // [] };
        if (@expected_mx) {
            my %expected_set = map { $_ => 1 } @expected_mx;
            my %found_set    = map { $_ => 1 } @ex;

            # Prüfe, ob alle erwarteten MX-Server vorhanden sind
            for my $expected (@expected_mx) {
                unless (exists $found_set{$expected}) {
                    push @notes, "FEHLER: Erwarteter MX-Server '$expected' fehlt.";
                    $status = worst_status($status, "fail");
                }
            }

            # Prüfe auf unerwartete MX-Server (wenn mx_allow_others = false)
            if (exists $profile->{mx_policy}{groups}[0]{mx_allow_others} &&
                !$profile->{mx_policy}{groups}[0]{mx_allow_others}) {
                for my $found (@ex) {
                    unless (exists $expected_set{$found}) {
                        push @notes, "FEHLER: Unerwarteter MX-Server '$found' gefunden.";
                        $status = worst_status($status, "fail");
                    }
                }
            }
        }
    }

    # --- Bestehende IP-Prüfung ---
    for my $mxh (@ex) {
        my $target = $mxh;
        $target =~ s/\.$//;
        next unless $target;

        my $pkt_a    = safe_dns_query($resolver, $target, 'A', 1, 2);
        my $pkt_aaaa = safe_dns_query($resolver, $target, 'AAAA', 1, 2);

        my $has_ip = 0;
        $has_ip = 1 if ($pkt_a    && grep { $_->type eq 'A'    } $pkt_a->answer);
        $has_ip = 1 if ($pkt_aaaa && grep { $_->type eq 'AAAA' } $pkt_aaaa->answer);

        unless ($has_ip) {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: MX-Host '$target' hat keine IP-Adresse (A oder AAAA Record fehlt).";
        }
    }

    return {
        status  => $status,
        message => $status eq 'ok' ? "MX vorhanden und erreichbar" :
                   $status eq 'warn' ? "MX hat Auffaelligkeiten" : "MX-Prüfung fehlerhaft",
        rfc     => "RFC 5321",
        mx      => \@ex,
        notes   => \@notes,
    };
}


sub check_spf {
    my ($resolver, $domain, $profile, $timeout) = @_;
    return { status => "skip", message => "SPF nicht gefordert", rfc => "RFC 7208" }
        unless $profile->{require_spf};

    $timeout //= DEFAULT_DNS_TIMEOUT;
    my @txt = get_txt_records($resolver, $domain, $timeout);

    my @spf_candidates = grep { /^v=spf1(\s|$)/i } @txt;
    if (@spf_candidates > 1) {
        return {
            status  => "fail",
            message => "Mehrere SPF Records gefunden (RFC 7208 4.5)",
            rfc     => "RFC 7208",
            record  => join(" | ", @spf_candidates),
            notes   => ["Loesung: Nur einen SPF Record behalten."],
        };
    }

    my $spf = $spf_candidates[0];
    unless ($spf) {
        return { status => "fail", message => "Kein SPF Record gefunden", rfc => "RFC 7208" };
    }

    my $spf_len = length($spf // "");

    my $status = "ok";
    my @notes;
    my %seen_mechanisms;
    my $has_redirect = 0;
    my $has_macros   = 0;

    my @raw_tokens = split(/\s+/, $spf);
    shift @raw_tokens if @raw_tokens && $raw_tokens[0] =~ /^v=spf1$/i;

    for (my $i = 0; $i < @raw_tokens; $i++) {
        my $orig = _trim($raw_tokens[$i] // "");
        next if $orig eq "";

        $has_macros = 1 if $orig =~ /\%\{[^\}]+\}/;

        my $nt    = spf_normalize_token($orig);
        my $mtype = spf_mechanism_type($orig);

        if ($mtype eq "ip4") {
            my ($ip_part) = $orig =~ /ip4:([^\s]+)/i;
            if ($ip_part && !spf_valid_ip4_cidr($ip_part)) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Ungueltiges ip4 Format: $orig";
            }
        }
        elsif ($mtype eq "ip6") {
            my ($ip_part) = $orig =~ /ip6:([^\s]+)/i;
            if ($ip_part && !spf_valid_ip6_cidr_basic($ip_part)) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Ungueltiges ip6 Format: $orig";
            }
        }

        if ($mtype eq "ptr") {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: 'ptr' ist deprecated und unsicher (RFC 7208 5.5).";
        }

        if ($mtype eq "all") {
            my $qual = ($orig =~ /^([\+\-\~\?])/) ? $1 : "+";

            if ($i < $#raw_tokens) {
                $status = worst_status($status, "warn");
                push @notes, "Warnung: '$orig' steht nicht am Ende. Praxisregel, kann zu unerwarteter Auswertung fuehren.";
            }
            if ($qual eq "+") {
                $status = worst_status($status, "fail");
                push @notes, "KRITISCH: '$orig' erlaubt jedem den Versand.";
            } elsif ($qual eq "~") {
                $status = worst_status($status, "warn");
                push @notes, "Hinweis: '~all' (SoftFail) ist schwaecher als '-all'.";
            }
        }

        if ($mtype eq "redirect") {
            if ($has_redirect) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: Mehrere redirect=";
            }
            if ($i < $#raw_tokens) {
                $status = worst_status($status, "fail");
                push @notes, "FEHLER: redirect= nicht am Ende";
            }
            $has_redirect = 1;
        }

        if ($nt ne "" && $seen_mechanisms{$nt}++) {
            $status = worst_status($status, "warn");
            push @notes, "Warnung: Token '$orig' ist doppelt (normalisiert: '$nt').";
        }

        if ($mtype eq "include" && $nt =~ /^include:([a-z0-9.-]+)/) {
            my $ext_spf = check_spf_external_domain($resolver, $1, $timeout);
            if (($ext_spf->{status} // "") eq "fail") {
                $status = worst_status($status, "warn");
                push @notes, "Warnung: include Domain '$1' fehlerhaft: $ext_spf->{message}";
            }
        }
    }

    my $spf_stats = { lookups => 0, void => 0, truncated => 0, dns_error => 0 };
    count_spf_lookups_recursive($resolver, $domain, $timeout, {}, 0, $spf_stats);

    my $lookup_count = $spf_stats->{lookups};
    my $void_count   = $spf_stats->{void};

    if ($lookup_count > MAX_SPF_LOOKUPS) {
        $status = worst_status($status, "fail");
        push @notes, "FEHLER: DNS Lookup Limit ueberschritten ($lookup_count/10).";
    }

    if ($void_count > 2) {
        $status = worst_status($status, "fail");
        push @notes, "FEHLER: Zu viele Void Lookups ($void_count/2). RFC 7208 4.6.4.";
    } else {
        push @notes, "Info: Lookups=$lookup_count/10, Void=$void_count/2.";
    }

    push @notes, "Info: DNS Fehler waehrend Lookup Analyse ($spf_stats->{dns_error}). Kann Limits verfälschen." if ($spf_stats->{dns_error} // 0) > 0;
    push @notes, "Hinweis: SPF Record ist lang ($spf_len Zeichen). Wenn TXT-Strings nicht korrekt zusammengesetzt sind, kann die Laengenanzeige irrefuehrend sein." if $spf_len > 450;
    push @notes, "Hinweis: Lookup Analyse wurde wegen Rekursionstiefe abgeschnitten, Ergebnis evtl. unvollstaendig." if ($spf_stats->{truncated});

    push @notes, "Warnung: SPF enthaelt Macros. Statische Pruefung ungenau." if $has_macros;

    return {
        status       => $status,
        message      => ($status eq "ok") ? "SPF ist valide" : "SPF Policy Fehler",
        rfc          => "RFC 7208",
        record       => $spf,
        notes        => \@notes,
        lookup_count => $lookup_count,
        void_count   => $void_count,
    };
}

sub check_spf_external_domain {
    my ($resolver, $domain, $timeout) = @_;
    my $stats = { lookups => 0, void => 0, truncated => 0, dns_error => 0 };
    count_spf_lookups_recursive($resolver, $domain, $timeout, {}, 0, $stats);

    if ($stats->{lookups} > MAX_SPF_LOOKUPS) {
        return { status => "fail", message => "Lookup Limit ueberschritten ($stats->{lookups}/10)" };
    }
    if ($stats->{void} > 2) {
        return { status => "fail", message => "Void Limit ueberschritten ($stats->{void}/2)" };
    }
    return { status => "ok" };
}

sub check_tls_rpt {
    my ($resolver, $domain, $profile, $timeout) = @_;

    return { status => "skip", message => "TLS-RPT nicht gefordert", rfc => "RFC 8460" }
        unless $profile->{require_tls_rpt};

    my $name = "_smtp._tls.$domain";
    my @txt  = get_txt_records($resolver, $name, $timeout);

    # RFC 8460: Wenn mehrere TXT Records geliefert werden, muessen zuerst alle verworfen werden,
    # die NICHT mit exakt "v=TLSRPTv1;" beginnen. Danach gilt: genau 1 Record, sonst gilt es als "kein Policy Record".
    my @candidates = grep { /^v=TLSRPTv1;/ } @txt;

    if (@candidates != 1) {
        return {
            status  => "fail",
            message => (@txt ? "Kein eindeutiger TLS-RPT Policy Record (Sender ignorieren Policy)" : "Kein TLS-RPT Record gefunden"),
            rfc     => "RFC 8460",
            record  => join(" | ", @txt),
            notes   => [
                "RFC 8460: Nur Records mit Prefix 'v=TLSRPTv1;' sind gueltig.",
                "RFC 8460: Wenn danach nicht genau 1 Record uebrig bleibt, gilt TLS-RPT als nicht implementiert.",
            ],
        };
    }

    my $rec = $candidates[0];

    my %tags;
    my @notes;
    my $status = "ok";

    for my $part (split /\s*;\s*/, $rec) {
        next unless $part =~ /=/;
        my ($k, $v) = split(/\s*=\s*/, $part, 2);
        $k = lc(_trim($k // ""));
        $v = _trim($v // "");
        $tags{$k} = $v if $k;
    }

    if (!defined $tags{rua} || $tags{rua} eq "") {
        $status = "fail";
        push @notes, "FEHLER: Tag 'rua=' fehlt. (RFC 8460)";
    } else {
        my @uris = split(/\s*,\s*/, $tags{rua});
        for my $uri (@uris) {
            # RFC 8460: Bestimmte Zeichen muessen percent-encoded sein, sonst ist die URI ungueltig.
            if ($uri =~ /[!;]/) {
                $status = "fail";
                push @notes, "FEHLER: URI enthaelt unencoded Sonderzeichen (! oder ;) und ist damit nicht RFC-konform: $uri";
                next;
            }

            if ($uri =~ /^mailto:/) {
                if ($uri =~ /mailto:.*\@([a-z0-9.-]+)/i) {
                    my $rpt_dom = lc($1);
                    if (!is_same_organizational_domain($domain, $rpt_dom)) {
                        push @notes, "Info: TLS-Berichte gehen an externe Domain ($rpt_dom).";
                    }
                } else {
                    $status = "fail";
                    push @notes, "FEHLER: Ungueltige mailto URI in rua: $uri";
                }
            } elsif ($uri =~ /^https:\/\//) {
                push @notes, "Info: Reporting via HTTPS-Submission ist aktiv.";
            } else {
                $status = "fail";
                push @notes, "FEHLER: Ungueltiges URI-Schema in rua: $uri (nur mailto: oder https:// erlaubt).";
            }
        }
    }

    return {
        status  => $status,
        message => ($status eq "ok") ? "TLS-RPT ist korrekt konfiguriert" : "TLS-RPT Konfigurationsfehler",
        rfc     => "RFC 8460",
        record  => $rec,
        tags    => \%tags,
        notes   => \@notes,
    };
}

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

sub run_checks_for_profile {
    my ($resolver, $domain, $profile, $timeout, $fast) = @_;

    # --- Fast-Modus: DANE/MTA-STS nur wenn explizit gefordert ---
    my $need_dane    = $fast ? ($profile->{require_dane}    ? 1 : 0) : 1;
    my $need_mta_sts = $fast ? ($profile->{require_mta_sts} ? 1 : 0) : 1;

    # --- DNSSEC separat prüfen (wird für DANE benötigt) ---
    my $dnssec_res = $DNS_CONF->{dnssec}
        ? check_dnssec_zone($resolver, $domain, $timeout)
        : { status => "skip", message => "DNSSEC Prüfung deaktiviert (CLI/Config)", rfc => "RFC 4033" };

    # --- Dynamische Check-Konfiguration ---
    my %check_config = (
        mx => {
            sub => \&check_mx,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_mx} },
            skip_msg => "MX nicht gefordert",
            rfc => "RFC 5321",
        },
        spf => {
            sub => \&check_spf,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_spf} },
            skip_msg => "SPF nicht gefordert",
            rfc => "RFC 7208",
        },
        dkim => {
            sub => \&check_dkim,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_dkim} },
            skip_msg => "DKIM nicht gefordert",
            rfc => "RFC 6376",
        },
        arc => {
            sub => \&check_arc,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_arc} },
            skip_msg => "ARC nicht gefordert",
            rfc => "RFC 8617",
        },
        dmarc => {
            sub => \&check_dmarc,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_dmarc} },
            skip_msg => "DMARC nicht gefordert",
            rfc => "RFC 7489",
        },
		bimi => {
			sub => \&check_bimi,
			args => sub {
				[$resolver, $domain, $profile, $timeout];
			},
			condition => sub { $profile->{require_bimi} },
			skip_msg => "BIMI nicht gefordert",
			spec => "IETF Internet Draft (BIMI)",
		},	
        tls_rpt => {
            sub => \&check_tls_rpt,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_tls_rpt} },
            skip_msg => "TLS-RPT nicht gefordert",
            rfc => "RFC 8460",
        },
        dane => {
            sub => \&check_dane,
            args => sub {
                my $dnssec_status = $dnssec_res->{status} // "warn";
                [$resolver, $domain, $profile, $timeout, $dnssec_status];
            },
            condition => sub { $profile->{require_dane} && $need_dane },
            skip_msg => "DANE nicht gefordert",
            rfc => "RFC 7672",
        },
        mta_sts => {
            sub => \&check_mta_sts,
            args => [$resolver, $domain, $profile, $timeout],
            condition => sub { $profile->{require_mta_sts} && $need_mta_sts },
            skip_msg => "MTA-STS nicht gefordert",
            rfc => "RFC 8461",
        },
    );

    # --- Checks dynamisch ausführen ---
    my %checks = (dnssec => $dnssec_res);
    for my $check_name (keys %check_config) {
        my $config = $check_config{$check_name};
        if ($config->{condition}->()) {
            my @args = ref($config->{args}) eq 'ARRAY'
                ? @{$config->{args}}
                : $config->{args}->();
            $checks{$check_name} = $config->{sub}->(@args);
        } else {
			$checks{$check_name} = {
				status  => "skip",
				message => $config->{skip_msg},
				(exists $config->{rfc}  ? (rfc  => $config->{rfc})  : ()),
				(exists $config->{spec} ? (spec => $config->{spec}) : ()),
			};
        }
    }

    # --- Ergebnis zurückgeben ---
    return {
        status => worst_status(map { $_->{status} // "fail" } values %checks),
        checks => \%checks,
    };
}

# ============================================================
# 13) ORCHESTRATION (PRO DOMAIN)
# Zweck:
#   Fuehrt pro Domain die passenden Profile und Checks aus und aggregiert Statuswerte.
# Inputs:
#   Domain, Timeout, Fast-Mode
# Output:
#   Domain Result Hashref inkl. Checks und Status
# Haupt-Subs:
#   process_domain(), run_checks_for_profile(), profile_matches_domain()
# ============================================================

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

    if (!$matched && exists $PROFILE_CONF->{default}) {
        my $p = $PROFILE_CONF->{default};
        $profile_results{default} = run_checks_for_profile($resolver, $domain, $p, $timeout, $fast);
        $overall_status = $profile_results{default}{status} // "fail";
    }

    return { domain => $domain, status => $overall_status, profiles => \%profile_results };
}

# ============================================================
# 14) MAIN / PROGRAM FLOW
# Zweck:
#   Entry Point: Config laden, Logging initialisieren, Domainliste bestimmen, Parallelisierung steuern, Report schreiben.
# Inputs:
#   CLI Optionen, Config
# Output:
#   Gesamt-Report JSON, Summary Logs
# Haupt-Subs:
#   main()
# ============================================================

sub main {
    my $config_file = $opt_config // $DEFAULT_CONFIG;

    $conf = load_config($config_file);
    $PROFILE_CONF = $conf->{profiles} // {};
    $DNS_CONF     = $conf->{dns}      // {};
    $DOMAINS_CONF = $conf->{domains}  // {};
    $OUT_CONF     = $conf->{output}   // {};
    $RUNTIME_CONF = $conf->{runtime}  // {};

    if (defined $opt_dnssec) {
        $DNS_CONF->{dnssec} = $opt_dnssec ? 1 : 0;
    } elsif (!exists $DNS_CONF->{dnssec}) {
        $DNS_CONF->{dnssec} = 0;
    }

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
        $log->warn("Audit läuft ohne Public Suffix List (nutze Heuristik).");
    }

    $MAX_PROCS = $opt_max_procs // $RUNTIME_CONF->{max_procs} // 1;
    $MAX_PROCS = 1 if !$MAX_PROCS || $MAX_PROCS < 1;

    my @domains = $opt_domain
        ? (lc $opt_domain)
        : _as_list($DOMAINS_CONF->{static_domains} // $DOMAINS_CONF->{list} // $DOMAINS_CONF->{domains} // []);

    @domains = map { lc _trim($_) } @domains;
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

    my $pm = Parallel::ForkManager->new($MAX_PROCS);
    my %results;

    $pm->run_on_finish(sub {
        my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data_ref) = @_;
        return unless $data_ref && ref($data_ref) eq "HASH";
        my $d = $data_ref->{domain};
        my $r = $data_ref->{result};
        $results{$d} = $r if defined $d && defined $r;
    });

    my $timeout = $DNS_CONF->{timeout} // DEFAULT_DNS_TIMEOUT;

    for my $dom (@domains) {
        $pm->start and next;

        my $r = try {
            process_domain($dom, $timeout, $opt_fast);
        } catch {
            $log->error("Fehler bei $dom: $_");
            { domain => $dom, status => "fail", error => "$_" };
        };

        $pm->finish(0, { domain => $dom, result => $r });
    }

    $pm->wait_all_children;

    my $date = strftime("%Y%m%d", localtime);

    my %stats = (
        total     => scalar(keys %results),

        ok        => 0,
        warn      => 0,
        fail      => 0,
        skip      => 0,
        info      => 0,

        evaluated => 0,
    );

    for my $dom (keys %results) {
        my $res = $results{$dom};
        next unless $res && ref($res) eq "HASH";

        my $st = lc($res->{status} // "");
        $st = "info" if $st eq "";
        $st = "info" unless exists $stats{$st};

        $stats{$st}++;

        if ($st ne "skip" && $st ne "info") {
            $stats{evaluated}++;
        }
    }

    $log->info(
        "Zusammenfassung: Total: $stats{total}, Evaluated: $stats{evaluated}, OK: $stats{ok}, WARN: $stats{warn}, FAIL: $stats{fail}, SKIP: $stats{skip}, INFO: $stats{info}"
    );

    my $final_data = {
        meta => {
            ts         => time,
            date       => $date,
            version    => VERSION,
            fast_mode  => $opt_fast ? 1 : 0,
            psl_loaded => $PSL_REF ? 1 : 0,
            max_procs  => $MAX_PROCS,
        },
        summary => \%stats,
        domains => \%results,
    };

    my $out_file = dated_output_path($OUT_CONF->{json_file}, $date);

    if ($opt_dry_run) {
        $log->info("Dry-Run: Statistik berechnet, aber kein Report geschrieben.");
        return;
    }

    try {
        atomic_write_json($out_file, $final_data);
        $log->info("Report erfolgreich geschrieben: $out_file");
    } catch {
        $log->error("Fehler beim Schreiben des Reports: $_");
    };

    return;
}

main();
