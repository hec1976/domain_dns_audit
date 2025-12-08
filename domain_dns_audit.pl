#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open qw(:std :utf8);

use Net::LDAP;
use Net::LDAP::Util qw(ldap_error_text);
use Net::DNS;
use JSON::MaybeXS qw(encode_json decode_json JSON);
use Log::Log4perl;
use POSIX qw(strftime);
use FindBin;
use File::Spec;
use File::Path ();
use Getopt::Long;
use Domain::PublicSuffix;
use Parallel::ForkManager;
use Time::Out qw(timeout);
use NetAddr::IP;

# =========================
# Version / Konstanten
# =========================

my $VERSION             = '1.1.0';
my $SCRIPT_DIR          = $FindBin::Bin;
my $DEFAULT_CONFIG      = File::Spec->catfile($SCRIPT_DIR, 'domain_dns_audit.json');
my $DEFAULT_LDAP_CONFIG = File::Spec->catfile($SCRIPT_DIR, 'domain_dns_ldap.json');

# =========================
# CLI Optionen
# =========================

my $opt_config;
my $opt_ldap_config;
my $opt_debug    = 0;
my $opt_domain;
my $opt_help     = 0;
my $opt_dry_run  = 0;
my $opt_max_procs;
my $opt_version  = 0;

GetOptions(
    'config=s'      => \$opt_config,      # Pfad zur JSON Config (DNS/Checks)
    'ldap-config=s' => \$opt_ldap_config, # separates LDAP Config File (optional)
    'debug'         => \$opt_debug,       # Debug Logging aktivieren
    'domain=s'      => \$opt_domain,      # nur eine Domain pruefen
    'dry-run'       => \$opt_dry_run,     # kein JSON schreiben, nur Log + Exitcode
    'max-procs=i'   => \$opt_max_procs,   # Anzahl paralleler Prozesse
    'version'       => \$opt_version,     # Version ausgeben
    'help'          => \$opt_help,        # Hilfe anzeigen
) or die "Fehler beim Parsen der Optionen. Verwende --help fuer Hilfe.\n";

if ($opt_help) {
    print <<"USAGE";
Verwendung: $0 [--config FILE] [--ldap-config FILE] [--domain DOMAIN] [--debug]
                [--max-procs N] [--dry-run] [--version]

Optionen:
  --config FILE       Pfad zur JSON Konfiguration (Default: $DEFAULT_CONFIG)
                      (DNS, Domains, Checks, Output usw.)
  --ldap-config FILE  Separates JSON nur fuer LDAP (optional).
                      Default Reihenfolge:
                        1) --ldap-config
                        2) ldap.ldapconfigpath in Haupt Config
                        3) $DEFAULT_LDAP_CONFIG (falls vorhanden)
                        4) ldap Block aus Haupt Config

  --domain DOMAIN     Nur diese eine Domain pruefen (LDAP/extra_domains werden ignoriert)
  --debug             Log Level DEBUG aktivieren

  --max-procs N       Anzahl paralleler Prozesse (Default: runtime.max_procs oder 20)
  --dry-run           Kein JSON Report schreiben, nur Log / Exitcode
  --version           Version von domain_dns_audit anzeigen
  --help              Diese Hilfe anzeigen

Beispiele:
  $0
  $0 --config /etc/mmbb/domain_dns_audit.json
  $0 --config /etc/mmbb/domain_dns_audit.json --ldap-config /etc/mmbb/domain_dns_ldap.json
  $0 --domain example.ch --debug
  $0 --max-procs 10 --dry-run
USAGE
    exit 0;
}

if ($opt_version) {
    print "domain_dns_audit Version $VERSION\n";
    exit 0;
}

# =========================
# Konfiguration laden
# =========================

my $config_file = $opt_config || $DEFAULT_CONFIG;
die "Config file does not exist: $config_file" unless -f $config_file;

open my $cfh, '<:raw', $config_file
  or die "Kann Config nicht oeffnen: $config_file: $!";

local $/;
my $config_json = <$cfh>;
close $cfh;

my $json_parser = JSON->new->utf8->relaxed->allow_nonref;
my $conf = eval {
    $json_parser->decode($config_json);
};

if ($@) {
    chomp $@;
    die "Fehler beim Parsen der JSON Config $config_file: $@\n";
}
die "Config $config_file ist kein JSON Objekt\n" unless ref $conf eq 'HASH';

# Haupt Config Bereiche
my $ldap_conf    = $conf->{ldap}    || {};
my $check_conf   = $conf->{check}   || {};
my $out_conf     = $conf->{output}  || {};
my $dns_conf     = $conf->{dns}     || {};
my $dom_conf     = $conf->{domains} || {};
my $runtime_conf = $conf->{runtime} || {};

# =========================
# Logging
# =========================

my $LOG_FILE  = $out_conf->{log_file}  || "/var/log/mmbb/domain_dns_audit.log";
my $JSON_FILE = $out_conf->{json_file} || "/var/log/mmbb/domain_dns_audit.json";
my $LOG_LEVEL = $out_conf->{log_level} || "INFO";

if ($opt_debug) {
    $LOG_LEVEL = "DEBUG";
}

my $log_conf = qq(
    log4perl.logger                    = $LOG_LEVEL, LOGFILE
    log4perl.appender.LOGFILE          = Log::Log4perl::Appender::File
    log4perl.appender.LOGFILE.filename = $LOG_FILE
    log4perl.appender.LOGFILE.layout   = Log::Log4perl::Layout::PatternLayout
    log4perl.appender.LOGFILE.layout.ConversionPattern = %d [%p] [%P] %m%n
    log4perl.appender.LOGFILE.binmode  = :encoding(UTF-8)
);

Log::Log4perl::init(\$log_conf);
my $log = Log::Log4perl->get_logger();

$log->info("Start domain_dns_audit Version $VERSION mit Config $config_file");
$log->info("CLI: debug=$opt_debug, domain=" . ($opt_domain // '') . ", dry_run=$opt_dry_run");

# =========================
# LDAP Config extern / Default
# =========================

my $ldap_config_file;

# 1. CLI
if (defined $opt_ldap_config) {
    $ldap_config_file = $opt_ldap_config;
    $log->info("LDAP Config per CLI gesetzt: $ldap_config_file");
}
# 2. Pfad aus Hauptconfig
elsif (defined $ldap_conf->{ldapconfigpath} && $ldap_conf->{ldapconfigpath} ne '') {
    $ldap_config_file = $ldap_conf->{ldapconfigpath};
    $log->info("LDAP Config aus Haupt Config (ldap.ldapconfigpath): $ldap_config_file");
}
# 3. Default im Scriptverzeichnis
elsif (-e $DEFAULT_LDAP_CONFIG) {
    $ldap_config_file = $DEFAULT_LDAP_CONFIG;
    $log->info("Verwende Default LDAP Config: $ldap_config_file");
}

if ($ldap_config_file) {
    open my $lfh, '<:utf8', $ldap_config_file
      or die "Kann LDAP Config nicht oeffnen: $ldap_config_file: $!";

    local $/;
    my $ldap_json = <$lfh>;
    close $lfh;

    my $ldap_raw = eval { decode_json($ldap_json) };
    die "Fehler beim Parsen der LDAP Config $ldap_config_file: $@" if $@;
    die "LDAP Config $ldap_config_file ist kein JSON Objekt\n" unless ref $ldap_raw eq 'HASH';

    if (exists $ldap_raw->{ldap} && ref $ldap_raw->{ldap} eq 'HASH') {
        $ldap_conf = $ldap_raw->{ldap};
        $log->info("LDAP Config aus ldap Block der externen Datei uebernommen");
    } else {
        $ldap_conf = $ldap_raw;
        $log->info("LDAP Config aus Root Objekt der externen Datei uebernommen");
    }
} else {
    $log->info("Keine separate LDAP Config Datei, nutze ldap Block aus Haupt Config");
}

# =========================
# Globale Settings aus Config
# =========================

my $suffix_handler = Domain::PublicSuffix->new();

sub _as_list {
    my ($val) = @_;
    return () unless defined $val;
    if (ref $val eq 'ARRAY') {
        return map { defined $_ ? $_ : () } @$val;
    } else {
        return map { s/^\s+|\s+$//gr } split /,/, $val;
    }
}

# LDAP optional / mehrere URIs moeglich
my @LDAP_URIS = _as_list($ldap_conf->{uri} // $ldap_conf->{uris});

my $LDAP_ENABLED;
if (exists $ldap_conf->{enabled}) {
    $LDAP_ENABLED = $ldap_conf->{enabled} ? 1 : 0;
} else {
    $LDAP_ENABLED = @LDAP_URIS ? 1 : 0;
}

$log->info(
    "LDAP_ENABLED = $LDAP_ENABLED"
    . (@LDAP_URIS ? " (URIs: " . join(", ", @LDAP_URIS) . ")" : "")
);

my $GLOBAL_REQUIRE_SPF  = exists $check_conf->{require_spf}
    ? ($check_conf->{require_spf} ? 1 : 0)
    : 1;

my $GLOBAL_REQUIRE_DKIM = exists $check_conf->{require_dkim}
    ? ($check_conf->{require_dkim} ? 1 : 0)
    : 1;

my @GLOBAL_DMARC_OK_POL  = _as_list($check_conf->{dmarc_ok_policies});
@GLOBAL_DMARC_OK_POL     = ("reject", "quarantine") unless @GLOBAL_DMARC_OK_POL;

my @GLOBAL_DKIM_SELECTORS             = _as_list($check_conf->{dkim_selectors});
my @GLOBAL_DKIM_TXT_REQUIRED_CONTAINS = _as_list($check_conf->{dkim_txt_required_contains});

my $GLOBAL_MX_POLICY    = $check_conf->{mx_policy}    || {};
my $GLOBAL_SPF_POLICY   = $check_conf->{spf_policy}   || {};
my $GLOBAL_DKIM_POLICY  = $check_conf->{dkim_policy}  || {};
my $GLOBAL_DMARC_POLICY = $check_conf->{dmarc_policy} || {};

# DNS Konfiguration aus JSON (mit Defaults)
my $DNS_TIMEOUT     = defined $dns_conf->{timeout}     ? $dns_conf->{timeout}     : 5;
my $DNS_UDP_TIMEOUT = defined $dns_conf->{udp_timeout} ? $dns_conf->{udp_timeout} : 2;
my $DNS_TCP_TIMEOUT = defined $dns_conf->{tcp_timeout} ? $dns_conf->{tcp_timeout} : 4;

my @DNS_SERVERS = _as_list($dns_conf->{servers});
if (@DNS_SERVERS) {
    $log->info(
        "DNS Server aus Config: " . join(", ", @DNS_SERVERS)
        . " (udp_timeout=$DNS_UDP_TIMEOUT, tcp_timeout=$DNS_TCP_TIMEOUT, alarm_timeout=$DNS_TIMEOUT)"
    );
} else {
    $log->info(
        "Kein DNS Server in Config, nutze System Resolver "
        . "(udp_timeout=$DNS_UDP_TIMEOUT, tcp_timeout=$DNS_TCP_TIMEOUT, alarm_timeout=$DNS_TIMEOUT)"
    );
}

my @EXTRA_DOMAINS   = map { lc $_ } _as_list($dom_conf->{extra_domains});
my @EXCLUDE_DOMAINS = map { lc $_ } _as_list($dom_conf->{exclude_domains});

my $PROFILE_CONF = $check_conf->{profiles} || {};

# Runtime / Parallelitaet
my $CONFIG_MAX_PROCS = $runtime_conf->{max_procs};
$CONFIG_MAX_PROCS = 20 unless defined $CONFIG_MAX_PROCS && $CONFIG_MAX_PROCS =~ /^\d+$/ && $CONFIG_MAX_PROCS > 0;

my $MAX_PROCS = defined $opt_max_procs && $opt_max_procs > 0 ? $opt_max_procs : $CONFIG_MAX_PROCS;
$log->info("Maximale parallele Prozesse: $MAX_PROCS (Config=" . $CONFIG_MAX_PROCS . ", CLI=" . ($opt_max_procs // 'undef') . ")");

# =========================
# DNS Resolver Konfiguration
# =========================

my %resolver_opts = (
    retry       => 2,
    udp_timeout => $DNS_UDP_TIMEOUT,
    tcp_timeout => $DNS_TCP_TIMEOUT,
);

if (@DNS_SERVERS) {
    $resolver_opts{nameservers} = \@DNS_SERVERS;
}

# =========================
# DNS Wrapper mit Timeout und Retries
# =========================

sub safe_dns_query {
    my ($resolver, $name, $type, $max_retries) = @_;
    $type        ||= 'A';
    $max_retries ||= 2;

    for my $attempt (1 .. $max_retries) {
        my $pkt;

        eval {
            timeout $DNS_TIMEOUT => sub {
                $pkt = $resolver->query($name, $type);
            };
        };

        if ($@) {
            if ($@ =~ /timeout/i) {
                $log->warn("[DNS] Timeout bei Query: $name ($type) Versuch $attempt");
            } else {
                $log->warn("[DNS] Fehler bei Query: $name ($type) Versuch $attempt: $@");
            }
            next;
        }

        return $pkt if $pkt;
    }

    $log->error("[DNS] Alle Versuche fuer $name ($type) fehlgeschlagen");
    return undef;
}

# =========================
# Hilfsfunktionen
# =========================

sub fetch_domains_from_ldap {
    my @uris = @LDAP_URIS;
    die "ldap.uri oder ldap.uris fehlt in LDAP Config\n" unless @uris;

    my $bind_dn = $ldap_conf->{bind_dn}     || "";
    my $bind_pw = $ldap_conf->{bind_pw}     || "";
    my $base_dn = $ldap_conf->{base_dn}     || die "ldap.base_dn fehlt in LDAP Config\n";
    my $filter  = $ldap_conf->{filter}      || "(objectClass=*)";

    # NEU: mehrere Attribute erlauben (Liste oder Komma-getrennt)
    my @attr_domains = _as_list(
        defined $ldap_conf->{attr_domain}
            ? $ldap_conf->{attr_domain}
            : "associatedDomain"
    );
    @attr_domains = ("associatedDomain") unless @attr_domains;

    my $last_err;
    my $ldap;
    my $mesg;

URI_LOOP:
    for my $uri (@uris) {
        $log->info(
            "Versuche LDAP Server: $uri "
            . "(BaseDN=$base_dn, Filter=$filter, Attrs=" . join(",", @attr_domains) . ")"
        );

        $ldap = Net::LDAP->new($uri, timeout => 10);
        if (!$ldap) {
            $last_err = "LDAP Verbindung fehlgeschlagen zu $uri: $@ oder $!";
            $log->warn($last_err);
            next URI_LOOP;
        }

        if ($bind_dn) {
            $mesg = $ldap->bind($bind_dn, password => $bind_pw);
        } else {
            $mesg = $ldap->bind;
        }

        if ($mesg->code) {
            $last_err = "LDAP Bind Fehler auf $uri: " . ldap_error_text($mesg->code);
            $log->warn($last_err);
            $ldap->unbind;
            $ldap = undef;
            next URI_LOOP;
        }

        $log->info("LDAP Bind erfolgreich auf $uri");
        last URI_LOOP;
    }

    die "Keiner der LDAP Server erreichbar oder bindbar: $last_err\n"
        unless $ldap;

    # NEU: alle konfigurierten Attribute holen
    $mesg = $ldap->search(
        base   => $base_dn,
        scope  => 'sub',
        filter => $filter,
        attrs  => \@attr_domains,
    );

    if ($mesg->code) {
        my $err = "LDAP Suche Fehler: " . ldap_error_text($mesg->code);
        $ldap->unbind;
        die "$err\n";
    }

    my %domains;

    foreach my $entry ($mesg->entries) {

        # alle konfigurierten Attribute durchgehen
        for my $attr (@attr_domains) {
            my @vals = $entry->get_value($attr);
            for my $d (@vals) {
                next unless defined $d;
                $d =~ s/^\s+|\s+$//g;
                next unless $d;
                $d = lc $d;
                $domains{$d} = 1;
            }
        }
    }

    $ldap->unbind;

    my @dom_list = sort keys %domains;
    $log->info("LDAP Domains gefunden: " . scalar(@dom_list));
    return @dom_list;
}


sub get_txt_records {
    my ($resolver, $name) = @_;
    my $pkt = safe_dns_query($resolver, $name, "TXT");
    return () unless $pkt;
    my @txt;

    foreach my $rr ($pkt->answer) {
        next unless $rr->type eq "TXT";

        # txtdata liefert in Listkontext alle Teilstrings
        my @parts = $rr->txtdata;

        # Fuer DKIM/SPF/DMARC wollen wir den logischen Gesamtstring
        my $full = join('', @parts);

        push @txt, $full;
    }

    return @txt;
}

sub get_txt_records_with_cname {
    my ($resolver, $name) = @_;

    my @txt = get_txt_records($resolver, $name);
    if (@txt) {
        return {
            txt          => \@txt,
            cname_used   => 0,
            cname_target => undef,
        };
    }

    my $pkt = safe_dns_query($resolver, $name, "CNAME");
    return {
        txt          => [],
        cname_used   => 0,
        cname_target => undef,
    } unless $pkt;

    my ($cname_rr) = grep { $_->type eq 'CNAME' } $pkt->answer;
    return {
        txt          => [],
        cname_used   => 0,
        cname_target => undef,
    } unless $cname_rr;

    my $target = $cname_rr->cname;
    my @txt2 = get_txt_records($resolver, $target);

    return {
        txt          => \@txt2,
        cname_used   => 1,
        cname_target => $target,
    };
}

sub spf_mode_rank {
    my ($mode) = @_;
    return 4 if $mode eq 'hard';
    return 3 if $mode eq 'soft';
    return 2 if $mode eq 'neutral';
    return 2 if $mode eq 'no-all';
    return 1 if $mode eq 'open';
    return 0 if $mode eq 'none';
    return 0;
}

sub org_domain {
    my ($dom) = @_;
    return undef unless defined $dom;

    my $root = $suffix_handler->get_root_domain($dom);

    if (defined $root) {
        return $root;
    }

    my @p = split /\./, $dom;
    return join('.', @p[-2, -1]) if @p >= 2;
    return $dom;
}

# =========================
# Hostname Validierung (MX / DKIM / SPF)
# =========================

sub _valid_hostname {
    my ($host) = @_;
    return 0 unless defined $host;
    $host =~ s/\.$//;
    return 0 if length($host) == 0 || length($host) > 253;

    my @labels = split /\./, $host;
    return 0 unless @labels >= 2;

    for my $lab (@labels) {
        return 0 if $lab eq '' || length($lab) > 63;
        return 0 if $lab =~ /^-/ || $lab =~ /-$/;
        return 0 unless $lab =~ /^[A-Za-z][A-Za-z0-9-]*$/;
    }
    return 1;
}

# =========================
# SPF Domain Validierung (SPF include/redirect, erlaubt _ am Anfang)
# =========================

sub _valid_spf_domain {
    my ($dom) = @_;
    return 0 unless defined $dom && $dom ne '';
    return 0 if length($dom) > 253;

    my @labels = split /\./, $dom;
    return 0 unless @labels;

    for my $lab (@labels) {
        return 0 if $lab eq '' || length($lab) > 63;
        # SPF Domains duerfen mit _ beginnen (z. B. _spf.example.com)
        return 0 unless $lab =~ /^[A-Za-z0-9_][A-Za-z0-9_-]*$/;
    }
    return 1;
}

# =========================
# SPF Syntax Validierung (RFC 7208, mit NetAddr::IP)
# =========================

sub validate_spf_syntax {
    my ($spf) = @_;
    my @errors;
    
    push @errors, "SPF muss mit 'v=spf1' beginnen"
        unless $spf =~ /^v=spf1(\s|$)/i;
    
    my @terms = split /\s+/, $spf;
    shift @terms if @terms && $terms[0] =~ /^v=spf1$/i;
    
    for my $term (@terms) {
        next if !defined $term || $term eq '';
        
        my $qualifier = '';
        if ($term =~ /^([\+\-\~\?])(.+)$/) {
            $qualifier = $1;
            $term      = $2;
        }
        
        if ($term =~ /^(all|include|a|mx|ptr|ip4|ip6|exists)(.*)$/i) {
            my $mech = lc($1);
            my $rest = $2 // '';
            
            if ($mech eq 'ip4') {
                if ($rest =~ /^:(.+)$/) {
                    my $cidr = $1;
                    my $ip   = NetAddr::IP->new($cidr);
                    unless ($ip && $ip->version == 4) {
                        push @errors, "Ungueltige IPv4/CIDR in SPF: $cidr";
                    }
                }
            }
            elsif ($mech eq 'ip6') {
                if ($rest =~ /^:(.+)$/) {
                    my $cidr = $1;
                    my $ip   = NetAddr::IP->new($cidr);
                    unless ($ip && $ip->version == 6) {
                        push @errors, "Ungueltige IPv6/CIDR in SPF: $cidr";
                    }
                }
            }
            # include/a/mx/ptr/exists werden nur syntaktisch akzeptiert
        }
        elsif ($term =~ /^(redirect|exp)=/i) {
            # bekannte Modifier, ok
        }
        else {
            # SPF Macros oder unbekannte Terms werden hier nur markiert
            push @errors, "Unbekannter oder komplexer SPF Term: $term";
        }
    }
    
    return \@errors;
}

# =========================
# DKIM Tag Parsing / Key Validierung
# =========================

sub parse_dkim_tag_string {
    my ($s) = @_;
    my %tags;

    return \%tags unless defined $s;
    $s =~ s/^\s+|\s+$//g;
    return \%tags unless length $s;

    for my $chunk (split /;/, $s) {
        $chunk =~ s/^\s+|\s+$//g;
        next unless $chunk;

        my ($k, $v) = split /=/, $chunk, 2;
        next unless defined $k && defined $v;

        $k =~ s/^\s+|\s+$//g;
        $v =~ s/^\s+|\s+$//g;

        $k = lc $k;
        $v =~ s/\s+//g;

        $tags{$k} = $v;
    }

    return \%tags;
}

sub dkim_txt_matches_expected {
    my ($effective, $expected) = @_;

    return 0 unless defined $effective && defined $expected;

    my $eff_tags = parse_dkim_tag_string($effective);
    my $exp_tags = parse_dkim_tag_string($expected);

    for my $k (keys %{$exp_tags}) {
        return 0 unless exists $eff_tags->{$k};
        return 0 unless $eff_tags->{$k} eq $exp_tags->{$k};
    }

    return 1;
}

sub analyze_dkim_rfc {
    my ($txt_combined) = @_;

    my $tags = parse_dkim_tag_string($txt_combined);
    my @errors;
    my @warnings;
    my $status = "ok";

    if (!defined $tags->{v}) {
        push @errors, "DKIM v Tag fehlt (RFC 6376 §3.6.1)";
        $status = "fail";
    } elsif (lc($tags->{v}) ne 'dkim1') {
        push @errors, "DKIM v Tag ist nicht 'DKIM1': " . $tags->{v};
        $status = "fail";
    }

    if (!defined $tags->{p} || $tags->{p} eq '') {
        push @errors, "DKIM p Tag fehlt oder ist leer (Schluessel deaktiviert/fehlt)";
        $status = "fail";
    } else {
        my $key_result = validate_dkim_key($tags->{p}, $tags->{k});
        
        push @errors,   @{$key_result->{errors}}   if $key_result->{errors};
        push @warnings, @{$key_result->{warnings}} if $key_result->{warnings};
        
        if ($key_result->{status} eq 'fail' && $status ne 'fail') {
            $status = 'fail';
        } elsif ($key_result->{status} eq 'warn' && $status eq 'ok') {
            $status = 'warn';
        }
    }

    if (defined $tags->{k}) {
        my $k = lc $tags->{k};
        if ($k ne 'rsa' && $k ne 'ed25519') {
            push @warnings, "Unbekannter DKIM k Parameter: $k (erwartet: rsa oder ed25519)";
            if ($status eq "ok") {
                $status = "warn";
            }
        }
    }

    if (defined $tags->{h}) {
        my @algs = split /:/, lc($tags->{h});
        my %allowed = map { $_ => 1 } qw(sha1 sha256);
        
        for my $alg (@algs) {
            if (!$allowed{$alg}) {
                push @warnings, "Unbekannter DKIM h Algorithmus: $alg (erwartet: sha1 oder sha256)";
                if ($status eq "ok") {
                    $status = "warn";
                }
            }
        }
        
        if (@algs == 1 && $algs[0] eq 'sha1') {
            push @warnings, "DKIM verwendet nur SHA-1 (unsicher, empfohlen: SHA-256)";
            if ($status eq "ok") {
                $status = "warn";
            }
        }
    }

    if (defined $tags->{s}) {
        my @svc = split /:/, lc($tags->{s});
        for my $s (@svc) {
            if ($s ne 'email' && $s ne '*' && $s ne 'dns') {
                push @warnings, "Unbekannter DKIM s Parameter: $s (erwartet: email, *, dns)";
                if ($status eq "ok") {
                    $status = "warn";
                }
            }
        }
    }

    if (defined $tags->{t}) {
        my $t = lc $tags->{t};
        if ($t =~ /y/) {
            push @warnings, "DKIM t Flag enthaelt 'y' (Testmodus, Signaturen sollten ignoriert werden)";
            if ($status eq "ok") {
                $status = "warn";
            }
        }
        if ($t =~ /s/) {
            push @warnings, "DKIM t Flag enthaelt 's' (Strenger Modus, Subdomains muessen signieren)";
        }
    }

    if (defined $tags->{n} && $tags->{n} ne '') {
        push @warnings, "DKIM n Tag vorhanden (Notiz): '" . substr($tags->{n}, 0, 50) . "'";
    }

    my @known_tags = qw(v p k h s t n);
    my %known = map { $_ => 1 } @known_tags;
    
    for my $tag (keys %$tags) {
        if (!$known{$tag}) {
            push @warnings, "Unbekanntes DKIM Tag: $tag";
            if ($status eq "ok") {
                $status = "warn";
            }
        }
    }

    my $detail = "DKIM RFC Analyse: $status";
    if (@errors) {
        $detail .= " [Fehler: " . join("; ", @errors) . "]";
    }
    if (@warnings) {
        $detail .= " [Warnungen: " . join("; ", @warnings) . "]";
    }

    return {
        status   => $status,
        errors   => \@errors,
        warnings => \@warnings,
        detail   => $detail,
        tags     => $tags,
    };
}

# =========================
# DKIM Key Validation (RFC 6376/8463)
# =========================

sub classify_rsa_bits {
    my ($approx_bits) = @_;

    # Typische RSA-Schlüsselgrössen
    my @known = (1024, 1536, 2048, 3072, 4096);

    my $best      = undef;
    my $best_diff = undef;

    for my $k (@known) {
        my $d = abs($approx_bits - $k);
        if (!defined $best_diff || $d < $best_diff) {
            $best      = $k;
            $best_diff = $d;
        }
    }

    return ($best, $best_diff);
}


sub validate_dkim_key {
    my ($p_tag, $k_tag) = @_;
    my @errors;
    my @warnings;
    my $status = "ok";

    # p Tag muss da sein
    unless (defined $p_tag && $p_tag ne '') {
        push @errors, "DKIM p Tag ist leer oder undefiniert";
        return { errors => \@errors, warnings => \@warnings, status => "fail" };
    }

    # 1. Base64 Grundvalidierung (RFC 4648)
    unless ($p_tag =~ m{^[A-Za-z0-9+/]+={0,2}$}) {
        push @errors, "DKIM p Tag: ungueltiges Base64 Format (RFC 4648)";
        $status = "fail";

        if ($p_tag =~ /[^A-Za-z0-9+\/=]/) {
            my @invalid_chars = $p_tag =~ /([^A-Za-z0-9+\/=])/g;
            my %unique_invalid = map { $_ => 1 } @invalid_chars;
            push @errors, "Ungueltige Zeichen im p Tag: " . join("", sort keys %unique_invalid);
        }

        if ($p_tag =~ /=./) {
            push @errors, "Base64 '=' Zeichen nicht nur am Ende";
        }

        return { errors => \@errors, warnings => \@warnings, status => $status };
    }

    # 2. Laengenberechnung auf Blob-Ebene (DER-Blob, NICHT reiner Modulus)
    my $base64_len = length($p_tag);

    my $padded_len = $base64_len;
    $padded_len-- while $padded_len > 0 && substr($p_tag, $padded_len-1, 1) eq '=';

    my $byte_len     = int($padded_len * 3 / 4);
    my $bit_len_blob = $byte_len * 8;

    # Grobe Schaetzung der eigentlichen Schluessellaenge
    # Typisch sind 1024 / 2048 / 4096 Bit; der DER-Overhead macht den Blob groesser.
    my $approx_bits;
    if    ($bit_len_blob < 1536) { $approx_bits = 1024; }
    elsif ($bit_len_blob < 3072) { $approx_bits = 2048; }
    elsif ($bit_len_blob < 6144) { $approx_bits = 4096; }
    else                         { $approx_bits = $bit_len_blob; }  # Fallback

    $log->debug("[DKIM Key] Base64 length=$base64_len, blob_bits=$bit_len_blob, approx_key_bits=$approx_bits");

	 my $key_type = lc($k_tag // 'rsa');

	if ($key_type eq 'rsa') {

		# approx_bits kommt aus deiner bisherigen Schätzung des Base64-Blobs
		my ($nominal_bits, $diff) = classify_rsa_bits($approx_bits);

		my $bits_for_policy;
		my $bits_label;

		if (defined $nominal_bits && $diff <= 200) {
			# z. B. 1296 -> 1024, 2110 -> 2048, 4100 -> 4096
			$bits_for_policy = $nominal_bits;
			$bits_label      = $nominal_bits . ' Bit';
		} else {
			# wirklich exotische Grösse, dann bleiben wir bei der Approximation
			$bits_for_policy = $approx_bits;
			$bits_label      = "ca. ${approx_bits} Bit";
		}

		# Policy anhand der "nominalen" Bitlänge
		if ($bits_for_policy < 1024) {
			push @errors, "DKIM RSA Schlüssel zu kurz, nur ${bits_label} (< 1024 Bit)";
			$status = "fail";
		}
		elsif ($bits_for_policy < 2048) {
			push @warnings, "DKIM RSA Schlüssel hat nur ${bits_label} (empfohlen sind 2048 Bit)";
			$status = "warn" if $status eq "ok";
		}
		elsif ($bits_for_policy > 4096) {
			push @warnings, "DKIM RSA Schlüssel sehr lang (${bits_label}, > 4096 Bit, kann Performance-Probleme verursachen)";
			$status = "warn" if $status eq "ok";
		}

	} elsif ($key_type eq 'ed25519') {

		# Für Ed25519 macht die Blob-Schätzung wenig Sinn, hier eher hart prüfen
		if ($byte_len != 32) {
			push @errors,
				"DKIM Ed25519 Schlüssel hat unerwartete Länge: ${byte_len} Bytes (erwartet: 32 Bytes, RFC 8463)";
			$status = "fail";
		}

		if ($approx_bits != 256) {
			push @warnings,
				"DKIM Ed25519 Schlüssel wirkt nicht wie 256 Bit (approx = ${approx_bits} Bit)";
			$status = "warn" if $status eq "ok";
		}

	} else {

		push @warnings,
			"Unbekannter DKIM Schlüsseltyp: ${key_type} (erwartet: rsa oder ed25519)";
		$status = "warn" if $status eq "ok";

		if ($approx_bits < 256) {
			push @warnings,
				"DKIM Schlüssel (${key_type}) wirkt sehr kurz (approx ${approx_bits} Bit)";
			$status = "warn" if $status eq "ok";
		}
	}


    # Platzhalter / offensichtlich schlechte Keys
    if ($p_tag =~ /^(?:YQ==|MTIz|AAAA)/) {
        push @warnings, "DKIM p Tag sieht aus wie Test oder Platzhalter Daten";
        $status = "warn" if $status eq "ok";
    }

    # Wiederholungsmuster im Base64 (kein harter Fehler, nur Hinweis)
    if ($base64_len > 20) {
        my $first_half  = substr($p_tag, 0, int($base64_len / 2));
        my $second_half = substr($p_tag, int($base64_len / 2));
        if ($first_half eq $second_half) {
            push @warnings, "DKIM Schluessel zeigt Wiederholungsmuster (moeglicherweise schwach generiert)";
            $status = "warn" if $status eq "ok";
        }
    }

    return {
        errors      => \@errors,
        warnings    => \@warnings,
        status      => $status,
        key_type    => $key_type,
        base64_len  => $base64_len,
        byte_len    => $byte_len,
        blob_bits   => $bit_len_blob,   # zur Info
        approx_bits => $approx_bits,    # geschaetzte Schluessellaenge
    };
}


# =========================
# DMARC / URI / RFC Analyse
# =========================

sub parse_dmarc_tag {
    my ($tagstr) = @_;
    my %tags;
    for my $p (split /;/, $tagstr) {
        $p =~ s/^\s+|\s+$//g;
        next unless $p;
        my ($k, $v) = split /=/, $p, 2;
        next unless defined $k and defined $v;
        $k =~ s/^\s+|\s+$//g;
        $v =~ s/^\s+|\s+$//g;
        $tags{lc $k} = $v;
    }
    return %tags;
}

sub validate_dmarc_uri {
    my ($uri) = @_;
    
    return "URI ist leer" unless $uri;
    
    if ($uri =~ /^mailto:([^\s!]+)$/i) {
        my $email = $1;
        
        if ($email =~ /^(.+?)!(\d+[km]?)$/i) {
            my ($addr, $size) = ($1, $2);
            return "Ungueltige Email in mailto: $addr"
                unless $addr =~ /^[^@]+@[^@]+\.[^@]+$/;
            if ($size =~ /^(\d+)([km]?)$/i) {
                my ($num, $unit) = ($1, lc($2 // ''));
                return "Size Limit zu gross" if $num > 1000000;
            } else {
                return "Ungueltiges Size Limit Format: $size";
            }
        } else {
            return "Ungueltige Email in mailto: $email"
                unless $email =~ /^[^@]+@[^@]+\.[^@]+$/;
        }
        
        return undef;
    }
    
    return "Nur mailto: URIs sind in DMARC erlaubt";
}

sub analyze_dmarc_rfc {
    my ($tags, $rua_raw, $ruf_raw) = @_;
    my @warnings;
    my $status = "ok";

    my $pct = defined $tags->{pct} ? $tags->{pct} : 100;
    if (!defined $tags->{pct}) {
        push @warnings, "DMARC pct nicht gesetzt, Default 100 wird angenommen";
    } else {
        if ($pct !~ /^\d+$/ || $pct < 0 || $pct > 100) {
            push @warnings, "DMARC pct ausserhalb 0 100: $pct";
            $status = "warn" if $status eq "ok";
        }
    }

    if (defined $tags->{ri}) {
        my $ri = $tags->{ri};
        if ($ri !~ /^\d+$/ || $ri <= 0) {
            push @warnings, "DMARC ri (Interval) ungueltig: $ri";
            $status = "warn" if $status eq "ok";
        } elsif ($ri < 3600) {
            push @warnings, "DMARC ri < 3600 Sekunden (ungewoehnlich klein): $ri";
        }
    }

    if (defined $tags->{fo}) {
        my @vals = split /:/, $tags->{fo};
        for my $v (@vals) {
            next if $v eq '0' || $v eq '1' || $v eq 'd' || $v eq 's';
            push @warnings, "Unbekannter DMARC fo Wert: $v";
            $status = "warn" if $status eq "ok";
        }
    }

    if (defined $tags->{rf}) {
        my @vals = split /:/, $tags->{rf};
        for my $v (@vals) {
            next if lc($v) eq 'afrf';
            push @warnings, "Unbekanntes DMARC rf Format: $v";
            $status = "warn" if $status eq "ok";
        }
    }

    for my $u (@$rua_raw, @$ruf_raw) {
        next unless defined $u && $u ne '';
        my $err = validate_dmarc_uri($u);
        if ($err) {
            push @warnings, "DMARC URI '$u' ungueltig: $err";
            $status = "warn" if $status eq "ok";
        }
    }

    return {
        status   => $status,
        warnings => \@warnings,
        pct      => $pct,
        ri       => $tags->{ri},
        fo       => $tags->{fo},
        rf       => $tags->{rf},
    };
}

sub extract_domain_from_mailto {
    my ($uri) = @_;
    return undef unless $uri;
    $uri =~ s/^\s+|\s+$//g;
    return undef unless $uri =~ /^mailto:/i;
    my ($addr) = $uri =~ /^mailto:([^?]+)/i;
    return undef unless $addr && $addr =~ /\@/;
    my (undef, $dom) = split /\@/, $addr, 2;
    $dom = lc $dom if defined $dom;
    return $dom;
}

sub check_external_dmarc_authorization {
    my ($resolver, $domain, $provider_domain) = @_;
    my $name = $domain . "._report._dmarc." . $provider_domain;
    my @txt = get_txt_records($resolver, $name);

    my $authorized = 0;
    for my $t (@txt) {
        if ($t =~ /v=DMARC1/i) {
            $authorized = 1;
            last;   # korrekt in Perl
        }
    }

    return {
        fqdn        => $name,
        authorized  => $authorized ? 1 : 0,
        txt_records => \@txt,
    };
}


# =========================
# MX Check mit RFC Analyse
# =========================

sub check_mx {
    my ($resolver, $domain, $mx_policy) = @_;

    my $pkt = safe_dns_query($resolver, $domain, "MX");
    my @mx_hosts;
    my @rfc_warnings;
    my $rfc_status = "ok";

    if ($pkt) {
        foreach my $rr ($pkt->answer) {
            next unless $rr->type eq "MX";
            my $ex  = lc($rr->exchange);
            my $pre = $rr->preference;

            if (!_valid_hostname($ex)) {
                push @rfc_warnings, "MX Hostname ungueltig: $ex";
                $rfc_status = "warn" if $rfc_status eq "ok";
            }

            if ($pre !~ /^\d+$/) {
                push @rfc_warnings, "MX Preference nicht numerisch fuer $ex: $pre";
                $rfc_status = "warn" if $rfc_status eq "ok";
            }

            push @mx_hosts, {
                exchange   => $ex,
                preference => $pre,
            };
        }
    }

    my @actual_names = map { $_->{exchange} } @mx_hosts;
    my $groups_conf  = $mx_policy->{groups} || [];
    my @groups       = ref $groups_conf eq 'ARRAY' ? @$groups_conf : ();

    if (!@mx_hosts) {
        return {
            status       => "fail",
            detail       => "Keine MX Records gefunden",
            mx           => \@mx_hosts,
            groups       => \@groups,
            rfc_analysis => {
                status    => "fail",
                severity  => "low",
                warnings  => ["Keine MX Records laut DNS"],
            },
        };
    }

    my %pref_count;
    for my $m (@mx_hosts) {
        $pref_count{$m->{preference}}++;
    }
    my @multi_pref = grep { $pref_count{$_} > 1 } keys %pref_count;
    if (@multi_pref) {
        push @rfc_warnings, "Mehrere MX Eintraege mit gleicher Preference: "
            . join(", ", @multi_pref);
        $rfc_status = "warn" if $rfc_status eq "ok";
    }

    if (!@groups) {
        my $detail = "MX Records gefunden: " . join(", ", @actual_names);
        return {
            status       => "ok",
            detail       => $detail,
            mx           => \@mx_hosts,
            groups       => [],
            rfc_analysis => {
                status    => $rfc_status,
                severity  => "low",
                warnings  => \@rfc_warnings,
            },
        };
    }

    my $overall_status = "fail";
    my @group_results;

    for my $g (@groups) {
        my @req = map { lc $_ } _as_list($g->{mx_required});
        my $allow_others = exists $g->{mx_allow_others} ? ($g->{mx_allow_others} ? 1 : 0) : 1;

        my %actual_set   = map { $_ => 1 } @actual_names;
        my %required_set = map { $_ => 1 } @req;

        my @missing;
        my @unexpected;

        for my $r (@req) {
            push @missing, $r unless $actual_set{$r};
        }

        if (@req) {
            for my $a (@actual_names) {
                push @unexpected, $a unless $required_set{$a};
            }
        }

        my $st = "ok";
        my @parts;

        push @parts, "MX Records: " . join(", ", @actual_names);

        if (@missing) {
            $st = "fail";
            push @parts, "fehlende MX: " . join(", ", @missing);
        }

        if (@unexpected) {
            if ($allow_others) {
                push @parts, "zusaetzliche MX erlaubt: " . join(", ", @unexpected);
            } else {
                $st = "fail";
                push @parts, "unerwartete MX: " . join(", ", @unexpected);
            }
        }

        push @group_results, {
            name             => $g->{name} // '',
            status           => $st,
            mx_required      => \@req,
            missing_required => \@missing,
            unexpected       => \@unexpected,
            mx_allow_others  => $allow_others + 0,
            detail           => join("; ", @parts),
        };

        if ($st eq 'ok' && $overall_status ne 'ok') {
            $overall_status = 'ok';
        }
    }

    my $detail = $overall_status eq 'ok'
        ? "MX Konfiguration entspricht mindestens einem Profil"
        : "Keine MX Profilgruppe wurde vollstaendig erfuellt";

    return {
        status       => $overall_status,
        detail       => $detail,
        mx           => \@mx_hosts,
        groups       => \@group_results,
        rfc_analysis => {
            status    => $rfc_status,
            severity  => "low",
            warnings  => \@rfc_warnings,
        },
    };
}

# =========================
# SPF Deep Analysis (RFC 7208)
# =========================

sub analyze_spf_recursion {
    my ($resolver, $domain, $stats, $seen) = @_;
    
    if ($seen->{$domain}) {
        push @{$stats->{warnings}}, "SPF Loop entdeckt bei Domain: $domain (Zyklus: " . join(" -> ", @{$stats->{path}}, $domain) . ")";
        $stats->{has_loop} = 1;
        return;
    }
    
    $seen->{$domain} = 1;
    push @{$stats->{path}}, $domain;

    if (scalar(@{$stats->{path}}) > 10) {
        push @{$stats->{warnings}}, "SPF Rekursion zu tief (>10 Ebenen) bei $domain";
        $stats->{too_deep} = 1;
        return;
    }

    my @txt = get_txt_records($resolver, $domain);
    my @spf_records = grep { /^v=spf1(\s|$)/i } @txt;

    if (!@spf_records) {
        $stats->{void_lookups}++;
        return;
    }
    
    if (@spf_records > 1) {
        push @{$stats->{warnings}}, "Mehrere SPF Records gefunden bei $domain";
        $stats->{multiple_spf} = 1;
        return;
    }

    my $spf_string = $spf_records[0];
    my @terms = split /\s+/, $spf_string;
    
    if ($log->is_debug()) {
        $log->debug("[SPF Analysis] Domain: $domain, SPF: " . substr($spf_string, 0, 100) . "...");
    }
    
    foreach my $term (@terms) {
        next if $term =~ /^v=spf1$/i;
        next unless $term;

        my $clean_term = $term;
        $clean_term =~ s/^[\+\-\~\?]//;
        
        if ($clean_term =~ /^include:(.*)/i) {
            $stats->{lookups}++;
            my $target = $1;
            
            if (_valid_spf_domain($target)) {
                analyze_spf_recursion($resolver, $target, $stats, { %$seen });
            } else {
                push @{$stats->{warnings}}, "Ungueltiges include Target in SPF: $target";
            }
        }
        elsif ($clean_term =~ /^redirect=(.*)/i) {
            $stats->{lookups}++;
            $stats->{redirects}++;
            my $target = $1;
            
            if (_valid_spf_domain($target)) {
                analyze_spf_recursion($resolver, $target, $stats, $seen);
            } else {
                push @{$stats->{warnings}}, "Ungueltiges redirect Target in SPF: $target";
            }
            last;
        }
        elsif ($clean_term =~ /^(?:a|mx|ptr|exists)(?:[:\/]|$)/i) {
            $stats->{lookups}++;
            
            if ($clean_term =~ /^(a|mx|ptr|exists):(.+)/i) {
                my ($mech, $param) = ($1, $2);
                if ($mech =~ /^(a|mx)$/i && $param =~ /^[a-z0-9]/i) {
                    $log->debug("[SPF] Mechanismus $mech mit Parameter: $param");
                }
            }
        }
    }
}

sub check_spf {
    my ($resolver, $domain, $profile, $global_spf_policy) = @_;

    my $spf_policy  = $profile->{spf_policy} || $global_spf_policy || {};
    my $require_spf = exists $profile->{require_spf}
        ? ($profile->{require_spf} ? 1 : 0)
        : $GLOBAL_REQUIRE_SPF;

    my @txt = get_txt_records($resolver, $domain);
    my @spf_all = grep { /^v=spf1(\s|$)/i } @txt;

    my $spf_orig = @spf_all ? $spf_all[0] : "";
    my $mode;
    my $has_all = 0;
    
    if (!@spf_all) {
        $mode = "none";
    } elsif ($spf_orig =~ /-all\b/i) {
        $mode = "hard"; $has_all = 1;
    } elsif ($spf_orig =~ /~all\b/i) {
        $mode = "soft"; $has_all = 1;
    } elsif ($spf_orig =~ /\?all\b/i) {
        $mode = "neutral"; $has_all = 1;
    } elsif ($spf_orig =~ /\ball\b/i) {
        $mode = "open"; $has_all = 1;
    } elsif ($spf_orig =~ /redirect=/i) {
        $mode = "redirect";
    } else {
        $mode = "no-all";
    }

    my @rfc_errors;
    my @rfc_warnings;
    my $rfc_status = "ok";
    
    for my $spf_record (@spf_all) {
        if (length($spf_record) > 255) {
            push @rfc_errors, "SPF TXT Record >255 Bytes (RFC 7208 §12.1 Limit)";
            $rfc_status = "fail";
        }
    }

    my $analysis_stats = {
        lookups      => 0,
        void_lookups => 0,
        redirects    => 0,
        warnings     => [],
        path         => [],
        multiple_spf => 0,
    };
    
    if (@spf_all) {
        analyze_spf_recursion($resolver, $domain, $analysis_stats, {});
    }

    if (@spf_all > 1) {
        push @rfc_errors, "Mehrere SPF Records gefunden (RFC 7208 §3.2 PermError)";
        $rfc_status = "fail";
        $analysis_stats->{multiple_spf} = 1;
    }

    if ($analysis_stats->{lookups} > 10) {
        push @rfc_errors, "SPF DNS Lookups >10 ($analysis_stats->{lookups}) (RFC 7208 §4.6.4 PermError)";
        $rfc_status = "fail";
    }

    if ($analysis_stats->{void_lookups} > 2) {
        push @rfc_errors, "SPF Void Lookups >2 ($analysis_stats->{void_lookups}) (RFC 7208 §4.6.4 PermError)";
        $rfc_status = "fail";
    }

    if ($analysis_stats->{redirects} > 1) {
        push @rfc_warnings, "Mehr als ein redirect= in SPF Struktur gefunden";
        if ($rfc_status eq "ok") {
            $rfc_status = "warn";
        }
    }

    if (!$has_all && $mode ne 'redirect' && @spf_all) {
        push @rfc_warnings, "SPF ohne 'all' Mechanismus (kann zu unerwartetem Verhalten fuehren)";
        if ($rfc_status eq "ok") {
            $rfc_status = "warn";
        }
    }

    my $syntax_errors = [];
    if ($spf_orig) {
        $syntax_errors = validate_spf_syntax($spf_orig);
        if (@$syntax_errors) {
            push @rfc_warnings, "SPF Syntax Warnungen: " . join("; ", @$syntax_errors);
            if ($rfc_status eq "ok" && @$syntax_errors) {
                $rfc_status = "warn";
            }
        }
    }

    if (@{$analysis_stats->{warnings}}) {
        push @rfc_warnings, "SPF Struktur: " . join("; ", @{$analysis_stats->{warnings}});
        if ($rfc_status eq "ok") {
            $rfc_status = "warn";
        }
    }

    if ($spf_orig && $spf_orig =~ /%\{/) {
        my @macros = $spf_orig =~ /%\{([^}]+)\}/g;
        my %seen_macros;
        for my $macro (@macros) {
            $seen_macros{$macro}++;
        }
        
        if (keys %seen_macros) {
            push @rfc_warnings, "SPF enthaelt Makros: " . join(", ", sort keys %seen_macros);
            if ($rfc_status eq "ok") {
                $rfc_status = "warn";
            }
        }
    }

    my $groups_conf   = $spf_policy->{groups}   || {};
    my $defaults_conf = $spf_policy->{defaults} || {};
    my @groups        = ref $groups_conf eq 'ARRAY' ? @$groups_conf : ();
    
    my $policy_status;
    my $detail;
    my @group_results;

    if (!@spf_all && !@groups) {
        if ($require_spf) {
            $policy_status = "fail";
            $detail = "Kein SPF Record vorhanden (require_spf=1)";
        } else {
            $policy_status = "warn";
            $detail = "Kein SPF Record vorhanden (require_spf=0)";
        }
    } elsif (@groups) {
        my $overall_status = "fail";
        
        for my $g (@groups) {
            my @allowed_modes = _as_list(
                exists $g->{allowed_modes}
                    ? $g->{allowed_modes}
                    : $defaults_conf->{allowed_modes}
            );
            my %allowed    = map { $_ => 1 } @allowed_modes;
            my @req_parts  = _as_list($g->{required_contains});

            my $gst    = "ok";
            my @g_notes;

            # Modus passend?
            if (@allowed_modes && !$allowed{$mode} && $mode ne 'redirect') {
                $gst = "fail";
                push @g_notes, "Modus $mode nicht erlaubt";
            }

            # Pflichtteile im SPF?
            for my $p (@req_parts) {
                if (index($spf_orig, $p) < 0) {
                    $gst = "fail";
                    push @g_notes, "Fehlt: $p";
                }
            }

            push @group_results, {
                name   => $g->{name},
                status => $gst,
                detail => join("; ", @g_notes),
            };

            # OR Logik: wenn mindestens eine Gruppe ok ist, ist overall ok
            if ($gst eq 'ok' && $overall_status ne 'ok') {
                $overall_status = 'ok';
            }
        }

        # Wenn mindestens eine Gruppe ok ist, dann sollen die
        # restlichen "fail"-Gruppen nur als "skip" erscheinen,
        # damit im GUI nicht alles rot wirkt.
        if ($overall_status eq 'ok') {
            for my $gr (@group_results) {
                next unless defined $gr->{status};
                next unless $gr->{status} eq 'fail';

                $gr->{status} = 'skip';  # wird im PHP als grau / neutral angezeigt
                if ($gr->{detail}) {
                    $gr->{detail} = "Profilbedingungen fuer diese Domain nicht erfuellt: "
                        . $gr->{detail};
                } else {
                    $gr->{detail} = "Profilbedingungen fuer diese Domain nicht erfuellt";
                }
            }
        }

        $policy_status = $overall_status;
        $detail        = "SPF Profil Check (Modus $mode)";
    } else {
        $policy_status = "ok";
        $detail = "SPF vorhanden (Modus $mode)";
        if ($mode eq 'open' && $defaults_conf->{forbid_open}) {
            $policy_status = "fail";
            $detail = "SPF Modus open verboten";
        }
    }

    my $final_status;
    my @final_notes;
    
    if ($rfc_status eq "fail") {
        $final_status = "fail";
        push @final_notes, "RFC Verletzung";
        $detail = "SPF ungueltig (RFC 7208): " . join("; ", @rfc_errors);
    } else {
        $final_status = $policy_status;
        
        if (@rfc_warnings) {
            push @final_notes, "RFC Hinweise: " . join("; ", @rfc_warnings);
        }
        
        if ($policy_status eq "fail") {
            push @final_notes, "Policy Verletzung";
        }
    }

    if (@final_notes) {
        $detail .= " [" . join("; ", @final_notes) . "]";
    }

    my $has_void_lookup_limit = ($analysis_stats->{void_lookups} > 2) ? 1 : 0;
    my $has_lookup_limit      = ($analysis_stats->{lookups} > 10)     ? 1 : 0;
    my $has_multiple_spf      = $analysis_stats->{multiple_spf};

    return {
        status       => $final_status,
        detail       => $detail,
        require_spf  => $require_spf + 0,
        raw_original => \@spf_all,
        mode         => $mode,
        rfc_analysis => {
            status                => $rfc_status,
            errors                => \@rfc_errors,
            warnings              => \@rfc_warnings,
            lookups               => $analysis_stats->{lookups},
            void_lookups          => $analysis_stats->{void_lookups},
            redirects             => $analysis_stats->{redirects},
            has_void_lookup_limit => $has_void_lookup_limit,
            has_lookup_limit      => $has_lookup_limit,
            has_multiple_spf      => $has_multiple_spf,
            syntax_errors         => $syntax_errors,
            path                  => $analysis_stats->{path},
        },
        groups       => \@group_results,
    };
}

# =========================
# DMARC Check (mit RFC Analyse)
# =========================

sub check_dmarc {
    my ($resolver, $domain, $profile, $global_dmarc_policy) = @_;

    my $dmarc_policy = $profile->{dmarc_policy} || $global_dmarc_policy || {};

    my @ok_policies = _as_list($dmarc_policy->{ok_policies});
    @ok_policies = _as_list($profile->{dmarc_ok_policies}) unless @ok_policies;
    @ok_policies = @GLOBAL_DMARC_OK_POL                     unless @ok_policies;

    my $lookup_domain   = $domain;
    my $inherited_from  = undef;

    my $name = "_dmarc.$lookup_domain";
    my @txt  = get_txt_records($resolver, $name);
    my @dmarc = grep { /^v=DMARC1/i } @txt;

    my $org_dom = org_domain($domain);

    if (!@dmarc && defined $org_dom && $org_dom ne $domain) {
        my $parent_name  = "_dmarc.$org_dom";
        my @txt_parent   = get_txt_records($resolver, $parent_name);
        my @dmarc_parent = grep { /^v=DMARC1/i } @txt_parent;

        if (@dmarc_parent) {
            $lookup_domain  = $org_dom;
            $inherited_from = $org_dom;
            @txt            = @txt_parent;
            @dmarc          = @dmarc_parent;
        }
    }

    if (!@dmarc) {
        return {
            status           => "fail",
            detail           => "Kein DMARC Record gefunden",
            raw              => \@txt,
            inherited_from   => undef,
            effective_domain => $lookup_domain,
        };
    }

    my %tags   = parse_dmarc_tag($dmarc[0]);
    my $policy = lc($tags{p} // "");

    my $policy_ok = 0;
    for my $pol (@ok_policies) {
        if ($policy eq $pol) {
            $policy_ok = 1;
            last;   
        }
    }

    my $rua         = $tags{rua} // "";
    my $ruf         = $tags{ruf} // "";
    my $require_rua = exists $dmarc_policy->{require_rua}
        ? ($dmarc_policy->{require_rua} ? 1 : 0)
        : 1;

    my @rua_raw = $rua ? split /,/, $rua : ();
    my @ruf_raw = $ruf ? split /,/, $ruf : ();
    my @rua_domains;
    for my $r (@rua_raw) {
        my $d = extract_domain_from_mailto($r);
        push @rua_domains, $d if $d;
    }

    my @allow_external = map { lc $_ } _as_list($dmarc_policy->{allow_external_rua_domains});
    my %allow_external = map { $_ => 1 } @allow_external;

    my $require_auth = exists $dmarc_policy->{require_external_authorization}
        ? ($dmarc_policy->{require_external_authorization} ? 1 : 0)
        : 0;

    my @local_rua;
    my @external_domains;
    my %external_seen;

    my $org_lookup = org_domain($lookup_domain);

    for my $rd (@rua_domains) {
        next unless $rd;
        my $rua_org = org_domain($rd);

        if (defined $rua_org && defined $org_lookup && $rua_org eq $org_lookup) {
            push @local_rua, $rd;
        } else {
            push @external_domains, $rd unless $external_seen{$rd}++;
        }
    }

    my @external_details;
    my @external_allowed;
    my @external_unapproved;

    for my $ext (@external_domains) {

        my $auth_info = check_external_dmarc_authorization($resolver, $lookup_domain, $ext);
        my $in_allow  = $allow_external{$ext} ? 1 : 0;

        push @external_details, {
            domain              => $ext,
            in_allowlist        => $in_allow,
            authorized_via_dns  => $auth_info->{authorized},
            auth_fqdn           => $auth_info->{fqdn},
            auth_txt            => $auth_info->{txt_records},
        };

        if ($in_allow) {
            push @external_allowed,   $ext;
        } else {
            push @external_unapproved, $ext;
        }
    }

    my $status = "ok";
    my @notes;

    if (!$policy_ok) {
        $status = "warn";
        push @notes, "DMARC Policy ist nicht streng (" . ($policy || "keine") . ")";
    }

    if ($require_rua && !@rua_domains) {
        $status = "warn" if $status eq "ok";
        push @notes, "Kein RUA Reporting konfiguriert, obwohl require_rua=1";
    }

    if ($require_auth) {

        if (@external_unapproved) {
            $status = "warn" if $status eq "ok";
            push @notes,
                "RUA nutzt nicht freigegebene externe Domains: "
                . join(", ", @external_unapproved);
        }

        my @not_authorized = grep {
            my $d = $_;
            my ($det) = grep { $_->{domain} eq $d } @external_details;
            $det && !$det->{authorized_via_dns}
        } @external_domains;

        if (@not_authorized) {
            $status = "warn" if $status eq "ok";
            push @notes,
                "Externe RUA Domains ohne _report._dmarc Autorisierung: "
                . join(", ", @not_authorized);
        }
    }

    my $rfc = analyze_dmarc_rfc(\%tags, \@rua_raw, \@ruf_raw);
    if ($rfc->{status} eq 'warn' && $status eq 'ok') {
        $status = 'warn';
    }

    my $detail = "DMARC ok";
    $detail .= " (" . join(", ", @notes) . ")" if @notes;
    if (@{$rfc->{warnings}}) {
        $detail .= " [DMARC RFC Hinweise: " . join("; ", @{$rfc->{warnings}}) . "]";
    }

    return {
        status           => $status,
        detail           => $detail,
        raw              => \@dmarc,
        tags             => \%tags,
        inherited_from   => $inherited_from,
        effective_domain => $lookup_domain,
        rua_analysis     => {
            rua_raw                        => \@rua_raw,
            rua_domains                    => \@rua_domains,
            local_rua                      => \@local_rua,
            external_domains               => \@external_domains,
            external_allowed               => \@external_allowed,
            external_unapproved            => \@external_unapproved,
            require_rua                    => $require_rua + 0,
            allowed_external_domains       => \@allow_external,
            require_external_authorization => $require_auth + 0,
            external_details               => \@external_details,
        },
        rfc_analysis     => $rfc,
    };
}

# =========================
# DKIM Check (mit RFC Analyse)
# =========================

sub check_dkim {
    my ($resolver, $domain, $profile, $global_dkim_policy) = @_;

    my $dkim_policy  = $profile->{dkim_policy} || $global_dkim_policy || {};

    my $require_dkim = exists $profile->{require_dkim}
        ? ($profile->{require_dkim} ? 1 : 0)
        : $GLOBAL_REQUIRE_DKIM;

    my @dkim_selectors = _as_list($dkim_policy->{selectors});
    @dkim_selectors = _as_list($profile->{dkim_selectors}) unless @dkim_selectors;
    @dkim_selectors = @GLOBAL_DKIM_SELECTORS               unless @dkim_selectors;

    if (!@dkim_selectors) {
        return {
            status => "warn",
            detail => "Keine DKIM Selector in Profil oder global definiert, Pruefung uebersprungen",
        };
    }

    my @dkim_required = _as_list($dkim_policy->{txt_required_contains});
    @dkim_required = _as_list($profile->{dkim_txt_required_contains}) unless @dkim_required;
    @dkim_required = @GLOBAL_DKIM_TXT_REQUIRED_CONTAINS               unless @dkim_required;

    my $mode = $dkim_policy->{evaluation_mode} || 'any_ok';
    $mode = 'any_ok' unless $mode =~ /^(any_ok|all_ok)$/;

    my $groups_conf = $dkim_policy->{groups} || [];
    my @groups      = ref $groups_conf eq 'ARRAY' ? @$groups_conf : ();

    my $expected_map = $dkim_policy->{expected_txt} || {};

    my %sel_results;
    my @statuses;

    for my $sel (@dkim_selectors) {
        my $name = $sel . "._domainkey.$domain";

        my $res = get_txt_records_with_cname($resolver, $name);
        my @txt          = @{ $res->{txt}          || [] };
        my $cname_used   = $res->{cname_used}   ? 1 : 0;
        my $cname_target = $res->{cname_target} || undef;

        my @dkim = grep { /^v=DKIM1/i } @txt;

        my $st;

        if (!@dkim) {
            $st = {
                status       => "fail",
                detail       => "Kein DKIM Record fuer Selector $sel (TXT oder CNAME Ziel)",
                raw          => \@txt,
                cname_used   => $cname_used,
                cname_target => $cname_target,
                groups       => [],
            };
        } else {
            my $txt_combined = join(" ", @dkim);

            my $sel_status = "ok";
            my @group_results;

            if (@groups) {
                my $any_ok = 0;

                for my $g (@groups) {
                    my @req = _as_list($g->{required_contains});
                    my @missing;

                    for my $p (@req) {
                        push @missing, $p unless index($txt_combined, $p) >= 0;
                    }

                    my $gst = @missing ? "fail" : "ok";
                    $any_ok ||= ($gst eq 'ok');

                    push @group_results, {
                        name                   => $g->{name} // '',
                        status                 => $gst,
                        required_contains      => \@req,
                        missing_required_parts => \@missing,
                    };
                }

                if ($mode eq 'any_ok') {
                    $sel_status = $any_ok ? "ok" : "fail";
                } else {
                    if (grep { $_->{status} eq 'fail' } @group_results) {
                        $sel_status = "fail";
                    } else {
                        $sel_status = "ok";
                    }
                }
            } else {
                my @missing_parts;
                if (@dkim_required) {
                    for my $part (@dkim_required) {
                        push @missing_parts, $part unless index($txt_combined, $part) >= 0;
                    }
                }

                if (@missing_parts) {
                    if ($require_dkim) {
                        $sel_status = 'fail';
                    } else {
                        $sel_status = 'warn';
                    }
                }

                @group_results = ({
                    name                   => 'required_parts',
                    status                 => @missing_parts ? ($require_dkim ? 'fail' : 'warn') : 'ok',
                    required_contains      => \@dkim_required,
                    missing_required_parts => \@missing_parts,
                });
            }

            my $rfc = analyze_dkim_rfc($txt_combined);

            if ($rfc->{status} eq 'fail') {
                $sel_status = 'fail';
            }

            my @notes;

            my $expected_val = $expected_map->{$sel};
            if (defined $expected_val && $expected_val ne '') {
                if (!dkim_txt_matches_expected($txt_combined, $expected_val)) {
                    if ($require_dkim && $sel_status ne 'fail') {
                        $sel_status = 'fail';
                    } elsif (!$require_dkim && $sel_status eq 'ok') {
                        $sel_status = 'warn';
                    }
                    push @notes, "DKIM TXT für Selector $sel entspricht nicht dem erwarteten Wert aus Config (Tag-Vergleich)";
                } else {
                    push @notes, "DKIM TXT für Selector $sel stimmt mit erwartetem Wert aus Config überein (Tag-Vergleich)";
                }
            }

            if ($cname_used && $cname_target) {
                push @notes, "DKIM TXT via CNAME-Ziel $cname_target";
            }

            # WICHTIG: KEINE RFC-Hinweise mehr in @notes pushen!
            # if (@{ $rfc->{warnings} }) {
            #     push @notes, "DKIM RFC Hinweise: " . join("; ", @{ $rfc->{warnings} });
            # }

            my $detail = @notes ? join("; ", @notes) : "DKIM Record für Selector $sel gefunden";


            $st = {
                status       => $sel_status,
                detail       => $detail,
                raw          => \@dkim,
                cname_used   => $cname_used,
                cname_target => $cname_target,
                groups       => \@group_results,
                rfc_analysis => $rfc,
            };
        }

        $sel_results{$sel} = $st;
        push @statuses, $st->{status};
    }

    my $overall_status;

    if ($mode eq 'all_ok') {
        if (grep { $_ eq 'fail' } @statuses) {
            $overall_status = 'fail';
        } elsif (grep { $_ eq 'warn' } @statuses) {
            $overall_status = 'warn';
        } else {
            $overall_status = 'ok';
        }
    } else {
        if (grep { $_ eq 'ok' } @statuses) {
            $overall_status = 'ok';
        } elsif (grep { $_ eq 'warn' } @statuses) {
            $overall_status = 'warn';
        } else {
            $overall_status = 'fail';
        }
    }

    if ($overall_status eq "fail" and !$require_dkim) {
        $overall_status = "warn";
    }

    my $detail = "DKIM Pruefung abgeschlossen (require_dkim=$require_dkim, mode=$mode)";

    return {
        status          => $overall_status,
        detail          => $detail,
        selectors       => \%sel_results,
        require_dkim    => $require_dkim + 0,
        required_parts  => \@dkim_required,
        evaluation_mode => $mode,
    };
}

# =========================
# Domain Verarbeitung
# =========================

sub process_domain {
    my ($dom, $resolver) = @_;

    $log->info("Pruefe Domain: $dom");

    my $dom_result;

    eval {
        my %profile_results;
        my $best_profile;
        my $best_status = 'fail';

        for my $pname (sort keys %{$PROFILE_CONF}) {
            my $p = $PROFILE_CONF->{$pname} || {};

            my $mx    = check_mx($resolver, $dom,    $p->{mx_policy}   || $GLOBAL_MX_POLICY);
            my $spf   = check_spf($resolver, $dom,   $p, $GLOBAL_SPF_POLICY);
            my $dmarc = check_dmarc($resolver, $dom, $p, $GLOBAL_DMARC_POLICY);
            my $dkim  = check_dkim($resolver, $dom,  $p, $GLOBAL_DKIM_POLICY);

            my @st = map { $_->{status} } ($mx, $spf, $dmarc, $dkim);

            my $profile_status = "ok";
            if (grep { $_ eq "fail" } @st) {
                $profile_status = "fail";
            } elsif (grep { $_ eq "warn" } @st) {
                $profile_status = "warn";
            }

            $profile_results{$pname} = {
                status => $profile_status,
                checks => {
                    mx    => $mx,
                    spf   => $spf,
                    dmarc => $dmarc,
                    dkim  => $dkim,
                },
            };

            if ($profile_status eq 'ok') {
                if ($best_status ne 'ok') {
                    $best_status  = 'ok';
                    $best_profile = $pname;
                }
            } elsif ($profile_status eq 'warn') {
                if ($best_status eq 'fail') {
                    $best_status  = 'warn';
                    $best_profile = $pname;
                }
            } elsif (!$best_profile) {
                $best_status  = 'fail';
                $best_profile = $pname;
            }
        }

        my $dom_status = $best_status || 'fail';

        $dom_result = {
            domain              => $dom,
            status              => $dom_status,
            best_profile        => $best_profile,
            best_profile_status => $best_status,
            profiles            => \%profile_results,
        };

        1;
    } or do {
        my $err = $@ || 'Unbekannter Fehler';
        $log->error("Fehler bei Domain $dom: $err");

        $dom_result = {
            domain => $dom,
            status => 'fail',
            error  => "$err",
        };
    };

    return $dom_result;
}

# =========================
# Hauptlogik mit Parallel::ForkManager
# =========================

my @domains;

if ($opt_domain) {
    @domains = (lc $opt_domain);
    $log->info("Nur Single Domain Modus aktiv: $opt_domain");
} else {
    if ($LDAP_ENABLED) {
        @domains = eval { fetch_domains_from_ldap() };
        if ($@) {
            $log->error("Fehler beim LDAP Abruf: $@");
            print STDERR "Fehler beim LDAP Abruf: $@\n";
            exit 1;
        }
    } else {
        $log->info("LDAP ist deaktiviert, verwende nur extra_domains");
        @domains = ();
    }

    push @domains, @EXTRA_DOMAINS if @EXTRA_DOMAINS;

    my %seen;
    @domains = grep { !$seen{$_}++ } @domains;

    if (@EXCLUDE_DOMAINS) {
        my %excl = map { $_ => 1 } @EXCLUDE_DOMAINS;
        my @before = @domains;
        @domains = grep { !$excl{$_} } @domains;

        my @removed = grep { $excl{$_} } @before;
        if (@removed) {
            $log->info("Ausgeschlossene Domains: " . join(", ", @removed));
        }
    }
}

if (!@domains) {
    $log->warn("Keine Domains zu pruefen nach Exclude Filter oder CLI Auswahl");
}

my @results;

my $pm = Parallel::ForkManager->new($MAX_PROCS);

$pm->run_on_finish(
    sub {
        my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data_ref) = @_;
        if ($data_ref && ref $data_ref eq 'HASH') {
            push @results, $data_ref;
        } else {
            $log->warn("Kindprozess $pid hat keine gueltigen Daten geliefert (exit_code=$exit_code)");
        }
    }
);

for my $dom (@domains) {
    $pm->start and next;

    my $child_resolver = Net::DNS::Resolver->new(%resolver_opts);
    $child_resolver->persistent_udp(1);
    $child_resolver->persistent_tcp(1);

    my $dom_result = process_domain($dom, $child_resolver);

    $pm->finish(0, $dom_result);
}

$pm->wait_all_children;

@results = sort {
    (lc($a->{domain} // '')) cmp (lc($b->{domain} // ''))
} @results;

my $global_status = "ok";

if (!@domains) {
    $global_status = "warn";
    $log->warn("Keine Domains zu pruefen, globaler Status auf WARN gesetzt");
} else {
    for my $dom_result (@results) {
        my $dom_status = $dom_result->{status} // 'fail';

        if ($dom_status eq "fail") {
            $global_status = "fail";
            last;
        } elsif ($dom_status eq "warn" and $global_status eq "ok") {
            $global_status = "warn";
        }
    }
}

my $date_str    = strftime("%Y%m%d", localtime);
my $json_target = $JSON_FILE;

if ($json_target =~ /(.*)\.json$/i) {
    $json_target = $1 . "_" . $date_str . ".json";
} else {
    $json_target = $json_target . "_" . $date_str;
}

my $summary = {
    timestamp     => strftime("%Y-%m-%dT%H:%M:%S", localtime),
    config_file   => $config_file,
    tool_version  => $VERSION,
    report_file   => $json_target,
    global_status => $global_status,
    domains_total => scalar(@domains),
    results       => \@results,
};

my $report_write_error = 0;

if ($opt_dry_run) {
    $log->info("Dry-Run aktiv: JSON Report wird NICHT geschrieben (global_status=$global_status, target=$json_target)");
} else {
    eval {
        my $json = encode_json($summary);

        my ($vol, $dir, undef) = File::Spec->splitpath($json_target);
        my $path_dir = File::Spec->catpath($vol, $dir, "");

        if ($path_dir && !-d $path_dir) {
            File::Path::make_path($path_dir) or die "Kann Verzeichnis nicht erstellen: $path_dir: $!";
        }

		open my $fh, '>:raw', $json_target
		  or die "Kann JSON File nicht schreiben: $json_target: $!";
		print {$fh} $json or die "Fehler beim Schreiben in $json_target: $!";
		close $fh or warn "Fehler beim Schliessen von $json_target: $!";


        $log->info("JSON Report nach $json_target geschrieben");
        1;
    } or do {
        my $err = $@ || "Unbekannter Fehler";
        $report_write_error = 1;
        $log->error("Fehler beim Schreiben des JSON Reports: $err");
    };
}

$log->info("Fertig, globaler Status: $global_status (Version $VERSION, report_write_error=$report_write_error)");

my $report_info = $opt_dry_run
    ? "Report: (dry-run, kein File geschrieben, Target $json_target)"
    : ($report_write_error ? "Report: FEHLER beim Schreiben (Target $json_target)" : "Report: $json_target");

print "domain_dns_audit v$VERSION: $global_status (Domains: "
    . scalar(@domains) . ", $report_info)\n";

if ($report_write_error) {
    exit 2;
} elsif ($global_status eq "ok") {
    exit 0;
} elsif ($global_status eq "warn") {
    exit 1;
} else {
    exit 2;
}
