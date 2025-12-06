# domain_dns_audit

```
        ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗   ██████╗ ███╗   ██╗███████╗   
        ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║   ██╔══██╗████╗  ██║██╔════╝ 
        ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║   ██║  ██║██╔██╗ ██║███████╗          
        ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║   ██║  ██║██║╚██╗██║╚════██║    
        ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║   ██████╔╝██║ ╚████║███████║     
        ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═══╝╚══════╝     
                            █████╗ ██╗   ██╗██████╗ ██╗████████╗ 
                           ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝   
                           ███████║██║   ██║██║  ██║██║   ██║
                           ██╔══██║██║   ██║██║  ██║██║   ██║
                           ██║  ██║╚██████╔╝██████╔╝██║   ██║
                           ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝       
```

[![Status](https://img.shields.io/badge/status-production-brightgreen)]()
[![Version](https://img.shields.io/badge/version-1.0.0-blue)]()
[![License](https://img.shields.io/badge/license-MIT-purple)]()
[![Perl](https://img.shields.io/badge/perl-5.30%2B-yellow)]()
![Security](https://img.shields.io/badge/CodeQL-Security%20Scan-blueviolet)


> **Projekt:** domain_dns_audit  
> **Beschreibung:** Enterprise DNS Security Audit & Compliance Tool (LDAP → DNS → JSON)  
> **Sprache:** Perl 5.30+  
> **Zweck:** Automatisierte DNS-Sicherheitsaudits für E-Mail Authentifizierung (MX, SPF, DKIM, DMARC)
---

`domain_dns_audit` ist ein Perl Tool zur automatisierten Prüfung der DNS Konfiguration von Mail Domains.  
Es wertet MX, SPF, DMARC und DKIM aus, unterstützt Profile pro Sicherheitsniveau und erzeugt einen strukturierten JSON Report, der sich ideal für Monitoring, Security Audits und Migrationsprojekte eignet.

## Features

- MX Prüfung
  - Unterstützung von Profilen und Gruppen
  - Prüfung erwarteter MX Hosts pro Profilgruppe
  - Optionale Toleranz für zusätzliche MX Records
- SPF Analyse
  - Auswertung des effektiven SPF Records inklusive `redirect=`
  - Bewertung der Modi `-all`, `~all`, `?all`, offen und ohne `all`
  - Profilbasierte Regeln (erlaubte Modi, Pflichtbestandteile, Verbot von offenem SPF)
- DMARC Prüfung
  - Lookup auf `_dmarc.domain` mit Fallback auf Organisationsdomain gemäss Public Suffix
  - Bewertung der Policy gegen konfigurierbare OK Policies (zum Beispiel `reject` oder `quarantine`)
  - RUA Analyse und Trennung in lokale und externe Empfänger
  - Optionale Prüfung externer RUA Ziele via `_report._dmarc` Autorisierung
- DKIM Prüfung
  - Mehrere Selector pro Profil oder global konfigurierbar
  - Prüfung auf Pflichtteile im DKIM TXT Record oder Gruppenregeln
  - Optionaler Exact Match Vergleich gegen erwartete DKIM Keys aus der Config (Tag basierter Vergleich)
  - Unterstützung von CNAME basierten DKIM Records
- LDAP Integration
  - Optionaler Abruf der zu prüfenden Domains aus LDAP (zum Beispiel `associatedDomain`)
  - Unterstützung mehrerer LDAP URIs mit Fallback
- Performance und Skalierung
  - Parallele Verarbeitung mit `Parallel::ForkManager`
  - Konfigurierbare Anzahl Prozesse (`runtime.max_procs` oder `--max-procs`)
  - DNS Resolver pro Child Prozess mit Timeouts und Retries
- Output und Betrieb
  - Strukturierter JSON Report für alle geprüften Domains
  - Logfile per Log4perl mit einstellbarem Log Level
  - Sinnvolle Exitcodes für Integration in Monitoring oder Pipelines

## Einsatzszenarien

- Validierung von Mail Security Konfigurationen für bestehende Domains
- Vorbereitung und Kontrolle von DMARC Einführungen
- Regelmässige Überwachung von kritischen Domains im Betrieb
- Qualitätssicherung nach DNS Anpassungen oder Providerwechseln
- Reporting und Dokumentation im Rahmen von Audits oder ISMS Kontrollen

---

## Voraussetzungen

### Laufzeitumgebung

- Linux oder Unix artige Umgebung (zum Beispiel openSUSE, SLES, Debian)
- Perl 5.10 oder neuer (empfohlen: aktuelle Distribution Version)

### Perl Module

Folgende Module werden benötigt:

- `Net::DNS`
- `Net::LDAP`
- `Net::LDAP::Util`
- `JSON::MaybeXS`
- `Log::Log4perl`
- `FindBin`
- `File::Spec`
- `Getopt::Long`
- `Domain::PublicSuffix`
- `Parallel::ForkManager`
- `Time::Out`
- `POSIX`

Auf vielen Distributionen können diese Module über Paketquellen installiert werden, zum Beispiel:

```bash
# Beispiele, Namen je nach Distribution anpassen
zypper install perl-Net-DNS perl-Net-LDAP perl-JSON-MaybeXS perl-Log-Log4perl \
  perl-Domain-PublicSuffix perl-Parallel-ForkManager perl-Time-Out
```

Falls ein Modul nicht als Paket verfügbar ist, kann es über cpan oder cpanm installiert werden.

---

## Installation

1. Repository klonen oder Script nach `/opt/mmbb_script/domain-check` kopieren:

```bash
mkdir -p /opt/mmbb_script/domain-check
cp domain_dns_audit.pl /opt/mmbb_script/domain-check/
chmod 750 /opt/mmbb_script/domain-check/domain_dns_audit.pl
```

2. Konfiguration anlegen, zum Beispiel:

```bash
cp domain_dns_audit.json.example /opt/mmbb_script/domain-check/domain_dns_audit.json
vi /opt/mmbb_script/domain-check/domain_dns_audit.json
```

3. Optional separate LDAP Konfiguration:

```bash
cp domain_dns_ldap.json.example /opt/mmbb_script/domain-check/domain_dns_ldap.json
vi /opt/mmbb_script/domain-check/domain_dns_ldap.json
```

4. Log Verzeichnis anlegen:

```bash
mkdir -p /var/log/mmbb
chown <user>:<group> /var/log/mmbb
chmod 750 /var/log/mmbb
```

---

## Konfiguration

Die Hauptkonfiguration liegt standardmässig im gleichen Verzeichnis wie das Script und heisst `domain_dns_audit.json`.

### Minimalbeispiel

```json
{
  "ldap": {
    "enabled": false
  },

  "domains": {
    "extra_domains": [
      "example.ch",
      "example.com"
    ],
    "exclude_domains": []
  },

  "output": {
    "log_file": "/var/log/mmbb/domain_dns_audit.log",
    "json_file": "/var/log/mmbb/domain_dns_audit.json",
    "log_level": "INFO"
  },

  "dns": {
    "servers": ["8.8.8.8", "1.1.1.1"],
    "timeout": 5,
    "udp_timeout": 2,
    "tcp_timeout": 4
  },

  "runtime": {
    "max_procs": 20
  },

  "check": {
    "require_spf": 1,
    "require_dkim": 1,

    "profiles": {
      "default": {
        "mx_policy": {},
        "spf_policy": {},
        "dmarc_policy": {},
        "dkim_policy": {}
      }
    }
  }
}
```

### LDAP Konfiguration

LDAP kann entweder in der Hauptconfig unter `ldap` oder in einer separaten Datei `domain_dns_ldap.json` definiert werden.

Beispiel separate Datei:

```json
{
  "ldap": {
    "enabled": true,
    "uris": [
      "ldap://ldap1.example.ch",
      "ldap://ldap2.example.ch"
    ],
    "bind_dn": "cn=reader,ou=svc,dc=example,dc=ch",
    "bind_pw": "geheim",
    "base_dn": "dc=example,dc=ch",
    "filter": "(objectClass=mailDomain)",
    "attr_domain": "associatedDomain"
  }
}
```

Wichtige Punkte:

- `uris` oder `uri` definieren einen oder mehrere LDAP Server.
- Wenn `enabled` nicht gesetzt ist, wird aus `uri`/`uris` abgeleitet, ob LDAP benutzt wird.
- Die im LDAP gefundenen Domains werden mit `domains.extra_domains` zusammengeführt, doppelte Einträge werden entfernt.
- Domains in `domains.exclude_domains` werden am Schluss wieder entfernt.

### DNS Einstellungen

Im Block `dns` können DNS spezifische Parameter gesetzt werden:

```json
"dns": {
  "servers": ["8.8.8.8", "1.1.1.1"],
  "timeout": 5,
  "udp_timeout": 2,
  "tcp_timeout": 4
}
```

- `servers`: Optional Liste von Nameservern. Wenn leer, wird der System Resolver genutzt.
- `timeout`: Maximaler Timeout pro DNS Anfrage in Sekunden (Time::Out um die Query).
- `udp_timeout` und `tcp_timeout`: interne Timeouts für `Net::DNS::Resolver`.

### Runtime Einstellungen

```json
"runtime": {
  "max_procs": 20
}
```

- `max_procs`: Maximale Anzahl paralleler Child Prozesse für Domain Checks. Kann zur Laufzeit mit `--max-procs` übersteuert werden.

### Profile und Policies

Die eigentlichen Prüfregeln leben im Bereich `check.profiles`.  
Ein Profil beschreibt ein gewünschtes Ziel Setup für eine Domain oder Domänengruppe.

Beispiel für ein strengeres Profil:

```json
"check": {
  "require_spf": 1,
  "require_dkim": 1,
  "dmarc_ok_policies": ["reject", "quarantine"],

  "profiles": {
    "internet-strict": {
      "mx_policy": {
        "groups": [
          {
            "name": "Primary MX Cluster",
            "mx_required": [
              "mx01.mail.example.ch",
              "mx02.mail.example.ch"
            ],
            "mx_allow_others": false
          }
        ]
      },

      "spf_policy": {
        "defaults": {
          "forbid_open": true,
          "allowed_modes": ["hard", "soft"]
        },
        "groups": [
          {
            "name": "Standard SPF",
            "required_contains": [
              "include:_spf.example.ch"
            ],
            "allowed_modes": ["hard"]
          }
        ]
      },

      "dmarc_policy": {
        "ok_policies": ["reject"],
        "require_rua": 1,
        "allow_external_rua_domains": [
          "dmarc-provider.example.com"
        ],
        "require_external_authorization": 1
      },

      "dkim_policy": {
        "selectors": ["dkim1", "dkim2"],
        "txt_required_contains": ["v=DKIM1", "k=rsa"],
        "evaluation_mode": "any_ok",

        "expected_txt": {
          "dkim1": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD...",
          "dkim2": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
        }
      }
    }
  }
}
```

Erläuterungen:

- `mx_policy.groups` beschreibt erwartete MX Hostnamen und ob zusätzliche MX zugelassen sind.
- `spf_policy.defaults` und `spf_policy.groups` definieren, welche SPF Modi und Inhalte akzeptabel sind.
- `dmarc_policy` steuert erlaubte Policies, Pflicht für RUA und externe RUA Freigaben.
- `dkim_policy.selectors` legt Selektoren fest, `txt_required_contains` und `groups` definieren Pflichtteile.
- `expected_txt` enthält optionale DKIM Keys pro Selector, gegen die Tag basiert verglichen wird.

---

## CLI Nutzung

Aufrufhilfe:

```bash
./domain_dns_audit.pl --help
```

Wichtige Optionen:

```text
--config FILE       Pfad zur JSON Konfiguration (Default: domain_dns_audit.json im Script Verzeichnis)
--ldap-config FILE  Separates JSON nur für LDAP (optional, Default: domain_dns_ldap.json im Script Verzeichnis)
--domain DOMAIN     Nur diese eine Domain prüfen (LDAP und extra_domains werden ignoriert)
--debug             Log Level DEBUG aktivieren
--max-procs N       Anzahl paralleler Prozesse (Default: runtime.max_procs oder 20)
--dry-run           Kein JSON Report schreiben, nur Log und Exitcode
--version           Version von domain_dns_audit anzeigen
--help              Hilfe anzeigen
```

Beispiele:

```bash
# Standardlauf mit Config im Script Verzeichnis
./domain_dns_audit.pl

# Konfiguration und LDAP Config explizit setzen
./domain_dns_audit.pl --config /etc/mmbb/domain_dns_audit.json \
                      --ldap-config /etc/mmbb/domain_dns_ldap.json

# Nur eine Domain prüfen
./domain_dns_audit.pl --domain example.ch

# Debug Logging und limitierte Parallelität
./domain_dns_audit.pl --debug --max-procs 5

# Nur prüfen, kein JSON Output schreiben
./domain_dns_audit.pl --dry-run
```

---

## JSON Output

Der Report wird standardmässig nach `output.json_file` geschrieben, zum Beispiel:

```json
{
  "timestamp": "2025-12-06T15:30:00",
  "config_file": "/opt/mmbb_script/domain-check/domain_dns_audit.json",
  "tool_version": "1.0.0",
  "global_status": "ok",
  "domains_total": 3,
  "results": [
    {
      "domain": "example.ch",
      "status": "ok",
      "best_profile": "internet-strict",
      "best_profile_status": "ok",
      "profiles": {
        "internet-strict": {
          "status": "ok",
          "checks": {
            "mx":    { "...": "..." },
            "spf":   { "...": "..." },
            "dmarc": { "...": "..." },
            "dkim":  { "...": "..." }
          }
        }
      }
    }
  ]
}
```

Die Struktur der einzelnen Checkblöcke (`mx`, `spf`, `dmarc`, `dkim`) ist bewusst detailliert gehalten, damit ein Frontend oder Monitoring Tool daraus eine übersichtliche Darstellung generieren kann.

---

## Logging und Exitcodes

### Logging

- Logfile Pfad und Level werden in der Config unter `output` definiert.
- Im Debug Modus (`--debug`) wird das Log Level auf `DEBUG` gesetzt.
- Das Log enthält unter anderem:
  - Start inkl. Version und Config Datei
  - LDAP Verbindungsversuche und Resultate
  - DNS Timeouts und Fehler
  - Pro Domain den Start und mögliche Fehler
  - Status beim Schreiben des JSON Reports

### Exitcodes

- `0` bei `global_status = ok`
- `1` bei `global_status = warn`
- `2` bei `global_status = fail`

Damit kann das Tool gut in Nagios, Icinga, Prometheus Exporter Wrapper oder eigene Skripte integriert werden.

---

## Best Practices

- DNS Timeouts und `max_procs` auf die Umgebung abstimmen, um Resolver oder DNS Server nicht zu überlasten.
- DMARC RUA Ziele regelmässig auf externe Provider prüfen und die `allow_external_rua_domains` Liste pflegen.
- `expected_txt` für DKIM nur dort nutzen, wo Keys stabil sind. Bei häufigen Keywechseln reicht oft die Prüfung auf Pflichtteile.
- Regelmässig eine `--dry-run` Ausführung mit `--debug` durchführen, um neue Profile oder Änderungen zu testen, bevor sie produktiv genutzt werden.

---

## Troubleshooting

### JSON Config Fehler

Fehlermeldung wie:

```text
Fehler beim Parsen der JSON Config ...: , or } expected while parsing object/hash ...
```

Hinweis:

- JSON erlaubt keine Kommentare.
- Nach jedem Eintrag in einem Objekt muss ein Komma folgen, ausser beim letzten.
- Nur doppelte Anführungszeichen verwenden.

Tipp: Config mit `jq` oder Perl testen:

```bash
perl -MJSON::PP -e 'decode_json do { local $/; <> }' /opt/mmbb_script/domain-check/domain_dns_audit.json
```

### DNS Timeouts

Wenn im Log viele Einträge wie

```text
[WARN] [PID] [DNS] Timeout bei Query: _dmarc.example.ch (TXT) Versuch 1
```

auftauchen:

- `dns.timeout` erhöhen oder `dns.servers` anpassen.
- `runtime.max_procs` reduzieren, um DNS Last zu senken.

### LDAP Probleme

Fehler wie:

```text
Keiner der LDAP Server erreichbar oder bindbar
```

prüfen:

- URIs korrekt (`ldap://host`, `ldaps://host`).
- Firewall und ACLs.
- `bind_dn` und `bind_pw` korrekt.
- `base_dn`, `filter` und `attr_domain` stimmen mit dem Schema überein.

---

## Roadmap / Ideen

Mögliche Erweiterungen:

- Konfigurierbare Zuordnung Profil pro Domain oder Domain Muster
- Export von Summary Metriken für Prometheus
- Zusätzliches HTML Summary für schnelle manuelle Sichtprüfungen
- Optionaler Support für DNSSEC Status Auswertung

Pull Requests, Issues und Verbesserungsvorschläge sind willkommen.
