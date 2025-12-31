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


## Übersicht
domain_dns_audit ist ein praxisnahes, robustes DNS und Mail Security Audit Tool für E Mail Domains.  
Es prüft automatisiert MX, SPF, DKIM, ARC, DMARC, DANE und MTA STS und erzeugt einen strukturierten JSON Report für Betrieb, Audit und Analyse.

Das Tool ist bewusst so gebaut, dass es ohne exotische Perl Module auskommt und stabil auf SUSE Linux Enterprise, openSUSE Leap und ähnlichen Systemen läuft.

Zielgruppe sind Administratoren, Security Engineers und Betreiber von Mail Infrastrukturen, die reproduzierbare und nachvollziehbare Resultate benötigen.

---

## Eigenschaften
- RFC konforme Prüfungen für MX, SPF, DKIM, ARC, DMARC, DANE und MTA STS
- Profilbasierte Policy Engine
- Optionaler DNSSEC Betrieb
- EDNS Steuerung zur Vermeidung von DNS Timeouts
- CNAME Follow für DKIM und ARC
- Schlüsselstärken Prüfung für RSA und ED25519
- Atomic JSON Writes
- Parallelisierung mit Forks
- Fast Mode für grosse Domain Sets
- Audit taugliche Resultate

---

## Architektur Überblick
Ablauf pro Lauf:
1. Laden der Konfiguration
2. Initialisierung des DNS Resolvers
3. Laden der Public Suffix List
4. Ermittlung der Domains
5. Parallelisierte Prüfung pro Domain
6. Aggregation der Profile Resultate
7. Schreiben eines versionierten JSON Reports

---

## Voraussetzungen

### Betriebssystem
- Linux empfohlen
- Getestet mit SUSE Linux Enterprise und openSUSE Leap

### Perl Version
- Perl 5.30 oder neuer

### Benötigte Perl Module
- Net::DNS
- JSON::MaybeXS
- Log::Log4perl
- Parallel::ForkManager
- HTTP::Tiny
- Try::Tiny

Optional:
- openssl Binary im Systempfad für DKIM Key Analyse

---

## Installation

### Repository klonen
```bash
git clone https://github.com/hec1976/domain_dns_audit.git
cd domain_dns_audit
```

### Verzeichnisstruktur
```text
domain_dns_audit/
├── script/
│   ├── domain_dns_audit.pl
│   ├── config/
│   │   └── domain_dns_audit.json
│   └── public_suffix_list.dat
├── log/
├── json/
└── README.md
```

### Rechte setzen
```bash
chmod +x script/domain_dns_audit.pl
```

---

## Konfiguration

### Grundstruktur domain_dns_audit.json
```json
{
  "dns": {
    "dnssec": 1,
    "edns_udp_size": 1232,
    "udp_timeout": 10,
    "tcp_timeout": 20
  },
  "domains": {
    "static_domains": [
      "example.ch",
      "example.org"
    ]
  },
  "runtime": {
    "max_procs": 4
  },
  "output": {
    "json_file": "json/domain_dns_audit_%Y%m%d.json",
    "log_file": "log/domain_dns_audit.log",
    "log_level": "INFO"
  },
  "profiles": {
    "default": {
      "require_mx": true,
      "require_spf": true,
      "require_dkim": true,
      "require_dmarc": true,
      "require_dane": false,
      "require_mta_sts": false
    }
  }
}
```

---

## DNSSEC und EDNS Hinweise
DNSSEC kann grosse DNS Antworten erzeugen.  
Ohne korrekt gesetzte EDNS UDP Groesse kann es zu Timeouts kommen.

Empfehlung:
- dnssec aktivieren
- edns_udp_size auf 1232 setzen

Falls dein Upstream Resolver DNSSEC nicht sauber unterstützt, dnssec auf 0 setzen.

---

## Profile und Policies

### Profil Matching
Profile können Domains direkt oder über Suffixe matchen.
```json
"match": {
  "domains": ["example.ch"],
  "suffixes": ["*.example.org"]
}
```

### SPF Policy
- Lookup Limit Prüfung
- Erkennung unsicherer all Mechanismen
- Token Vergleich mit optionalem Qualifier

### DKIM Policy
- Selektor Liste
- Erwartete TXT Records
- Schlüsselstärken Prüfung
- Revocation Erkennung

### DMARC Policy
- Policy Modus Prüfung
- RUA Domain Prüfung
- External Reporting Authorization

---

## Fast Mode
Der Fast Mode reduziert Prüfungen auf zwingend erforderliche Checks.
```bash
./domain_dns_audit.pl --fast
```

Ideal für grosse Domain Listen oder regelmässige Jobs.

---

## CLI Optionen
```text
--domain <domain>     Nur eine Domain prüfen
--config <file>      Alternative Config Datei
--debug              Debug Logging
--dry-run            Kein JSON Output
--max-procs <n>      Parallelität
--fast               Schnellmodus
--version            Version anzeigen
--help               Hilfe anzeigen
```

---

## Ausgabeformat

### JSON Report Struktur
```json
{
  "ts": 1700000000,
  "date": "20251230",
  "version": "2.6.7",
  "domains": {
    "example.ch": {
      "status": "ok",
      "profiles": {
        "default": {
          "status": "ok",
          "checks": {
            "spf": { "status": "ok" },
            "dkim": { "status": "ok" }
          }
        }
      }
    }
  }
}
```

---

## Betrieb und Automation

### Cron Beispiel
```bash
0 3 * * * /opt/domain_dns_audit/script/domain_dns_audit.pl
```

### Empfehlung
- Regelmässiger Lauf
- JSON Reports versioniert aufbewahren
- Ergebnisse mit Dashboard oder jq auswerten

---

## Sicherheit
- Keine Schreibzugriffe ausserhalb definierter Pfade
- Atomic Writes verhindern kaputte JSON Files
- Kein Netzverkehr ausser DNS und HTTPS für MTA STS

---

## Lizenz
MIT License

---

## Status
Produktionsreif und audit tauglich.
