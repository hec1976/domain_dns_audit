# domain_dns_audit – DNS-Audit für Mail-Domains (MX, SPF, DMARC, DKIM)

domain_dns_audit ist ein leistungsfähiges Perl-Tool zur automatisierten Überprüfung von Mail-Domain-Konfigurationen.
Es analysiert MX, SPF, DMARC (inkl. RUA-Checks nach RFC 7489) sowie DKIM, gruppiert die Ergebnisse nach frei definierbaren Profilen und erzeugt einen strukturierten JSON-Report für Monitoring, Security-Audits oder Migrationsprojekte.

## Typische Anwendungsfälle
- Überprüfung von Mail-Security-Konfigurationen  
- Vorbereitung oder Kontrolle von DMARC-Reports  
- Identifikation fehlerhafter oder unsicherer DNS-Setups  
- Automatisiertes Monitoring im Betrieb  

# Funktionen

## ✓ MX-Analyse
- Unterstützung von Profilen (mehrere MX-Gruppen)
- Prüfung erwarteter Hosts
- Option, ob zusätzliche MX erlaubt sind

## ✓ SPF-Analyse
- Erkennung von redirect=
- Bewertung aller Modi: -all, ~all, ?all, offen
- Prüfung auf Pflichtbestandteile
- Profilbasierte Regeln (z. B. open verboten)

## ✓ DMARC-Analyse (RFC-konform)
- Ermittlung der DMARC-Policy
- Korrekte DMARC-Vererbung über Organizational Domain (Public Suffix List)
- Analyse der RUA-Adressen (lokal, extern)
- Optional: Prüfung externer Autorisierung via `<domain>._report._dmarc.<provider> TXT "v=DMARC1"`

## ✓ DKIM-Analyse
- Unterstützung mehrerer Selector pro Profil
- TXT Records direkt oder via CNAME
- Prüfung auf Pflichtteile oder Gruppenkriterien

## ✓ JSON-Report
- Übersicht zu allen geprüften Domains
- Detailauswertung pro Profil und Check
- Status: ok, warn, fail
- Ideal für Monitoring-Systeme

## ✓ LDAP-Integration (optional)
- Automatischer Abruf von Domains via `associatedDomain`
- Alternativ: statische Domains aus Config

## ✓ CLI-Funktionen
- `--domain example.ch` für Einzelchecks
- `--debug` für erweitertes Logging
- `--config FILE` zum Überschreiben der Konfiguration

# Installation

## Perl-Module (Beispiele)
Unter openSUSE / SLES z. B. via Zypper oder CPAN installierbar:

- Net::LDAP  
- Net::DNS  
- JSON::MaybeXS  
- Log::Log4perl  
- Domain::PublicSuffix  
- Getopt::Long  

## Script ausführbar machen
```bash
chmod +x domain_dns_audit.pl
```

# Konfiguration

Standard-Datei:
```
./domain_dns_audit.json
```

Diese definiert:
- DNS-Server  
- Output-Pfade  
- Domains (statisch, LDAP, Ausschlusslisten)  
- Globale Sicherheitsvorgaben  
- Profile: MX/SPF/DMARC/DKIM-Regeln  

Ein vollständiges Beispiel liegt als
`domain_dns_audit.json.example`
im Repo.

# Beispiele

## Alle Domains prüfen
```bash
./domain_dns_audit.pl
```

## Nur eine Domain prüfen
```bash
./domain_dns_audit.pl --domain example.ch --debug
```

## Eigene Config nutzen
```bash
./domain_dns_audit.pl --config /etc/mmbb/domain_dns_audit.json
```

# Output

## Logfile
Ort wird in der Config definiert, z. B.:
```
/var/log/mmbb/domain_dns_audit.log
```

## JSON-Report
Vollständige Auswertung:
```
/var/log/mmbb/domain_dns_audit.json
```

Enthält u. a.:
- globalen Status  
- Status pro Domain  
- bestes Profil  
- Detailchecks MX/SPF/DMARC/DKIM  

# DMARC-Vererbung (RFC 7489)

Beispiele:

| Domain              | Org-Domain   |
|--------------------|--------------|
| mail.example.ch    | example.ch   |
| service.test.co.uk | test.co.uk   |
| shop.example.com   | example.com  |

Falls `_dmarc.sub.example.ch` fehlt → automatisch `_dmarc.example.ch`.

# Exitcodes

| Code | Bedeutung           |
|------|----------------------|
| 0    | Alles OK             |
| 1    | Warnungen vorhanden  |
| 2    | Fehler gefunden       |

Cronjob Beispiel:
```
0 3 * * * /opt/mmbb_script/domain-dns-audit/domain_dns_audit.pl >/dev/null 2>&1
```

# Lizenz

Empfehlung: MIT Lizenz  
Frei verwendbar in Unternehmen, Open Source Projekten und im privaten Umfeld.
