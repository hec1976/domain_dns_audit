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

# Konfiguration (domain_dns_audit.json)

Die Konfiguration steuert sämtliche Funktionen des Tools: welche Domains geprüft werden, welche DNS-Server genutzt werden und welche Sicherheitsrichtlinien gelten.

## 1. LDAP-Konfiguration (optional)

```json
{
  "enabled": false,
  "uri": "",
  "bind_dn": "",
  "bind_pw": "",
  "base_dn": "",
  "filter": "(objectClass=*)",
  "attr_domain": "associatedDomain"
}
```

## 2. DNS-Resolver

```json
{
  "servers": ["8.8.8.8", "9.9.9.9"]
}
```

## 3. Domainlisten

```json
{
  "extra_domains": ["example.ch", "shop.example.ch"],
  "exclude_domains": ["legacy.example.ch"]
}
```

## 4. Output

```json
{
  "log_file": "/var/log/mmbb/domain_dns_audit.log",
  "json_file": "/var/log/mmbb/domain_dns_audit.json",
  "log_level": "INFO"
}
```

## 5. Globale Prüfparameter

```json
{
  "require_spf": 1,
  "require_dkim": 1,
  "dmarc_ok_policies": ["reject", "quarantine"],
  "dkim_selectors": ["selector1", "selector2"],
  "dkim_txt_required_contains": ["v=DKIM1", "k=rsa", "p="]
}
```

## 6. Profile

### 6.1 internet-strict (Produktion)

```json
{
  "mx_policy": {
    "groups": [
      {
        "name": "Primary MX Cluster",
        "mx_required": ["mx1.mail.example.ch", "mx2.mail.example.ch"],
        "mx_allow_others": 0
      }
    ]
  },
  "spf_policy": {
    "defaults": {
      "allowed_modes": ["hard", "soft"],
      "forbid_open": 1
    },
    "groups": [
      {
        "name": "Standard SPF",
        "allowed_modes": ["hard", "soft"],
        "required_contains": ["include:_spf.example.ch"],
        "forbid_open": 1
      }
    ]
  },
  "dmarc_policy": {
    "ok_policies": ["reject", "quarantine"],
    "require_rua": 1,
    "allow_external_rua_domains": ["reports.dmarc-provider.tld"],
    "require_external_authorization": 1
  },
  "dkim_policy": {
    "selectors": ["selector1", "selector2"],
    "txt_required_contains": ["v=DKIM1", "k=rsa", "p="],
    "evaluation_mode": "any_ok"
  }
}
```

### 6.2 internet-relaxed (Testsysteme)

```json
{
  "mx_policy": {
    "groups": [
      {
        "name": "Any MX allowed",
        "mx_required": [],
        "mx_allow_others": 1
      }
    ]
  },
  "spf_policy": {
    "defaults": {
      "allowed_modes": ["hard", "soft", "neutral"]
    }
  },
  "dmarc_policy": {
    "ok_policies": ["reject", "quarantine", "none"],
    "require_rua": 0
  },
  "dkim_policy": {
    "selectors": ["selector1"],
    "txt_required_contains": ["v=DKIM1", "p="],
    "evaluation_mode": "any_ok"
  }
}
```

## 7. Vollständiges Minimalbeispiel

```json
{
  "ldap": {
    "enabled": false
  },
  "dns": {
    "servers": ["8.8.8.8"]
  },
  "domains": {
    "extra_domains": ["example.ch"],
    "exclude_domains": []
  },
  "output": {
    "log_file": "/var/log/mmbb/domain_dns_audit.log",
    "json_file": "/var/log/mmbb/domain_dns_audit.json"
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
