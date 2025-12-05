# domain_dns_audit – DNS-Audit für Mail-Domains (MX, SPF, DMARC, DKIM)

domain_dns_audit ist ein Perl-Tool zur automatisierten Überprüfung von Mail-Domain-Konfigurationen.
Es analysiert MX, SPF, DMARC (inklusive RUA-Checks nach RFC 7489) sowie DKIM, gruppiert die Ergebnisse nach frei definierbaren Profilen und erzeugt einen strukturierten JSON-Report für Monitoring, Security-Audits oder Migrationsprojekte.

## Typische Anwendungsfälle

- Prüfung von Mail-Security-Konfigurationen in Produktion und Test
- Vorbereitung und Qualitätssicherung von DMARC-Reports
- Identifikation fehlerhafter oder unsicherer DNS-Setups
- Automatisiertes Monitoring im Regelbetrieb und in Migrationen

---

## Funktionsumfang

### MX-Analyse

- Unterstützung mehrerer Profile (zum Beispiel Produktion, Test)
- Prüfung, ob alle erwarteten MX-Hosts vorhanden sind
- Optionale Regel, ob zusätzliche MX-Einträge erlaubt sind (mx_allow_others)

### SPF-Analyse

- Erkennung von `redirect=` und Auswertung der finalen Policy
- Bewertung der Modi `-all`, `~all`, `?all` und offene SPF-Records
- Prüfung auf Pflichtbestandteile (zum Beispiel bestimmte `include:` Einträge)
- Profilbasierte Regeln, zum Beispiel: offene SPF-Records verboten

### DMARC-Analyse (RFC 7489 konform)

- Ermittlung der effektiven DMARC-Policy einer Domain
- Korrekte DMARC-Vererbung über die Organizational Domain (Public Suffix List)
- Analyse der RUA-Adressen (lokal oder extern)
- Optional: Prüfung externer Autorisierung via  
  `<domain>._report._dmarc.<provider> TXT "v=DMARC1"`

### DKIM-Analyse

- Unterstützung mehrerer Selector pro Profil
- Auswertung von TXT Records direkt oder über CNAME
- Prüfung auf Pflichtteile wie `v=DKIM1`, `k=rsa`, `p=...`
- Bewertung pro Profil (zum Beispiel alle Selector ok oder mindestens einer ok)

### JSON-Report

- Übersicht über alle geprüften Domains
- Detailauswertung pro Profil und Check (MX, SPF, DMARC, DKIM)
- Zusammenfassender Status: `ok`, `warn`, `fail`
- Ideal als Input für Monitoring-Systeme (Monit, Icinga, Zabbix, Splunk usw.)

### LDAP-Integration (optional)

- Automatischer Abruf von Domains aus LDAP via Attribut `associatedDomain`
- Alternativ: statische Domainliste aus der Konfiguration

### CLI

- `--domain example.ch` für Einzelchecks
- `--debug` für erweitertes Logging
- `--config FILE` zum Überschreiben der Standardkonfiguration

---

## Installation

### Perl-Module (Beispiele, openSUSE / SLES)

Installation zum Beispiel via Zypper oder CPAN:

- Net::LDAP  
- Net::DNS  
- JSON::MaybeXS  
- Log::Log4perl  
- Domain::PublicSuffix  
- Getopt::Long  

Script ausführbar machen:

```bash
chmod +x domain_dns_audit.pl
```

Empfohlener Pfad im Betrieb:

```text
/opt/mmbb_script/domain-dns-audit/domain_dns_audit.pl
```

---

## Konfiguration

Standard-Datei (falls nicht über `--config` überschrieben):

```text
./domain_dns_audit.json
```

Die Konfiguration steuert:

- DNS-Resolver
- Domains (statisch, LDAP, Ausschlusslisten)
- Output-Pfade für Logfile und JSON-Report
- Globale Sicherheitsvorgaben
- Profile mit MX-, SPF-, DMARC- und DKIM-Regeln

Ein ausführliches Beispiel liegt als `domain_dns_audit.json.example` im Repository.

### 1. LDAP-Konfiguration (optional)

```json
{
  "ldap": {
    "enabled": false,
    "uri": "ldaps://ldap.example.ch",
    "bind_dn": "cn=reader,dc=example,dc=ch",
    "bind_pw": "geheim",
    "base_dn": "dc=example,dc=ch",
    "filter": "(objectClass=mailDomain)",
    "attr_domain": "associatedDomain"
  }
}
```

**Bedeutung:**

- `enabled`: `true` aktiviert den LDAP-Abruf von Domains
- `uri`: LDAP oder LDAPS URI
- `bind_dn` und `bind_pw`: Konto für lesenden Zugriff
- `base_dn`: Basis für die Suche
- `filter`: LDAP-Filter für Domainobjekte
- `attr_domain`: Attribut, das die Domainnamen enthält

Wenn `enabled` auf `false` steht, werden nur statische Domains aus dem Bereich `domains` verwendet.

### 2. DNS-Resolver

```json
{
  "dns": {
    "servers": ["8.8.8.8", "9.9.9.9"]
  }
}
```

**Bedeutung:**

- `servers`: Liste der DNS-Server, die für alle Abfragen verwendet werden.  
  Alternativ kann das System-Resolver-Setup genutzt werden, wenn keine Server hinterlegt sind.

### 3. Domainlisten

```json
{
  "domains": {
    "extra_domains": [
      "example.ch",
      "shop.example.ch"
    ],
    "exclude_domains": [
      "legacy.example.ch"
    ]
  }
}
```

**Bedeutung:**

- `extra_domains`: statische Domains, die immer geprüft werden
- `exclude_domains`: Domains, die trotz LDAP oder Profilen explizit ausgeschlossen werden

### 4. Output und Logging

```json
{
  "output": {
    "log_file": "/var/log/mmbb/domain_dns_audit.log",
    "json_file": "/var/log/mmbb/domain_dns_audit.json",
    "log_level": "INFO"
  }
}
```

**Bedeutung:**

- `log_file`: Pfad für das Logfile (für Betrieb und Troubleshooting)
- `json_file`: Pfad für den JSON-Gesamtbericht
- `log_level`: zum Beispiel `DEBUG`, `INFO`, `WARN`, `ERROR`

### 5. Globale Prüfparameter

```json
{
  "check": {
    "require_spf": 1,
    "require_dkim": 1,
    "dmarc_ok_policies": ["reject", "quarantine"],
    "dkim_selectors": ["selector1", "selector2"],
    "dkim_txt_required_contains": ["v=DKIM1", "k=rsa", "p="]
  }
}
```

**Bedeutung:**

- `require_spf`: 1 bedeutet, dass Domains ohne SPF als Fehler gewertet werden
- `require_dkim`: 1 bedeutet, dass Domains ohne gültige DKIM-Keys als Fehler gewertet werden
- `dmarc_ok_policies`: Liste von DMARC-Policies, die als ausreichend streng gelten
- `dkim_selectors`: Standard-Selectorliste, wenn Profile nichts anderes definieren
- `dkim_txt_required_contains`: Pflichtstrings, die im DKIM-TXT-Record vorkommen müssen

### 6. Profile

Profile erlauben unterschiedliche Anforderungen pro Umgebung, zum Beispiel Produktion versus Test.

#### 6.1 Profil `internet-strict` (Produktion)

```json
{
  "profiles": {
    "internet-strict": {
      "mx_policy": {
        "groups": [
          {
            "name": "Primary MX Cluster",
            "mx_required": [
              "mx1.mail.example.ch",
              "mx2.mail.example.ch"
            ],
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
  }
}
```

**Einsatz:**

- Strenges Produktionsprofil mit klar definierten MX-Hosts
- SPF muss mindestens `~all` oder `-all` verwenden, offene Policies sind verboten
- DMARC verlangt mindestens `quarantine`, bevorzugt `reject`
- Externe DMARC-Reporter müssen explizit autorisiert sein
- DKIM wird über mehrere Selector geprüft

#### 6.2 Profil `internet-relaxed` (Testsysteme)

```json
{
  "profiles": {
    "internet-relaxed": {
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
  }
}
```

**Einsatz:**

- Lockeres Profil für Test und Entwicklung
- MX-Konfiguration ist deutlich toleranter
- DMARC kann auch `none` sein, RUA ist optional
- DKIM wird geprüft, ist aber weniger strikt

### 7. Vollständiges Minimalbeispiel

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

Dieses Beispiel prüft eine einzige Domain (`example.ch`) mit minimalen Vorgaben.  
Profile können schrittweise ausgebaut werden.

---

## Beispiele

### Alle Domains aus Konfiguration prüfen

```bash
/opt/mmbb_script/domain-dns-audit/domain_dns_audit.pl
```

### Nur eine Domain prüfen (Debug an)

```bash
/opt/mmbb_script/domain-dns-audit/domain_dns_audit.pl \
  --domain example.ch \
  --debug
```

### Eigene Config verwenden

```bash
/opt/mmbb_script/domain-dns-audit/domain_dns_audit.pl \
  --config /etc/mmbb/domain_dns_audit.json
```

---

## Output

### Logfile

Pfad wird in der Konfiguration definiert, zum Beispiel:

```text
/var/log/mmbb/domain_dns_audit.log
```

### JSON-Report

Vollständige Auswertung:

```text
/var/log/mmbb/domain_dns_audit.json
```

Der JSON-Report enthält unter anderem:

- globalen Status (`ok`, `warn`, `fail`)
- Status pro Domain
- bestes Profil pro Domain
- Detailergebnisse zu MX, SPF, DMARC und DKIM

---

## DMARC-Vererbung (RFC 7489)

Beispiele für Organizational Domains:

| Domain              | Org-Domain   |
|---------------------|--------------|
| mail.example.ch     | example.ch   |
| service.test.co.uk  | test.co.uk   |
| shop.example.com    | example.com  |

Wenn zum Beispiel `_dmarc.sub.example.ch` fehlt, wird automatisch `_dmarc.example.ch` als übergeordneter Eintrag verwendet.

---

## Exitcodes

| Code | Bedeutung              |
|------|------------------------|
| 0    | Alles ok               |
| 1    | Warnungen vorhanden    |
| 2    | Fehler gefunden        |

Beispiel Cronjob:

```cron
0 3 * * * /opt/domain-dns-audit/domain_dns_audit.pl >/dev/null 2>&1
```

---

## Lizenz

Empfehlung: MIT Lizenz.  
Frei verwendbar in Unternehmen, Open Source Projekten und im privaten Umfeld.
