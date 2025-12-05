# README – domain_dns_audit  
DNS Audit für MX, SPF, DMARC, DKIM (mit globalen Defaults & Profilen)

Dieses Dokument beschreibt **ausschliesslich die Konfigurationsdatei `domain_dns_audit.json`**.  
Alle Felder sind vollständig erklärt und mit Beispielen versehen.  
Die README ist bewusst kompakt, sauber strukturiert und praxistauglich.

---

# 1. Gesamtstruktur der Konfiguration

```jsonc
{
  "ldap": { ... },
  "domains": { ... },
  "dns": { ... },
  "output": { ... },
  "check": {
    "require_spf": 1,
    "require_dkim": 1,
    "dmarc_ok_policies": ["reject", "quarantine"],
    "dkim_selectors": ["selector1", "selector2"],
    "dkim_txt_required_contains": ["v=DKIM1", "k=rsa", "p="],
    "profiles": {
      "default": { ... }
    }
  }
}
```

Die Konfiguration besteht aus **globalen Bereichen** (`ldap`, `domains`, `dns`, `output`) und dem Block **check**, der **globale Regeln und Profile** enthält.

---

# 2. Block `ldap` – optional

Wird nur verwendet, wenn Domains aus LDAP gelesen werden sollen.

```jsonc
"ldap": {
  "enabled": false,
  "uri": "ldap://ldap.example.ch",
  "bind_dn": "",
  "bind_pw": "",
  "base_dn": "dc=example,dc=ch",
  "filter": "(objectClass=*)",
  "attr_domain": "associatedDomain"
}
```

### Felder

| Feld            | Beschreibung |
|-----------------|--------------|
| enabled         | true/false. Schaltet LDAP ein oder aus. Wenn `uri` gesetzt ist, reicht das bereits. |
| uri             | LDAP URI |
| bind_dn, bind_pw| Optionaler Bind Benutzer |
| base_dn         | Startpunkt für LDAP Suche |
| filter          | LDAP Filter |
| attr_domain     | Attribut, das Domains enthält |

Wenn `enabled=false` und `uri` fehlt, wird LDAP ignoriert.

---

# 3. Block `domains`

```jsonc
"domains": {
  "extra_domains": ["example.ch"],
  "exclude_domains": ["test.example.ch"]
}
```

### Felder

| Feld            | Beschreibung |
|-----------------|--------------|
| extra_domains   | Statische Domainliste, zusätzlich zu LDAP |
| exclude_domains | Domains, die ignoriert werden sollen |

---

# 4. Block `dns`

```jsonc
"dns": {
  "servers": ["1.1.1.1", "8.8.8.8"]
}
```

### Felder

| Feld            | Beschreibung |
|-----------------|--------------|
| servers         | Falls gesetzt, nutzt der Resolver diese Server. Wenn leer, wird der Systemresolver verwendet. |

---

# 5. Block `output`

```jsonc
"output": {
  "log_file": "/var/log/mmbb/domain_dns_audit.log",
  "json_file": "/var/log/mmbb/domain_dns_audit.json",
  "log_level": "INFO"
}
```

### Felder

| Feld        | Beschreibung |
|-------------|--------------|
| log_file    | Pfad zur Log Datei |
| json_file   | Pfad zum Ergebnisreport |
| log_level   | DEBUG, INFO, WARN, ERROR |

---

# 6. Block `check` – **globale Defaults + Profile**

Dieser Bereich bestimmt das **Verhalten aller DNS Prüfungen**.

---

## 6.1 Globale Regeln (Defaults)

```jsonc
"check": {
  "require_spf": 1,
  "require_dkim": 1,
  "dmarc_ok_policies": ["reject", "quarantine"],
  "dkim_selectors": ["selector1", "selector2"],
  "dkim_txt_required_contains": ["v=DKIM1", "k=rsa", "p="]
}
```

| Feld                         | Wirkung |
|------------------------------|---------|
| require_spf                  | 1 = SPF Pflicht, 0 = Warnung statt Fehler |
| require_dkim                 | 1 = DKIM Pflicht |
| dmarc_ok_policies           | Welche DMARC Policies als "stark genug" gelten |
| dkim_selectors              | Globale Standard Selector |
| dkim_txt_required_contains  | Pflichtstrings im DKIM TXT Record |

**Wichtig:** Profile können alle diese Werte **überschreiben**.  
Wenn ein Profil keinen Wert definiert, gilt der globale Default.

---

# 6.2 Profile

Jede Domain wird gegen **alle Profile geprüft**, das beste Profil gewinnt (ok > warn > fail).

Beispiel:

```jsonc
"profiles": {
  "default": {
    "mx_policy": {},
    "spf_policy": {},
    "dmarc_policy": {},
    "dkim_policy": {}
  }
}
```

---

# 7. Profilblöcke

## 7.1 MX Profil

```jsonc
"mx_policy": {
  "groups": [
    {
      "name": "Primary MX",
      "mx_required": ["mx1.example.ch", "mx2.example.ch"],
      "mx_allow_others": 0
    }
  ]
}
```

| Feld             | Beschreibung |
|------------------|--------------|
| mx_required       | Erwartete MX Server |
| mx_allow_others   | 1 = zusätzliche MX sind ok, 0 = Fehler |

Die Domain muss **mindestens eine MX Gruppe** erfüllen.

---

## 7.2 SPF Profil

```jsonc
"spf_policy": {
  "defaults": {
    "allowed_modes": ["hard", "soft"],
    "forbid_open": 1
  },
  "groups": [
    {
      "name": "Standard SPF",
      "allowed_modes": ["hard"],
      "required_contains": ["include:_spf.example.ch"]
    }
  ]
}
```

### SPF Modi

- `hard` = -all  
- `soft` = ~all  
- `neutral` = ?all  
- `open` = all oder +all  
- `no-all` = v=spf1 ohne all  
- `none` = kein SPF vorhanden  

### Felder

| Feld               | Bedeutung |
|-------------------|-----------|
| allowed_modes     | Welche Modi erlaubt sind |
| forbid_open       | Falls 1 → "open" wird als Fehler gewertet |
| required_contains | Strings, die im SPF enthalten sein müssen |

---

## 7.3 DMARC Profil

```jsonc
"dmarc_policy": {
  "ok_policies": ["reject", "quarantine"],
  "require_rua": 1,
  "allow_external_rua_domains": ["provider.net"],
  "require_external_authorization": 1
}
```

### Felder

| Feld                               | Bedeutung |
|-----------------------------------|-----------|
| ok_policies                       | Erlaubte Policies für OK |
| require_rua                       | RUA Eintrag Pflicht |
| allow_external_rua_domains        | Externe Provider, die erlaubt sind |
| require_external_authorization    | Prüft `_report._dmarc.<domain>` TXT Eintrag |

---

## 7.4 DKIM Profil

```jsonc
"dkim_policy": {
  "selectors": ["selector1", "selector2"],
  "txt_required_contains": ["v=DKIM1", "p="],
  "evaluation_mode": "any_ok"
}
```

| Feld                   | Bedeutung |
|------------------------|-----------|
| selectors              | Selector Liste für dieses Profil |
| txt_required_contains  | Pflichtteile im DKIM TXT |
| evaluation_mode        | any_ok = 1 OK reicht, all_ok = alle Selektoren müssen OK sein |

---

# 8. Minimale vollständige Beispielkonfiguration

```jsonc
{
  "ldap": { "enabled": false },
  "domains": { "extra_domains": ["example.ch"] },
  "dns": { "servers": [] },
  "output": {
    "log_file": "/var/log/mmbb/domain_dns_audit.log",
    "json_file": "/var/log/mmbb/domain_dns_audit.json",
    "log_level": "INFO"
  },
  "check": {
    "require_spf": 1,
    "require_dkim": 1,
    "dmarc_ok_policies": ["reject", "quarantine"],
    "dkim_selectors": ["selector1", "selector2"],
    "dkim_txt_required_contains": ["v=DKIM1", "k=rsa", "p="],
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

Damit läuft der Audit mit globalen Defaults und einem einfachen Profil.

---



