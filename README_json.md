# domain_dns_audit

`domain_dns_audit` ist ein Audit-Tool zur Überprüfung von DNS- und Mail-Sicherheitsmechanismen pro Domain.
Der Fokus liegt auf RFC-konformer Prüfung mit praxisnaher Bewertung für reale Mail-Infrastrukturen.

---

## Geprüfte Mechanismen

- MX
- SPF (RFC 7208)
- DKIM (RFC 6376)
- DMARC (RFC 7489)
- ARC (RFC 8617)
- DANE / TLSA (RFC 7672)
- DNSSEC (RFC 4033/4034/4035)
- BIMI (IETF Draft)
- optional MTA-STS und TLS-RPT

---

## Voraussetzungen

- Perl >= 5.28
- Module:
  - Net::DNS
  - Crypt::OpenSSL::RSA
  - JSON::MaybeXS
  - Log::Log4perl
  - Parallel::ForkManager
  - HTTP::Tiny
  - Cache::Memcached (optional)

---

## Verwendung

```bash
perl domain_dns_audit.pl
perl domain_dns_audit.pl --domain example.ch
perl domain_dns_audit.pl --config /pfad/config.json
perl domain_dns_audit.pl --debug
perl domain_dns_audit.pl --dry-run
```

---

## Konfigurationsparameter (vollständig)

### Root-Level

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| version | string | Versionsinfo |
| description | string | Freitext |
| public_suffix_list | string | Pfad zur Public Suffix List Datei |

---

### domains

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| static_domains | array | Domains, die geprüft werden |
| exclude_domains | array | Domains, die ausgeschlossen werden |

---

### profiles

Profiles definieren, welche Checks für welche Domains gelten.

#### profiles.<name>.match

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| domains | array | Exakte Domains |
| suffixes | array | Wildcards wie *.example.ch |

#### Check-Flags

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| require_mx | bool | MX prüfen |
| require_spf | bool | SPF prüfen |
| require_dkim | bool | DKIM prüfen |
| require_dmarc | bool | DMARC prüfen |
| require_arc | bool | ARC prüfen |
| require_dane | bool | DANE prüfen |
| require_mta_sts | bool | MTA-STS prüfen |
| require_tls_rpt | bool | TLS-RPT prüfen |
| require_bimi | bool | BIMI prüfen |

---

### DMARC

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| dmarc_strict_alignment | bool | Strenges Alignment |
| dmarc_ok_policies | array | Erlaubte Policies |
| dmarc_policy.allow_external_rua_domains | array | Erlaubte externe RUA Domains |

---

### DKIM

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| dkim_selectors | array | DKIM Selektoren |
| dkim_policy.evaluation_mode | string | all_ok oder any_ok |
| dkim_policy.expected_txt | object | Erwartete TXT Inhalte je Selektor |

---

### ARC

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| arc_selectors | array | ARC Selektoren |

---

### SPF

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| spf_policy.groups | array | SPF Regelgruppen |
| allowed_modes | array | hard oder soft |
| required_contains | array | Tokens die enthalten sein müssen |
| required_contains_any | array | Mindestens eines muss vorkommen |

---

### MX Policy

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| mx_policy.groups | array | MX Regelgruppen |
| mx_required | array | Erwartete MX Hosts |
| mx_allow_others | bool | Weitere MX erlauben |

---

### BIMI

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| bimi_policy.allowed_logo_domains | array | Erlaubte Logo Domains |

---

### DANE

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| dane_ports | array | Ports für TLSA |
| dane_policy.min_tls_version | string | Minimale TLS Version |

---

### dns

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| timeout | int | Allgemeiner Timeout |
| udp_timeout | int | UDP Timeout |
| tcp_timeout | int | TCP Timeout |
| retrans | int | Retransmits |
| retry | int | Retry Count |
| dnssec | bool | DNSSEC aktiv |
| edns_udp_size | int | EDNS UDP Size |
| servers | array | Nameserver |

---

### output

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| log_file | string | Logfile Pfad |
| json_file | string | JSON Output Basis |
| log_level | string | Log Level |

---

### runtime

| Parameter | Typ | Beschreibung |
|---------|-----|--------------|
| max_procs | int | Parallelisierung |

---

## Statuswerte

- ok
- warn
- fail
- info
- skip

---

## Philosophie

Das Tool ist streng, aber realistisch.
Nicht jede Abweichung ist kritisch, aber jede Schwäche wird sichtbar gemacht.

---

## Lizenz

Internes Projekt / Ausbildungs- und Audit-Zwecke.
