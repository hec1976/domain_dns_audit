# domain_dns_audit

> **English summary**  
> `domain_dns_audit` is a Perl-based DNS audit tool for mail domains.  
> It checks **MX, SPF, DMARC (incl. RUA & external authorization)** and **DKIM**,  
> validates results against **profile-based policies**, and generates a structured  
> **JSON report** for monitoring, security audits, compliance checks and migrations.

---

## 🇩🇪 Übersicht

`domain_dns_audit` ist ein leistungsfähiges DNS-Audit-Tool zur automatisierten Prüfung von Mail-Domain-Konfigurationen.  
Es analysiert **MX, SPF, DMARC und DKIM**, wendet **regelbasierte Profile** an und erzeugt einen strukturierten **JSON-Report** für Monitoring-Systeme, Security-Audits oder Mail-Migrationsprojekte.

### ✨ Hauptfunktionen

- **MX-Analyse** mit Profilen & Gruppen (mehrere MX-Layouts möglich)  
- **SPF-Analyse** inkl. Modusbewertung (hard, soft, neutral, open, none)  
- **DMARC-Analyse**  
  - Fallback auf Organizational Domain (Public Suffix Logik)  
  - Prüfung von `rua=` (lokal vs. extern)  
  - Validierung externer RUA-Provider über `_report._dmarc.<domain>`  
- **DKIM-Analyse**  
  - mehrere Selector  
  - CNAME-Auflösung  
  - Pflichtteile im DKIM-TXT  
  - Profilbasiertes Bewertungsmodell  
- **LDAP-Integration** für Domain-Ermittlung (optional)  
- **JSON-Report** mit detaillierter Struktur & Gesamtstatus  
- **Logging & Exitcodes** für automatisches Monitoring

---

## 📦 Dokumentation

- **Konfigurationshandbuch**  
  👉 [`domain_dns_config_README.md`](./domain_dns_config_README.md)

- **Beispielkonfiguration**  
  👉 [`domain_dns_audit.json.example`](./domain_dns_audit.json.example)

---

## 🚀 Kurzes Beispiel

```bash
perl domain_dns_audit.pl --config ./domain_dns_audit.json
```

JSON-Output liegt danach unter:

```
/var/log/mmbb/domain_dns_audit.json
```

---

## 🔧 Typische Anwendungsfälle

- E-Mail Security Audits (MX/SPF/DMARC/DKIM)
- Vorbereitung oder Kontrolle von DMARC-Rollouts
- Monitoring & Alerting (Nagios/Checkmk/Prometheus via JSON)
- Mail-Migrationen & Domain-Inventare
- Security-Compliance (z. B. Richtlinien für SPF/DMARC/DKIM)

---

## 📄 Lizenz

MIT License (siehe LICENSE)
