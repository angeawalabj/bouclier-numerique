# 🔍 Jour 29 — Threat Intelligence Feed (STIX 2.1)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![STIX](https://img.shields.io/badge/STIX-2.1-e74c3c?style=flat-square)
![Sources](https://img.shields.io/badge/AbuseCH%20·%20OpenPhish%20·%20CIRCL%20CVE-3%20sources-00e5a0?style=flat-square)

**Collecte, normalise et exporte des IoC depuis des sources publiques en STIX 2.1.**

```bash
python3 threat_intel.py demo
python3 threat_intel.py collect --db /opt/ti.db --output rapport.html
python3 threat_intel.py lookup 185.234.219.47 --db /opt/ti.db
```

Sources : AbuseCH/Feodo (IPs C2), URLhaus (URLs malware), OpenPhish (phishing), CIRCL CVE (vulnérabilités). Base SQLite avec déduplication, scoring de confiance, export STIX 2.1 bundle + CSV. Intégrable avec firewall/SIEM/EDR. Conformité MITRE ATT&CK · ISO 27001 A.12.6.

---
_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 29/30_
