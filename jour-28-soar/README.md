# 🤖 Jour 28 — SOAR — Réponse Automatisée aux Incidents

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![ISO](https://img.shields.io/badge/ISO%2027001-A.16-0078d4?style=flat-square)
![RGPD](https://img.shields.io/badge/RGPD-Art.%2033%20automatisé-ff3b3b?style=flat-square)

**7 incidents, 62 actions, <100ms. Sans SOAR : 7 × 30min d'analyse manuelle.**

```bash
python3 soar.py demo
python3 soar.py simulate --type phishing --severity CRITIQUE --ip 185.23.4.5
```

7 playbooks intégrés : brute_force, phishing, malware, data_exfiltration, credential_stuffing, sql_injection, dos. Chaque playbook : enrichissement IP, actions automatiques (block/quarantine/lock/reset), ticket ITSM, notification DPO si données personnelles exfiltrées. Conformité ISO 27001 A.16 · RGPD Art.33/34 · NIS2 Art.23.

---
_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 28/30_
