# 🔐 Jour 26 — Zero Trust Access Controller

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![NIST](https://img.shields.io/badge/NIST-SP%20800--207-0078d4?style=flat-square)
![Algo](https://img.shields.io/badge/RBAC%20+%20Trust%20Score%20+%20mTLS-implémenté-00e5a0?style=flat-square)

**"Never Trust, Always Verify" — implémenté en Python.**

```bash
python3 zero_trust.py demo
python3 zero_trust.py check --user alice --resource /admin/dashboard --action read
```

Score de confiance dynamique (0-100) calculé sur : identité vérifiée, appareil enregistré, réseau, heure, comportement historique. Décisions : ALLOW / DENY / STEP_UP (MFA requis). Conformité NIST SP 800-207 · NIST CSF PR.AC.

---
_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 26/30_
