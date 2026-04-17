# 💉 Jour 22 — Scanner d'Injections Web (OWASP A03)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![OWASP](https://img.shields.io/badge/OWASP-A03%3A2021%20Injection-e74c3c?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-SQLi·XSS·SSTI·CMDi-f39c12?style=flat-square)

**Les injections représentent 34% des vulnérabilités critiques en 2023. Ce scanner les détecte automatiquement.**
Crawl HTML · SQLi error+time-based · XSS réfléchi · SSTI · Command Injection · Rapport HTML

---

## 🎯 Problème résolu

OWASP A03:2021 — Injection est la 3e vulnérabilité la plus répandue. Une seule injection SQL non détectée peut mener à l'exfiltration complète de la base de données. Ce scanner automatise ce que ferait un pentesteur lors de la phase de test des entrées.

```bash
# Démonstration sur app vulnérable locale (Flask auto-démarré)
python3 injection_scanner.py demo

# Scanner votre app
python3 injection_scanner.py scan https://app.monentreprise.com

# Tester un paramètre spécifique
python3 injection_scanner.py scan https://app.com --param "https://app.com/search?q=test"
```

---

## 🔬 Techniques de détection

| Technique | Méthode | Signature |
|-----------|---------|-----------|
| **SQLi error-based** | Injection de `'` et opérateurs | Message d'erreur MySQL/PostgreSQL dans la réponse |
| **SQLi time-based** | `SLEEP(3)` / `pg_sleep(3)` | Latence mesurée > baseline + 2s |
| **XSS réfléchi** | Marqueur unique `BNUMxxxxxx` | Marqueur retrouvé non-encodé dans le DOM |
| **SSTI** | `{{7*7}}` / `${7*7}` | `49` dans la réponse |
| **Command Injection** | `; id` / `$(id)` | `uid=` ou `root:` dans la réponse |

---

## ✨ Fonctionnalités

- **Crawl automatique** des formulaires HTML (GET et POST) via HTMLParser stdlib
- **60+ payloads** couvrant 5 types d'injection
- App de démonstration Flask volontairement vulnérable intégrée
- Rapport HTML avec score de sécurité, preuves et remédiations actionnables
- Mode CI/CD avec exit code 1 si vulnérabilité critique

---

## ⚖️ Conformité

| Référentiel | Couverture |
|------------|-----------|
| **OWASP A03:2021** | Injection — SQLi, XSS, SSTI, CMDi |
| **ISO 27001 A.14.2.8** | Tests de sécurité des systèmes |
| **RGPD Art. 32** | Évaluation de la sécurité des traitements |

---
_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 22/30_
