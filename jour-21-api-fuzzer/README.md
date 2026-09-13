# 🕷️ Jour 21 — Fuzzer d'API Automatique (OWASP API Top 10)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-e74c3c?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-API1%20→%20API10-f39c12?style=flat-square)
![Legal](https://img.shields.io/badge/Usage-Vos%20APIs%20uniquement-27ae60?style=flat-square)

**Une API non testée est une API vulnérable. Ce fuzzer le prouve en quelques secondes.**  
IDOR · SQLi · SSRF · JWT bypass · Rate limiting · Headers · Endpoints cachés · Rapport HTML

</div>

---

## 🎯 Problème résolu

Les APIs REST modernes concentrent la quasi-totalité des vulnérabilités applicatives. L'OWASP API Security Top 10 montre que les mêmes failles se retrouvent dans 90% des audits : IDOR (accès aux données d'autres utilisateurs), absence de rate limiting, JWT mal vérifiés, endpoints d'administration oubliés...

```
Exemple réel — Twitter 2022 : IDOR sur /api/users permettait
d'énumérer 5,4 millions de comptes via des IDs séquentiels.
→ RGPD Art. 33 : notification CNIL sous 72h obligatoire
→ Amende potentielle : millions d'euros

Ce fuzzer aurait détecté cette faille en < 30 secondes.
```

---

## ⚡ Démarrage rapide

```bash
# Démonstration sur une API vulnérable locale (aucune installation requise)
python3 api_fuzzer.py demo

# Scanner votre propre API
python3 api_fuzzer.py scan https://api.monapp.com \
  --token "mon-token-jwt" \
  --endpoint /api/v1/users/1 \
  --endpoint /api/v1/login \
  --output rapport_pentest.html

# Rate limité pour éviter de saturer la cible
python3 api_fuzzer.py scan https://api.monapp.com --rate 0.5
```

---

## 🔬 Architecture du moteur de fuzzing

```
ApiFuzzer
├── Reconnaissance
│   ├── test_security_headers()   → API8 : X-Frame, HSTS, CSP...
│   └── test_hidden_endpoints()   → API9 : /admin, /debug, /swagger...
│
├── Authentification & Autorisation
│   ├── test_auth()               → API2 : alg:none, token absent
│   ├── test_idor()               → API1 : ID manipulation
│   └── test_http_methods()       → API5 : PUT/DELETE non restreints
│
├── Injections
│   ├── test_injections()         → API10 : SQLi, XSS, Path Traversal
│   └── test_ssrf()               → API7 : AWS metadata, localhost...
│
└── Ressources
    └── test_rate_limiting()      → API4 : absence de limite
```

**Bibliothèque de payloads :** 60+ payloads couvrant SQLi, XSS, SSRF, Path Traversal, JWT attacks, IDOR enumeration.

---

## 📊 Rapport HTML généré

Le rapport inclut pour chaque vulnérabilité :
- Sévérité (Critique / Élevée / Modérée / Faible) avec score global /100
- Catégorie OWASP API Top 10 précise
- Preuve technique (payload + réponse serveur)
- **Remédiation actionnable** avec référence à l'article RGPD/ISO correspondant
- URL exacte affectée + timestamp

---

## ⚠️ Usage légal

> Ce fuzzer effectue de vraies requêtes HTTP contre la cible. **Ne l'utilisez que sur :**
> - Vos propres APIs en développement ou staging
> - Des environnements de test dédiés
> - Des cibles pour lesquelles vous avez une **autorisation écrite** explicite

Utilisation non autorisée : **Art. L323-1 Code pénal** — jusqu'à 2 ans et 60 000 €.

---

## ⚖️ Conformité

| Référentiel | Lien |
|------------|------|
| **OWASP API Security Top 10 2023** | Couverture complète API1→API10 |
| **ISO 27001 A.14.2.8** | Tests de sécurité des systèmes |
| **RGPD Art. 32** | Évaluation régulière des mesures de sécurité |
| **ANSSI** | Guide de tests d'intrusion |

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 21/30 · Semaine 5 — Red Team_
