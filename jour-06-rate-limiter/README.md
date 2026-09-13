# 🚦 Jour 06 — Rate Limiter & Pare-feu Applicatif

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Algorithm](https://img.shields.io/badge/Algorithm-Token+Bucket+·+Sliding+Window-00e5a0?style=flat-square)
![Protection](https://img.shields.io/badge/Protection-DDoS+·+Brute+Force-ff3b3b?style=flat-square)

</div>

---

## 🎯 Problème résolu

Une API sans rate limiting est une cible parfaite pour le brute force (mots de passe), le credential stuffing (listes de comptes volés), et les attaques DDoS de couche 7. Ce rate limiter bloque automatiquement les sources abusives.

**Cas réel** : en 2022, une API de vérification d'emails sans rate limiting a permis à un attaquant d'énumérer 2 millions de comptes en 48 heures.

---

## ⚡ Usage

```bash
# Démo avec simulation d'attaque
python rate_limiter.py demo

# Lancer le middleware (intégration Flask/FastAPI)
python rate_limiter.py server --port 8080

# Vérifier le statut d'une IP
python rate_limiter.py status 192.168.1.100
```

---

## ✨ Fonctionnalités

- Token Bucket : lissage des pics de trafic légitime
- Sliding Window : précision sur les fenêtres glissantes
- Blocklist automatique avec durée configurable
- Whitelist pour IPs internes
- Middleware Python (décorateur `@rate_limit`)
- Tableau de bord des requêtes bloquées

---

## ⚖️ Conformité

OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 06/30_
