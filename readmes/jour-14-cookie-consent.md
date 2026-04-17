# 🍪 Jour 14 — Cookie Consent Manager Conforme CNIL

<div align="center">

![JS](https://img.shields.io/badge/JS-Vanilla+ES6+-yellow?style=flat-square&logo=javascript?style=flat-square)
![Python](https://img.shields.io/badge/Python-Backend-3776AB?style=flat-square&logo=python)
![CNIL](https://img.shields.io/badge/CNIL-Délibération+2020--091-ff3b3b?style=flat-square)

</div>

---

## 🎯 Problème résolu

Google a été condamné à **150 M€** par la CNIL en 2022 parce que le bouton "Refuser" était moins accessible que "Accepter". Facebook : 60 M€. Amazon : 35 M€. Toutes ces amendes pour des problèmes d'implémentation de bandeau cookies.

Ce module fournit un bandeau conforme avec tracking réel des consentements, blocage des scripts tiers, et piste d'audit pour les contrôles CNIL.

---

## ⚡ Usage

```html
<!-- Intégration en 2 lignes -->
<script src="cookie-consent.js"></script>
<!-- Le bandeau apparaît automatiquement si pas de consentement valide -->
```
```bash
# Backend Python (stockage et audit)
python cookie_consent.py demo

# Statistiques de consentement
python cookie_consent.py stats --campaign CAMP-2026-Q1
```

---

## ✨ Fonctionnalités

- Boutons 'Accepter' et 'Refuser' équitables (exigence CNIL 2020-091)
- Blocage réel des scripts avant consentement (XHR + createElement intercept)
- 5 catégories : Nécessaires, Analytique, Marketing, Fonctionnel, Social
- Preuve de consentement : timestamp + IP hash + user-agent + choix
- Retrait aussi simple que l'octroi (Art. 7.3 RGPD)
- Expiration 6 mois avec renouvellement automatique

---

## ⚖️ Conformité

ePrivacy Art. 5§3 · RGPD Art. 6(1)(a) · CNIL délibération 2020-091

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 14/30_
