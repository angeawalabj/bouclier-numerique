# Jour 14 — Cookie Consent Manager Conforme CNIL

JS vanilla ES6 · Backend Python · CNIL délibération 2020-091

---

## Problème résolu

Google a été condamné à 150 M€ par la CNIL en 2022 parce que le bouton "Refuser" était moins accessible que "Accepter". Facebook : 60 M€. Amazon : 35 M€. Toutes ces amendes pour des problèmes d'implémentation de bandeau cookies, pas pour l'absence de bandeau en soi.

Ce module génère un bandeau conforme qui bloque réellement les scripts tiers avant consentement (pas juste visuellement — au niveau réseau), garde une preuve de chaque choix, et journalise les retraits.

---

## Usage

```bash
# Backend Python : simulation de consentements + stats + génération JS
python cookie_consent.py demo

# Générer le JS de la bannière à intégrer sur un site
python cookie_consent.py generate --site "Mon Site" --dpo dpo@monsite.fr --output cookie-consent.js
```

```html
<!-- Intégration en 1 ligne -->
<script src="cookie-consent.js"></script>
<!-- Le bandeau apparaît automatiquement si pas de consentement valide -->
```

Ouvrir `cookie_consent_demo.html` dans un navigateur pour voir la bannière interactive complète (indépendante du script Python).

---

## Fonctionnalités

- Boutons "Accepter" et "Refuser" équitables (exigence CNIL 2020-091)
- Blocage réel des scripts avant consentement (interception de XHR, fetch et `document.createElement`)
- Catégories : nécessaire (exempté), analytique, marketing, fonctionnel
- Preuve de consentement : timestamp + IP hashée + user-agent hashé + choix par catégorie
- Retrait aussi simple que l'octroi (Art. 7(3) RGPD)
- Expiration à 180 jours (recommandation CNIL)

---

## Conformité

ePrivacy Art. 5§3 · RGPD Art. 6(1)(a) · CNIL délibération 2020-091

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 14/30_
