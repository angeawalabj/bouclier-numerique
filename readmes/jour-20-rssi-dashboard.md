# 📊 Jour 20 — Tableau de Bord RSSI — SOC Dashboard

<div align="center">

![HTML](https://img.shields.io/badge/HTML-Vanilla+JS-f5a623?style=flat-square&logo=html5?style=flat-square)
![Design](https://img.shields.io/badge/Design-SOC+Terminal+·+Dark+UI-00e5a0?style=flat-square)
![Live](https://img.shields.io/badge/Live-Alertes+temps+réel-ff3b3b?style=flat-square)

</div>

---

## 🎯 Problème résolu

Un RSSI doit piloter 19 outils de sécurité simultanément. Sans tableau de bord centralisé, il navigue entre 19 fenêtres différentes, rate les alertes critiques, et ne peut pas présenter une vue globale à la direction. Ce dashboard agrège tous les indicateurs en un seul écran de pilotage.

---

## ⚡ Usage

Ouvrir `rssi_dashboard.html` dans un navigateur.

Aucune dépendance. Aucun serveur. Fonctionne offline.

Pour intégrer des données réelles, modifier la section `DATA` dans le JavaScript :
```javascript
const MODULES = [
  { id:1, name:'Coffre-fort', status:'ok', metric:'1247', ... },
  // Connecter à vos APIs réelles ici
];
```

---

## ✨ Fonctionnalités

- Score RSSI global animé (jauge SVG)
- 19 modules avec statut temps réel et sparklines 7 jours
- Journal d'alertes live (nouvelle alerte toutes les 7s)
- Barres de conformité : ISO 27001, RGPD, PCI-DSS, NIS2, ANSSI
- 4 CVE critiques actionnables (du Jour 15)
- Heatmap d'activité sur 30 jours
- Carte des menaces avec pulses animés

---

## ⚖️ Conformité

Tableau de bord de pilotage conforme ISO 27001 A.18.2

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 20/30_
