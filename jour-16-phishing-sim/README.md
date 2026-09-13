# 🎣 Jour 16 — Simulation de Phishing & Formation

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Ethics](https://img.shields.io/badge/Ethics-Usage+interne+uniquement-00e5a0?style=flat-square)
![ANSSI](https://img.shields.io/badge/ANSSI-Mesure+42-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

**91% des cyberattaques commencent par un email de phishing**. La meilleure défense : entraîner régulièrement vos utilisateurs à reconnaître les signaux d'alerte. Ce simulateur crée de vraies campagnes internes, trackle les clics, et redirige immédiatement vers une page éducative qui explique les erreurs commises.

⚠️ Usage exclusivement interne avec accord DRH écrit. Usage malveillant = délit (Art. 323-1 Code pénal).

---

## ⚡ Usage

```bash
# Démo complète (12 utilisateurs simulés)
python phishing_sim.py demo

# Créer une campagne
python phishing_sim.py create --template reset_password --company "Mon Entreprise"

# Rapport de la campagne
python phishing_sim.py report --campaign CAMP-20260312-A1B2C3

# Lancer le serveur de tracking
python phishing_sim.py server --port 8765
```

---

## ✨ Fonctionnalités

- 5 templates : reset_password, it_security, hr_document, invoice, shared_file
- Token unique par destinataire (tracking individuel)
- Page d'éducation interactive avec quiz (3 questions, score immédiat)
- Email annoté montrant les 5 signaux d'alerte
- Rapport par département : taux de clic, niveau de risque
- Recommandations de formation ciblées

---

## ⚖️ Conformité

ANSSI mesure 42 — sensibilisation par tests réguliers

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 16/30_
