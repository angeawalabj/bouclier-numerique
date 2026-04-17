# 💧 Jour 03 — Détecteur de Fuites Have I Been Pwned

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Protocol](https://img.shields.io/badge/Protocol-k--anonymity+·+SHA--1-00e5a0?style=flat-square)
![RGPD](https://img.shields.io/badge/RGPD-Art.+33-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

**8 milliards** de credentials ont été exposés dans des violations de données. Votre email est probablement dedans. Ce détecteur interroge l'API Have I Been Pwned sans jamais envoyer votre mot de passe ou email en clair.

**Propriété de k-anonymity** : seuls les 5 premiers caractères du hash SHA-1 sont transmis. Le serveur renvoie ~500 hashes correspondants. La comparaison finale se fait localement. HIBP ne sait jamais quel mot de passe vous vérifiez.

---

## ⚡ Usage

```bash
pip install requests

# Vérifier un email
python leak_detector.py check email@exemple.fr

# Vérifier un mot de passe (k-anonymity)
python leak_detector.py check-password --stdin

# Vérifier une liste d'emails
python leak_detector.py bulk emails.txt

# Démo
python leak_detector.py demo
```

---

## ✨ Fonctionnalités

- k-anonymity : votre mot de passe n'est jamais transmis
- Vérification email : base 12 milliards de comptes compromis
- Vérification mot de passe : 700 millions de hashes
- Traitement par lot pour audits RH/IT
- Score de risque et recommandations de remédiation

---

## ⚖️ Conformité

RGPD Art. 33 — obligation de notification en cas de violation

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 03/30_
