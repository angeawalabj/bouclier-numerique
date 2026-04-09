# 🕵️ Jour 24 — Crawler OSINT

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Sources](https://img.shields.io/badge/Sources-DNS·SSL·crt.sh·Headers-0078d4?style=flat-square)
![Legal](https://img.shields.io/badge/Légal-Données%20publiques-00e5a0?style=flat-square)

**En 30 secondes, un attaquant cartographie votre domaine. Faites-le avant lui.**  
DNS · SPF/DMARC · Certificats CT logs · Sous-domaines · Headers HTTP

</div>

---

## 🎯 Problème résolu

L'OSINT est la première étape de tout test d'intrusion. Ce scanner collecte toutes les informations publiques sur votre domaine : sous-domaines exposés via les CT logs, configuration email anti-phishing, headers révélant vos technologies.

```bash
python3 osint_crawler.py scan votre-domaine.fr
python3 osint_crawler.py scan votre-domaine.fr --output rapport.html
python3 osint_crawler.py demo
```

## 🔬 Sources exploitées (100% légal)

| Source | Ce qu'on collecte |
|--------|------------------|
| **DNS** | A, MX, NS, TXT, SPF, DMARC |
| **crt.sh (CT logs)** | Tous les sous-domaines des certificats SSL |
| **SSL direct** | Validité, expiration, SANs, émetteur |
| **Headers HTTP** | Server, X-Powered-By, headers de sécurité |

## ⚠️ Ce que l'absence de DMARC permet

Sans DMARC, n'importe qui peut envoyer un email avec `From: direction@votre-domaine.fr` et il sera livré normalement. C'est ainsi que fonctionnent 90% des attaques de phishing ciblé (spear phishing).

## ⚖️ Conformité

| Référentiel | Lien |
|------------|------|
| **ISO 27001 A.18.1.4** | Identification des actifs exposés |
| **RGPD Art. 32** | Évaluation de la surface d'attaque |
| **ANSSI** | Hygiène informatique — maîtrise du SI exposé |

---
_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 24/30_
