# 🛡️ Le Bouclier Numérique — 30-Day Cybersecurity Challenge

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-RGPD%20%7C%20ISO%2027001%20%7C%20ANSSI-00e5a0?style=flat-square)
![Days](https://img.shields.io/badge/Progress-20%2F30%20jours-f5a623?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Language](https://img.shields.io/badge/Langue-Français-blue?style=flat-square)

**Un outil de cybersécurité opérationnel par jour, pendant 30 jours.**  
Chiffrement · RGPD · Détection d'intrusion · E2EE · Red Team · Résilience

[Voir les outils →](#-outils-par-semaine) · [Démarrage rapide →](#-démarrage-rapide) · [Conformité →](#-conformité-réglementaire)

</div>

---

## 🎯 Concept

**Le Bouclier Numérique** est un challenge de sécurité informatique pratique : un outil fonctionnel, documenté et prêt à l'emploi, chaque jour pendant 30 jours. Chaque outil répond à un problème concret rencontré par les équipes IT, RSSI et DPO.

> **Philosophie** : pas de théorie sans pratique. Chaque jour produit du code qui tourne, des démos qui prouvent, et des explications qui enseignent.

**Couverture technique :**
- 🔐 Cryptographie appliquée (AES-256-GCM, X25519, HKDF, scrypt)
- 📋 Conformité RGPD (Art. 6, 17, 28, 30, 32, 33, 34)
- 🕵️ Détection d'intrusion (HIDS/FIM, honeypot, analyseur de logs)
- 🌐 Sécurité réseau (rate limiting, scanner, pare-feu applicatif)
- 🧪 Sensibilisation (phishing simulation, formation utilisateurs)
- 📈 Gouvernance (PCA/BCP, tableau de bord RSSI, registres)

---

## 🗂️ Outils par Semaine

### Semaine 1 — Fondations de Sécurité

| Jour | Outil | Technologie clé | Statut |
|------|-------|-----------------|--------|
| [J01](./jour-01-password-vault/) | 🔑 Coffre-fort mots de passe | scrypt · AES-256-GCM | ✅ |
| [J02](./jour-02-exif-cleaner/) | 🖼️ Nettoyeur de métadonnées EXIF | Pillow · piexif | ✅ |
| [J03](./jour-03-leak-detector/) | 💧 Détecteur de fuites (HIBP) | k-anonymity · SHA-1 | ✅ |
| [J04](./jour-04-file-vault/) | 🗄️ Chiffrement de fichiers AES-256 | AES-256-GCM · PBKDF2 | ✅ |
| [J05](./jour-05-permission-audit/) | 🔍 Auditeur de permissions | stat · os.walk | ✅ |

### Semaine 2 — Sécurité Réseau

| Jour | Outil | Technologie clé | Statut |
|------|-------|-----------------|--------|
| [J06](./jour-06-rate-limiter/) | 🚦 Rate Limiter / Pare-feu | Token bucket · SQLite | ✅ |
| [J07](./jour-07-honeypot/) | 🍯 Honeypot multi-protocoles | asyncio · socket | ✅ |
| [J08](./jour-08-immutable-backup/) | 💾 Backup chiffré immuable | WORM · SHA-256 | ✅ |
| [J09](./jour-09-log-anonymizer/) | 📝 Anonymiseur de logs RGPD | pseudonymisation · regex | ✅ |
| [J10](./jour-10-port-scanner/) | 🔭 Scanner de ports réseau | asyncio · socket · CVE | ✅ |

### Semaine 3 — Conformité RGPD

| Jour | Outil | Technologie clé | Statut |
|------|-------|-----------------|--------|
| [J11](./jour-11-right-to-erasure/) | 🗑️ Droit à l'effacement (Art. 17) | Multi-source · audit trail | ✅ |
| [J12](./jour-12-treatment-registry/) | 📋 Registre des traitements (Art. 30) | SQLite · HTML · DOCX | ✅ |
| [J13](./jour-13-data-masking/) | 🎭 Data Masking RBAC | 4 rôles · 7 types · proxy | ✅ |
| [J14](./jour-14-cookie-consent/) | 🍪 Cookie Consent Manager (CNIL) | JS · XHR intercept · CNIL | ✅ |
| [J15](./jour-15-dependency-audit/) | 🔎 Audit CVE des dépendances | OSV.dev · CVSS · CI/CD | ✅ |
| ➕ | 📄 Générateur DPA (Art. 28) | DOCX · jinja2 | ✅ bonus |

### Semaine 4 — Résilience & Gestion de Crise

| Jour | Outil | Technologie clé | Statut |
|------|-------|-----------------|--------|
| [J16](./jour-16-phishing-sim/) | 🎣 Simulation de Phishing | SMTP · tracking · éducation | ✅ |
| [J17](./jour-17-ids-hids/) | 👁️ Détecteur d'Infiltration HIDS | SHA-256 · FIM · inotify | ✅ |
| [J18](./jour-18-e2ee/) | 🔒 Messagerie E2EE | X25519 · HKDF · AES-GCM | ✅ |
| [J19](./jour-19-pca/) | 📖 Plan de Continuité (PCA/BCP) | RTO/RPO · ISO 22301 | ✅ |
| [J20](./jour-20-rssi-dashboard/) | 📊 Tableau de Bord RSSI | HTML · JS · SOC UI | ✅ |

### Semaine 5 — Red Team & Offensif _(à venir)_

| Jour | Outil prévu | Statut |
|------|-------------|--------|
| J21 | 🧪 Fuzzer d'API automatique | 🔜 |
| J22 | 💉 Scanner d'injections SQL/XSS | 🔜 |
| J23 | 🔓 Craqueur de hachages (éthique) | 🔜 |
| J24 | 🕸️ Crawler de reconnaissance OSINT | 🔜 |
| J25 | ⚔️ Rapport de pentest automatique | 🔜 |

### Semaine 6 — Architecture & Finalisation _(à venir)_

| Jour | Outil prévu | Statut |
|------|-------------|--------|
| J26 | 🏗️ Zero Trust Access Controller | 🔜 |
| J27 | 🔑 PKI & gestion de certificats | 🔜 |
| J28 | 🤖 SOAR — Réponse automatisée | 🔜 |
| J29 | 📡 Threat Intelligence Feed | 🔜 |
| J30 | 🏆 Suite complète intégrée | 🔜 |

---

## ⚡ Démarrage Rapide

### Prérequis

```bash
Python >= 3.10
pip install cryptography pillow requests sqlite3
```

### Installation

```bash
git clone https://github.com/votre-username/bouclier-numerique.git
cd bouclier-numerique
pip install -r requirements.txt
```

### Lancer une démo

Chaque outil est autonome et dispose d'un mode `demo` :

```bash
# Coffre-fort mots de passe
python jour-01-password-vault/password_vault.py demo

# Détecteur de fuites
python jour-03-leak-detector/leak_detector.py check email@exemple.fr

# Honeypot
python jour-07-honeypot/honeypot.py --ports 22,80,3306

# Audit CVE
python jour-15-dependency-audit/dependency_audit.py audit . --block-on CRITICAL

# IDS / File Integrity Monitor
python jour-17-ids-hids/ids_monitor.py demo
```

---

## 🔬 Aperçu Technique

### Algorithmes cryptographiques utilisés

| Algorithme | Usage | Norme |
|-----------|-------|-------|
| AES-256-GCM | Chiffrement symétrique authentifié | NIST SP 800-38D |
| scrypt | Dérivation de mot de passe | RFC 7914 |
| X25519 (ECDH) | Échange de clés E2EE | RFC 7748 |
| HKDF-SHA256 | Dérivation de clés secondaires | RFC 5869 |
| SHA-256 | Intégrité, fingerprint, FIM | FIPS 180-4 |

### Architecture des outils

```
bouclier-numerique/
├── jour-01-password-vault/
│   ├── password_vault.py      # Outil principal
│   └── README.md              # Documentation
├── jour-07-honeypot/
│   ├── honeypot.py
│   └── README.md
├── ...
└── jour-20-rssi-dashboard/
    ├── rssi_dashboard.html    # Dashboard interactif
    └── README.md
```

---

## ⚖️ Conformité Réglementaire

| Référentiel | Articles couverts | Score |
|-------------|------------------|-------|
| **RGPD** | Art. 6, 17, 25, 28, 30, 32, 33, 34 | 86/100 |
| **ISO 27001** | A.9, A.10, A.12, A.13, A.17, A.18 | 82/100 |
| **ANSSI RGS** | Crypto · Journalisation · Continuité | 79/100 |
| **PCI-DSS** | 3.4, 6.3.3, 10.5.5 | 71/100 |
| **NIS2** | Art. 21 · Chiffrement · Résilience | 68/100 |

---

## 📚 Ressources & Références

- [ANSSI — Guide d'hygiène informatique](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/)
- [CNIL — Recommandations techniques](https://www.cnil.fr/fr/securite-des-donnees)
- [OWASP Top 10](https://owasp.org/Top10/)
- [OSV.dev — Vulnerability Database](https://osv.dev/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [No More Ransom Project](https://www.nomoreransom.org/fr/)

---

## 🤝 Contribuer

Les contributions sont bienvenues ! Consultez [CONTRIBUTING.md](./CONTRIBUTING.md) pour les guidelines.

```bash
git checkout -b feature/jour-21-api-fuzzer
# Votre outil ici
git commit -m "feat(j21): ajout fuzzer API automatique"
git push origin feature/jour-21-api-fuzzer
```

---

## 📄 Licence

MIT License — voir [LICENSE](./LICENSE)

---

<div align="center">

**Construit pour apprendre · Documenté pour partager · Testé pour protéger**

⭐ Si ce projet vous a été utile, une étoile est appréciée !

</div>
