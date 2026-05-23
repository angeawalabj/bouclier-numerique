# 🛡️ Le Bouclier Numérique — 30-Day Cybersecurity Challenge

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Progress](https://img.shields.io/badge/Challenge-30%2F30%20jours%20✅-00e5a0?style=flat-square)
![Security](https://img.shields.io/badge/Security-RGPD%20%7C%20ISO%2027001%20%7C%20ANSSI-0a0a0a?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Language](https://img.shields.io/badge/Langue-Français-blue?style=flat-square)
![Commits](https://img.shields.io/badge/Commits-109-blueviolet?style=flat-square)

**30 outils de cybersécurité opérationnels. 30 jours. 0 théorie sans pratique.**

Chiffrement · RGPD · Détection d'intrusion · E2EE · Red Team · Résilience · Zero Trust

[Voir les outils →](#️-les-30-outils) · [Démarrage rapide →](#-démarrage-rapide) · [Ce que j'ai appris →](#-ce-que-jai-appris)

*Par [Ange Awala](https://github.com/angeawalabj) · Porto-Novo, Bénin 🇧🇯 · [LinkedIn](https://www.linkedin.com/in/ange-awala-57aa1b363/)*

</div>

---

## 🎯 Pourquoi ce projet existe

La cybersécurité est souvent enseignée en théorie. Des slides, des normes, des acronymes.

Ce challenge part d'un principe différent : **chaque concept de sécurité doit produire du code qui tourne le jour où on l'apprend.**

30 jours. 30 outils fonctionnels, documentés, prêts à être lus et compris. Chaque outil répond à un problème concret rencontré par les équipes IT, RSSI et DPO.

> *"Pas de théorie sans pratique. Chaque jour produit du code qui prouve."*

**Ce que couvre le challenge :**
- 🔐 Cryptographie appliquée — AES-256-GCM, X25519, HKDF, scrypt
- 📋 Conformité RGPD — Art. 6, 17, 25, 28, 30, 32, 33, 34
- 🕵️ Détection d'intrusion — HIDS, FIM, honeypot, analyse de logs
- 🌐 Sécurité réseau — rate limiting, scanner de ports, WAF applicatif
- 🧪 Red Team éthique — fuzzer API, scanner injections, OSINT, pentest
- 🏗️ Architecture avancée — Zero Trust, PKI, SOAR, Threat Intelligence

---

## 🗂️ Les 30 outils

### Semaine 1 — Fondations de Sécurité

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J01](./jour-01-password-vault/) | 🔑 Coffre-fort mots de passe | scrypt · AES-256-GCM |
| [J02](./jour-02-exif-cleaner/) | 🖼️ Nettoyeur de métadonnées EXIF | Pillow · piexif |
| [J03](./jour-03-leak-detector/) | 💧 Détecteur de fuites (HIBP) | k-anonymity · SHA-1 |
| [J04](./jour-04-file-vault/) | 🗄️ Chiffrement de fichiers AES-256 | AES-256-GCM · PBKDF2 |
| [J05](./jour-05-permission-audit/) | 🔍 Auditeur de permissions fichiers | stat · os.walk |

### Semaine 2 — Sécurité Réseau

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J06](./jour-06-rate-limiter/) | 🚦 Rate Limiter / Pare-feu applicatif | Token bucket · SQLite |
| [J07](./jour-07-honeypot/) | 🍯 Honeypot multi-protocoles | asyncio · socket |
| [J08](./jour-08-immutable-backup/) | 💾 Backup chiffré immuable | WORM · SHA-256 |
| [J09](./jour-09-log-anonymizer/) | 📝 Anonymiseur de logs RGPD | pseudonymisation · regex |
| [J10](./jour-10-port-scanner/) | 🔭 Scanner de ports réseau + CVE | asyncio · socket · CVE |

### Semaine 3 — Conformité RGPD

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J11](./jour-11-right-to-erasure/) | 🗑️ Droit à l'effacement (Art. 17) | Multi-source · audit trail |
| [J12](./jour-12-treatment-registry/) | 📋 Registre des traitements (Art. 30) | SQLite · HTML · DOCX |
| [J13](./jour-13-data-masking/) | 🎭 Data Masking RBAC | 4 rôles · 7 types · proxy |
| [J14](./jour-14-cookie-consent/) | 🍪 Cookie Consent Manager (CNIL) | JS · XHR intercept |
| [J15](./jour-15-dependency-audit/) | 🔎 Audit CVE des dépendances | OSV.dev · CVSS · CI/CD |
| [Bonus](./jour-bonus-dpa-generator/) | 📄 Générateur DPA (Art. 28) | DOCX · jinja2 |

### Semaine 4 — Résilience & Gestion de Crise

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J16](./jour-16-phishing-sim/) | 🎣 Simulation de Phishing éducative | SMTP · tracking |
| [J17](./jour-17-ids-hids/) | 👁️ Détecteur d'Infiltration HIDS/FIM | SHA-256 · inotify |
| [J18](./jour-18-e2ee/) | 🔒 Messagerie E2EE | X25519 · HKDF · AES-GCM |
| [J19](./jour-19-pca/) | 📖 Plan de Continuité PCA/BCP | RTO/RPO · ISO 22301 |
| [J20](./jour-20-rssi-dashboard/) | 📊 Tableau de Bord RSSI interactif | HTML · JS · SOC UI |

### Semaine 5 — Red Team & Offensif Éthique

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J21](./jour-21-api-fuzzer/) | 🧪 Fuzzer d'API automatique | aiohttp · payloads |
| [J22](./jour-22-injection-scanner/) | 💉 Scanner SQL/XSS | patterns · requests |
| [J23](./jour-23-hash-cracker/) | 🔓 Craqueur de hachages (éthique) | hashlib · wordlists |
| [J24](./jour-24-osint-crawler/) | 🕸️ Crawler de reconnaissance OSINT | DNS · WHOIS · Shodan |
| [J25](./jour-25-pentest-report/) | ⚔️ Générateur de rapport pentest | DOCX · CVSS · templates |

### Semaine 6 — Architecture & Finalisation

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J26](./jour-26-zero-trust/) | 🏗️ Zero Trust Access Controller | JWT · mTLS · policies |
| [J27](./jour-27-pki/) | 🔑 PKI & gestion de certificats | X.509 · openssl · CA |
| [J28](./jour-28-soar/) | 🤖 SOAR — Réponse automatisée | playbooks · alerting |
| J29 | 📡 Threat Intelligence Feed | STIX · TAXII · feeds |
| [J30](./jour-30-suite-integree/) | 🏆 Suite complète intégrée | Orchestration · CLI |

---

## ⚡ Démarrage Rapide

```bash
git clone https://github.com/angeawalabj/bouclier-numerique.git
cd bouclier-numerique
pip install -r requirements.txt
```

Chaque outil est autonome et dispose d'un mode `demo` :

```bash
# Coffre-fort mots de passe
python jour-01-password-vault/password_vault.py demo

# Honeypot multi-protocoles
python jour-07-honeypot/honeypot.py --ports 22,80,3306

# Audit CVE des dépendances
python jour-15-dependency-audit/dependency_audit.py audit . --block-on CRITICAL

# IDS / File Integrity Monitor
python jour-17-ids-hids/ids_monitor.py demo

# Fuzzer d'API
python jour-21-api-fuzzer/api_fuzzer.py --target https://api.example.com

# Rapport pentest automatique
python jour-25-pentest-report/pentest_report.py generate --format docx
```

---

## 🔬 Cryptographie utilisée

| Algorithme | Usage | Norme |
|-----------|-------|-------|
| AES-256-GCM | Chiffrement symétrique authentifié | NIST SP 800-38D |
| scrypt | Dérivation de mot de passe | RFC 7914 |
| X25519 (ECDH) | Échange de clés E2EE | RFC 7748 |
| HKDF-SHA256 | Dérivation de clés secondaires | RFC 5869 |
| SHA-256 | Intégrité, fingerprint, FIM | FIPS 180-4 |

---

## ⚖️ Conformité couverte

| Référentiel | Articles / Contrôles | Score estimé |
|-------------|---------------------|--------------|
| **RGPD** | Art. 6, 17, 25, 28, 30, 32, 33, 34 | 86/100 |
| **ISO 27001** | A.9, A.10, A.12, A.13, A.17, A.18 | 82/100 |
| **ANSSI RGS** | Crypto · Journalisation · Continuité | 79/100 |
| **PCI-DSS** | 3.4, 6.3.3, 10.5.5 | 71/100 |
| **NIS2** | Art. 21 · Chiffrement · Résilience | 68/100 |

---

## 📖 Ce que j'ai appris

30 jours à coder des outils de sécurité du niveau débutant (coffre-fort) jusqu'au niveau avancé (Zero Trust, SOAR) m'ont appris quelque chose que les cours ne disent pas :

**La sécurité n'est pas une liste de fonctionnalités. C'est une façon de penser.**

Chaque outil m'a forcé à répondre à deux questions : *qu'est-ce qui peut mal tourner ici ?* et *comment est-ce que je le prouve ?*

- Le honeypot (J07) m'a appris que les attaquants sont prévisibles — ils essaient toujours les mêmes ports d'abord.
- Le Data Masking RBAC (J13) m'a appris que l'accès aux données n'est jamais binaire — il y a toujours au moins 4 niveaux.
- Le SOAR (J28) m'a appris que la réponse à incident la plus rapide est celle qu'on a planifiée avant l'incident.

> Tout le code est commenté ligne par ligne. Pas de magie noire.

---

## 📚 Références

- [ANSSI — Guide d'hygiène informatique](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/)
- [CNIL — Recommandations techniques](https://www.cnil.fr/fr/securite-des-donnees)
- [OWASP Top 10](https://owasp.org/Top10/)
- [OSV.dev — Vulnerability Database](https://osv.dev/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

---

## 🤝 Contribuer

Les contributions sont bienvenues — correction de bug, amélioration de doc, variante d'outil.

```bash
git checkout -b feature/jour-XX-nom-outil
git commit -m "feat(jXX): description de l'outil"
git push origin feature/jour-XX-nom-outil
```

Voir [CONTRIBUTING.md](./CONTRIBUTING.md) pour les guidelines.

---

## 📄 Licence

MIT — voir [LICENSE](./LICENSE)

---

<div align="center">

**Construit pour apprendre · Documenté pour partager · Testé pour protéger**

*[Ange Awala](https://github.com/angeawalabj) · Porto-Novo, Bénin 🇧🇯 · 2026*

⭐ Si ce projet t'a été utile, une étoile est appréciée !

</div>
