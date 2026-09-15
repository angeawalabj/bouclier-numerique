# Le Bouclier Numérique — 30 jours, 30 outils de cybersécurité

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Langue](https://img.shields.io/badge/Langue-Français-blue?style=flat-square)

**30 outils de cybersécurité et de conformité RGPD, chacun autonome, documenté et utilisable en dehors du challenge.**

Chiffrement · RGPD · Détection d'intrusion · E2EE · Red Team · Résilience · Zero Trust

[Voir les outils →](#les-30-outils) · [Démarrage rapide →](#démarrage-rapide) · [Ce que j'ai appris →](#ce-que-jai-appris)

*Par [Ange Awala](https://github.com/angeawalabj) · Porto-Novo, Bénin · [LinkedIn](https://www.linkedin.com/in/ange-awala-57aa1b363/)*

</div>

---

## Pourquoi ce projet existe

La cybersécurité s'enseigne souvent en théorie — slides, normes, acronymes, peu de code qui tourne réellement.

Ce challenge part d'un principe différent : **chaque concept de sécurité doit produire un outil qui fonctionne le jour où on l'apprend.**

30 jours, 30 outils. Chacun répond à un problème concret rencontré par une équipe IT, un RSSI ou un DPO , un script qu'on peut réellement lancer sur son propre poste, sa propre API, son propre registre de traitements. Là où un outil ne pouvait raisonnablement pas être testé en conditions réelles (parler à un vrai serveur distant, par exemple), le mode `demo` le dit explicitement.

**Ce que couvre le challenge :**
- Cryptographie appliquée — AES-256-GCM, X25519, HKDF, scrypt
- Conformité RGPD — Art. 6, 17, 25, 28, 30, 32, 33, 34
- Détection d'intrusion — HIDS, FIM, honeypot, analyse de logs
- Sécurité réseau — rate limiting, scanner de ports, threat intelligence
- Red Team éthique — fuzzer API, scanner d'injections, OSINT, pentest
- Architecture avancée — Zero Trust, PKI, SOAR, orchestration

---

## Les 30 outils

### Semaine 1 — Fondations de Sécurité

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J01](./jour-01-password-vault/) | Gestionnaire de mots de passe (chiffrement réversible) | scrypt · AES-256-GCM |
| [J02](./jour-02-exif-cleaner/) | Nettoyeur de métadonnées EXIF | Pillow |
| [J03](./jour-03-leak-detector/) | Détecteur de fuites (HIBP) | k-anonymat · SHA-1 |
| [J04](./jour-04-file-vault/) | Chiffrement de fichiers AES-256 | AES-256-GCM · PBKDF2 |
| [J05](./jour-05-permission-audit/) | Auditeur de permissions fichiers | /proc · stat |

### Semaine 2 — Sécurité Réseau

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J06](./jour-06-rate-limiter/) | Rate Limiter / anti brute-force | Fenêtre glissante · SQLite |
| [J07](./jour-07-honeypot/) | Honeypot multi-pièges | Flask · SQLite |
| [J08](./jour-08-immutable-backup/) | Backup immuable anti-ransomware | chattr +i · SHA-256 |
| [J09](./jour-09-log-anonymizer/) | Anonymiseur de logs RGPD | HMAC-SHA256 · regex |
| [J10](./jour-10-port-scanner/) | Scanner de ports réseau | TCP connect · pool de threads |

### Semaine 3 — Conformité RGPD

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J11](./jour-11-right-to-erasure/) | Droit à l'effacement (Art. 17) | Multi-source · audit trail |
| [J12](./jour-12-treatment-registry/) | Registre des traitements (Art. 30) | SQLite · score calculé |
| [J13](./jour-13-data-masking/) | Data Masking RBAC | 4 rôles · proxy transparent |
| [J14](./jour-14-cookie-consent/) | Cookie Consent Manager (CNIL) | JS · interception XHR/fetch |
| [J15](./jour-15-dependency-audit/) | Audit CVE des dépendances | OSV.dev · CVSS · CI/CD |
| [Bonus](./jour-bonus-dpa-generator/) | Générateur de DPA (Art. 28) | python-docx |

### Semaine 4 — Résilience & Gestion de Crise

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J16](./jour-16-phishing-sim/) | Simulation de phishing éducative | SMTP réel · tracking |
| [J17](./jour-17-ids-hids/) | Détection d'intrusion HIDS/FIM | SHA-256 · SQLite |
| [J18](./jour-18-e2ee/) | Messagerie E2EE (relais HTTP réel) | X25519 · HKDF · AES-GCM |
| [J19](./jour-19-pca/) | Plan de Continuité PCA/BCP | python-docx · RTO/RPO |
| [J20](./jour-20-rssi-dashboard/) | Tableau de bord RSSI (mesures réelles) | Python · HTML/JS |

### Semaine 5 — Red Team & Offensif Éthique

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J21](./jour-21-api-fuzzer/) | Fuzzer d'API — OWASP API Top 10 | urllib · payloads |
| [J22](./jour-22-injection-scanner/) | Scanner SQLi/XSS/SSTI | urllib · patterns |
| [J23](./jour-23-hash-cracker/) | Craqueur de hachages (éthique) | hashlib · bcrypt · wordlists |
| [J24](./jour-24-osint-crawler/) | Crawler de reconnaissance OSINT | DNS · crt.sh · RDAP |
| [J25](./jour-25-pentest-report/) | Générateur de rapport pentest | python-docx · CVSS |

### Semaine 6 — Architecture & Finalisation

| Jour | Outil | Technologie clé |
|------|-------|-----------------|
| [J26](./jour-26-zero-trust/) | Contrôleur d'accès Zero Trust | RBAC · trust score |
| [J27](./jour-27-pki/) | PKI & gestion de certificats | openssl · X.509 |
| [J28](./jour-28-soar/) | SOAR — réponse automatisée | playbooks · IoC réels (J29) |
| [J29](./jour-29-threat-intel/) | Threat Intelligence (flux publics réels) | STIX 2.1 · Feodo/URLhaus/CIRCL |
| [J30](./jour-30-suite-integree/) | Orchestrateur — 6 outils enchaînés réellement | intégration inter-outils |

---

## Démarrage Rapide

```bash
git clone https://github.com/angeawalabj/bouclier-numerique.git
cd bouclier-numerique
pip install -r requirements.txt
```

Chaque outil est autonome et dispose d'un mode `demo` sans configuration :

```bash
# Gestionnaire de mots de passe — récupération réelle du secret
python jour-01-password-vault/password_vault.py demo

# Honeypot multi-pièges
python jour-07-honeypot/honeypot.py server

# Audit CVE des dépendances (requête OSV.dev en direct)
python jour-15-dependency-audit/dependency_audit.py audit . --block-on CRITICAL

# HIDS / File Integrity Monitor
python jour-17-ids-hids/ids_monitor.py demo

# Fuzzer d'API contre une cible réelle
python jour-21-api-fuzzer/api_fuzzer.py scan https://api.exemple.com

# Rapport de pentest (HTML + DOCX)
python jour-25-pentest-report/pentest_report.py generate "Mon Application" --docx rapport.docx

# Orchestrateur — 6 outils exécutés en séquence sur ce poste
python jour-30-suite-integree/suite_integree.py demo
```

Chaque `README.md` de dossier documente l'usage complet, y compris les
commandes pour un usage réel au-delà du mode démo.

---

## Cryptographie utilisée

| Algorithme | Usage | Norme |
|-----------|-------|-------|
| AES-256-GCM | Chiffrement symétrique authentifié | NIST SP 800-38D |
| scrypt | Dérivation de mot de passe | RFC 7914 |
| X25519 (ECDH) | Échange de clés E2EE | RFC 7748 |
| HKDF-SHA256 | Dérivation de clés secondaires | RFC 5869 |
| SHA-256 | Intégrité, empreinte, FIM | FIPS 180-4 |

---

## Conformité couverte

| Référentiel | Articles / Contrôles |
|-------------|---------------------|
| **RGPD** | Art. 6, 17, 25, 28, 30, 32, 33, 34 |
| **ISO 27001** | A.9, A.10, A.12, A.13, A.17, A.18 |
| **ANSSI RGS** | Cryptographie, journalisation, continuité |
| **PCI-DSS** | 3.4, 6.3.3, 10.5.5 |
| **NIS2** | Art. 21 — chiffrement, résilience |

Le Jour 12
(registre des traitements) et le Jour 20 (tableau de bord) calculent
chacun un score réel à partir de données qu'ils mesurent effectivement ;
voir leurs README respectifs pour la méthode de calcul.

---

## Ce que j'ai appris

30 jours à coder des outils de sécurité, du niveau débutant (gestionnaire de mots de passe) au niveau avancé (Zero Trust, SOAR), m'ont appris quelque chose que les cours ne disent pas :

**La sécurité n'est pas une liste de fonctionnalités. C'est une façon de penser.**

Chaque outil m'a forcé à répondre à deux questions : *qu'est-ce qui peut mal tourner ici ?* et *comment est-ce que je le prouve ?*

- Le honeypot (J07) m'a appris que les attaquants sont prévisibles, ils essaient toujours les mêmes chemins d'abord (`/wp-admin`, `/.env`, `/phpmyadmin`).
- Le Data Masking RBAC (J13) m'a appris que l'accès aux données n'est jamais binaire, il y a toujours au moins 4 niveaux entre "tout voir" et "rien voir".
- Le SOAR (J28) m'a appris que la réponse à incident la plus rapide est celle qu'on a planifiée avant l'incident, et qu'un enrichissement automatisé n'a de valeur que s'il consulte une vraie source, pas une donnée inventée pour l'occasion.
- Relire ce projet après coup m'a appris qu'un outil qui *prétend* fonctionner et un outil qui fonctionne réellement se ressemblent beaucoup en apparence, et qu'il faut vraiment lancer chaque commande pour faire la différence.

---

## Références

- [ANSSI — Guide d'hygiène informatique](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/)
- [CNIL — Recommandations techniques](https://www.cnil.fr/fr/securite-des-donnees)
- [OWASP Top 10](https://owasp.org/Top10/)
- [OSV.dev — Vulnerability Database](https://osv.dev/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

---

## Contribuer

Les contributions sont bienvenues, correction de bug, amélioration de doc, variante d'outil.

```bash
git checkout -b feature/jour-XX-nom-outil
git commit -m "feat(jXX): description de l'outil"
git push origin feature/jour-XX-nom-outil
```

Voir [CONTRIBUTING.md](./CONTRIBUTING.md) pour les guidelines.

---

## Licence

MIT — voir [LICENSE](./LICENSE)

---

<div align="center">

**Construit pour apprendre · Documenté pour partager · Testé pour protéger**

*[Ange Awala](https://github.com/angeawalabj) · Porto-Novo, Bénin · 2026*

</div>
