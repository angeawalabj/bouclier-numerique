# Jour 24 — Crawler OSINT

DNS · SPF/DMARC · Certificats (crt.sh) · Sous-domaines · Headers HTTP · WHOIS/RDAP · GitHub

---

## Problème résolu

L'OSINT (reconnaissance passive) est la première étape de tout test d'intrusion : un attaquant cartographie l'empreinte publique d'une cible avant d'envoyer la moindre requête offensive. Ce script reproduit cette collecte à des fins défensives, pour qu'une organisation découvre sa propre surface d'attaque — sous-domaines oubliés, configuration email vulnérable au phishing, headers révélant ses technologies — avant qu'un tiers ne le fasse.

```bash
python3 osint_crawler.py scan votre-domaine.fr
python3 osint_crawler.py scan votre-domaine.fr --output rapport.html --json donnees.json
python3 osint_crawler.py demo
```

## Sources exploitées (données publiques)

| Source | Ce qu'on collecte |
|--------|------------------|
| **DNS (DoH Cloudflare)** | A, MX, NS, TXT, SPF, DMARC |
| **crt.sh (Certificate Transparency)** | Sous-domaines révélés par les certificats SSL émis |
| **TLS direct** | Version, cipher, validité, expiration, SANs |
| **Headers HTTP** | Server, X-Powered-By, headers de sécurité (HSTS, CSP...) |
| **RDAP** | Registrar, dates de création/expiration, nameservers |
| **GitHub API** | Dépôts publics de l'organisation |
| **ipapi.co** | Géolocalisation et ASN des IPs résolues |

## Pourquoi l'absence de DMARC est un vrai problème

Sans DMARC, rien n'empêche un tiers d'envoyer un email avec `From: direction@votre-domaine.fr` et de le voir livré normalement dans les boîtes de réception. C'est le vecteur derrière la majorité des campagnes de phishing ciblé (spear phishing).

## Conformité

| Référentiel | Lien |
|------------|------|
| **ISO 27001 A.18.1.4** | Identification des actifs exposés |
| **RGPD Art. 32** | Évaluation de la surface d'attaque |
| **ANSSI** | Hygiène informatique — maîtrise du SI exposé |

---
_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 24/30_
