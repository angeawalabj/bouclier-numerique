# 🔎 Jour 15 — Audit CVE des Dépendances

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![OSV](https://img.shields.io/badge/Source-OSV.dev%20·%20CVSS-ff3b3b?style=flat-square)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions%20ready-00e5a0?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-A06%3A2021-f5a623?style=flat-square)

**Scanner de vulnérabilités CVE pour Python et Node.js. Bloque le déploiement si critique.**  
OSV.dev · CVSS scoring · SBOM · CI/CD integration

</div>

---

## 🎯 Problème résolu

**Log4Shell (CVE-2021-44228, CVSS 10.0)** a compromis des milliers d'entreprises parce que `log4j` était enfoui 3 niveaux deep dans les dépendances. Personne ne savait qu'ils l'utilisaient. Ce scanner détecte et bloque ce genre de bombe à retardement **avant le déploiement**.

```
Sans scanner :  Code pushé → Tests OK → Déploiement → 💥 CVE en prod
Avec scanner :  Code pushé → Tests OK → ❌ CVE CRITIQUE détecté → Déploiement BLOQUÉ
```

---

## ⚡ Démarrage rapide

```bash
# Audit du répertoire courant
python dependency_audit.py audit . --block-on CRITICAL

# Audit avec génération SBOM
python dependency_audit.py audit . --sbom --output sbom.json

# Mode démo (projet fictif avec 13 CVE)
python dependency_audit.py demo
```

### Output type

```
🔴 CRITIQUE  pyyaml 5.3.1        CVE-2020-14343  CVSS 9.8  → pip install pyyaml>=5.4
🔴 CRITIQUE  jsonwebtoken 8.5.1  CVE-2022-23529  CVSS 9.8  → npm install jsonwebtoken@9.0.0
🟠 ÉLEVÉ     django 4.1.0        CVE-2024-27351  CVSS 7.5  → pip install django>=4.2.11
🟡 MODÉRÉ    requests 2.28.1     CVE-2023-32681  CVSS 6.1  → pip install requests>=2.31.0

Déploiement : ❌ BLOQUÉ (4 CVE critiques)
Exit code   : 1
```

---

## 🔬 Sources de vulnérabilités

| Source | Couverture | API key requise |
|--------|-----------|----------------|
| **OSV.dev** (Google) | Python + npm + Go + Rust + ... | ❌ Gratuit |
| **Base locale** | 12 packages courants pré-chargés | ❌ Offline |
| **npm audit** | Node.js uniquement | ❌ (npm requis) |
| **PyPI Advisory** | Python uniquement | ❌ Gratuit |

---

## 📦 Formats supportés

| Fichier | Ecosystème | Détection |
|---------|-----------|-----------|
| `requirements.txt` | Python | ✅ Auto |
| `Pipfile` / `Pipfile.lock` | Python | ✅ Auto |
| `package.json` | Node.js | ✅ Auto |
| `package-lock.json` | Node.js | ✅ Auto |

Détection automatique récursive — exclut `node_modules`, `.venv`, `__pycache__`.

---

## 🔄 Intégration CI/CD

### GitHub Actions

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Audit CVE des dépendances
        run: python dependency_audit.py audit . --block-on CRITICAL
        # Exit 1 si CVE critique → merge bloqué automatiquement
      
      - name: Générer SBOM
        run: python dependency_audit.py audit . --sbom --output sbom.json
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json
```

### Niveaux de blocage configurables

| Flag | Comportement |
|------|-------------|
| `--block-on CRITICAL` | Bloque si CVSS ≥ 9.0 |
| `--block-on HIGH` | Bloque si CVSS ≥ 7.0 |
| `--block-on MEDIUM` | Bloque si CVSS ≥ 4.0 |
| _(aucun)_ | Audit seul, exit 0 toujours |

---

## 📋 SBOM (Software Bill of Materials)

Le flag `--sbom` génère un inventaire de tous les composants :

```json
{
  "generated": "2026-03-12T09:00:00",
  "components": [
    {
      "name": "django",
      "version": "4.1.0",
      "ecosystem": "PyPI",
      "vulnerabilities": ["CVE-2024-27351"]
    }
  ]
}
```

Requis pour : assurances cyber · audits ISO 27001 · conformité PCI-DSS 6.3.3.

---

## 🏆 Cas réels prévenus

| CVE | Package | CVSS | Impact |
|-----|---------|------|--------|
| CVE-2021-44228 | log4j | **10.0** | RCE — compromis des milliers de serveurs |
| CVE-2020-14343 | pyyaml < 5.4 | 9.8 | Exécution code arbitraire via yaml.load() |
| CVE-2022-23529 | jsonwebtoken < 9 | 9.8 | RCE via clé secrète malformée |
| CVE-2021-44906 | minimist < 1.2.6 | 9.8 | Prototype pollution |

---

## ⚖️ Conformité

| Référentiel | Exigence |
|------------|---------|
| **OWASP A06:2021** | Composants vulnérables et obsolètes |
| **ISO 27001 A.12.6.1** | Gestion des vulnérabilités techniques |
| **PCI-DSS 6.3.3** | Mise à jour des composants logiciels |
| **ANSSI** | Guide développement sécurisé (R6.4) |

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 15/30_
