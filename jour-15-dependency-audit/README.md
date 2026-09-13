# Jour 15 — Audit CVE des Dépendances

Python 3.10+ · OSV.dev · CVSS scoring · SBOM · intégration CI/CD

Scanner de vulnérabilités CVE pour manifestes Python et Node.js. Bloque le déploiement si une CVE critique est détectée.

---

## Problème résolu

Log4Shell (CVE-2021-44228, CVSS 10.0) a compromis des milliers d'entreprises parce que `log4j` était enfoui trois niveaux de profondeur dans les dépendances transitives — personne ne savait qu'ils l'utilisaient. Ce scanner détecte ce genre de dépendance oubliée avant le déploiement, pas après l'incident.

```
Sans scanner :  Code pushé -> Tests OK -> Déploiement -> CVE découverte en prod
Avec scanner :  Code pushé -> Tests OK -> CVE critique détectée -> Déploiement bloqué
```

---

## Démarrage rapide

```bash
# Audit du répertoire courant
python dependency_audit.py audit . --block-on CRITICAL

# Audit avec génération SBOM
python dependency_audit.py audit . --sbom --output sbom.json

# Mode démo (manifeste fictif, base locale hors-ligne)
python dependency_audit.py demo
```

### Output type

```
[CRITICAL] pyyaml 5.3.1        CVE-2020-14343  CVSS 9.8  -> pip install pyyaml>=5.4
[CRITICAL] jsonwebtoken 8.5.1  CVE-2022-23529  CVSS 9.8  -> npm install jsonwebtoken@9.0.0
[HIGH]     django 4.1.0        CVE-2024-27351  CVSS 7.5  -> pip install django>=4.2.11
[MEDIUM]   requests 2.28.1     CVE-2023-32681  CVSS 6.1  -> pip install requests>=2.31.0

Déploiement : BLOQUÉ (2 CVE critiques)
Exit code   : 1
```

---

## Sources de vulnérabilités

| Source | Couverture | Clé API requise |
|--------|-----------|----------------|
| OSV.dev (Google) | Python, npm, Go, Rust, ... — requêtes réseau réelles | Non, gratuit |
| Base locale | ~12 CVE connues pré-chargées, utilisée en mode `demo` et en secours hors-ligne | Non |

`--no-network` désactive OSV.dev et n'utilise que la base locale.

---

## Formats supportés

| Fichier | Écosystème |
|---------|-----------|
| `requirements.txt` | Python |
| `Pipfile` | Python |
| `package.json` | Node.js |

Détection automatique récursive — exclut `node_modules`, `.venv`, `venv`.

---

## Intégration CI/CD

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
        # Exit 1 si CVE critique -> merge bloqué automatiquement

      - name: Générer SBOM
        run: python dependency_audit.py audit . --sbom --output sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json
```

### Niveaux de blocage

| Flag | Comportement |
|------|-------------|
| `--block-on CRITICAL` | Bloque si CVSS >= 9.0 (défaut) |
| `--block-on HIGH` | Bloque si CVSS >= 7.0 |
| `--block-on MEDIUM` | Bloque si CVSS >= 4.0 |

Codes de sortie : `0` autorisé, `1` bloqué (CRITICAL détecté), `2` warning (HIGH détecté).

---

## SBOM (Software Bill of Materials)

Le flag `--sbom` génère un inventaire de tous les composants détectés, format inspiré CycloneDX. Utile pour les audits ISO 27001 et la conformité PCI-DSS 6.3.3.

---

## Conformité

| Référentiel | Exigence |
|------------|---------|
| OWASP A06:2021 | Composants vulnérables et obsolètes |
| ISO 27001 A.12.6.1 | Gestion des vulnérabilités techniques |
| PCI-DSS 6.3.3 | Mise à jour des composants logiciels |
| ANSSI | Guide développement sécurisé (R6.4) |

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 15/30_
