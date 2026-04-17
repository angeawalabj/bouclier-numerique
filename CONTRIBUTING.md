# 🤝 Guide de Contribution — Le Bouclier Numérique

Merci de vouloir contribuer ! Ce guide explique comment participer, qu'il s'agisse de corriger un bug, d'améliorer un outil existant, ou de proposer un nouveau jour de challenge.

---

## 📋 Table des matières

- [Code de conduite](#code-de-conduite)
- [Comment contribuer](#comment-contribuer)
- [Standards de code](#standards-de-code)
- [Ajouter un nouvel outil](#ajouter-un-nouvel-outil)
- [Signaler un bug](#signaler-un-bug)
- [Proposer une amélioration](#proposer-une-amélioration)
- [Processus de review](#processus-de-review)

---

## Code de conduite

Ce projet suit le [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). En contribuant, vous vous engagez à respecter ses termes. Signalement d'incidents : voir `CODE_OF_CONDUCT.md`.

---

## Comment contribuer

### 1. Préparer votre environnement

```bash
# Fork le dépôt sur GitHub, puis :
git clone https://github.com/VOTRE-USERNAME/bouclier-numerique.git
cd bouclier-numerique

# Créer un environnement virtuel
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Installer les dépendances
pip install -r requirements.txt
pip install -r requirements-dev.txt  # outils de dev : pytest, ruff, mypy
```

### 2. Créer une branche

Nommage des branches :

```bash
# Correction de bug
git checkout -b fix/jour-03-hibp-timeout

# Nouvelle fonctionnalité
git checkout -b feat/jour-21-api-fuzzer

# Documentation
git checkout -b docs/jour-17-readme-update

# Amélioration conformité
git checkout -b compliance/jour-14-cnil-2024
```

### 3. Développer et tester

```bash
# Lancer les tests du module concerné
pytest tests/test_jour07_honeypot.py -v

# Lancer tous les tests
pytest tests/ -v --tb=short

# Vérifier le style
ruff check jour-07-honeypot/honeypot.py
ruff format jour-07-honeypot/honeypot.py

# Vérifier les types (optionnel mais apprécié)
mypy jour-07-honeypot/honeypot.py
```

### 4. Committer

Nous suivons la convention [Conventional Commits](https://www.conventionalcommits.org/fr/) :

```bash
# Format : <type>(<scope>): <description courte>

git commit -m "fix(j03): corriger timeout HIBP API en mode offline"
git commit -m "feat(j21): ajouter fuzzer API avec détection OWASP Top 10"
git commit -m "docs(j17): clarifier la section PCI-DSS 10.5.5"
git commit -m "test(j15): ajouter cas de test CVE-2021-44228 log4shell"
git commit -m "perf(j10): améliorer la vitesse du scan réseau x3"
git commit -m "security(j18): mettre à jour X25519 vers dernière version"
```

Types acceptés : `feat`, `fix`, `docs`, `test`, `perf`, `security`, `compliance`, `refactor`, `chore`

### 5. Ouvrir une Pull Request

```bash
git push origin feat/jour-21-api-fuzzer
```

Puis sur GitHub : **New Pull Request** → remplir le template fourni.

---

## Standards de code

### Python

Tous les scripts Python doivent respecter :

```python
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR XX : NOM DE L'OUTIL             ║
║  Objectif  : Ce que fait l'outil en une ligne                   ║
║  Conformité: Référentiel légal couvert                          ║
╚══════════════════════════════════════════════════════════════════╝

Description étendue : contexte légal, problème résolu, algorithmes utilisés.
"""
# ✅ Imports stdlib avant imports tiers
import os
import sys
from pathlib import Path

# ✅ Imports tiers avec try/except et message d'erreur utile
try:
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("❌ Dépendance manquante : pip install cryptography")
    sys.exit(1)
```

**Règles :**
- Python 3.10+ minimum (utilisation de `match/case` autorisée)
- Type hints sur toutes les fonctions publiques
- Docstrings en français sur les fonctions complexes
- Zéro warnings `ruff` — configuration dans `pyproject.toml`
- Chaque script doit avoir un mode `demo` fonctionnel sans paramètres
- Pas de secrets hardcodés, jamais (clés API, mots de passe...)

### Sécurité du code

- **Pas de `eval()` ou `exec()`** sur des données externes
- **Pas de `shell=True`** dans `subprocess` avec entrées utilisateur
- **Pas de `pickle`** pour désérialiser des données non fiables
- **Chiffrement** : uniquement des algorithmes approuvés ANSSI (AES-256, SHA-256+, X25519)
- **Secrets** : utiliser `secrets.token_bytes()` jamais `random`

### Tests

```
tests/
├── test_jour01_password_vault.py
├── test_jour07_honeypot.py
├── fixtures/
│   ├── sample_photo_with_gps.jpg
│   └── sample_requirements.txt
└── conftest.py
```

Chaque test doit :
- Être isolé (pas de dépendance entre tests)
- Nettoyer ses fichiers temporaires (`tmp_path` pytest)
- Couvrir au moins : happy path, erreur attendue, edge case
- Cible de couverture : **80% minimum**

---

## Ajouter un nouvel outil

Si vous proposez un outil pour les jours 21-30, voici la checklist :

```
jour-XX-nom-de-loutil/
├── README.md          ← obligatoire, template ci-dessous
├── nom_de_loutil.py   ← script principal
├── requirements.txt   ← dépendances spécifiques (si besoin)
└── tests/
    └── test_nom.py    ← au moins 5 tests
```

**Template README minimum :**

```markdown
# 🔧 Jour XX — Nom de l'Outil

## 🎯 Problème résolu
<!-- Scénario concret d'attaque ou de non-conformité que cet outil résout -->

## ⚡ Usage
<!-- Commandes prêtes à copier-coller -->

## 🔬 Architecture
<!-- Comment ça fonctionne, pourquoi ces choix techniques -->

## ⚖️ Conformité
<!-- Référentiels couverts : RGPD, ISO 27001, ANSSI, PCI-DSS, NIS2 -->
```

**Critères d'acceptation :**
- ✅ L'outil résout un vrai problème de sécurité (pas un doublon)
- ✅ Mode `demo` fonctionnel sans configuration
- ✅ Conformité à au moins un référentiel documentée
- ✅ Tests passants
- ✅ Pas de dépendances inutiles (préférer stdlib)
- ✅ Usage légal uniquement, avertissement inclus si offensif

---

## Signaler un bug

Utilisez le template **Bug Report** dans les Issues GitHub.

Informations requises :
- Version Python et OS
- Commande exacte qui a échoué
- Sortie complète (stdout + stderr)
- Comportement attendu vs observé

**🔴 Vulnérabilité de sécurité** → Ne pas ouvrir une Issue publique. Voir [SECURITY.md](SECURITY.md).

---

## Proposer une amélioration

Utilisez le template **Feature Request** dans les Issues GitHub.

Une bonne proposition inclut :
- Le problème de sécurité ou de conformité qu'elle résout
- Le référentiel légal concerné (RGPD, ISO 27001, ANSSI...)
- Une esquisse de l'approche technique
- Des alternatives considérées

---

## Processus de review

1. **CI automatique** — Les checks GitHub Actions doivent passer (tests, ruff, mypy)
2. **Review humaine** — Un maintainer examine dans les 7 jours ouvrés
3. **Feedback** — Des changements peuvent être demandés, c'est normal
4. **Merge** — Squash merge sur `main` une fois approuvé

Les reviews portent sur : correction technique, sécurité du code, clarté de la documentation, couverture de tests, conformité légale.

---

## Premiers pas — Issues "good first issue"

Cherchez les issues tagguées [`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) pour un premier pas dans le projet.

---

*Merci pour votre contribution au Bouclier Numérique 🛡️*