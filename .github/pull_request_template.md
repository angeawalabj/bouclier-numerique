# Pull Request — Le Bouclier Numérique

## 📝 Description

<!-- Résumé des changements apportés et pourquoi -->

Fixes #<!-- numéro d'issue -->

## 🔧 Type de changement

- [ ] 🐛 Correction de bug
- [ ] ✨ Nouvelle fonctionnalité (nouvel outil ou ajout majeur)
- [ ] 📚 Documentation
- [ ] 🔒 Correction de sécurité
- [ ] ⚖️ Mise à jour conformité (nouveau référentiel ou article)
- [ ] ♻️ Refactoring (pas de changement fonctionnel)
- [ ] ⚡ Performance
- [ ] 🧪 Tests uniquement

## ✅ Checklist

### Code
- [ ] Mon code suit les standards définis dans [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] J'ai ajouté des type hints sur les nouvelles fonctions
- [ ] Zéro warning `ruff` — vérifié avec `ruff check .`
- [ ] Aucun secret hardcodé (clé API, mot de passe, token)
- [ ] Le mode `demo` fonctionne sans paramètres : `python3 outil.py demo`

### Tests
- [ ] J'ai ajouté des tests couvrant mes changements
- [ ] Tous les tests passent : `pytest tests/ -v`
- [ ] La couverture n'a pas diminué : `pytest --cov`

### Documentation
- [ ] J'ai mis à jour le README de l'outil concerné
- [ ] J'ai mis à jour CHANGELOG.md (section `[Unreleased]`)
- [ ] Les commandes d'usage dans le README sont à jour

### Sécurité
- [ ] Pas de `eval()`, `exec()`, `pickle` sur données externes
- [ ] Pas de `shell=True` avec entrées utilisateur
- [ ] Algorithmes cryptographiques approuvés ANSSI uniquement
- [ ] Si outil offensif : avertissement légal inclus

## 🧪 Comment tester

```bash
# Instructions pour tester spécifiquement ce PR
python3 outil_modifie.py demo
pytest tests/test_outil_modifie.py -v
```

## 📸 Captures d'écran (si pertinent)

<!-- Pour les changements visuels (dashboard HTML, rapports...) -->

## ⚖️ Impact sur la conformité

<!-- Si le changement affecte la conformité RGPD/ISO/ANSSI, décrire l'impact -->
