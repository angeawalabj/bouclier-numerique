# Jour 23 — Craqueur de Hachages Éthique

Dictionnaire, règles Hashcat, bruteforce, benchmark et audit de base de
données. Python 3.10+.

---

## Problème résolu

Quand une base de données est volée, l'attaquant obtient des hachages. Ce script simule exactement ce qu'il ferait — sur VOS hachages — avant lui. En moins d'une seconde, il récupère tous les mots de passe MD5/SHA.

```bash
python3 hash_cracker.py benchmark         # Compare les algorithmes
python3 hash_cracker.py crack 5f4dcc3b5aa765d61d8327deb882cf99  # MD5 de "password"
python3 hash_cracker.py audit base.json   # Audite toute une base
python3 hash_cracker.py demo              # Démonstration complète
```

## Résultats du benchmark

| Algorithme | Vitesse | 1M tentatives | Recommandé |
|-----------|---------|---------------|-----------|
| MD5 | 1 500 000 hash/s | < 1 seconde | CRITIQUE — déconseillé |
| SHA-256 | 1 400 000 hash/s | < 1 seconde | FAIBLE — déconseillé |
| PBKDF2 | 5 hash/s | 2,3 jours | BON |
| scrypt | 21 hash/s | 1 300 heures | EXCELLENT |
| bcrypt | ~10 hash/s | 27 heures | BON |

## Conformité

| Référentiel | Exigence |
|------------|---------|
| **RGPD Art. 32** | Mesures techniques appropriées — MD5 = NON approprié |
| **ANSSI RGS** | bcrypt(≥12), scrypt, argon2id recommandés |
| **OWASP 2023** | PBKDF2 avec ≥ 600 000 itérations SHA-256 |

---
_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 23/30_
