"""Rend chaque script jour-XX-*/ importable depuis les tests.

Les outils du challenge ne sont pas empaquetés (chaque jour-XX-*/ est un
dossier autonome, pas un package Python) — plutôt que de dupliquer une
manipulation de sys.path dans chaque fichier de test, ce conftest ajoute
une fois pour toutes le dossier de chaque outil utilisé par au moins un
test.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TOOL_DIRS = [
    "jour-01-password-vault",
    "jour-08-immutable-backup",
    "jour-12-treatment-registry",
    "jour-17-ids-hids",
    "jour-18-e2ee",
    "jour-19-pca",
    "jour-28-soar",
    "jour-29-threat-intel",
    "jour-30-suite-integree",
    "jour-bonus-dpa-generator",
]

for _dir in TOOL_DIRS:
    _path = str(ROOT / _dir)
    if _path not in sys.path:
        sys.path.insert(0, _path)
