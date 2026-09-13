# Jour 11 — Droit à l'Effacement RGPD (Art. 17)

Effacement multi-sources (SQL, JSON, CSV, logs) avec piste d'audit et
certificat horodaté. Python 3.10+.

---

## Problème résolu

Lorsqu'un utilisateur demande la suppression de ses données (RGPD Art. 17), votre organisation a **30 jours** pour les effacer de TOUTES les sources : base de données principale, backups, logs, emails, CRM, analytics... L'oubli d'une source constitue une violation. Ce module automatise et certifie le processus.

---

## Usage

```bash
# Traiter une demande d'effacement (dry-run par défaut recommandé d'abord)
python right_to_erasure.py erase --email user@exemple.fr --dry-run
python right_to_erasure.py erase --email user@exemple.fr

# Vérifier le statut d'une demande
python right_to_erasure.py status REQ-2026-0142

# Afficher le certificat d'effacement (preuve RGPD)
python right_to_erasure.py cert REQ-2026-0142

# Démo
python right_to_erasure.py demo
```

---

## Fonctionnalités

- Suppression multi-sources : SQL, JSON, CSV, logs (configurable par table/fichier)
- Mode `--dry-run` pour prévisualiser sans supprimer
- Certificat d'effacement horodaté (preuve en cas de contrôle)
- Exceptions légales documentées (Art. 17.3 : obligations légales)
- Audit trail complet

---

## Conformité

RGPD Art. 17 — droit à l'effacement · Art. 12 — délais de réponse

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 11/30_
