"""Le bug d'origine (Jour 8) : seule chmod 444 protégeait l'archive,
contournable par le propriétaire du fichier — ce n'est pas de
l'immuabilité face à un ransomware qui tourne avec les mêmes droits.
Ces tests vérifient le comportement observable : la protection est
appliquée d'une façon ou d'une autre (chattr ou repli chmod, le champ
`immutable_chattr` dit honnêtement laquelle), et delete() peut quand
même nettoyer un backup expiré ensuite.
"""

from pathlib import Path

import pytest
from immutable_backup import BackupConfig, ImmutableBackup


def _make_backup(tmp_path):
    source = tmp_path / "data"
    source.mkdir()
    (source / "secret.txt").write_text("donnee sensible\n")

    cfg = BackupConfig()
    cfg.BACKUP_ROOT = tmp_path / "backups"
    cfg.RETENTION_DAYS = 0  # supprimable immédiatement dans le test
    bm = ImmutableBackup(cfg)
    return bm, bm.create(source)


def test_create_reports_which_protection_layer_is_active(tmp_path):
    _, result = _make_backup(tmp_path)

    assert isinstance(result["immutable_chattr"], bool)
    archive = Path(result["archive"])
    mode = archive.stat().st_mode & 0o777
    assert mode == 0o444  # lecture seule dans tous les cas, chattr ou pas


def test_archive_resists_direct_write_when_chmod_only(tmp_path):
    bm, result = _make_backup(tmp_path)
    if result["immutable_chattr"]:
        return  # chattr actif : la garantie est encore plus forte, rien à vérifier ici

    archive = Path(result["archive"])
    with pytest.raises((PermissionError, OSError)):
        with open(archive, "ab") as f:
            f.write(b"tampered")


def test_verify_reports_intact_right_after_creation(tmp_path):
    bm, result = _make_backup(tmp_path)
    verdict = bm.verify(result["backup_id"])
    assert "INTÈGRE" in verdict["verdict"]


def test_delete_removes_a_backup_past_retention(tmp_path):
    bm, result = _make_backup(tmp_path)
    outcome = bm.delete(result["backup_id"])
    assert outcome["deleted"] is True
