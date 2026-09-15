"""Le bug d'origine (Jour 1) : le coffre ne stockait que des hachages à
sens unique, donc get() n'a jamais pu exister. Ces tests verrouillent
la propriété qui compte vraiment : un secret ajouté doit ressortir
identique, et seul le bon mot de passe maître doit permettre de le lire.
"""

import pytest
from password_vault import Vault, VaultError


def test_add_then_get_returns_original_secret(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.create("maître-correct")
    vault.add("github", "s3cr3t-P@ssw0rd")

    assert vault.get("github") == "s3cr3t-P@ssw0rd"


def test_secret_survives_reopening_the_vault(tmp_path):
    path = tmp_path / "vault.json"
    vault = Vault(path)
    vault.create("maître-correct")
    vault.add("github", "s3cr3t-P@ssw0rd")

    reopened = Vault(path)
    reopened.unlock("maître-correct")
    assert reopened.get("github") == "s3cr3t-P@ssw0rd"


def test_wrong_master_password_is_rejected(tmp_path):
    path = tmp_path / "vault.json"
    Vault(path).create("bon-mot-de-passe")

    with pytest.raises(VaultError):
        Vault(path).unlock("mauvais-mot-de-passe")


def test_get_unknown_service_raises(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.create("maître")

    with pytest.raises(VaultError):
        vault.get("service-inconnu")


def test_list_services_reflects_additions_and_removals(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.create("maître")
    vault.add("a", "x")
    vault.add("b", "y")
    assert vault.list_services() == ["a", "b"]

    vault.remove("a")
    assert vault.list_services() == ["b"]


def test_vault_file_is_not_world_readable(tmp_path):
    path = tmp_path / "vault.json"
    Vault(path).create("maître")
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600
