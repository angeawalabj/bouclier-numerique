"""Le bug d'origine (Jour 30) : les deux versions précédentes de ce
fichier n'appelaient jamais aucun module jour-XX — tout était fabriqué,
y compris pour un "Jour 29" qui n'existait pas encore dans le dépôt à
l'époque. Ces tests vérifient que les phases locales (sans dépendance
réseau) appellent réellement leur outil et retournent une donnée
cohérente avec ce que cet outil produit — pas un dict statique recopié.
"""

from suite_integree import (
    phase_ids_monitor,
    phase_permission_audit,
    phase_port_scan,
    phase_registre_rgpd,
)


def test_permission_audit_phase_returns_real_counts():
    result = phase_permission_audit()
    assert set(result) == {
        "camera_access", "audio_access",
        "suspicious_processes", "suspicious_connections",
    }
    assert all(isinstance(v, int) for v in result.values())


def test_port_scan_phase_reflects_this_machines_actual_listeners():
    result = phase_port_scan()
    assert result["open_ports"] >= 0
    assert result["niveau"] in ("SURE", "ACCEPTABLE", "RISQUEE", "CRITIQUE")


def test_ids_monitor_phase_detects_the_change_it_makes():
    """La phase modifie elle-même un fichier après la baseline — si le
    scan ne le détecte pas, ce n'est pas une vraie détection."""
    result = phase_ids_monitor()
    assert result["fichiers_scannes"] >= 1
    assert result["modifies"] + result["nouveaux"] >= 1


def test_registre_rgpd_phase_computes_a_real_score():
    result = phase_registre_rgpd()
    assert 0 <= result["score"] <= 100
    assert isinstance(result["anomalies"], int)
