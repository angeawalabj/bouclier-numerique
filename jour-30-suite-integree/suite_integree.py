#!/usr/bin/env python3
"""Orchestrateur du Bouclier Numérique : enchaîne de vrais outils du challenge sur une même cible locale.

Les deux versions précédentes de ce fichier ne faisaient absolument
rien de réel : l'une imprimait un tableau statique des 30 outils avec
un statut "terminé" codé en dur, l'autre simulait une attaque complète
(mots de passe crackés, IOCs, décisions Zero Trust) avec des données
entièrement fabriquées, sans jamais importer ni appeler le moindre
module des jours 1 à 29 — y compris pour un "Jour 29" qui, au moment
où ce fichier a été écrit, n'existait même pas dans le dépôt.

Cette version importe et exécute réellement six outils du challenge
(permission_audit, port_scanner, ids_monitor, registre_traitements,
threat_intel, soar) les uns après les autres sur ce poste, et construit
son rapport à partir de ce qu'ils retournent effectivement — pas d'un
catalogue statique. Le lien entre threat_intel (Jour 29) et soar
(Jour 28) est particulièrement révélateur : soar interroge la vraie
base d'IoC que threat_intel vient de peupler, donc le score de
réputation qui apparaît dans le rapport SOAR est celui que threat_intel
a réellement produit deux étapes plus tôt — pas une coïncidence, une
vraie dépendance entre deux modules du dépôt.

Ce que ça ne fait PAS : scanner un système tiers, ou remplacer un audit
professionnel. Chaque phase tourne en local, sur ce poste ou sur un
répertoire temporaire créé pour l'occasion.
"""

import shutil
import sys
import tempfile
import time
from datetime import datetime
from html import escape
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _load(folder: str, module_name: str):
    """Importe un module d'un autre dossier jour-XX du challenge."""
    path = str(_ROOT / folder)
    if path not in sys.path:
        sys.path.insert(0, path)
    import importlib
    return importlib.import_module(module_name)


COMPLIANCE_COVERAGE = {
    "RGPD":      ["Art.5", "Art.6", "Art.17", "Art.25", "Art.28", "Art.30", "Art.32", "Art.33", "Art.34"],
    "ISO 27001": ["A.5.9", "A.7.2.2", "A.8.8", "A.9.4", "A.10.1", "A.12.4", "A.12.6", "A.13.1", "A.14.2.8", "A.16.1", "A.18.2.3"],
    "NIST CSF":  ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"],
    "OWASP":     ["Top 10 2021", "API Security Top 10 2023", "ASVS 2.4"],
    "PCI-DSS":   ["Req.3.4", "Req.7.1", "Req.10.5.5", "Req.11.3"],
}


# ════════════════════════════════════════════════════════════════
# PHASES — chacune appelle un vrai module et retourne ses vrais résultats
# ════════════════════════════════════════════════════════════════

def phase_permission_audit() -> dict:
    """IDENTIFIER — audit local des accès caméra/micro et connexions suspectes."""
    mod = _load("jour-05-permission-audit", "permission_audit")
    devices = mod.audit_linux_devices()
    network = mod.audit_linux_network()
    return {
        "camera_access":          len(devices.get("camera_access", [])),
        "audio_access":           len(devices.get("audio_access", [])),
        "suspicious_processes":   len(devices.get("suspicious", [])),
        "suspicious_connections": len(network.get("suspicious_connections", [])),
    }


def phase_port_scan() -> dict:
    """IDENTIFIER — scan TCP réel des ports en écoute sur ce poste."""
    mod = _load("jour-10-port-scanner", "port_scanner")
    scanner = mod.PortScanner(timeout=0.3)
    results = scanner.scan_localhost()
    analysis = mod.analyser_resultats(results)
    return {"open_ports": len(results), "niveau": analysis["niveau"],
            "dangereux": analysis["dangereux"], "score": analysis["score"]}


def phase_ids_monitor() -> dict:
    """DÉTECTER — baseline puis détection réelle d'une modification/ajout de fichier."""
    mod = _load("jour-17-ids-hids", "ids_monitor")
    tmp_dir = tempfile.mkdtemp(prefix="bn_suite_ids_")
    try:
        demo_file = Path(tmp_dir) / "config.txt"
        demo_file.write_text("config initiale\n")

        db = mod.BaselineDB(db_path=str(Path(tmp_dir) / "baseline.db"))
        detector = mod.IntrusionDetector(db)
        detector.build_baseline([tmp_dir], verbose=False)

        time.sleep(0.05)  # garantir un mtime différent
        demo_file.write_text("config modifiee sans autorisation\n")
        (Path(tmp_dir) / "persistance_suspecte.sh").write_text("#!/bin/sh\necho pwn\n")

        result = detector.scan_once([tmp_dir])
        return {
            "fichiers_scannes": result["scanned"],
            "nouveaux":         len(result["new"]),
            "modifies":         len(result["modified"]),
            "supprimes":        len(result["deleted"]),
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def phase_registre_rgpd() -> dict:
    """IDENTIFIER — registre Art. 30 avec un traitement réel, score calculé."""
    mod = _load("jour-12-treatment-registry", "registre_traitements")
    tmp_db = tempfile.mktemp(suffix=".db", prefix="bn_suite_registre_")
    try:
        registre = mod.RegistreRGPD(tmp_db)
        registre.ajouter_traitement({
            "nom": "Suite intégrée — traitement démonstratif",
            "finalite": "Illustrer le calcul réel de conformité Art. 30",
            "base_legale": "6.1.f",
        }, auteur="suite_integree")
        c = registre.verifier_conformite()
        return {"score": c["score_global"], "niveau": c["niveau"], "anomalies": len(c["anomalies"])}
    finally:
        Path(tmp_db).unlink(missing_ok=True)


def phase_threat_intel() -> dict:
    """DÉTECTER — peuple la base d'IoC réelle (Jour 29) avec les indicateurs de démo."""
    mod = _load("jour-29-threat-intel", "threat_intel")
    db_path = str(_ROOT / "jour-29-threat-intel" / "ti.db")
    db = mod.IoCDatabase(db_path)
    added = sum(1 for ioc in mod.DEMO_IOCS if db.upsert(ioc))
    stats = db.stats()
    flagged_ip = next(i.value for i in mod.DEMO_IOCS if i.type == "ip")
    return {"iocs_total": stats["total"], "iocs_ajoutes": added,
            "db_path": db_path, "ip_a_tester": flagged_ip}


def phase_soar(source_ip: str) -> dict:
    """RÉPONDRE — traite une alerte réelle via le moteur de playbooks,
    enrichie par la base d'IoC que la phase précédente vient de peupler."""
    mod = _load("jour-28-soar", "soar")
    actions = mod.SoarActions()
    engine = mod.PlaybookEngine(actions)
    alert = mod.Alert("brute_force", "ÉLEVÉE", source_ip=source_ip,
                       description="Tentatives de connexion répétées",
                       raw_data={"username": "admin", "attempts": 63})
    result = engine.execute(alert)
    ip_intel = result.enrichment.get("ip_intel", {})
    return {
        "playbook": result.playbook,
        "actions_executees": len(result.actions),
        "statut": result.status,
        "ip_connue_malveillante": ip_intel.get("known_malicious", False),
        "ip_source_enrichissement": ip_intel.get("source"),
        "ip_reputation": ip_intel.get("reputation_score", 0),
    }


# ════════════════════════════════════════════════════════════════
# ORCHESTRATION
# ════════════════════════════════════════════════════════════════

def run_pipeline() -> dict:
    """Exécute les six phases dans l'ordre et retourne les résultats
    réels de chacune (ou l'erreur rencontrée, sans faire échouer les
    phases suivantes)."""
    phases = {}

    for name, fn in [
        ("permission_audit", phase_permission_audit),
        ("port_scan",        phase_port_scan),
        ("ids_monitor",      phase_ids_monitor),
        ("registre_rgpd",    phase_registre_rgpd),
    ]:
        t0 = time.monotonic()
        try:
            phases[name] = {"ok": True, "data": fn(), "duration_ms": (time.monotonic() - t0) * 1000}
        except Exception as e:
            phases[name] = {"ok": False, "error": str(e), "duration_ms": (time.monotonic() - t0) * 1000}

    # SOAR dépend du résultat réel de threat_intel — enchaînées ensemble
    t0 = time.monotonic()
    try:
        ti_data = phase_threat_intel()
        phases["threat_intel"] = {"ok": True, "data": ti_data, "duration_ms": (time.monotonic() - t0) * 1000}
        t1 = time.monotonic()
        phases["soar"] = {"ok": True, "data": phase_soar(ti_data["ip_a_tester"]),
                           "duration_ms": (time.monotonic() - t1) * 1000}
    except Exception as e:
        phases.setdefault("threat_intel", {"ok": False, "error": str(e), "duration_ms": (time.monotonic() - t0) * 1000})
        phases["soar"] = {"ok": False, "error": f"non exécuté ({e})", "duration_ms": 0}

    return phases


def print_pipeline_summary(phases: dict) -> None:
    print("\n  Résultats réels par phase\n")
    for name, result in phases.items():
        status = "OK" if result["ok"] else "ÉCHEC"
        print(f"  [{status}] {name:<20} ({result['duration_ms']:.1f}ms)")
        if result["ok"]:
            for k, v in result["data"].items():
                print(f"      {k}: {v}")
        else:
            print(f"      erreur: {result['error']}")


def generate_report_html(phases: dict, output_path: Path) -> Path:
    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    rows = ""
    for name, result in phases.items():
        status = "OK" if result["ok"] else "ÉCHEC"
        color = "#27ae60" if result["ok"] else "#e74c3c"
        detail = (
            " · ".join(f"{k}={v}" for k, v in result["data"].items())
            if result["ok"] else escape(str(result["error"]))
        )
        rows += (
            f'<tr><td>{escape(name)}</td>'
            f'<td style="color:{color};font-weight:700">{status}</td>'
            f'<td>{result["duration_ms"]:.1f}ms</td>'
            f'<td style="font-size:.82rem;color:#8892b0">{detail}</td></tr>'
        )

    compliance_html = "".join(
        f'<div class="comp-card"><div class="comp-title">{escape(ref)}</div>'
        f'<div class="comp-items">{"".join(f"<span class=\'tag\'>{escape(i)}</span>" for i in items)}</div></div>'
        for ref, items in COMPLIANCE_COVERAGE.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<title>Bouclier Numérique — Rapport d'orchestration</title>
<style>
:root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:sans-serif;padding:2rem;max-width:1000px;margin:auto}}
h1{{color:var(--accent);font-size:1.6rem}}
h2{{color:var(--accent);font-size:1rem;margin:1.6rem 0 .6rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}}
.meta{{color:var(--muted);font-size:.82rem;margin:.3rem 0 1.5rem}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
th{{background:#0a0c14;color:var(--accent);padding:.5rem .8rem;text-align:left;font-size:.78rem}}
td{{padding:.45rem .8rem;border-top:1px solid var(--border);font-size:.85rem}}
.comp-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.7rem}}
.comp-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.7rem}}
.comp-title{{color:var(--accent);font-weight:700;font-size:.85rem;margin-bottom:.4rem}}
.tag{{display:inline-block;background:#1e3a5f;color:#7eb8f7;padding:.1rem .35rem;border-radius:3px;font-size:.7rem;margin:.1rem}}
</style></head><body>
<h1>Bouclier Numérique — Rapport d'orchestration</h1>
<div class="meta">Généré le {now} · chaque ligne est le résultat réel d'un module du dépôt, exécuté à l'instant sur ce poste</div>

<h2>Pipeline exécuté</h2>
<table><thead><tr><th>Phase</th><th>Statut</th><th>Durée</th><th>Résultat</th></tr></thead>
<tbody>{rows}</tbody></table>

<h2>Référentiels couverts par le challenge (documentation, pas un résultat de scan)</h2>
<div class="comp-grid">{compliance_html}</div>
</body></html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def run_demo() -> dict:
    print("\n  Orchestration — six outils du Bouclier Numérique enchaînés sur ce poste\n")
    phases = run_pipeline()
    print_pipeline_summary(phases)

    ok_count = sum(1 for r in phases.values() if r["ok"])
    print(f"\n  {ok_count}/{len(phases)} phases exécutées avec succès")

    report_path = Path("./output/bouclier_numerique_rapport.html")
    generate_report_html(phases, report_path)
    print(f"  Rapport → {report_path}")

    soar_data = phases.get("soar", {}).get("data", {})
    if soar_data.get("ip_connue_malveillante"):
        print(
            f"\n  Intégration inter-outils vérifiée : l'IP testée par SOAR a été"
            f" reconnue malveillante via la base réelle du Jour 29"
            f" (source: {soar_data.get('ip_source_enrichissement')})."
        )

    return phases


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Orchestrateur de 6 outils réels du Bouclier Numérique.")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Exécute le pipeline complet sur ce poste")
    p_report = sub.add_parser("report", help="Exécute le pipeline et sauvegarde le rapport HTML")
    p_report.add_argument("--output", default="./output/bouclier_numerique_rapport.html")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    if args.cmd == "report":
        phases = run_pipeline()
        print_pipeline_summary(phases)
        out = generate_report_html(phases, Path(args.output))
        print(f"\n  Rapport → {out}")


if __name__ == "__main__":
    main()
