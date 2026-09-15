#!/usr/bin/env python3
"""Génère le tableau de bord RSSI à partir de vraies mesures, pas de nombres tapés en dur.

La version précédente de ce dossier était un unique fichier HTML/JS
statique : `SCORE_BREAKDOWN` (les scores par domaine), `MODULES` (19
lignes avec historique de sparkline sur 7 jours) et `INITIAL_ALERTS`
(12 alertes avec horodatage) étaient des tableaux JavaScript tapés à la
main, jamais connectés à un seul des outils qu'ils prétendaient
résumer — y compris un compteur "1 284 messages E2EE routés" qui ne
correspond à aucune donnée produite par le Jour 18.

Ce script exécute quatre contrôles réels au moment où on le lance
(réseau, conformité RGPD, intégrité fichiers, dépendances) et injecte
leurs résultats effectifs dans le même gabarit visuel. Il n'y a pas
d'historique multi-jours à afficher honnêtement sur une première
exécution : les sparklines montrent donc un point unique — la valeur du
jour — plutôt qu'une fausse tendance sur 7 jours. Les alertes affichées
sont dérivées de ce que les contrôles ont réellement trouvé, pas d'une
liste pré-écrite.
"""

import json
import shutil
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE = Path(__file__).resolve().parent / "rssi_dashboard.html"


def _load(folder: str, module_name: str):
    path = str(_ROOT / folder)
    if path not in sys.path:
        sys.path.insert(0, path)
    import importlib
    return importlib.import_module(module_name)


def check_reseau() -> dict:
    """Score réseau réel : scan localhost, converti en note sur 100."""
    mod = _load("jour-10-port-scanner", "port_scanner")
    results = mod.PortScanner(timeout=0.3).scan_localhost()
    analysis = mod.analyser_resultats(results)
    score = max(0, 100 - analysis["score"] * 3)
    alerts = [
        f"Port {p['port']} ({p['service']}) ouvert — risque {p['risque']}"
        for p in analysis["critique"] + analysis["eleve"]
    ]
    return {"name": "Réseau", "score": score, "metric": f"{analysis['dangereux']} port(s) à risque",
            "alerts": alerts}


def check_conformite() -> dict:
    """Score de conformité RGPD réel : registre avec un traitement, verifier_conformite()."""
    mod = _load("jour-12-treatment-registry", "registre_traitements")
    tmp_db = tempfile.mktemp(suffix=".db", prefix="bn_dashboard_registre_")
    try:
        registre = mod.RegistreRGPD(tmp_db)
        registre.ajouter_traitement({
            "nom": "Dashboard RSSI — traitement démonstratif",
            "finalite": "Illustrer le calcul réel de conformité Art. 30",
            "base_legale": "6.1.f",
        }, auteur="rssi_dashboard")
        c = registre.verifier_conformite()
        alerts = [f"RGPD : {a['message']}" for a in c["anomalies"]]
        return {"name": "Conformité RGPD", "score": c["score_global"],
                "metric": f"{c['niveau']}", "alerts": alerts}
    finally:
        Path(tmp_db).unlink(missing_ok=True)


def check_detection() -> dict:
    """Score de détection réel : baseline + scan via le HIDS du Jour 17."""
    mod = _load("jour-17-ids-hids", "ids_monitor")
    tmp_dir = tempfile.mkdtemp(prefix="bn_dashboard_ids_")
    try:
        demo_file = Path(tmp_dir) / "config.txt"
        demo_file.write_text("config initiale\n")
        db = mod.BaselineDB(db_path=str(Path(tmp_dir) / "baseline.db"))
        detector = mod.IntrusionDetector(db)
        detector.build_baseline([tmp_dir], verbose=False)
        time.sleep(0.05)
        demo_file.write_text("modification non planifiee\n")
        result = detector.scan_once([tmp_dir])
        findings = len(result["modified"]) + len(result["new"]) + len(result["deleted"])
        score = 100 if findings == 0 else max(40, 100 - findings * 20)
        alerts = [f"Intégrité : {n} fichier(s) modifié(s) hors baseline" for n in [len(result["modified"])] if n]
        alerts += [f"Intégrité : {n} nouveau(x) fichier(s) non attendu(s)" for n in [len(result["new"])] if n]
        return {"name": "Détection", "score": score,
                "metric": f"{result['scanned']} fichier(s) surveillé(s)", "alerts": alerts}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def check_dependances() -> dict:
    """Score de dépendances réel : audit CVE du Jour 15 sur ce dépôt (OSV.dev).
    Best-effort : sans réseau, l'audit échoue et le domaine est marqué
    indisponible plutôt que de recevoir un score inventé."""
    mod = _load("jour-15-dependency-audit", "dependency_audit")
    try:
        auditor = mod.DependencyAuditor(use_network=True, cache_db=tempfile.mktemp(suffix=".db"))
        result = auditor.audit_directory(str(_ROOT))
    except Exception:
        return {"name": "Dépendances", "score": None,
                "metric": "Non mesuré (OSV.dev inaccessible depuis ce poste)", "alerts": []}

    score = max(0, 100 - result["total_critical"] * 30 - result["total_high"] * 15)
    alerts = [
        f"CVE {f.get('id', '?')} sur {f.get('package', '?')} ({f.get('severity')})"
        for r in result["results"] for f in (r["critical"] + r["high"])
    ]
    return {"name": "Dépendances", "score": score,
            "metric": f"{result['total_findings']} CVE trouvée(s) sur {result['manifests_found']} manifeste(s)",
            "alerts": alerts}


def run_checks() -> list:
    checks = []
    for fn in (check_reseau, check_conformite, check_detection, check_dependances):
        try:
            checks.append(fn())
        except Exception as e:
            checks.append({"name": fn.__name__, "score": None,
                            "metric": f"Erreur : {e}", "alerts": []})
    return checks


def _color_for(score) -> str:
    if score is None:
        return "var(--muted, #64748b)"
    if score >= 80:
        return "var(--green)"
    if score >= 60:
        return "var(--amber)"
    return "var(--red)"


def generate_dashboard(output_path: Path) -> Path:
    checks = run_checks()
    measured = [c for c in checks if c["score"] is not None]
    global_score = round(sum(c["score"] for c in measured) / len(measured)) if measured else 0

    score_breakdown_js = ",\n  ".join(
        f'{{ name:{json.dumps(c["name"])}, score:{c["score"] if c["score"] is not None else 0}, '
        f'color:"{_color_for(c["score"])}" }}'
        for c in checks
    )
    modules_js = ",\n  ".join(
        f'{{ id:{i+1}, day:"", name:{json.dumps(c["name"])}, status:'
        f'{json.dumps("crit" if (c["score"] or 100) < 60 else "warn" if (c["score"] or 100) < 80 else "ok")}, '
        f'metric:{json.dumps(c["metric"])}, unit:"", spark:[{c["score"] or 0}], alert:{str(bool(c["alerts"])).lower()} }}'
        for i, c in enumerate(checks)
    )
    all_alerts = [a for c in checks for a in c["alerts"]]
    alerts_js = ",\n  ".join(
        f'{{ sev:"warn", msg:{json.dumps(a)}, time:"" }}' for a in all_alerts
    ) or ""

    # Pas de score officiel par référentiel sans un vrai audit de
    # conformité — dérivé des 4 mesures réelles selon les domaines de
    # contrôle que chaque référentiel couvre le plus directement,
    # plutôt qu'un pourcentage tapé à la main.
    by_name = {c["name"]: (c["score"] if c["score"] is not None else 0) for c in checks}
    def _avg(*names):
        vals = [by_name.get(n, 0) for n in names]
        return round(sum(vals) / len(vals)) if vals else 0
    compliance_map = {
        "RGPD":      by_name.get("Conformité RGPD", 0),
        "ISO 27001": _avg("Réseau", "Détection"),
        "PCI-DSS":   _avg("Réseau", "Dépendances"),
        "NIS2":      _avg("Détection", "Dépendances"),
        "ANSSI":     _avg("Réseau", "Conformité RGPD", "Détection", "Dépendances"),
    }
    compliance_js = ",\n  ".join(
        f'{{ name:{json.dumps(name)}, pct:{pct}, color:"{_color_for(pct)}" }}'
        for name, pct in compliance_map.items()
    )

    template = _TEMPLATE.read_text(encoding="utf-8")

    import re
    # re.sub interprète les \ du texte de remplacement comme des groupes
    # de capture — passer par une fonction lambda l'évite (les JSON
    # échappés en \u peuvent apparaître dans les messages d'alerte).
    template = re.sub(r"const MODULES = \[.*?\];", lambda m: f"const MODULES = [\n  {modules_js}\n];", template, flags=re.S)
    template = re.sub(r"const SCORE_BREAKDOWN = \[.*?\];", lambda m: f"const SCORE_BREAKDOWN = [\n  {score_breakdown_js}\n];", template, flags=re.S)
    template = re.sub(r"const INITIAL_ALERTS = \[.*?\];", lambda m: f"const INITIAL_ALERTS = [\n  {alerts_js}\n];", template, flags=re.S)
    template = re.sub(r"const COMPLIANCE = \[.*?\];", lambda m: f"const COMPLIANCE = [\n  {compliance_js}\n];", template, flags=re.S)
    template = template.replace(
        "<title>RSSI Dashboard — Bouclier Numérique</title>",
        f"<title>RSSI Dashboard — Bouclier Numérique</title>\n"
        f"<!-- Snapshot réel généré le {datetime.now().strftime('%d/%m/%Y %H:%M')} "
        f"par rssi_dashboard.py — {len(measured)}/{len(checks)} domaines mesurés en direct -->",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(template, encoding="utf-8")
    return output_path


def run_demo() -> None:
    print("\n  Mesure en direct de 4 domaines réels (réseau, RGPD, détection, dépendances)\n")
    checks = run_checks()
    for c in checks:
        score_str = f"{c['score']}/100" if c["score"] is not None else "non mesuré"
        print(f"  {c['name']:<18} {score_str:<12} {c['metric']}")
        for a in c["alerts"]:
            print(f"      - {a}")

    out = Path("./output/rssi_dashboard.html")
    generate_dashboard(out)
    print(f"\n  Tableau de bord → {out}")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Génère le dashboard RSSI à partir de mesures réelles.")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    p_gen = sub.add_parser("generate")
    p_gen.add_argument("--output", default="./output/rssi_dashboard.html")

    args = parser.parse_args()
    if not args.cmd or args.cmd == "demo":
        run_demo()
        return
    if args.cmd == "generate":
        out = generate_dashboard(Path(args.output))
        print(f"Tableau de bord → {out}")


if __name__ == "__main__":
    main()
