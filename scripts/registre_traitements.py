#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 10 : REGISTRE DES TRAITEMENTS    ║
║  Obligation : Art. 30 RGPD — Registre obligatoire (50+ salariés)║
║  Conforme   : Modèle CNIL 2024 · ISO 27701 · ePrivacy           ║
║  Fonctions  : CRUD traitements · Score conformité · Export HTML  ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 30 RGPD — Toute organisation traitant des
données personnelles doit tenir un registre écrit de l'ensemble
de ses activités de traitement. Obligatoire pour les entreprises
de 50+ salariés, fortement recommandé en-dessous.

Contenu obligatoire du registre (Art. 30 §1) :
  a) Nom et coordonnées du responsable de traitement + DPO
  b) Finalités du traitement
  c) Catégories de personnes concernées et de données
  d) Catégories de destinataires
  e) Transferts vers pays tiers + garanties
  f) Délais de conservation prévus
  g) Description des mesures de sécurité (Art. 32)

Sanctions : Art. 83 §4 — jusqu'à 10M€ ou 2% CA mondial
pour défaut de registre lors d'un contrôle CNIL.

Cas réel : La CNIL peut demander le registre à tout moment
lors d'une inspection. Absence = mise en demeure immédiate.
"""

import os
import sys
import json
import csv
import sqlite3
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, date
from typing import Optional
from collections import defaultdict

# ================================================================
# RÉFÉRENTIELS CNIL
# ================================================================

# Bases légales Art. 6 RGPD
BASES_LEGALES = {
    "CONSENTEMENT":      "Art. 6(1)(a) — Consentement de la personne",
    "CONTRAT":           "Art. 6(1)(b) — Exécution d'un contrat",
    "OBLIGATION_LEGALE": "Art. 6(1)(c) — Obligation légale",
    "INTERET_VITAL":     "Art. 6(1)(d) — Intérêt vital",
    "MISSION_PUBLIQUE":  "Art. 6(1)(e) — Mission d'intérêt public",
    "INTERET_LEGITIME":  "Art. 6(1)(f) — Intérêt légitime du responsable",
}

# Catégories spéciales Art. 9 — exigent une base légale renforcée
CATEGORIES_SPECIALES = [
    "données_de_sante", "données_genetiques", "données_biometriques",
    "origine_raciale_ethnique", "opinions_politiques",
    "convictions_religieuses", "appartenance_syndicale",
    "vie_sexuelle_orientation", "condamnations_penales",
]

# Délais de conservation recommandés par type
DELAIS_RECOMMANDES = {
    "clients":          ("3 ans",  "CNIL — délai prescription commerciale"),
    "employes":         ("5 ans",  "Code du travail — après départ"),
    "comptabilite":     ("10 ans", "Code de commerce Art. L123-22"),
    "video":            ("30 jours", "CNIL — vidéosurveillance standard"),
    "logs_acces":       ("6 mois", "CNIL — recommandation logs"),
    "cookies":          ("13 mois","CNIL — durée maximale consentement"),
    "candidatures":     ("2 ans",  "CNIL — conservation CVs"),
    "contrats":         ("10 ans", "Prescription contractuelle"),
    "medical":          ("20 ans", "Code de la santé publique"),
    "mineur":           ("5 ans après majorité", "Protection mineurs"),
}

# Pays avec décision d'adéquation (transferts libres)
PAYS_ADEQUATION = {
    "Andorre", "Argentine", "Canada", "Îles Féroé", "Guernesey",
    "Israël", "Île de Man", "Japon", "Jersey", "Nouvelle-Zélande",
    "République de Corée", "Suisse", "Royaume-Uni", "Uruguay",
    "États-Unis (DPF)", "Canada (commercial)",
}

# Mesures de sécurité Art. 32
MESURES_SECURITE = [
    "chiffrement_donnees",
    "pseudonymisation",
    "controle_acces_rbac",
    "authentification_mfa",
    "journalisation_acces",
    "backup_chiffre",
    "procedure_violation",
    "formation_personnel",
    "evaluation_impact_aipd",
    "clause_contractuelle_dpa",
]


# ================================================================
# BASE DE DONNÉES DU REGISTRE
# ================================================================

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS organisation (
    id              INTEGER PRIMARY KEY,
    nom             TEXT NOT NULL,
    siren           TEXT,
    dpo_nom         TEXT,
    dpo_email       TEXT,
    dpo_tel         TEXT,
    responsable_nom TEXT,
    responsable_email TEXT,
    secteur         TEXT,
    effectif        INTEGER,
    created_at      TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS traitements (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ref                 TEXT UNIQUE NOT NULL,
    nom                 TEXT NOT NULL,
    description         TEXT,
    finalite            TEXT NOT NULL,
    base_legale         TEXT NOT NULL,
    base_legale_detail  TEXT,
    categories_personnes TEXT,
    categories_donnees  TEXT,
    categories_speciales TEXT DEFAULT '[]',
    destinataires       TEXT DEFAULT '[]',
    sous_traitants      TEXT DEFAULT '[]',
    transferts_tiers    TEXT DEFAULT '[]',
    delai_conservation  TEXT,
    mesures_securite    TEXT DEFAULT '[]',
    aipd_requise        INTEGER DEFAULT 0,
    aipd_realisee       INTEGER DEFAULT 0,
    statut              TEXT DEFAULT 'ACTIF',
    responsable_metier  TEXT,
    date_creation       TEXT,
    date_modification   TEXT,
    notes               TEXT
);

CREATE TABLE IF NOT EXISTS historique (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    traitement_ref TEXT,
    action      TEXT,
    auteur      TEXT,
    timestamp   TEXT,
    details     TEXT
);

CREATE TABLE IF NOT EXISTS violations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_violation   TEXT UNIQUE,
    traitement_ref  TEXT,
    date_decouverte TEXT,
    date_notification_cnil TEXT,
    date_notification_personnes TEXT,
    nature          TEXT,
    gravite         TEXT,
    personnes_affectees INTEGER,
    description     TEXT,
    mesures_prises  TEXT,
    statut          TEXT DEFAULT 'OUVERT'
);
"""


class RegistreRGPD:
    def __init__(self, db_path: str = "/tmp/registre_rgpd.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(DB_SCHEMA)
            conn.commit()

    def _log(self, conn, ref: str, action: str,
             auteur: str = "system", details: str = ""):
        conn.execute(
            "INSERT INTO historique (traitement_ref, action, auteur, timestamp, details) "
            "VALUES (?,?,?,?,?)",
            (ref, action, auteur, datetime.now().isoformat(), details)
        )

    # ── Organisation ──

    def set_organisation(self, data: dict):
        now = datetime.now().isoformat()
        with self._conn() as conn:
            existing = conn.execute("SELECT id FROM organisation").fetchone()
            if existing:
                cols = ", ".join(f"{k}=?" for k in data if k != "id")
                conn.execute(
                    f"UPDATE organisation SET {cols}, updated_at=? WHERE id=?",
                    [*[v for k, v in data.items() if k != "id"], now, existing["id"]]
                )
            else:
                data["created_at"] = now
                data["updated_at"] = now
                cols = ", ".join(data.keys())
                vals = ", ".join("?" * len(data))
                conn.execute(f"INSERT INTO organisation ({cols}) VALUES ({vals})",
                             list(data.values()))
            conn.commit()

    def get_organisation(self) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM organisation LIMIT 1").fetchone()
            return dict(row) if row else None

    # ── Traitements ──

    def ajouter_traitement(self, data: dict, auteur: str = "system") -> str:
        """Ajoute un traitement au registre."""
        now = datetime.now().isoformat()

        # Générer une référence unique
        if "ref" not in data:
            count = self._conn().execute(
                "SELECT COUNT(*) FROM traitements"
            ).fetchone()[0]
            data["ref"] = f"TRT-{date.today().year}-{count+1:04d}"

        data.setdefault("date_creation", now)
        data["date_modification"] = now

        # Sérialiser les listes en JSON
        for field in ["categories_speciales", "destinataires",
                      "sous_traitants", "transferts_tiers", "mesures_securite"]:
            if field in data and isinstance(data[field], list):
                data[field] = json.dumps(data[field], ensure_ascii=False)

        with self._conn() as conn:
            cols = ", ".join(data.keys())
            vals = ", ".join("?" * len(data))
            conn.execute(f"INSERT INTO traitements ({cols}) VALUES ({vals})",
                         list(data.values()))
            self._log(conn, data["ref"], "CREATION", auteur,
                      f"Traitement '{data.get('nom')}' ajouté")
            conn.commit()

        return data["ref"]

    def modifier_traitement(self, ref: str, updates: dict,
                            auteur: str = "system"):
        updates["date_modification"] = datetime.now().isoformat()
        for field in ["categories_speciales", "destinataires",
                      "sous_traitants", "transferts_tiers", "mesures_securite"]:
            if field in updates and isinstance(updates[field], list):
                updates[field] = json.dumps(updates[field], ensure_ascii=False)

        cols = ", ".join(f"{k}=?" for k in updates)
        with self._conn() as conn:
            conn.execute(f"UPDATE traitements SET {cols} WHERE ref=?",
                         [*updates.values(), ref])
            self._log(conn, ref, "MODIFICATION", auteur,
                      f"Champs modifiés : {list(updates.keys())}")
            conn.commit()

    def get_traitement(self, ref: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM traitements WHERE ref=?", (ref,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            for field in ["categories_speciales", "destinataires",
                          "sous_traitants", "transferts_tiers",
                          "mesures_securite"]:
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except Exception:
                        d[field] = []
            return d

    def lister_traitements(self, statut: str = None) -> list:
        query = "SELECT * FROM traitements"
        params = []
        if statut:
            query += " WHERE statut=?"
            params.append(statut)
        query += " ORDER BY ref"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for field in ["categories_speciales", "destinataires",
                          "sous_traitants", "transferts_tiers",
                          "mesures_securite"]:
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except Exception:
                        d[field] = []
            result.append(d)
        return result

    # ── Violations ──

    def enregistrer_violation(self, data: dict) -> str:
        ref = f"VIO-{date.today().strftime('%Y%m%d')}-{os.urandom(3).hex().upper()}"
        data["ref_violation"] = ref
        with self._conn() as conn:
            cols = ", ".join(data.keys())
            vals = ", ".join("?" * len(data))
            conn.execute(f"INSERT INTO violations ({cols}) VALUES ({vals})",
                         list(data.values()))
            conn.commit()
        return ref

    def lister_violations(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM violations ORDER BY date_decouverte DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ================================================================
    # VÉRIFICATEUR DE CONFORMITÉ CNIL
    # ================================================================

    def verifier_conformite(self) -> dict:
        """
        Vérifie la conformité du registre selon les exigences CNIL.
        Génère un score 0-100 et une liste d'actions correctives.
        """
        traitements = self.lister_traitements()
        org         = self.get_organisation()

        rapport = {
            "date_verification":  datetime.now().isoformat(),
            "score_global":       0,
            "niveau":             "",
            "nb_traitements":     len(traitements),
            "checks":             {},
            "anomalies":          [],
            "recommandations":    [],
            "traitements_risque": [],
        }

        if not traitements:
            rapport["anomalies"].append({
                "gravite": "CRITIQUE",
                "message": "Aucun traitement enregistré — registre vide",
                "article": "Art. 30 RGPD",
            })
            rapport["score_global"] = 0
            rapport["niveau"] = "❌ NON CONFORME"
            return rapport

        points_total = 0
        points_obtenus = 0

        # ── Check 1 : Organisation renseignée ──
        points_total += 10
        if org and org.get("nom") and org.get("dpo_email"):
            points_obtenus += 10
            rapport["checks"]["organisation"] = "✅ Renseignée"
        elif org and org.get("nom"):
            points_obtenus += 6
            rapport["checks"]["organisation"] = "⚠️ DPO manquant"
            rapport["anomalies"].append({
                "gravite": "MAJEUR",
                "message": "Coordonnées DPO non renseignées",
                "article": "Art. 30(1)(a)",
            })
        else:
            rapport["checks"]["organisation"] = "❌ Non renseignée"
            rapport["anomalies"].append({
                "gravite": "CRITIQUE",
                "message": "Informations organisation manquantes",
                "article": "Art. 30(1)(a)",
            })

        # ── Check 2 : Champs obligatoires par traitement ──
        points_total += 30
        champs_ok = 0
        for t in traitements:
            manquants = []
            if not t.get("finalite"):
                manquants.append("finalite")
            if not t.get("base_legale"):
                manquants.append("base_legale")
            if not t.get("categories_donnees"):
                manquants.append("categories_donnees")
            if not t.get("delai_conservation"):
                manquants.append("delai_conservation")

            if not manquants:
                champs_ok += 1
            else:
                rapport["anomalies"].append({
                    "gravite": "MAJEUR",
                    "ref":     t["ref"],
                    "message": f"[{t['ref']}] Champs manquants : {', '.join(manquants)}",
                    "article": "Art. 30(1)(b-f)",
                })

        ratio = champs_ok / max(len(traitements), 1)
        points_obtenus += int(30 * ratio)
        rapport["checks"]["champs_obligatoires"] = (
            f"✅ {champs_ok}/{len(traitements)}" if ratio == 1.0
            else f"⚠️  {champs_ok}/{len(traitements)} complets"
        )

        # ── Check 3 : Mesures de sécurité Art. 32 ──
        points_total += 20
        avec_mesures = sum(1 for t in traitements if t.get("mesures_securite"))
        ratio_sec = avec_mesures / max(len(traitements), 1)
        points_obtenus += int(20 * ratio_sec)
        rapport["checks"]["mesures_securite"] = (
            f"✅ {avec_mesures}/{len(traitements)}"
            if ratio_sec == 1.0 else
            f"⚠️  {avec_mesures}/{len(traitements)} documentées"
        )
        if ratio_sec < 1.0:
            rapport["anomalies"].append({
                "gravite": "MAJEUR",
                "message": f"{len(traitements)-avec_mesures} traitement(s) sans mesures de sécurité",
                "article": "Art. 32 RGPD",
            })

        # ── Check 4 : Catégories spéciales + AIPD ──
        points_total += 15
        speciales_sans_aipd = []
        for t in traitements:
            cats_spec = t.get("categories_speciales", [])
            if cats_spec and not t.get("aipd_realisee"):
                speciales_sans_aipd.append(t["ref"])
                rapport["traitements_risque"].append({
                    "ref":     t["ref"],
                    "nom":     t["nom"],
                    "risque":  "Données sensibles Art. 9 sans AIPD",
                    "article": "Art. 35 RGPD",
                })

        if not speciales_sans_aipd:
            points_obtenus += 15
            rapport["checks"]["aipd"] = "✅ AIPD réalisées pour données sensibles"
        else:
            points_obtenus += max(0, 15 - len(speciales_sans_aipd) * 3)
            rapport["checks"]["aipd"] = (
                f"❌ {len(speciales_sans_aipd)} traitement(s) nécessitent une AIPD"
            )
            rapport["anomalies"].append({
                "gravite": "CRITIQUE",
                "message": f"AIPD obligatoire non réalisée : {', '.join(speciales_sans_aipd)}",
                "article": "Art. 35 RGPD",
            })

        # ── Check 5 : Transferts hors UE ──
        points_total += 10
        transferts_non_encadres = []
        for t in traitements:
            for transfert in (t.get("transferts_tiers") or []):
                pays = transfert.get("pays", "")
                garantie = transfert.get("garantie", "")
                if pays and pays not in PAYS_ADEQUATION and not garantie:
                    transferts_non_encadres.append(f"{t['ref']} → {pays}")

        if not transferts_non_encadres:
            points_obtenus += 10
            rapport["checks"]["transferts"] = "✅ Transferts conformes (ou absents)"
        else:
            rapport["checks"]["transferts"] = (
                f"❌ {len(transferts_non_encadres)} transfert(s) non encadré(s)"
            )
            rapport["anomalies"].append({
                "gravite": "CRITIQUE",
                "message": f"Transferts hors UE sans garantie : {transferts_non_encadres}",
                "article": "Art. 44-49 RGPD",
            })

        # ── Check 6 : Délais de conservation ──
        points_total += 10
        sans_delai = [t["ref"] for t in traitements if not t.get("delai_conservation")]
        if not sans_delai:
            points_obtenus += 10
            rapport["checks"]["conservation"] = "✅ Délais définis pour tous"
        else:
            points_obtenus += max(0, 10 - len(sans_delai) * 2)
            rapport["checks"]["conservation"] = (
                f"⚠️  {len(sans_delai)} traitement(s) sans délai défini"
            )

        # ── Check 7 : Violations documentées ──
        points_total += 5
        violations = self.lister_violations()
        vio_en_retard = [
            v for v in violations
            if not v.get("date_notification_cnil")
            and v.get("gravite") in ("ELEVEE", "CRITIQUE")
        ]
        if not vio_en_retard:
            points_obtenus += 5
            rapport["checks"]["violations"] = (
                f"✅ {len(violations)} violation(s) enregistrée(s)"
                if violations else "✅ Aucune violation"
            )
        else:
            rapport["checks"]["violations"] = (
                f"❌ {len(vio_en_retard)} notification(s) CNIL en retard"
            )
            rapport["anomalies"].append({
                "gravite": "CRITIQUE",
                "message": (
                    f"{len(vio_en_retard)} violation(s) élevée(s) non notifiées "
                    "à la CNIL dans les 72h"
                ),
                "article": "Art. 33 RGPD",
            })

        # ── Score final ──
        score = int((points_obtenus / points_total) * 100) if points_total > 0 else 0
        rapport["score_global"] = score
        rapport["points"] = f"{points_obtenus}/{points_total}"

        if score >= 90:
            rapport["niveau"] = "✅ CONFORME"
        elif score >= 70:
            rapport["niveau"] = "⚠️  PARTIELLEMENT CONFORME"
        elif score >= 50:
            rapport["niveau"] = "🟠 NON CONFORME — Actions requises"
        else:
            rapport["niveau"] = "❌ NON CONFORME — Risque élevé"

        # Recommandations
        if score < 100:
            rapport["recommandations"] = _generer_recommandations(rapport["anomalies"])

        return rapport


def _generer_recommandations(anomalies: list) -> list:
    recs = []
    for a in sorted(anomalies, key=lambda x: {"CRITIQUE": 0, "MAJEUR": 1}.get(x["gravite"], 2)):
        rec = {
            "priorite": a["gravite"],
            "action":   "",
            "article":  a.get("article", ""),
            "delai":    "",
        }
        msg = a["message"]
        if "DPO" in msg:
            rec["action"] = "Nommer et enregistrer le DPO (obligatoire si >250 personnes ou données sensibles)"
            rec["delai"]  = "Immédiat"
        elif "AIPD" in msg:
            rec["action"] = "Réaliser une Analyse d'Impact (AIPD) pour les traitements à risque élevé"
            rec["delai"]  = "Avant mise en production"
        elif "mesures de sécurité" in msg:
            rec["action"] = "Documenter les mesures Art. 32 pour chaque traitement"
            rec["delai"]  = "30 jours"
        elif "notification" in msg.lower() and "cnil" in msg.lower():
            rec["action"] = "Notifier la CNIL dans les 72h (Art. 33) et les personnes si risque élevé"
            rec["delai"]  = "URGENT — 72h légales"
        elif "transferts" in msg.lower():
            rec["action"] = "Mettre en place des Clauses Contractuelles Types (CCT) ou BCR"
            rec["delai"]  = "Avant tout transfert"
        elif "manquants" in msg:
            rec["action"] = "Compléter les champs obligatoires du traitement concerné"
            rec["delai"]  = "7 jours"
        else:
            rec["action"] = f"Corriger : {msg[:80]}"
            rec["delai"]  = "30 jours"
        recs.append(rec)
    return recs[:10]


# ================================================================
# EXPORT HTML — Rapport officiel CNIL
# ================================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Registre des traitements — {{ org.nom }}</title>
  <style>
    :root {
      --primary: #003189; --accent: #e63946;
      --ok: #2a9d8f; --warn: #e9c46a; --err: #e63946;
      --bg: #f8f9fa; --card: #ffffff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif;
           background: var(--bg); color: #1d1d1d; font-size: 14px; }
    .page { max-width: 1200px; margin: 0 auto; padding: 30px 20px; }

    /* Header */
    header { background: var(--primary); color: #fff;
             padding: 30px; border-radius: 8px; margin-bottom: 30px; }
    header h1 { font-size: 24px; margin-bottom: 6px; }
    header .meta { font-size: 12px; opacity: .8; }
    .logo { float: right; font-size: 40px; }

    /* Score card */
    .score-section { display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
    .score-card {
      background: var(--card); border-radius: 8px; padding: 20px;
      box-shadow: 0 2px 8px rgba(0,0,0,.08); flex: 1; min-width: 180px;
      text-align: center;
    }
    .score-big { font-size: 48px; font-weight: 900; line-height: 1; }
    .score-label { font-size: 12px; color: #666; margin-top: 4px; }
    .score-ok   { color: var(--ok); }
    .score-warn { color: #e9c46a; }
    .score-err  { color: var(--err); }

    /* Checks */
    .checks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                   gap: 12px; margin-bottom: 30px; }
    .check-item { background: var(--card); border-radius: 6px; padding: 12px 16px;
                  border-left: 4px solid #ccc; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
    .check-item.ok   { border-left-color: var(--ok); }
    .check-item.warn { border-left-color: var(--warn); }
    .check-item.err  { border-left-color: var(--err); }
    .check-name  { font-weight: 600; font-size: 12px; color: #555; text-transform: uppercase; margin-bottom: 4px; }
    .check-value { font-size: 14px; }

    /* Table */
    .section { background: var(--card); border-radius: 8px; padding: 24px;
               margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,.06); }
    .section h2 { font-size: 16px; color: var(--primary); margin-bottom: 16px;
                  padding-bottom: 10px; border-bottom: 2px solid #eee; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #f0f4ff; color: var(--primary); padding: 10px 12px;
         text-align: left; font-weight: 600; white-space: nowrap; }
    td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
    tr:hover td { background: #fafbff; }
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 10px;
      font-size: 11px; font-weight: 600;
    }
    .badge-ok   { background: #d4edda; color: #155724; }
    .badge-warn { background: #fff3cd; color: #856404; }
    .badge-err  { background: #f8d7da; color: #721c24; }
    .badge-blue { background: #cce5ff; color: #004085; }

    /* Anomalies */
    .anomalie { padding: 10px 14px; border-radius: 6px; margin-bottom: 8px;
                border-left: 4px solid; }
    .anomalie.CRITIQUE { border-color: var(--err); background: #fff5f5; }
    .anomalie.MAJEUR   { border-color: var(--warn); background: #fffdf0; }
    .anomalie h4 { font-size: 12px; text-transform: uppercase; margin-bottom: 3px; }
    .anomalie p  { font-size: 13px; }
    .anomalie small { color: #888; font-size: 11px; }

    /* Footer */
    footer { text-align: center; color: #aaa; font-size: 11px;
             margin-top: 40px; padding-top: 20px;
             border-top: 1px solid #eee; }

    @media print {
      body { background: white; }
      .page { padding: 10px; }
      header { -webkit-print-color-adjust: exact; }
    }
  </style>
</head>
<body>
<div class="page">

  <header>
    <div class="logo">📋</div>
    <h1>Registre des activités de traitement</h1>
    <p>{{ org.nom }}{% if org.siren %} · SIREN {{ org.siren }}{% endif %}</p>
    <div class="meta">
      Généré le {{ now }} · Conforme Art. 30 RGPD
      {% if org.dpo_nom %} · DPO : {{ org.dpo_nom }} ({{ org.dpo_email }}){% endif %}
    </div>
  </header>

  <!-- Score de conformité -->
  <div class="score-section">
    <div class="score-card">
      <div class="score-big {% if conformite.score_global >= 90 %}score-ok{% elif conformite.score_global >= 60 %}score-warn{% else %}score-err{% endif %}">
        {{ conformite.score_global }}%
      </div>
      <div class="score-label">Score de conformité</div>
      <div style="margin-top:6px;font-size:13px">{{ conformite.niveau }}</div>
    </div>
    <div class="score-card">
      <div class="score-big" style="color:var(--primary)">{{ conformite.nb_traitements }}</div>
      <div class="score-label">Traitements enregistrés</div>
    </div>
    <div class="score-card">
      <div class="score-big score-{% if conformite.anomalies|length == 0 %}ok{% elif conformite.anomalies|length < 3 %}warn{% else %}err{% endif %}">
        {{ conformite.anomalies|length }}
      </div>
      <div class="score-label">Anomalies détectées</div>
    </div>
    <div class="score-card">
      <div class="score-big" style="color:#888">{{ violations|length }}</div>
      <div class="score-label">Violations enregistrées</div>
    </div>
  </div>

  <!-- Checks détaillés -->
  <div class="section">
    <h2>📊 État des contrôles de conformité</h2>
    <div class="checks-grid">
      {% for name, value in conformite.checks.items() %}
      <div class="check-item {% if '✅' in value %}ok{% elif '❌' in value %}err{% else %}warn{% endif %}">
        <div class="check-name">{{ name.replace('_', ' ') }}</div>
        <div class="check-value">{{ value }}</div>
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- Registre des traitements -->
  <div class="section">
    <h2>🗂️ Registre des activités de traitement (Art. 30 RGPD)</h2>
    <table>
      <thead>
        <tr>
          <th>Réf.</th>
          <th>Traitement</th>
          <th>Finalité</th>
          <th>Base légale</th>
          <th>Données</th>
          <th>Conservation</th>
          <th>Sécurité</th>
          <th>Statut</th>
        </tr>
      </thead>
      <tbody>
        {% for t in traitements %}
        <tr>
          <td><strong>{{ t.ref }}</strong></td>
          <td>
            {{ t.nom }}<br>
            {% if t.responsable_metier %}
            <small style="color:#888">{{ t.responsable_metier }}</small>
            {% endif %}
          </td>
          <td style="max-width:200px">{{ t.finalite[:80] }}{% if t.finalite|length > 80 %}…{% endif %}</td>
          <td>
            <span class="badge badge-blue">{{ t.base_legale }}</span>
          </td>
          <td style="max-width:180px">
            {{ t.categories_donnees[:60] if t.categories_donnees else '—' }}
            {% if t.categories_speciales %}
            <br><span class="badge badge-err">Art. 9 — Données sensibles</span>
            {% endif %}
          </td>
          <td>{{ t.delai_conservation or '⚠️ Non défini' }}</td>
          <td>
            {% if t.mesures_securite %}
            <span class="badge badge-ok">{{ t.mesures_securite|length }} mesure(s)</span>
            {% else %}
            <span class="badge badge-err">Non documenté</span>
            {% endif %}
          </td>
          <td>
            <span class="badge {% if t.statut == 'ACTIF' %}badge-ok{% elif t.statut == 'SUSPENDU' %}badge-warn{% else %}badge-err{% endif %}">
              {{ t.statut }}
            </span>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Anomalies -->
  {% if conformite.anomalies %}
  <div class="section">
    <h2>⚠️ Anomalies de conformité détectées</h2>
    {% for a in conformite.anomalies %}
    <div class="anomalie {{ a.gravite }}">
      <h4>{{ a.gravite }}{% if a.get('ref') %} · {{ a.ref }}{% endif %}</h4>
      <p>{{ a.message }}</p>
      {% if a.get('article') %}<small>{{ a.article }}</small>{% endif %}
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- Recommandations -->
  {% if conformite.recommandations %}
  <div class="section">
    <h2>🎯 Plan d'action recommandé</h2>
    <table>
      <thead>
        <tr><th>Priorité</th><th>Action corrective</th><th>Article</th><th>Délai</th></tr>
      </thead>
      <tbody>
        {% for r in conformite.recommandations %}
        <tr>
          <td>
            <span class="badge {% if r.priorite == 'CRITIQUE' %}badge-err{% elif r.priorite == 'MAJEUR' %}badge-warn{% else %}badge-blue{% endif %}">
              {{ r.priorite }}
            </span>
          </td>
          <td>{{ r.action }}</td>
          <td><small>{{ r.article }}</small></td>
          <td><strong>{{ r.delai }}</strong></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- Violations -->
  {% if violations %}
  <div class="section">
    <h2>🚨 Registre des violations (Art. 33 RGPD)</h2>
    <table>
      <thead>
        <tr><th>Réf.</th><th>Traitement</th><th>Date</th><th>Gravité</th>
            <th>Personnes</th><th>Notif. CNIL</th><th>Statut</th></tr>
      </thead>
      <tbody>
        {% for v in violations %}
        <tr>
          <td><strong>{{ v.ref_violation }}</strong></td>
          <td>{{ v.traitement_ref or '—' }}</td>
          <td>{{ v.date_decouverte[:10] }}</td>
          <td><span class="badge {% if v.gravite == 'CRITIQUE' %}badge-err{% elif v.gravite == 'ELEVEE' %}badge-warn{% else %}badge-blue{% endif %}">{{ v.gravite }}</span></td>
          <td>{{ v.personnes_affectees or '?' }}</td>
          <td>{% if v.date_notification_cnil %}✅ {{ v.date_notification_cnil[:10] }}{% else %}<span class="badge badge-err">Non notifiée</span>{% endif %}</td>
          <td>{{ v.statut }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <footer>
    Registre généré automatiquement le {{ now }} · Art. 30 RGPD
    · Confidentiel — Usage interne uniquement
    · Bouclier Numérique Jour 10
  </footer>
</div>
</body>
</html>"""


def generer_rapport_html(registre: RegistreRGPD, output_path: Path) -> str:
    """Génère le rapport HTML officiel."""
    try:
        from jinja2 import Environment
        env = Environment()
        # Allow .get() on dicts in Jinja2
        env.globals['dict'] = dict
        template = env.from_string(HTML_TEMPLATE)
    except ImportError:
        raise ImportError("pip install jinja2")

    org          = registre.get_organisation() or {"nom": "Organisation non renseignée"}
    traitements  = registre.lister_traitements()
    violations   = registre.lister_violations()
    conformite   = registre.verifier_conformite()

    html = template.render(
        org         = org,
        traitements = traitements,
        violations  = violations,
        conformite  = conformite,
        now         = datetime.now().strftime("%d/%m/%Y à %H:%M"),
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return str(output_path)


# ================================================================
# JEUX DE DONNÉES DE DÉMONSTRATION
# ================================================================

def charger_demo(registre: RegistreRGPD):
    """Charge un jeu de données réaliste pour la démo."""

    registre.set_organisation({
        "nom":                "TechCorp SARL",
        "siren":              "123 456 789",
        "dpo_nom":            "Claire Bernard",
        "dpo_email":          "dpo@techcorp.fr",
        "dpo_tel":            "+33 1 23 45 67 89",
        "responsable_nom":    "Pierre Dupont",
        "responsable_email":  "pdupont@techcorp.fr",
        "secteur":            "Édition de logiciels (NAF 5829C)",
        "effectif":           87,
    })

    traitements_demo = [
        {
            "nom":                "Gestion de la relation client (CRM)",
            "finalite":           "Suivi commercial, facturation, support client, historique achats",
            "base_legale":        "CONTRAT",
            "base_legale_detail": "Exécution du contrat de vente",
            "categories_personnes": "Clients, prospects, contacts entreprises",
            "categories_donnees": "Nom, prénom, email, téléphone, adresse, historique achats, preferences",
            "destinataires":      json.dumps(["Équipe commerciale", "Support client", "Comptabilité"]),
            "sous_traitants":     json.dumps([
                {"nom": "Salesforce", "pays": "États-Unis (DPF)", "dpa": True},
            ]),
            "delai_conservation": "3 ans après dernier contact",
            "mesures_securite":   json.dumps(["chiffrement_donnees", "controle_acces_rbac",
                                              "authentification_mfa", "journalisation_acces"]),
            "aipd_requise":       0,
            "responsable_metier": "Direction Commerciale",
        },
        {
            "nom":                "Gestion des ressources humaines",
            "finalite":           "Administration du personnel, paie, formation, gestion des accès",
            "base_legale":        "OBLIGATION_LEGALE",
            "base_legale_detail": "Code du travail, obligations fiscales et sociales",
            "categories_personnes": "Salariés, stagiaires, alternants",
            "categories_donnees": ("Identité, coordonnées, RIB, numéro SS, contrat, "
                                   "salaire, absences, évaluations"),
            "categories_speciales": json.dumps(["donnees_de_sante"]),
            "destinataires":      json.dumps(["RH", "Direction", "URSSAF", "Mutuelle"]),
            "sous_traitants":     json.dumps([
                {"nom": "PayFit", "pays": "France", "dpa": True},
            ]),
            "delai_conservation": "5 ans après départ du salarié",
            "mesures_securite":   json.dumps(["chiffrement_donnees", "controle_acces_rbac",
                                              "authentification_mfa", "backup_chiffre"]),
            "aipd_requise":       1,
            "aipd_realisee":      1,
            "responsable_metier": "DRH",
        },
        {
            "nom":                "Statistiques d'utilisation (Analytics)",
            "finalite":           "Amélioration du produit, mesure audience, détection bugs",
            "base_legale":        "CONSENTEMENT",
            "base_legale_detail": "Cookie analytics — bandeau CNIL obligatoire",
            "categories_personnes": "Utilisateurs du logiciel",
            "categories_donnees": "IP pseudonymisée, pages visitées, durée session, navigateur",
            "destinataires":      json.dumps(["Équipe produit", "Développement"]),
            "sous_traitants":     json.dumps([
                {"nom": "Matomo (auto-hébergé)", "pays": "France", "dpa": False},
            ]),
            "delai_conservation": "13 mois (recommandation CNIL cookies)",
            "mesures_securite":   json.dumps(["pseudonymisation", "chiffrement_donnees"]),
            "responsable_metier": "Product Manager",
        },
        {
            "nom":                "Vidéosurveillance des locaux",
            "finalite":           "Sécurité des personnes et des biens",
            "base_legale":        "INTERET_LEGITIME",
            "base_legale_detail": "Intérêt légitime — sécurité des locaux professionnels",
            "categories_personnes": "Salariés, visiteurs, prestataires",
            "categories_donnees": "Images et vidéos de personnes",
            "destinataires":      json.dumps(["Direction", "Sécurité", "Police (si réquisition)"]),
            "delai_conservation": "30 jours (maximum légal)",
            "mesures_securite":   json.dumps(["controle_acces_rbac", "journalisation_acces"]),
            "responsable_metier": "Direction des services généraux",
            # Délibérément sans affichage légal pour la démo
        },
        {
            "nom":                "Recrutement et gestion des candidatures",
            "finalite":           "Sélection de candidats, constitution de viviers RH",
            "base_legale":        "INTERET_LEGITIME",
            "categories_personnes": "Candidats",
            "categories_donnees": "CV, lettre motivation, diplômes, expériences, entretiens",
            "destinataires":      json.dumps(["RH", "Managers recruteurs"]),
            "sous_traitants":     json.dumps([
                {"nom": "LinkedIn Talent", "pays": "États-Unis (DPF)", "dpa": True},
                {"nom": "Welcome to the Jungle", "pays": "France", "dpa": True},
            ]),
            "delai_conservation": "2 ans (CNIL — avec consentement du candidat)",
            # Pas de mesures de sécurité documentées — anomalie intentionnelle
            "responsable_metier": "DRH",
        },
        {
            "nom":                "Transferts financiers internationaux",
            "finalite":           "Paiements clients et fournisseurs hors UE",
            "base_legale":        "CONTRAT",
            "categories_personnes": "Clients et fournisseurs internationaux",
            "categories_donnees": "IBAN, RIB, coordonnées bancaires, montants",
            "destinataires":      json.dumps(["Comptabilité", "Banques partenaires"]),
            "transferts_tiers":   json.dumps([
                {"pays": "Inde", "garantie": "CCT 2021",
                 "description": "Prestataire comptable Bangalore"},
                {"pays": "Maroc", "garantie": "",     # Anomalie : sans garantie
                 "description": "Filiale commerciale Casablanca"},
            ]),
            "delai_conservation": "10 ans (Code commerce)",
            "mesures_securite":   json.dumps(["chiffrement_donnees", "authentification_mfa"]),
            "responsable_metier": "DAF",
        },
    ]

    for t in traitements_demo:
        registre.ajouter_traitement(t, auteur="demo_loader")

    # Violations simulées
    registre.enregistrer_violation({
        "traitement_ref":            "TRT-2026-0001",
        "date_decouverte":           "2026-01-15",
        "date_notification_cnil":    "2026-01-17",
        "date_notification_personnes": None,
        "nature":                    "Accès non autorisé à la base clients",
        "gravite":                   "ELEVEE",
        "personnes_affectees":       1240,
        "description":               "Credential compromis d'un compte admin CRM — accès externe détecté",
        "mesures_prises":            "Reset credentials, revocation tokens, audit accès",
        "statut":                    "CLOTURE",
    })


# ================================================================
# DÉMONSTRATION COMPLÈTE
# ================================================================

def run_demo(output_html: Path = None):
    import tempfile

    SEP = "=" * 62

    print(f"\n{SEP}")
    print("  DEMO -- Registre des traitements RGPD (TechCorp SARL)")
    print(f"{SEP}\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        db   = Path(tmpdir) / "registre.db"
        html = output_html or Path(tmpdir) / "registre_rgpd.html"

        registre = RegistreRGPD(str(db))
        charger_demo(registre)

        traitements = registre.lister_traitements()
        org         = registre.get_organisation()

        # ── Aperçu ──
        print(f"  Organisation : {org['nom']} ({org['effectif']} salariés)")
        print(f"  DPO          : {org['dpo_nom']} — {org['dpo_email']}")
        print(f"  Traitements  : {len(traitements)}\n")

        print(f"  {'─'*60}")
        print(f"  📋  REGISTRE DES TRAITEMENTS")
        print(f"  {'─'*60}")
        print(f"  {'Réf.':<16} {'Nom':<35} {'Base légale':<22} {'Conservation'}")
        print(f"  {'─'*16} {'─'*35} {'─'*22} {'─'*15}")
        for t in traitements:
            has_spec = bool(t.get("categories_speciales"))
            flag = " 🔴" if has_spec else ""
            print(f"  {t['ref']:<16} {t['nom'][:34]:<35} "
                  f"{t['base_legale']:<22} {(t.get('delai_conservation') or '?')[:18]}{flag}")

        # ── Analyse de conformité ──
        print(f"\n  {'─'*60}")
        print(f"  📊  VERIFICATION DE CONFORMITE CNIL")
        print(f"  {'─'*60}\n")

        conformite = registre.verifier_conformite()

        # Barre de score
        score = conformite["score_global"]
        filled = score // 5
        bar = "█" * filled + "░" * (20 - filled)
        color_label = ("CONFORME" if score >= 90
                       else "PARTIELLEMENT CONFORME" if score >= 70
                       else "NON CONFORME")
        print(f"  Score global : [{bar}] {score}/100 — {color_label}")
        print(f"  Points       : {conformite['points']}\n")

        print(f"  Contrôles détaillés :")
        for check, value in conformite["checks"].items():
            print(f"    {check.replace('_',' '):<28} {value}")

        if conformite["anomalies"]:
            print(f"\n  {len(conformite['anomalies'])} anomalie(s) détectée(s) :")
            for a in conformite["anomalies"]:
                icon = "🔴" if a["gravite"] == "CRITIQUE" else "🟠"
                print(f"    {icon} [{a['gravite']:<8}] {a['message'][:65]}")
                if a.get("article"):
                    print(f"             → {a['article']}")

        if conformite["recommandations"]:
            print(f"\n  Plan d'action :")
            for i, r in enumerate(conformite["recommandations"][:5], 1):
                print(f"    {i}. [{r['priorite']:<8}] {r['action'][:62]}")
                print(f"              Délai : {r['delai']} · {r['article']}")

        # ── Violations ──
        violations = registre.lister_violations()
        print(f"\n  Violations enregistrées : {len(violations)}")
        for v in violations:
            notif = f"CNIL notifiée {v['date_notification_cnil'][:10]}" \
                    if v.get("date_notification_cnil") else "⚠️ Non notifiée"
            print(f"    {v['ref_violation']} · {v['gravite']:<8} · "
                  f"{v['personnes_affectees']} personnes · {notif}")

        # ── Export HTML ──
        print(f"\n  {'─'*60}")
        print(f"  📄  GÉNÉRATION DU RAPPORT HTML OFFICIEL")
        print(f"  {'─'*60}\n")

        if output_html is None:
            # Si pas de chemin spécifié, copier dans outputs
            html_final = Path("/mnt/user-data/outputs/registre_rgpd.html")
        else:
            html_final = output_html

        generer_rapport_html(registre, html_final)
        print(f"  ✅  Rapport généré : {html_final}")
        print(f"  Taille : {html_final.stat().st_size:,} octets")

        # ── Bilan ──
        print(f"\n{SEP}")
        print(f"  📋  CONFORMITÉ ART. 30 RGPD")
        print(f"{SEP}\n")
        print(
            "  Ce registre couvre les 7 mentions obligatoires :\n"
            "  ✅  (a) Responsable de traitement + DPO\n"
            "  ✅  (b) Finalités de chaque traitement\n"
            "  ✅  (c) Catégories de personnes et de données\n"
            "  ✅  (d) Destinataires internes et sous-traitants\n"
            "  ✅  (e) Transferts hors UE avec garanties\n"
            "  ✅  (f) Délais de conservation\n"
            "  ✅  (g) Mesures de sécurité Art. 32\n"
            "\n"
            "  + Bonus : Score de maturité RGPD automatique\n"
            "          Plan d'action priorisé\n"
            "          Registre des violations Art. 33\n"
            "          Export HTML imprimable (CNIL-ready)\n"
            "\n"
            "  En cas de contrôle CNIL :\n"
            "  python3 registre_traitements.py export --html rapport_cnil.html\n"
            "  → Rapport prêt en 3 secondes\n"
        )

        print(f"  Sanction possible sans registre :\n"
              f"  Art. 83 §4 → jusqu'à 10M€ ou 2% CA mondial\n")


# ================================================================
# CLI
# ================================================================

def main():
    print(__doc__)
    parser = argparse.ArgumentParser(description="Registre RGPD — Bouclier Numérique Jour 10")
    sub    = parser.add_subparsers(dest="cmd")

    sub.add_parser("demo", help="Démonstration complète")

    p_export = sub.add_parser("export", help="Exporter le rapport")
    p_export.add_argument("--html", default="registre_rgpd.html")
    p_export.add_argument("--db",   default="/tmp/registre_rgpd.db")

    p_check = sub.add_parser("check", help="Vérifier la conformité")
    p_check.add_argument("--db", default="/tmp/registre_rgpd.db")

    p_list = sub.add_parser("list", help="Lister les traitements")
    p_list.add_argument("--db", default="/tmp/registre_rgpd.db")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    db       = getattr(args, "db", "/tmp/registre_rgpd.db")
    registre = RegistreRGPD(db)

    if args.cmd == "export":
        generer_rapport_html(registre, Path(args.html))
        print(f"\n  ✅  Rapport HTML : {args.html}")

    elif args.cmd == "check":
        c = registre.verifier_conformite()
        print(f"\n  Score : {c['score_global']}/100 — {c['niveau']}")
        for k, v in c["checks"].items():
            print(f"  {k}: {v}")
        for a in c["anomalies"]:
            print(f"\n  ⚠️  {a['gravite']}: {a['message']}")

    elif args.cmd == "list":
        ts = registre.lister_traitements()
        print(f"\n  {len(ts)} traitement(s) :")
        for t in ts:
            print(f"  {t['ref']:<18} {t['nom']}")


if __name__ == "__main__":
    main()
