#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 16 : SIMULATION DE PHISHING       ║
║  Objectif  : Tester la vigilance des collaborateurs              ║
║  Méthode   : Email simulé → Tracking clic → Page d'éducation     ║
║  Éthique   : Usage interne uniquement · Accord DRH obligatoire   ║
╚══════════════════════════════════════════════════════════════════╝

Contexte légal et éthique :
  Une simulation de phishing est légale ET recommandée quand :
  ✅  La direction / DRH a donné son accord écrit
  ✅  Les employés sont prévenus qu'ils PEUVENT recevoir des tests
  ✅  Le but est éducatif, pas punitif
  ✅  Les données de clic sont anonymisées après analyse
  ✅  Une formation est proposée aux personnes ayant cliqué

  Cadre légal France :
  • ANSSI — Guide d'hygiène informatique (mesure 42)
  • CNIL — Surveillance des salariés : accord DRH + info collective
  • Art. L1222-4 Code du travail : information préalable obligatoire

Ce que le système fait :
  1. Génère des emails de phishing réalistes (templates variés)
  2. Intègre un pixel de tracking + lien traçable unique par destinataire
  3. Lance un serveur HTTP local qui enregistre les clics
  4. Redirige immédiatement vers la page d'éducation
  5. Génère des rapports de sensibilisation pour la direction

Scénarios disponibles :
  • reset_password  — "Réinitialisez votre mot de passe maintenant"
  • it_security      — "Alerte sécurité : accès suspect détecté"
  • hr_document      — "Document RH à signer avant vendredi"
  • invoice          — "Facture fournisseur en attente de validation"
  • shared_file      — "Fichier partagé vous attend sur OneDrive"
"""

import os
import sys
import json
import uuid
import sqlite3
import hashlib
import argparse
import threading
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ================================================================
# TEMPLATES D'EMAILS DE PHISHING
# ================================================================

EMAIL_TEMPLATES = {

    "reset_password": {
        "subject":    "[SÉCURITÉ] Action requise : réinitialisez votre mot de passe",
        "sender_name": "Équipe IT — Support Informatique",
        "urgency":    "haute",
        "indicators": [
            "Domaine expéditeur différent du domaine interne",
            "Urgence artificielle (24h)",
            "Lien de réinitialisation suspect",
            "Signature générique sans prénom",
            "URL qui ne correspond pas au domaine officiel",
        ],
        "html": """
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;border:1px solid #e0e0e0">
  <div style="background:#c0392b;padding:16px 24px">
    <span style="color:white;font-weight:bold;font-size:18px">🔐 Alerte Sécurité</span>
  </div>
  <div style="padding:24px;background:#fff">
    <p style="color:#333">Bonjour,</p>
    <p style="color:#333">Notre système de sécurité a détecté une connexion inhabituelle
    à votre compte depuis un appareil non reconnu.</p>
    <div style="background:#fff3cd;border-left:4px solid #ffc107;padding:12px;margin:16px 0">
      <strong>⚠️ Vous avez 24 heures pour sécuriser votre compte.</strong><br>
      <small>Passé ce délai, votre accès sera suspendu.</small>
    </div>
    <a href="{{TRACKING_URL}}" style="display:inline-block;background:#c0392b;color:white;
    padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;margin:8px 0">
      Sécuriser mon compte maintenant →
    </a>
    <p style="color:#666;font-size:12px;margin-top:24px">
      Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.<br>
      Support IT — <a href="mailto:it-support@{{FAKE_DOMAIN}}">it-support@{{FAKE_DOMAIN}}</a>
    </p>
  </div>
</div>""",
    },

    "it_security": {
        "subject":    "[URGENT] Votre compte a été compromis — intervention immédiate",
        "sender_name": "CERT Interne — Cybersécurité",
        "urgency":    "critique",
        "indicators": [
            "Pression extrême et urgence (URGENT en majuscules)",
            "Menace de suspension immédiate",
            "Demande de credentials via un formulaire externe",
            "Expéditeur non vérifié",
            "Absence de référence interne (ticket, numéro)",
        ],
        "html": """
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
  <div style="background:#1a1a2e;padding:20px 24px;text-align:center">
    <span style="color:#e94560;font-size:22px;font-weight:bold">⚠️ ALERTE SÉCURITÉ CRITIQUE</span>
  </div>
  <div style="background:#0f3460;padding:20px 24px">
    <p style="color:#e0e0e0">Nous avons détecté une activité malveillante associée à votre compte.
    Des données sensibles ont peut-être été exposées.</p>
    <p style="color:#e94560;font-weight:bold">ACTION REQUISE DANS LES 2 HEURES</p>
    <a href="{{TRACKING_URL}}" style="display:block;text-align:center;background:#e94560;
    color:white;padding:14px;text-decoration:none;border-radius:4px;font-weight:bold;
    font-size:16px;margin:16px 0">
      🔒 VÉRIFIER MON IDENTITÉ MAINTENANT
    </a>
    <p style="color:#aaa;font-size:11px">
      Réf. ticket : INC-{{FAKE_ID}} | CERT Interne | Ne pas transférer
    </p>
  </div>
</div>""",
    },

    "hr_document": {
        "subject":    "Document à signer : Avenant à votre contrat de travail",
        "sender_name": "Ressources Humaines",
        "urgency":    "normale",
        "indicators": [
            "Demande de signature via service externe non officiel",
            "Pas de mention du nom complet du destinataire",
            "Lien DocuSign-like mais domaine différent",
            "Aucune référence à un échange RH préalable",
            "Pièce jointe ou lien suspect",
        ],
        "html": """
<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;border:1px solid #ddd">
  <div style="background:#2c3e50;padding:18px 24px;display:flex;align-items:center">
    <span style="color:white;font-size:16px">📋 Ressources Humaines</span>
  </div>
  <div style="padding:28px;background:#fff">
    <p>Bonjour,</p>
    <p>Suite aux discussions récentes, veuillez trouver ci-joint votre avenant contractuel
    pour l'exercice 2026. Ce document nécessite votre signature électronique avant le
    <strong>vendredi 28 février 2026</strong>.</p>
    <div style="border:1px solid #e0e0e0;border-radius:6px;padding:16px;margin:20px 0;
    background:#f9f9f9">
      <p style="margin:0 0 8px"><strong>📄 Avenant_Contrat_2026.pdf</strong></p>
      <p style="margin:0;color:#666;font-size:13px">Signature requise · Confidentiel</p>
    </div>
    <a href="{{TRACKING_URL}}" style="display:inline-block;background:#27ae60;color:white;
    padding:11px 26px;text-decoration:none;border-radius:4px;font-size:14px">
      ✍️ Signer le document
    </a>
    <p style="color:#888;font-size:12px;margin-top:24px;border-top:1px solid #eee;padding-top:16px">
      Ressources Humaines · {{COMPANY_NAME}}<br>
      <em>Ce message et ses pièces jointes sont confidentiels.</em>
    </p>
  </div>
</div>""",
    },

    "invoice": {
        "subject":    "Facture #INV-2026-0892 en attente de validation — Échéance dépassée",
        "sender_name": "Service Comptabilité",
        "urgency":    "haute",
        "indicators": [
            "Pression sur l'échéance et pénalités",
            "RIB différent des coordonnées habituelles du fournisseur",
            "Email expéditeur avec domaine proche mais différent (typosquatting)",
            "Lien vers un portail de paiement non officiel",
            "Aucune référence à un bon de commande interne",
        ],
        "html": """
<div style="font-family:Georgia,serif;max-width:600px;margin:0 auto;border:1px solid #ccc">
  <div style="background:#f0f0f0;padding:16px 24px;border-bottom:3px solid #e67e22">
    <strong style="font-size:18px">FACTURE — RELANCE URGENTE</strong>
  </div>
  <div style="padding:24px;background:#fff">
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="background:#f9f9f9"><td style="padding:8px;border:1px solid #ddd"><strong>Réf.</strong></td>
      <td style="padding:8px;border:1px solid #ddd">INV-2026-0892</td></tr>
      <tr><td style="padding:8px;border:1px solid #ddd"><strong>Montant TTC</strong></td>
      <td style="padding:8px;border:1px solid #ddd;color:#c0392b"><strong>4 890,00 €</strong></td></tr>
      <tr style="background:#f9f9f9"><td style="padding:8px;border:1px solid #ddd"><strong>Échéance</strong></td>
      <td style="padding:8px;border:1px solid #ddd;color:#c0392b">DÉPASSÉE — pénalités en cours</td></tr>
    </table>
    <p style="margin-top:16px">Merci de procéder au règlement immédiat pour éviter les pénalités
    contractuelles (1,5% par semaine de retard).</p>
    <a href="{{TRACKING_URL}}" style="display:inline-block;background:#e67e22;color:white;
    padding:12px 24px;text-decoration:none;border-radius:4px;font-weight:bold;margin-top:8px">
      💳 Accéder au portail de paiement
    </a>
    <p style="font-size:11px;color:#999;margin-top:20px">
      Comptabilité Fournisseurs · contact@{{FAKE_DOMAIN}}<br>
      IBAN : FR76 XXXX XXXX XXXX XXXX XXXX — BIC : XXXXFRXX
    </p>
  </div>
</div>""",
    },

    "shared_file": {
        "subject":    "{{SENDER_FIRSTNAME}} a partagé un fichier avec vous",
        "sender_name": "Microsoft OneDrive",
        "urgency":    "basse",
        "indicators": [
            "Email 'de Microsoft' mais expéditeur non-Microsoft",
            "Prénom d'un collègue réel utilisé (harvesting LinkedIn)",
            "Bouton 'Ouvrir dans OneDrive' → domaine non-Microsoft",
            "Absence de logo officiel Microsoft authentique",
            "URL prévisualisée ne correspond pas à sharepoint.com",
        ],
        "html": """
<div style="font-family:'Segoe UI',sans-serif;max-width:600px;margin:0 auto">
  <div style="background:#0078d4;padding:16px 24px">
    <span style="color:white;font-weight:600;font-size:16px">Microsoft OneDrive</span>
  </div>
  <div style="background:#fff;padding:28px;border:1px solid #e0e0e0">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <div style="width:40px;height:40px;background:#0078d4;border-radius:50%;
      display:flex;align-items:center;justify-content:center;color:white;font-weight:bold">
        {{SENDER_INITIAL}}
      </div>
      <div>
        <strong>{{SENDER_FIRSTNAME}} {{SENDER_LASTNAME}}</strong><br>
        <span style="color:#666;font-size:13px">a partagé un fichier avec vous</span>
      </div>
    </div>
    <div style="border:1px solid #e0e0e0;border-radius:4px;padding:16px;
    background:#f8f8f8;margin-bottom:20px">
      <span style="font-size:24px">📊</span>
      <strong style="display:block;margin-top:4px">Rapport_Q1_2026_confidentiel.xlsx</strong>
      <span style="color:#666;font-size:12px">Partagé le {{DATE}} · 2,4 Mo</span>
    </div>
    <a href="{{TRACKING_URL}}" style="display:inline-block;background:#0078d4;color:white;
    padding:11px 22px;text-decoration:none;border-radius:4px;font-weight:600">
      Ouvrir dans OneDrive
    </a>
    <p style="font-size:11px;color:#aaa;margin-top:20px">
      Microsoft Corporation · One Microsoft Way · Redmond, WA 98052
    </p>
  </div>
</div>""",
    },
}


# ================================================================
# BASE DE DONNÉES DE TRACKING
# ================================================================

class PhishingTracker:
    def __init__(self, db_path: str = "/tmp/phishing_sim.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id           TEXT PRIMARY KEY,
                    name         TEXT,
                    template     TEXT,
                    created_at   TEXT,
                    launched_at  TEXT,
                    status       TEXT DEFAULT 'DRAFT',
                    company      TEXT,
                    sender_name  TEXT,
                    notes        TEXT
                );
                CREATE TABLE IF NOT EXISTS targets (
                    id           TEXT PRIMARY KEY,
                    campaign_id  TEXT,
                    token        TEXT UNIQUE NOT NULL,
                    email_hash   TEXT,
                    department   TEXT,
                    sent_at      TEXT,
                    opened_at    TEXT,
                    clicked_at   TEXT,
                    submitted_at TEXT,
                    ip_hash      TEXT,
                    user_agent   TEXT,
                    educated     INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    token        TEXT,
                    event_type   TEXT,
                    timestamp    TEXT,
                    ip_hash      TEXT,
                    details      TEXT
                );
            """)
            conn.commit()

    def create_campaign(self, name: str, template: str,
                         company: str = "TechCorp") -> str:
        cid = f"CAMP-{datetime.now().strftime('%Y%m%d')}-{os.urandom(3).hex().upper()}"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO campaigns (id,name,template,created_at,company) VALUES (?,?,?,?,?)",
                (cid, name, template, datetime.now().isoformat(), company)
            )
            conn.commit()
        return cid

    def add_target(self, campaign_id: str, email: str,
                    department: str = "") -> str:
        token    = hashlib.sha256(
            f"{campaign_id}{email}{os.urandom(8).hex()}".encode()
        ).hexdigest()[:16]
        email_h  = hashlib.sha256(email.lower().encode()).hexdigest()[:16]
        tid      = f"TGT-{os.urandom(4).hex().upper()}"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO targets (id,campaign_id,token,email_hash,department) "
                "VALUES (?,?,?,?,?)",
                (tid, campaign_id, token, email_h, department)
            )
            conn.commit()
        return token

    def record_event(self, token: str, event_type: str,
                      ip: str = "", details: str = ""):
        ip_h = hashlib.sha256(ip.encode()).hexdigest()[:12] if ip else ""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO events (token,event_type,timestamp,ip_hash,details) "
                "VALUES (?,?,?,?,?)",
                (token, event_type, datetime.now().isoformat(), ip_h, details)
            )
            if event_type == "CLICK":
                conn.execute(
                    "UPDATE targets SET clicked_at=?, ip_hash=? WHERE token=?",
                    (datetime.now().isoformat(), ip_h, token)
                )
            elif event_type == "OPEN":
                conn.execute(
                    "UPDATE targets SET opened_at=? WHERE token=?",
                    (datetime.now().isoformat(), token)
                )
            elif event_type == "EDUCATED":
                conn.execute(
                    "UPDATE targets SET educated=1 WHERE token=?", (token,)
                )
            conn.commit()

    def get_stats(self, campaign_id: str) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            total   = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE campaign_id=?", (campaign_id,)
            ).fetchone()[0]
            sent    = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE campaign_id=? AND sent_at IS NOT NULL",
                (campaign_id,)
            ).fetchone()[0]
            opened  = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE campaign_id=? AND opened_at IS NOT NULL",
                (campaign_id,)
            ).fetchone()[0]
            clicked = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE campaign_id=? AND clicked_at IS NOT NULL",
                (campaign_id,)
            ).fetchone()[0]
            educated = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE campaign_id=? AND educated=1",
                (campaign_id,)
            ).fetchone()[0]
            by_dept  = conn.execute(
                """SELECT department, COUNT(*) as total,
                   SUM(CASE WHEN clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicked
                   FROM targets WHERE campaign_id=? GROUP BY department""",
                (campaign_id,)
            ).fetchall()

        base = max(sent, 1)
        return {
            "total":      total,
            "sent":       sent,
            "opened":     opened,
            "clicked":    clicked,
            "educated":   educated,
            "open_rate":  round(opened  / base * 100),
            "click_rate": round(clicked / base * 100),
            "edu_rate":   round(educated / max(clicked, 1) * 100),
            "by_dept":    [dict(r) for r in by_dept],
        }

    def get_campaign(self, cid: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(
                "SELECT * FROM campaigns WHERE id=?", (cid,)
            ).fetchone()


# ================================================================
# GÉNÉRATEUR D'EMAILS
# ================================================================

def generate_email_html(template_name: str, tracking_url: str,
                          config: dict) -> tuple:
    """Retourne (subject, html_body)."""
    tpl = EMAIL_TEMPLATES.get(template_name)
    if not tpl:
        raise ValueError(f"Template inconnu : {template_name}")

    subject = tpl["subject"]
    html    = tpl["html"]

    # Remplacements
    replacements = {
        "{{TRACKING_URL}}":       tracking_url,
        "{{FAKE_DOMAIN}}":        config.get("fake_domain",   "techcorp-it.net"),
        "{{COMPANY_NAME}}":       config.get("company_name",  "TechCorp SARL"),
        "{{FAKE_ID}}":            str(hash(tracking_url))[-6:],
        "{{SENDER_FIRSTNAME}}":   config.get("sender_first",  "Marie"),
        "{{SENDER_LASTNAME}}":    config.get("sender_last",   "Laurent"),
        "{{SENDER_INITIAL}}":     config.get("sender_first",  "M")[0].upper(),
        "{{DATE}}":               datetime.now().strftime("%d/%m/%Y"),
    }
    for k, v in replacements.items():
        html    = html.replace(k, v)
        subject = subject.replace(k, v)

    return subject, html


def generate_email_text(template_name: str, tracking_url: str) -> str:
    """Version texte de l'email (fallback)."""
    tpl = EMAIL_TEMPLATES.get(template_name, {})
    return (
        f"[SIMULATION DE PHISHING — TEST INTERNE]\n\n"
        f"Template : {template_name}\n"
        f"Lien de tracking : {tracking_url}\n\n"
        f"Indicateurs de phishing :\n" +
        "\n".join(f"  • {ind}" for ind in tpl.get("indicators", []))
    )


# ================================================================
# SERVEUR DE TRACKING (HTTP local)
# ================================================================

class TrackingHandler(BaseHTTPRequestHandler):
    """
    Serveur HTTP qui :
    - Enregistre les clics sur /track/<token>
    - Sert la page d'éducation
    - Sert le pixel de tracking (1x1 gif)
    - Fournit les stats en JSON (/stats/<campaign_id>)
    """

    tracker: PhishingTracker = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path

        if path.startswith("/track/"):
            token = path.split("/track/")[1].split("?")[0]
            self._handle_click(token)
        elif path.startswith("/pixel/"):
            token = path.split("/pixel/")[1].split(".")[0]
            self._handle_pixel(token)
        elif path.startswith("/stats/"):
            campaign_id = path.split("/stats/")[1]
            self._handle_stats(campaign_id)
        elif path == "/health":
            self._send_response(200, b"OK", "text/plain")
        else:
            self._send_response(404, b"Not found", "text/plain")

    def _handle_click(self, token: str):
        ip = self.client_address[0]
        ua = self.headers.get("User-Agent", "")
        if self.tracker:
            self.tracker.record_event(token, "CLICK", ip, ua[:100])
            self.tracker.record_event(token, "EDUCATED", ip)
        # Redirect to education page
        self.send_response(302)
        self.send_header("Location", f"/education?token={token}")
        self.end_headers()

    def _handle_pixel(self, token: str):
        ip = self.client_address[0]
        if self.tracker:
            self.tracker.record_event(token, "OPEN", ip)
        # 1x1 transparent GIF
        gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
               b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
               b"\x00\x00\x02\x02D\x01\x00;")
        self._send_response(200, gif, "image/gif")

    def _handle_stats(self, campaign_id: str):
        if self.tracker:
            stats = self.tracker.get_stats(campaign_id)
            data  = json.dumps(stats, indent=2).encode()
            self._send_response(200, data, "application/json")
        else:
            self._send_response(500, b"No tracker", "text/plain")

    def _send_response(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # Silencer les logs HTTP par défaut


def start_tracking_server(port: int, tracker: PhishingTracker) -> HTTPServer:
    """Lance le serveur de tracking en arrière-plan."""
    TrackingHandler.tracker = tracker
    server = HTTPServer(("127.0.0.1", port), TrackingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ================================================================
# RAPPORT DE CAMPAGNE
# ================================================================

def generate_report(campaign_id: str, tracker: PhishingTracker) -> str:
    """Génère un rapport de sensibilisation pour la direction."""
    stats    = tracker.get_stats(campaign_id)
    campaign = tracker.get_campaign(campaign_id)
    if not campaign:
        return "Campagne introuvable"

    campaign = dict(campaign)
    tpl_name = campaign.get("template", "")
    tpl      = EMAIL_TEMPLATES.get(tpl_name, {})

    SEP = "=" * 62
    lines = [
        f"\n{SEP}",
        f"  RAPPORT DE SIMULATION DE PHISHING",
        f"  {campaign.get('company','?')} · {campaign.get('name','?')}",
        f"{SEP}",
        f"",
        f"  Campagne    : {campaign_id}",
        f"  Template    : {tpl_name} — {tpl.get('urgency','?')} urgence",
        f"  Date        : {campaign.get('created_at','?')[:10]}",
        f"",
        f"  {'─'*58}",
        f"  📊  MÉTRIQUES DE LA CAMPAGNE",
        f"  {'─'*58}",
        f"",
        f"  Emails envoyés    : {stats['sent']:>4}",
        f"  Emails ouverts    : {stats['opened']:>4}  ({stats['open_rate']:>3}%)",
    ]

    # Barre visuelle du taux de clic
    click_pct = stats['click_rate']
    bar_len   = 30
    filled    = int(click_pct / 100 * bar_len)
    bar       = "█" * filled + "░" * (bar_len - filled)
    risk_icon = "🔴" if click_pct > 30 else "🟠" if click_pct > 15 else "🟡" if click_pct > 5 else "🟢"

    lines += [
        f"  Liens cliqués     : {stats['clicked']:>4}  ({click_pct:>3}%) {risk_icon}",
        f"  Taux de clic      : [{bar}] {click_pct}%",
        f"  Personnes formées : {stats['educated']:>4}  ({stats['edu_rate']:>3}% des cliqueurs)",
        f"",
    ]

    # Évaluation du risque
    if click_pct > 30:
        risk = "CRITIQUE — Formation urgente requise"
        risk_icon_full = "🔴"
    elif click_pct > 15:
        risk = "ÉLEVÉ — Renforcer la sensibilisation"
        risk_icon_full = "🟠"
    elif click_pct > 5:
        risk = "MODÉRÉ — Amélioration possible"
        risk_icon_full = "🟡"
    else:
        risk = "FAIBLE — Bonne résistance au phishing"
        risk_icon_full = "🟢"

    lines += [
        f"  Niveau de risque  : {risk_icon_full}  {risk}",
        f"",
    ]

    # Par département
    if stats["by_dept"]:
        lines += [
            f"  {'─'*58}",
            f"  🏢  RÉSULTATS PAR DÉPARTEMENT",
            f"  {'─'*58}",
            f"",
            f"  {'Département':<22} {'Envoyés':>8} {'Cliqués':>8} {'Taux':>8}",
            f"  {'─'*22} {'─'*8} {'─'*8} {'─'*8}",
        ]
        for dept in stats["by_dept"]:
            rate  = round(dept["clicked"] / max(dept["total"], 1) * 100)
            icon  = "🔴" if rate > 30 else "🟠" if rate > 15 else "🟢"
            lines.append(
                f"  {dept['department']:<22} {dept['total']:>8} "
                f"{dept['clicked']:>8} {rate:>7}% {icon}"
            )
        lines.append("")

    # Indicateurs de phishing utilisés
    if tpl.get("indicators"):
        lines += [
            f"  {'─'*58}",
            f"  🔍  INDICATEURS DE PHISHING UTILISÉS",
            f"  {'─'*58}",
            f"",
        ]
        for ind in tpl["indicators"]:
            lines.append(f"  ⚠️  {ind}")
        lines.append("")

    # Recommandations
    lines += [
        f"  {'─'*58}",
        f"  💡  RECOMMANDATIONS",
        f"  {'─'*58}",
        f"",
        f"  1. Former les collaborateurs ayant cliqué ({stats['clicked']} personnes)",
        f"     → Module e-learning : 'Reconnaître un email de phishing'",
        f"",
        f"  2. Règles techniques à déployer immédiatement :",
        f"     → SPF / DKIM / DMARC sur tous les domaines",
        f"     → Anti-phishing dans le gateway email (ex: Proofpoint)",
        f"     → Signalement facile (bouton 'Signaler phishing')",
        f"",
        f"  3. Rejouer la campagne dans 90 jours pour mesurer le progrès",
        f"",
        f"  ANSSI — Guide d'hygiène informatique mesure 42 :",
        f"  'Sensibiliser les utilisateurs aux risques de l'ingénierie",
        f"   sociale et du phishing par des tests réguliers.'",
        f"{SEP}",
    ]

    return "\n".join(lines)


# ================================================================
# DÉMONSTRATION
# ================================================================

def run_demo():
    import time

    SEP = "=" * 62
    print(f"\n{SEP}")
    print("  DEMO — Simulation de Phishing (Sensibilisation interne)")
    print(f"{SEP}\n")
    print(
        "  ⚠️  AVERTISSEMENT ÉTHIQUE :\n"
        "  Cet outil est réservé aux tests internes avec accord\n"
        "  écrit de la direction et information des IRP.\n"
        "  Usage malveillant = délit (Art. 323-1 Code pénal).\n"
    )

    tracker = PhishingTracker("/tmp/demo_phishing.db")

    # ── Étape 1 : Afficher les templates disponibles ──
    print(f"  {'─'*60}")
    print(f"  📧  ÉTAPE 1 : TEMPLATES DISPONIBLES")
    print(f"  {'─'*60}\n")

    for name, tpl in EMAIL_TEMPLATES.items():
        urgency_icon = {"haute": "🔴", "critique": "🚨",
                         "normale": "🟡", "basse": "🟢"}.get(tpl["urgency"], "⚪")
        print(f"  {urgency_icon}  [{name:<18}]  {tpl['subject'][:55]}")
    print()

    # ── Étape 2 : Créer une campagne ──
    print(f"  {'─'*60}")
    print(f"  🎯  ÉTAPE 2 : CRÉATION DE LA CAMPAGNE")
    print(f"  {'─'*60}\n")

    camp_id = tracker.create_campaign(
        name     = "Test phishing Q1 2026 — Reset password",
        template = "reset_password",
        company  = "TechCorp SARL",
    )
    print(f"  Campagne créée : {camp_id}")
    print(f"  Template       : reset_password")
    print(f"  Urgence        : haute\n")

    # Ajouter des destinataires simulés
    targets_data = [
        ("alice.martin@techcorp.fr",    "Comptabilité"),
        ("bob.dupont@techcorp.fr",      "Comptabilité"),
        ("claire.bernard@techcorp.fr",  "Commercial"),
        ("david.moreau@techcorp.fr",    "Commercial"),
        ("emma.leroy@techcorp.fr",      "IT"),
        ("francois.simon@techcorp.fr",  "IT"),
        ("gabriel.thomas@techcorp.fr",  "Direction"),
        ("helene.petit@techcorp.fr",    "RH"),
        ("ivan.henry@techcorp.fr",      "Marketing"),
        ("julia.robert@techcorp.fr",    "Marketing"),
        ("kevin.blanc@techcorp.fr",     "Comptabilité"),
        ("laura.garcia@techcorp.fr",    "Commercial"),
    ]

    tokens = []
    for email, dept in targets_data:
        token = tracker.add_target(camp_id, email, dept)
        tokens.append((email, dept, token))
        # Marquer comme envoyé
        with sqlite3.connect(tracker.db_path) as conn:
            conn.execute("UPDATE targets SET sent_at=? WHERE token=?",
                         (datetime.now().isoformat(), token))
            conn.commit()

    print(f"  {len(tokens)} destinataires ajoutés")
    print(f"\n  Emails préparés :")
    base_url = "http://127.0.0.1:8765"
    for email, dept, token in tokens[:3]:
        print(f"  → {email:<36} [{dept}]")
        print(f"    Lien tracké : {base_url}/track/{token}")
    print(f"  ... ({len(tokens)-3} autres)\n")

    # ── Étape 3 : Simuler des comportements ──
    print(f"  {'─'*60}")
    print(f"  🎭  ÉTAPE 3 : SIMULATION DE COMPORTEMENTS")
    print(f"  {'─'*60}\n")

    # Définir qui "clique" dans notre simulation
    clickers = [
        (tokens[0][2], "Comptabilité"),   # Alice — clic
        (tokens[1][2], "Comptabilité"),   # Bob — clic
        (tokens[2][2], "Commercial"),     # Claire — clic
        (tokens[4][2], "IT"),             # Emma — NO clic (IT résiste)
        (tokens[5][2], "IT"),             # François — NO clic
        (tokens[7][2], "RH"),             # Hélène — clic
        (tokens[8][2], "Marketing"),      # Ivan — clic
        (tokens[10][2], "Comptabilité"),  # Kevin — clic
    ]

    click_tokens = {c[0] for c in clickers}

    # Simuler ouvertures
    for _, _, token in tokens[:9]:
        tracker.record_event(token, "OPEN", "10.0.0." + str(hash(token) % 200))

    # Simuler clics
    for token, dept in clickers:
        tracker.record_event(token, "CLICK", "10.0.0." + str(hash(token) % 200))
        tracker.record_event(token, "EDUCATED", "10.0.0." + str(hash(token) % 200))
        print(f"  🔴 CLIC  : {next(e for e,d,t in tokens if t==token):<38} [{dept}]")

    not_clicked = [
        (e, d, t) for e, d, t in tokens
        if t not in {c[0] for c in clickers}
    ]
    for email, dept, _ in not_clicked[:4]:
        print(f"  🟢 OK    : {email:<38} [{dept}]")
    print(f"  🟢 OK    : ... ({len(not_clicked)-4} autres résistants)\n")

    # ── Étape 4 : Rapport ──
    print(f"  {'─'*60}")
    print(f"  📊  ÉTAPE 4 : RAPPORT DE CAMPAGNE")
    print(f"  {'─'*60}")

    report = generate_report(camp_id, tracker)
    print(report)

    # ── Indicateurs de phishing expliqués ──
    print(f"\n  {'─'*60}")
    print(f"  🔍  LES 5 INDICATEURS À RECONNAÎTRE")
    print(f"  {'─'*60}\n")
    print(f"  Template utilisé : reset_password\n")
    for i, ind in enumerate(EMAIL_TEMPLATES["reset_password"]["indicators"], 1):
        print(f"  {i}. {ind}")

    print(f"\n  {'─'*60}")
    print(f"  🖥️   PAGE D'ÉDUCATION")
    print(f"  {'─'*60}\n")
    print(
        "  Chaque personne ayant cliqué est redirigée vers\n"
        "  phishing_education.html — une page qui :\n"
        "  ✅  Explique qu'il s'agissait d'un test\n"
        "  ✅  Montre les indicateurs du faux email\n"
        "  ✅  Enseigne comment reconnaître un vrai phishing\n"
        "  ✅  Donne les bonnes pratiques et le contact IT\n"
        "\n"
        "  Usage production :\n"
        "  python3 phishing_sim.py create --template reset_password\n"
        "  python3 phishing_sim.py add-targets --file targets.csv\n"
        "  python3 phishing_sim.py launch --send\n"
        "  python3 phishing_sim.py report --campaign CAMP-XXXXX\n"
    )


def main():
    print(__doc__)
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_create = sub.add_parser("create")
    p_create.add_argument("--template", default="reset_password",
                           choices=list(EMAIL_TEMPLATES.keys()))
    p_create.add_argument("--name",    default="Campagne phishing")
    p_create.add_argument("--company", default="Mon Entreprise")

    p_report = sub.add_parser("report")
    p_report.add_argument("--campaign", required=True)

    p_server = sub.add_parser("server")
    p_server.add_argument("--port", type=int, default=8765)

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    tracker = PhishingTracker()

    if args.cmd == "create":
        cid = tracker.create_campaign(args.name, args.template, args.company)
        print(f"\n  ✅  Campagne créée : {cid}\n")

    elif args.cmd == "report":
        print(generate_report(args.campaign, tracker))

    elif args.cmd == "server":
        print(f"\n  🌐  Serveur de tracking démarré sur port {args.port}")
        server = start_tracking_server(args.port, tracker)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Serveur arrêté.")


if __name__ == "__main__":
    main()
