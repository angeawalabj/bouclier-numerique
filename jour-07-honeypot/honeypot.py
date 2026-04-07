#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 7 : LE HONEYPOT (POT DE MIEL)    ║
║  Type    : Web Honeypot — Fake Admin Panel                       ║
║  Stack   : Flask · SQLite · SMTP · Threading                     ║
║  Pièges  : /admin · /wp-admin · /phpmyadmin · /.env · /config   ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 32 RGPD — "mettre en place des procédures
visant à tester, à analyser et à évaluer régulièrement l'efficacité
des mesures techniques et organisationnelles."

Principe légal : Un honeypot est légal en France à condition :
  ✅ Qu'il n'incite pas activement à commettre une infraction
  ✅ Qu'il se contente de détecter et enregistrer les intrusions
  ✅ Que les données collectées soient utilisées pour la défense
  ❌ Il ne peut pas être utilisé comme piège actif pour "hacker back"

Problème : 80% des tentatives d'intrusion ciblent des URLs
"standard" (wp-admin, phpmyadmin, .env, /admin) en espérant
trouver des systèmes non protégés ou des credentials par défaut.
Ces scanners automatiques frappent TOUS les serveurs exposés.

Solution technique :
  1. Déployer de fausses pages admin ultra-réalistes
  2. Toute interaction → alerte immédiate + fingerprint complet
  3. Collecter les patterns d'attaque pour enrichir les blacklists
  4. Ralentir les scanners (tar pit) pour consommer leur temps

Risque évité : Détection précoce d'une intrusion avant qu'elle
n'atteigne les vrais systèmes. Valeur forensique : les logs
honeypot peuvent servir de preuves légales (Art. 323-1 CP).
"""

import os
import sys
import json
import time
import sqlite3
import threading
import smtplib
import hashlib
import random
import string
import ipaddress
import socket
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from typing import Optional

from flask import (Flask, request, render_template_string,
                   redirect, url_for, jsonify, Response)

# ─── Configuration ─────────────────────────────────────────────────

class HoneypotConfig:
    # Serveur Flask
    HOST            = "0.0.0.0"
    PORT            = 8080
    DEBUG           = False

    # Base de données
    DB_PATH         = "/tmp/honeypot.db"

    # Alertes email (configurer avec vos credentials)
    SMTP_HOST       = "smtp.gmail.com"
    SMTP_PORT       = 587
    SMTP_USER       = "your@gmail.com"       # À configurer
    SMTP_PASS       = "your_app_password"    # App password Gmail
    ALERT_TO        = "admin@yourcompany.com"

    # Alertes Slack (optionnel)
    SLACK_WEBHOOK   = ""   # URL webhook Slack

    # Tar Pit — délai artificiel pour ralentir les scanners (secondes)
    TARPIT_DELAY_MIN = 2
    TARPIT_DELAY_MAX = 8

    # Seuil d'alerte : alerter seulement à partir de N actions suspectes
    ALERT_THRESHOLD = 1    # 1 = alerte à chaque interaction

    # Nom affiché dans la fausse interface admin
    FAKE_COMPANY    = "MonEntreprise SA"
    FAKE_VERSION    = "v2.4.1"


# ─── Base de données ───────────────────────────────────────────────

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS intrusions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       REAL NOT NULL,
            ip              TEXT NOT NULL,
            country         TEXT,
            hostname        TEXT,
            method          TEXT,
            url             TEXT NOT NULL,
            trap_name       TEXT,
            user_agent      TEXT,
            referer         TEXT,
            post_data       TEXT,
            headers         TEXT,
            fingerprint     TEXT,
            severity        TEXT DEFAULT 'MEDIUM',
            notified        INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS credentials_tried (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            intrusion_id INTEGER,
            username    TEXT,
            password    TEXT,
            timestamp   REAL,
            FOREIGN KEY(intrusion_id) REFERENCES intrusions(id)
        );

        CREATE TABLE IF NOT EXISTS stats (
            date        TEXT PRIMARY KEY,
            hits        INTEGER DEFAULT 0,
            unique_ips  INTEGER DEFAULT 0,
            top_trap    TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_intrusions_ip
            ON intrusions(ip);
        CREATE INDEX IF NOT EXISTS idx_intrusions_time
            ON intrusions(timestamp);
    """)
    conn.commit()
    conn.close()


# ─── Fingerprinting de l'attaquant ────────────────────────────────

def fingerprint_visitor(req) -> dict:
    """
    Collecte le maximum d'informations sur le visiteur du honeypot.
    Tout ceci est légal car c'est sur notre propre infrastructure.
    """
    ip = req.headers.get("X-Forwarded-For",
                         req.remote_addr or "0.0.0.0").split(",")[0].strip()

    # Résolution DNS inverse (hostname de l'attaquant)
    hostname = "?"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "unresolved"

    # Parsing User-Agent
    ua = req.headers.get("User-Agent", "")
    bot_signatures = [
        "sqlmap", "nikto", "nmap", "masscan", "zgrab",
        "python-requests", "curl", "wget", "Go-http-client",
        "dirbuster", "gobuster", "wfuzz", "burpsuite",
        "havij", "acunetix", "nessus", "openvas", "metasploit",
    ]
    is_bot = any(sig.lower() in ua.lower() for sig in bot_signatures)
    is_scanner = any(sig.lower() in ua.lower()
                     for sig in ["sqlmap", "nikto", "dirbuster", "gobuster", "wfuzz"])

    # Hasher l'IP pour un ID stable (pseudonymisation RGPD)
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]

    # Évaluation de la menace
    severity = "LOW"
    if is_scanner:
        severity = "CRITICAL"
    elif is_bot:
        severity = "HIGH"
    elif req.method == "POST":
        severity = "HIGH"

    # Headers complets (valeur forensique)
    all_headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in ("cookie", "authorization")}

    return {
        "ip":           ip,
        "ip_hash":      ip_hash,
        "hostname":     hostname,
        "user_agent":   ua,
        "is_bot":       is_bot,
        "is_scanner":   is_scanner,
        "severity":     severity,
        "referer":      req.referrer or "",
        "method":       req.method,
        "url":          req.url,
        "headers":      all_headers,
        "accept_lang":  req.headers.get("Accept-Language", ""),
        "accept":       req.headers.get("Accept", ""),
    }


# ─── Alertes ───────────────────────────────────────────────────────

def format_alert_email(fp: dict, trap: str,
                       creds: dict = None, config: HoneypotConfig = None) -> str:
    """Formate un email d'alerte riche en contexte."""
    cfg = config or HoneypotConfig()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_emoji = {
        "CRITICAL": "🔴🚨",
        "HIGH":     "🟠⚠️",
        "MEDIUM":   "🟡🔔",
        "LOW":      "🔵ℹ️",
    }.get(fp["severity"], "🔔")

    creds_section = ""
    if creds:
        creds_section = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔑  CREDENTIALS TESTÉS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Login    : {creds.get('username', '?')}
  Password : {creds.get('password', '?')}
  (Stockés pour analyse — à comparer avec vos vrais credentials)
"""

    return f"""
{severity_emoji} ALERTE HONEYPOT — {cfg.FAKE_COMPANY}
{'='*50}
  Heure    : {now}
  Sévérité : {fp['severity']}
  Piège    : {trap}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐  IDENTIFICATION ATTAQUANT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  IP       : {fp['ip']}
  Hostname : {fp['hostname']}
  IP Hash  : {fp['ip_hash']} (pseudonymisé)
  User-Agent : {fp['user_agent'][:80]}
  Bot/Scanner : {'OUI ⚠️' if fp['is_bot'] else 'NON (humain probable)'}
  Langue   : {fp['accept_lang'][:30]}
  Referer  : {fp['referer'] or 'direct'}
  URL      : {fp['url']}
{creds_section}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯  ACTIONS RECOMMANDÉES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Ajouter {fp['ip']} à votre firewall/fail2ban
  2. Vérifier les logs de vos vrais systèmes
  3. Conserver cet email comme preuve (Art. 323-1 CP)
  4. Signaler à votre SIEM/SOC si entreprise

{'⚠️  SCANNER DÉTECTÉ : ' + fp['user_agent'][:50] if fp['is_scanner'] else ''}

— Honeypot Bouclier Numérique
"""


def send_email_alert(fp: dict, trap: str, creds: dict = None,
                     config: HoneypotConfig = None):
    """Envoie un email d'alerte (en production)."""
    cfg = config or HoneypotConfig()

    if cfg.SMTP_USER == "your@gmail.com":
        # Mode démo : simuler l'envoi sans vrai SMTP
        print(f"\n  📧  [SIMULATION EMAIL] Alerte envoyée à {cfg.ALERT_TO}")
        print(format_alert_email(fp, trap, creds, cfg))
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 HONEYPOT ALERT [{fp['severity']}] — {trap} — {fp['ip']}"
        msg["From"]    = cfg.SMTP_USER
        msg["To"]      = cfg.ALERT_TO

        body = format_alert_email(fp, trap, creds, cfg)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT) as server:
            server.starttls()
            server.login(cfg.SMTP_USER, cfg.SMTP_PASS)
            server.sendmail(cfg.SMTP_USER, cfg.ALERT_TO, msg.as_string())

        print(f"  ✅  Email envoyé : {cfg.ALERT_TO}")
    except Exception as e:
        print(f"  ❌  Erreur email : {e}")


def log_intrusion(fp: dict, trap: str, post_data: dict = None,
                  db_path: str = None) -> int:
    """Enregistre l'intrusion en base de données."""
    db_path = db_path or HoneypotConfig.DB_PATH
    now = time.time()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO intrusions
               (timestamp, ip, hostname, method, url, trap_name,
                user_agent, referer, post_data, headers, fingerprint, severity)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                fp["ip"],
                fp["hostname"],
                fp["method"],
                fp["url"],
                trap,
                fp["user_agent"],
                fp["referer"],
                json.dumps(post_data or {}, ensure_ascii=False),
                json.dumps(fp["headers"], ensure_ascii=False),
                fp["ip_hash"],
                fp["severity"],
            )
        )
        intrusion_id = cursor.lastrowid

        # Logger les credentials si c'est une tentative de login
        if post_data and ("username" in post_data or "password" in post_data):
            conn.execute(
                """INSERT INTO credentials_tried
                   (intrusion_id, username, password, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (intrusion_id,
                 post_data.get("username", post_data.get("user", "")),
                 post_data.get("password", post_data.get("pass", "")),
                 now)
            )
        conn.commit()
    return intrusion_id


# ─── Templates HTML des pièges ─────────────────────────────────────

FAKE_ADMIN_LOGIN = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Administration — {{ company }}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #1a1a2e;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-card {
      background: #16213e;
      border: 1px solid #0f3460;
      border-radius: 12px;
      padding: 40px;
      width: 380px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    .logo { text-align: center; margin-bottom: 30px; }
    .logo-icon { font-size: 48px; margin-bottom: 10px; }
    .logo h1 { color: #e94560; font-size: 20px; font-weight: 700; }
    .logo p { color: #a8a8b3; font-size: 12px; margin-top: 5px; }
    .badge {
      display: inline-block; background: #0f3460; color: #4fc3f7;
      font-size: 10px; padding: 2px 8px; border-radius: 10px; margin-top: 5px;
    }
    label { color: #a8a8b3; font-size: 13px; display: block; margin-bottom: 6px; }
    input[type=text], input[type=password] {
      width: 100%; padding: 12px 15px;
      background: #0f3460; border: 1px solid #1a4a8a;
      border-radius: 8px; color: #fff; font-size: 14px;
      transition: border-color 0.2s;
    }
    input:focus { outline: none; border-color: #e94560; }
    .field { margin-bottom: 20px; }
    .btn {
      width: 100%; padding: 13px;
      background: linear-gradient(135deg, #e94560, #c62a47);
      border: none; border-radius: 8px; color: #fff;
      font-size: 15px; font-weight: 600; cursor: pointer;
      transition: opacity 0.2s;
    }
    .btn:hover { opacity: 0.9; }
    .footer { text-align: center; margin-top: 25px; color: #555; font-size: 11px; }
    {% if error %}
    .error {
      background: rgba(233,69,96,0.15); border: 1px solid #e94560;
      border-radius: 6px; padding: 10px 14px; color: #e94560;
      font-size: 13px; margin-bottom: 20px;
    }
    {% endif %}
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">
      <div class="logo-icon">🔐</div>
      <h1>{{ company }}</h1>
      <p>Panneau d'administration</p>
      <span class="badge">{{ version }} · Sécurisé</span>
    </div>
    {% if error %}
    <div class="error">⚠️ Identifiants incorrects. Tentative enregistrée.</div>
    {% endif %}
    <form method="POST" action="/admin/login">
      <div class="field">
        <label>Identifiant administrateur</label>
        <input type="text" name="username" placeholder="admin" autocomplete="off">
      </div>
      <div class="field">
        <label>Mot de passe</label>
        <input type="password" name="password" placeholder="••••••••">
      </div>
      <button type="submit" class="btn">Se connecter</button>
    </form>
    <div class="footer">
      Accès réservé au personnel autorisé · {{ company }}<br>
      Toute tentative non autorisée est tracée et signalée.
    </div>
  </div>
</body>
</html>"""

FAKE_PHPMYADMIN = """<!DOCTYPE html>
<html>
<head>
  <title>phpMyAdmin</title>
  <style>
    body { font-family: sans-serif; background: #f5f5f5; }
    .wrap { max-width: 400px; margin: 80px auto; background: #fff;
            border: 1px solid #ddd; border-radius: 4px; padding: 30px; }
    h1 { color: #e87722; font-size: 22px; margin-bottom: 20px; }
    input { width: 100%; padding: 8px; margin-bottom: 12px; border: 1px solid #ccc;
            border-radius: 3px; box-sizing: border-box; }
    button { background: #e87722; color: #fff; border: none; padding: 9px 20px;
             border-radius: 3px; cursor: pointer; }
    .footer { color: #888; font-size: 11px; margin-top: 15px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>phpMyAdmin</h1>
    <form method="POST">
      <input type="text" name="pma_username" placeholder="Nom d'utilisateur" value="root">
      <input type="password" name="pma_password" placeholder="Mot de passe">
      <button type="submit">Connexion</button>
    </form>
    <div class="footer">phpMyAdmin 5.2.1 · Serveur: localhost</div>
  </div>
</body>
</html>"""

FAKE_ENV_FILE = """# Application Configuration
APP_ENV=production
APP_KEY=base64:xJ7kP9mN3qR5tY8wB2cE6vA1nL4sF0hD
APP_DEBUG=false
APP_URL=https://app.monentreprise.fr

# Database
DB_CONNECTION=mysql
DB_HOST=db-prod-01.internal
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app_user
DB_PASSWORD=Pr0d@2024!SecureDB

# Redis Cache
REDIS_HOST=redis-01.internal
REDIS_PASSWORD=Redis@Secure#2024
REDIS_PORT=6379

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=eu-west-3
AWS_BUCKET=monentreprise-prod-assets

# Stripe
STRIPE_KEY=pk_live_HONEYPOT_FAKE_KEY_51ABC
STRIPE_SECRET=sk_live_HONEYPOT_FAKE_SECRET

# Email
MAIL_MAILER=smtp
MAIL_HOST=smtp.sendgrid.net
MAIL_USERNAME=apikey
MAIL_PASSWORD=SG.HoneyPot.FakeKey.DETECTED

# JWT
JWT_SECRET=HONEYPOT_DETECTED_DO_NOT_USE
"""

FAKE_WORDPRESS_LOGIN = """<!DOCTYPE html>
<html lang="fr-FR">
<head>
  <title>Connexion ‹ {{ company }} — WordPress</title>
  <style>
    body { background:#f0f0f1; font-family:-apple-system,sans-serif; }
    #login { margin: 80px auto; width: 320px; }
    h1 a { display:block; text-align:center; font-size:20px; margin-bottom:20px;
           text-decoration:none; color:#1d2327; }
    .login input[type=text], .login input[type=password] {
      width:100%; padding:8px; margin-bottom:16px; border:1px solid #8c8f94;
      border-radius:4px; box-sizing:border-box; font-size:15px; }
    .button-primary { background:#2271b1; color:#fff; border:none; padding:10px;
                      width:100%; border-radius:3px; font-size:14px; cursor:pointer; }
    #backtoblog, #nav { text-align:center; margin-top:10px; font-size:13px; }
    #backtoblog a, #nav a { color:#2271b1; text-decoration:none; }
    .login { background:#fff; border:1px solid #c3c4c7; border-radius:4px; padding:26px; }
  </style>
</head>
<body>
  <div id="login">
    <h1><a>{{ company }}</a></h1>
    <div class="login">
      <form name="loginform" method="post" action="/wp-login.php">
        <label>Identifiant ou e-mail</label>
        <input type="text" name="log" size="20"><br>
        <label>Mot de passe</label>
        <input type="password" name="pwd" size="20">
        <input type="submit" name="wp-submit" class="button-primary" value="Se connecter">
      </form>
    </div>
    <p id="backtoblog"><a href="/">← Retour vers {{ company }}</a></p>
  </div>
</body>
</html>"""


# ─── Application Flask Honeypot ────────────────────────────────────

def create_honeypot(config: HoneypotConfig = None) -> Flask:
    cfg = config or HoneypotConfig()
    app = Flask(__name__)
    db_path = cfg.DB_PATH
    init_db(db_path)

    # File d'alertes thread-safe
    alert_queue = []
    alert_lock  = threading.Lock()

    def trigger(req, trap_name: str, severity_override: str = None):
        """Déclenche le piège : log + fingerprint + alerte."""
        fp        = fingerprint_visitor(req)
        post_data = req.form.to_dict() if req.method == "POST" else {}

        if severity_override:
            fp["severity"] = severity_override

        # Log en base
        intrusion_id = log_intrusion(fp, trap_name, post_data, db_path)

        # Alerte en thread séparé (non-bloquant)
        def _alert():
            creds = post_data if post_data else None
            send_email_alert(fp, trap_name, creds, cfg)

        threading.Thread(target=_alert, daemon=True).start()

        return fp, post_data, intrusion_id

    def tar_pit():
        """Ralentit les scanners automatiques."""
        delay = random.uniform(cfg.TARPIT_DELAY_MIN, cfg.TARPIT_DELAY_MAX)
        time.sleep(delay)

    # ════════════════════════════════════════════════════════════════
    # PIÈGES — Routes honeypot
    # ════════════════════════════════════════════════════════════════

    @app.route("/admin")
    @app.route("/admin/")
    @app.route("/admin/login", methods=["GET", "POST"])
    @app.route("/administrator", methods=["GET", "POST"])
    @app.route("/panel", methods=["GET", "POST"])
    @app.route("/backend", methods=["GET", "POST"])
    def fake_admin():
        fp, post_data, iid = trigger(request, "FAKE_ADMIN_PANEL")
        tar_pit()

        error = False
        if request.method == "POST":
            error = True  # Toujours faux — jamais de succès
            # ici on pourrait logger les credentials et prolonger le tar pit

        return render_template_string(
            FAKE_ADMIN_LOGIN,
            company=cfg.FAKE_COMPANY,
            version=cfg.FAKE_VERSION,
            error=error
        ), 200

    @app.route("/wp-admin", methods=["GET", "POST"])
    @app.route("/wp-admin/", methods=["GET", "POST"])
    @app.route("/wp-login.php", methods=["GET", "POST"])
    @app.route("/wordpress/wp-admin", methods=["GET", "POST"])
    def fake_wordpress():
        trigger(request, "FAKE_WORDPRESS", severity_override="HIGH")
        tar_pit()
        return render_template_string(
            FAKE_WORDPRESS_LOGIN,
            company=cfg.FAKE_COMPANY
        ), 200

    @app.route("/phpmyadmin", methods=["GET", "POST"])
    @app.route("/phpmyadmin/", methods=["GET", "POST"])
    @app.route("/pma", methods=["GET", "POST"])
    @app.route("/mysql", methods=["GET", "POST"])
    @app.route("/db", methods=["GET", "POST"])
    def fake_phpmyadmin():
        trigger(request, "FAKE_PHPMYADMIN", severity_override="CRITICAL")
        tar_pit()
        return FAKE_PHPMYADMIN, 200

    @app.route("/.env")
    @app.route("/.env.local")
    @app.route("/.env.production")
    @app.route("/.env.backup")
    @app.route("/config.env")
    def fake_env():
        trigger(request, "FAKE_ENV_FILE", severity_override="CRITICAL")
        tar_pit()
        # Renvoyer un faux .env avec des credentials piégés
        return Response(FAKE_ENV_FILE, mimetype="text/plain"), 200

    @app.route("/config.php")
    @app.route("/configuration.php")
    @app.route("/settings.php")
    @app.route("/database.php")
    @app.route("/db.php")
    def fake_config_php():
        trigger(request, "FAKE_CONFIG_PHP", severity_override="CRITICAL")
        tar_pit()
        fake_php = """<?php
// Configuration de production — NE PAS PARTAGER
define('DB_HOST', 'db-prod.internal');
define('DB_NAME', 'app_db');
define('DB_USER', 'db_admin');
define('DB_PASS', 'H0n3yP0t_F@ke_2024!');
define('SECRET_KEY', 'HONEYPOT_DETECTED_FAKE_KEY');
define('API_KEY', 'FAKE_API_KEY_DO_NOT_USE');
?>"""
        return Response(fake_php, mimetype="text/plain"), 200

    @app.route("/backup.sql")
    @app.route("/dump.sql")
    @app.route("/database.sql")
    @app.route("/db_backup.zip")
    @app.route("/backup.zip")
    def fake_backup():
        trigger(request, "FAKE_BACKUP_FILE", severity_override="CRITICAL")
        tar_pit()
        # Simuler un début de fichier SQL avant de "couper"
        fake_sql = "-- MySQL dump 10.19\n-- Host: localhost\n-- HONEYPOT DETECTED\n"
        return Response(fake_sql, mimetype="text/plain",
                        headers={"Content-Disposition": "attachment"}), 200

    @app.route("/.git/config")
    @app.route("/.git/HEAD")
    @app.route("/.svn/entries")
    def fake_vcs():
        trigger(request, "FAKE_GIT_CONFIG", severity_override="HIGH")
        fake_git = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        return Response(fake_git, mimetype="text/plain"), 200

    @app.route("/api/v1/admin/users")
    @app.route("/api/admin")
    @app.route("/api/config")
    @app.route("/api/keys")
    def fake_api():
        trigger(request, "FAKE_API_ENDPOINT", severity_override="HIGH")
        tar_pit()
        fake_data = {
            "users": [
                {"id": 1, "email": "admin@honeypot.fake",
                 "token": "HONEYPOT_FAKE_TOKEN_DETECTED"},
            ],
            "_note": "HONEYPOT — This access has been logged and reported"
        }
        return jsonify(fake_data), 200

    @app.route("/server-status")
    @app.route("/server-info")
    @app.route("/.htaccess")
    @app.route("/web.config")
    def fake_server_info():
        trigger(request, "FAKE_SERVER_INFO")
        tar_pit()
        return "Apache Server Status\nHoneypot active.", 200

    # ════════════════════════════════════════════════════════════════
    # DASHBOARD — Vue des intrusions (à protéger en prod !)
    # ════════════════════════════════════════════════════════════════

    @app.route("/honeypot/dashboard")
    def dashboard():
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            intrusions = conn.execute(
                """SELECT * FROM intrusions
                   ORDER BY timestamp DESC LIMIT 50"""
            ).fetchall()
            stats = {
                "total":    conn.execute("SELECT COUNT(*) FROM intrusions").fetchone()[0],
                "unique":   conn.execute("SELECT COUNT(DISTINCT ip) FROM intrusions").fetchone()[0],
                "critical": conn.execute("SELECT COUNT(*) FROM intrusions WHERE severity='CRITICAL'").fetchone()[0],
                "today":    conn.execute(
                    "SELECT COUNT(*) FROM intrusions WHERE timestamp > ?",
                    (time.time() - 86400,)
                ).fetchone()[0],
                "top_trap": conn.execute(
                    """SELECT trap_name, COUNT(*) as c FROM intrusions
                       GROUP BY trap_name ORDER BY c DESC LIMIT 1"""
                ).fetchone(),
            }

        rows = "\n".join(
            f"""<tr>
              <td>{datetime.fromtimestamp(r['timestamp']).strftime('%H:%M:%S')}</td>
              <td><b>{r['ip']}</b></td>
              <td>{r['trap_name']}</td>
              <td><span style="color:{'red' if r['severity']=='CRITICAL' else 'orange' if r['severity']=='HIGH' else 'gold'}">{r['severity']}</span></td>
              <td style="font-size:11px;max-width:200px;overflow:hidden">{r['user_agent'][:60]}</td>
              <td>{r['method']}</td>
            </tr>"""
            for r in intrusions
        )

        top = stats["top_trap"]
        top_str = f"{top['trap_name']} ({top['c']})" if top else "—"

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Honeypot Dashboard</title>
<meta http-equiv="refresh" content="10">
<style>
  body{{font-family:monospace;background:#0d0d0d;color:#00ff88;padding:20px}}
  h1{{color:#ff4444;margin-bottom:20px}}
  .stat{{display:inline-block;background:#1a1a1a;border:1px solid #333;
         padding:15px 25px;margin:5px;border-radius:6px;text-align:center}}
  .stat .n{{font-size:32px;font-weight:bold;color:#fff}}
  .stat .l{{font-size:12px;color:#666;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;margin-top:20px;font-size:13px}}
  th{{background:#1a1a1a;color:#888;padding:8px;text-align:left;border-bottom:1px solid #333}}
  td{{padding:7px 8px;border-bottom:1px solid #1a1a1a}}
  tr:hover{{background:#111}}
</style></head><body>
<h1>🍯 HONEYPOT DASHBOARD — {cfg.FAKE_COMPANY}</h1>
<div>
  <div class="stat"><div class="n">{stats['total']}</div><div class="l">Total hits</div></div>
  <div class="stat"><div class="n">{stats['unique']}</div><div class="l">IPs uniques</div></div>
  <div class="stat"><div class="n" style="color:#ff4444">{stats['critical']}</div><div class="l">CRITICAL</div></div>
  <div class="stat"><div class="n">{stats['today']}</div><div class="l">Aujourd'hui</div></div>
  <div class="stat"><div class="n" style="font-size:16px">{top_str}</div><div class="l">Piège #1</div></div>
</div>
<table>
  <tr><th>Heure</th><th>IP</th><th>Piège</th><th>Sévérité</th><th>User-Agent</th><th>Method</th></tr>
  {rows}
</table>
<p style="color:#333;font-size:11px;margin-top:20px">Refresh auto toutes les 10s · GET /honeypot/dashboard</p>
</body></html>""", 200

    @app.route("/honeypot/api/stats")
    def api_stats():
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            total    = conn.execute("SELECT COUNT(*) FROM intrusions").fetchone()[0]
            unique   = conn.execute("SELECT COUNT(DISTINCT ip) FROM intrusions").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM intrusions WHERE severity='CRITICAL'").fetchone()[0]
            by_trap  = conn.execute(
                "SELECT trap_name, COUNT(*) as c FROM intrusions GROUP BY trap_name ORDER BY c DESC"
            ).fetchall()
            recent   = conn.execute(
                "SELECT ip, trap_name, severity, timestamp FROM intrusions ORDER BY timestamp DESC LIMIT 10"
            ).fetchall()
        return jsonify({
            "total_intrusions": total,
            "unique_attackers":  unique,
            "critical_events":   critical,
            "by_trap":  [{"trap": r["trap_name"], "count": r["c"]} for r in by_trap],
            "recent":   [{"ip": r["ip"], "trap": r["trap_name"],
                          "severity": r["severity"],
                          "time": datetime.fromtimestamp(r["timestamp"]).isoformat()}
                         for r in recent],
        }), 200

    # Route racine — pas un piège, juste un 404 normal
    @app.route("/")
    def index():
        return "Not found", 404

    return app


# ════════════════════════════════════════════════════════════════
# SIMULATION DE DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    """Simule des attaques sur le honeypot sans lancer le serveur HTTP."""
    SEP = "═" * 62

    print(f"\n{SEP}")
    print("  🎬  DÉMO HONEYPOT — Simulation d'attaques")
    print(f"{SEP}\n")

    cfg     = HoneypotConfig()
    db_path = cfg.DB_PATH
    init_db(db_path)

    # Attaquants simulés
    attackers = [
        {
            "ip": "185.220.101.45",
            "ua": "sqlmap/1.7.8#stable (https://sqlmap.org)",
            "desc": "Attaquant 1 — sqlmap scanner automatique",
            "attacks": [
                ("/.env",              "FAKE_ENV_FILE",     "GET",  {}),
                ("/config.php",        "FAKE_CONFIG_PHP",   "GET",  {}),
                ("/backup.sql",        "FAKE_BACKUP_FILE",  "GET",  {}),
                ("/.git/config",       "FAKE_GIT_CONFIG",   "GET",  {}),
            ]
        },
        {
            "ip": "45.83.193.150",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
            "desc": "Attaquant 2 — humain testant les accès admin",
            "attacks": [
                ("/admin",       "FAKE_ADMIN_PANEL",  "GET",  {}),
                ("/admin/login", "FAKE_ADMIN_PANEL",  "POST",
                 {"username": "admin", "password": "admin123"}),
                ("/admin/login", "FAKE_ADMIN_PANEL",  "POST",
                 {"username": "admin", "password": "password"}),
                ("/admin/login", "FAKE_ADMIN_PANEL",  "POST",
                 {"username": "admin", "password": "admin@2024"}),
            ]
        },
        {
            "ip": "91.108.56.130",
            "ua": "WPScan v3.8.24 (https://wpscan.com/)",
            "desc": "Attaquant 3 — scanner WordPress",
            "attacks": [
                ("/wp-admin",     "FAKE_WORDPRESS",    "GET", {}),
                ("/wp-login.php", "FAKE_WORDPRESS",    "POST",
                 {"log": "admin", "pwd": "wordpress"}),
                ("/phpmyadmin",   "FAKE_PHPMYADMIN",   "GET", {}),
            ]
        },
    ]

    total_intrusions = 0

    for attacker in attackers:
        print(f"  {'─'*60}")
        print(f"  🔴 {attacker['desc']}")
        print(f"     IP : {attacker['ip']}  |  UA : {attacker['ua'][:55]}")
        print(f"  {'─'*60}")

        for url, trap, method, post_data in attacker["attacks"]:
            # Simuler le fingerprinting
            is_scanner = any(s in attacker["ua"].lower()
                             for s in ["sqlmap", "wpscan", "dirbuster", "nikto"])
            severity = "CRITICAL" if is_scanner else ("HIGH" if method == "POST" else "MEDIUM")

            fp = {
                "ip":       attacker["ip"],
                "ip_hash":  hashlib.sha256(attacker["ip"].encode()).hexdigest()[:16],
                "hostname": "unresolved",
                "user_agent": attacker["ua"],
                "is_bot":   True,
                "is_scanner": is_scanner,
                "severity": severity,
                "referer":  "",
                "method":   method,
                "url":      f"http://monentreprise.fr{url}",
                "headers":  {"User-Agent": attacker["ua"]},
                "accept_lang": "en-US",
            }

            intrusion_id = log_intrusion(fp, trap, post_data, db_path)
            total_intrusions += 1

            creds_str = ""
            if post_data:
                u = post_data.get("username", post_data.get("log", "?"))
                p = post_data.get("password", post_data.get("pwd", "?"))
                creds_str = f"  login={u} / pwd={p}"

            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
            print(f"  {sev_icon}  [{method:<4}] {url:<25} → Piège: {trap}")
            if creds_str:
                print(f"       Credentials testés : {creds_str}")

        # Envoyer l'alerte (simulée)
        last_fp = {
            "ip": attacker["ip"],
            "ip_hash": hashlib.sha256(attacker["ip"].encode()).hexdigest()[:16],
            "hostname": "unresolved",
            "user_agent": attacker["ua"],
            "is_bot": True,
            "is_scanner": True,
            "severity": "HIGH",
            "referer": "",
            "method": "GET",
            "url": "...",
            "headers": {},
            "accept_lang": "en-US",
        }
        print(f"\n  📧  Alerte déclenchée :")
        print(f"      → Email à {cfg.ALERT_TO}")
        print(f"      → IP {attacker['ip']} ajoutée en watchlist")
        print()

    # ── Stats finales ──
    print(f"\n{SEP}")
    print(f"  📊  TABLEAU DE BORD POST-ATTAQUE")
    print(f"{SEP}")

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        total    = conn.execute("SELECT COUNT(*) FROM intrusions").fetchone()[0]
        unique   = conn.execute("SELECT COUNT(DISTINCT ip) FROM intrusions").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM intrusions WHERE severity='CRITICAL'").fetchone()[0]
        by_trap  = conn.execute(
            "SELECT trap_name, COUNT(*) as c FROM intrusions GROUP BY trap_name ORDER BY c DESC"
        ).fetchall()
        creds    = conn.execute("SELECT * FROM credentials_tried").fetchall()

    print(f"\n  Intrusions totales  : {total}")
    print(f"  IPs distinctes      : {unique}")
    print(f"  Événements critiques: {critical}")

    print(f"\n  Pièges les plus touchés :")
    for r in by_trap:
        bar = "█" * r["c"]
        print(f"    {r['trap_name']:<28} {bar} ({r['c']})")

    if creds:
        print(f"\n  🔑  Credentials testés par les attaquants ({len(creds)}) :")
        for c in creds:
            print(f"    login={c['username']:<20} pwd={c['password']}")
        print(f"\n  ⚠️  IMPORTANT : Si un de ces credentials correspond à")
        print(f"  un vrai compte, changez-le IMMÉDIATEMENT !")

    print(f"""
  {SEP}
  🏗️   DÉPLOIEMENT EN PRODUCTION
  {SEP}

  1. Intégrer le honeypot SUR LE MÊME serveur que l'app réelle
     (ou sur un sous-domaine dédié) :

     from honeypot import create_honeypot
     honeypot = create_honeypot()
     # Monter sur /admin, /wp-admin, etc. AVANT vos vraies routes

  2. Configurer les alertes email dans HoneypotConfig :
     SMTP_USER = "alert@votredomaine.com"
     ALERT_TO  = "soc@votreentreprise.com"

  3. Lancer :
     python3 honeypot.py server

  4. Dashboard temps réel :
     http://votreserveur:8080/honeypot/dashboard

  📋  Valeur légale des logs honeypot :
  Les logs constituent des preuves recevables pour une plainte
  en vertu de l'Art. 323-1 du Code Pénal (accès frauduleux
  à un système d'information : jusqu'à 3 ans + 100 000€).
  Conservez les logs avec horodatage certifié (RFC 3161).
""")


# ─── CLI ──────────────────────────────────────────────────────────

USAGE = """
Usage :
  python3 honeypot.py demo     Simulation d'attaques (sans serveur)
  python3 honeypot.py server   Lancer le honeypot HTTP (port 8080)
  python3 honeypot.py stats    Statistiques depuis la DB
"""

def main():
    print(__doc__)
    args = sys.argv[1:]

    if not args or args[0] == "demo":
        run_demo()

    elif args[0] == "server":
        cfg = HoneypotConfig()
        print(f"  🍯  Honeypot démarré sur {cfg.HOST}:{cfg.PORT}")
        print(f"  Pièges actifs : /admin, /wp-admin, /phpmyadmin,")
        print(f"                  /.env, /config.php, /backup.sql,")
        print(f"                  /.git/config, /api/admin, ...")
        print(f"  Dashboard     : http://localhost:{cfg.PORT}/honeypot/dashboard")
        print()
        app = create_honeypot(cfg)
        app.run(host=cfg.HOST, port=cfg.PORT, debug=False)

    elif args[0] == "stats":
        db_path = HoneypotConfig.DB_PATH
        if not Path(db_path).exists():
            print("  ❌  Aucune base de données trouvée. Lancez d'abord 'demo' ou 'server'.")
            sys.exit(1)
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            total  = conn.execute("SELECT COUNT(*) FROM intrusions").fetchone()[0]
            recent = conn.execute(
                "SELECT * FROM intrusions ORDER BY timestamp DESC LIMIT 20"
            ).fetchall()
        print(f"  Total intrusions : {total}\n")
        for r in recent:
            t = datetime.fromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  [{t}] {r['ip']:<18} {r['trap_name']:<25} {r['severity']}")

    else:
        print(USAGE)


if __name__ == "__main__":
    main()
