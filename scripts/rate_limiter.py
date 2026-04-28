#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 6 : LE FIREWALL APPLICATIF       ║
║  Mécanisme : Rate Limiting + IP Blocking (Anti-Brute Force)      ║
║  Stack     : Flask middleware · SQLite · threading               ║
║  Stratégies: Progressive delay · Sliding window · IP reputation  ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 32 RGPD — "garantir la confidentialité,
l'intégrité, la disponibilité et la résilience permanentes des
systèmes et services de traitement."

ISO 27001 — Contrôle A.9.4.2 : "Des procédures d'ouverture de
session sécurisée doivent être mises en place pour accéder aux
systèmes et aux applications."

Problème : Une attaque brute force sur un formulaire de connexion
peut tester des millions de combinaisons mot de passe/login sans
aucune friction si le serveur ne réagit pas. Les bots modernes
peuvent effectuer 10 000+ tentatives/minute depuis une seule IP.

Solution technique — 3 couches de défense :
  1. Rate Limiting   : Max N tentatives par fenêtre glissante
  2. Progressive Backoff : Délai exponentiel entre les tentatives
  3. IP Reputation   : Bannissement temporaire après X échecs

Risque évité : Compromission de comptes utilisateurs, credential
stuffing, password spraying. Coût moyen d'une violation de données
en France : 4,4M€ (IBM Cost of Data Breach Report 2024).
"""

import sqlite3
import threading
import time
import json
import hashlib
import ipaddress
import logging
import os
import sys
import random
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from typing import Optional, Callable
from collections import defaultdict

from flask import Flask, request, jsonify, g

# ─── Configuration du Rate Limiter ───────────────────────────────

class RateLimitConfig:
    """
    Paramètres de la politique anti-brute force.
    Tous les seuils sont configurables pour s'adapter à votre risque.
    """
    # Fenêtre de temps pour compter les tentatives (secondes)
    WINDOW_SECONDS         = 300      # 5 minutes

    # Seuils de blocage progressif
    WARN_THRESHOLD         = 3        # Avertissement silencieux
    SLOWDOWN_THRESHOLD     = 5        # Délai artificiel ajouté
    BLOCK_THRESHOLD        = 10       # Blocage temporaire
    PERMANENT_BAN_THRESHOLD = 50      # Bannissement 24h

    # Durées de blocage
    BLOCK_DURATION_SEC     = 900      # 15 minutes
    PERMANENT_BAN_SEC      = 86400    # 24 heures

    # Délai progressif (secondes) par palier d'échecs
    PROGRESSIVE_DELAYS     = {
        3: 1,    # 3 échecs  → +1 seconde
        5: 3,    # 5 échecs  → +3 secondes
        7: 10,   # 7 échecs  → +10 secondes
        9: 30,   # 9 échecs  → +30 secondes
    }

    # IPs toujours autorisées (localhost, réseau interne)
    WHITELIST = {
        "127.0.0.1", "::1",
        "10.0.0.1",     # Passerelle interne type
    }

    # IPs connues malveillantes (normalement chargées depuis une threat feed)
    BLACKLIST = {
        "192.0.2.1",    # Exemple : IP d'un scanner connu
        "198.51.100.0", # Exemple : Plage TEST-NET
    }


# ─── Base de données SQLite ───────────────────────────────────────

DB_PATH = "/tmp/rate_limiter.db"
db_lock = threading.Lock()


def get_db():
    """Connexion thread-safe à SQLite."""
    if not hasattr(g, "_db"):
        g._db = sqlite3.connect(DB_PATH)
        g._db.row_factory = sqlite3.Row
    return g._db


def init_db():
    """Initialise les tables de suivi."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            username    TEXT,
            timestamp   REAL NOT NULL,
            success     INTEGER DEFAULT 0,
            user_agent  TEXT,
            country     TEXT
        );

        CREATE TABLE IF NOT EXISTS blocks (
            ip          TEXT PRIMARY KEY,
            reason      TEXT,
            blocked_at  REAL NOT NULL,
            expires_at  REAL NOT NULL,
            attempts    INTEGER DEFAULT 0,
            is_permanent INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            alert_type  TEXT NOT NULL,
            details     TEXT,
            timestamp   REAL NOT NULL,
            notified    INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_attempts_ip_time
            ON attempts(ip, timestamp);
        CREATE INDEX IF NOT EXISTS idx_blocks_ip
            ON blocks(ip);
    """)
    conn.commit()
    conn.close()


# ─── Moteur de Rate Limiting ──────────────────────────────────────

class RateLimiter:
    """
    Moteur central du système anti-brute force.

    Architecture :
    - Sliding window counter par IP + endpoint
    - Cache mémoire + persistance SQLite
    - Thread-safe via threading.Lock
    """

    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        self._cache = defaultdict(list)   # {ip: [timestamps]}
        self._lock  = threading.RLock()
        init_db()
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("RateLimiter")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        ))
        if not logger.handlers:
            logger.addHandler(handler)
        return logger

    def _get_real_ip(self, req) -> str:
        """
        Extrait la vraie IP en respectant les proxies/load balancers.
        X-Forwarded-For peut être falsifié — on prend le premier hop
        uniquement si on fait confiance au proxy.
        """
        # En production derrière un proxy de confiance :
        xff = req.headers.get("X-Forwarded-For")
        if xff:
            ip = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass
        return req.remote_addr or "0.0.0.0"

    def _count_recent_failures(self, ip: str, endpoint: str) -> int:
        """Compte les échecs dans la fenêtre glissante (mémoire + DB)."""
        cutoff = time.time() - self.config.WINDOW_SECONDS

        with self._lock:
            # Nettoyer le cache en mémoire
            self._cache[ip] = [t for t in self._cache[ip] if t > cutoff]
            mem_count = len(self._cache[ip])

        # Compléter avec la base de données (survie aux redémarrages)
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                """SELECT COUNT(*) FROM attempts
                   WHERE ip = ? AND endpoint = ?
                   AND timestamp > ? AND success = 0""",
                (ip, endpoint, cutoff)
            ).fetchone()
            db_count = row[0] if row else 0

        return max(mem_count, db_count)

    def record_attempt(self, ip: str, endpoint: str,
                       username: str = None, success: bool = False,
                       user_agent: str = None):
        """Enregistre une tentative d'accès."""
        now = time.time()

        if not success:
            with self._lock:
                self._cache[ip].append(now)

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """INSERT INTO attempts
                   (ip, endpoint, username, timestamp, success, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ip, endpoint, username, now, int(success), user_agent)
            )
            conn.commit()

    def check_ip(self, ip: str, endpoint: str) -> dict:
        """
        Évalue le statut d'une IP et retourne l'action à prendre.

        Returns:
            {
              "allowed": bool,
              "status": "ok"|"warn"|"slowdown"|"blocked"|"blacklisted",
              "delay":  int (secondes à attendre),
              "failures": int,
              "expires": float (timestamp expiration du bloc)
            }
        """
        cfg = self.config

        # 1. Whitelist — toujours autorisé
        if ip in cfg.WHITELIST:
            return {"allowed": True, "status": "whitelisted", "delay": 0, "failures": 0}

        # 2. Blacklist statique
        if ip in cfg.BLACKLIST:
            self._create_alert(ip, "BLACKLIST_HIT", "IP dans la liste noire statique")
            return {"allowed": False, "status": "blacklisted", "delay": 0,
                    "failures": 0, "message": "Accès refusé"}

        # 3. Vérifier si l'IP est actuellement bloquée
        block = self._get_block(ip)
        if block:
            if time.time() < block["expires_at"]:
                remaining = int(block["expires_at"] - time.time())
                return {
                    "allowed":  False,
                    "status":   "blocked",
                    "delay":    remaining,
                    "failures": block["attempts"],
                    "expires":  block["expires_at"],
                    "message":  f"IP bloquée. Réessayez dans {remaining}s."
                }
            else:
                # Bloc expiré → nettoyer
                self._remove_block(ip)

        # 4. Compter les échecs récents
        failures = self._count_recent_failures(ip, endpoint)

        # 5. Vérifier les seuils
        if failures >= cfg.PERMANENT_BAN_THRESHOLD:
            self._block_ip(ip, cfg.PERMANENT_BAN_SEC, failures, permanent=True)
            self._create_alert(ip, "PERMANENT_BAN",
                               f"{failures} tentatives — bannissement 24h")
            self.logger.warning(f"🔴 BAN PERMANENT : {ip} ({failures} tentatives)")
            return {"allowed": False, "status": "banned", "delay": cfg.PERMANENT_BAN_SEC,
                    "failures": failures, "message": "Accès définitivement refusé"}

        if failures >= cfg.BLOCK_THRESHOLD:
            self._block_ip(ip, cfg.BLOCK_DURATION_SEC, failures)
            self._create_alert(ip, "BLOCK",
                               f"{failures} tentatives en {cfg.WINDOW_SECONDS}s")
            self.logger.warning(f"🟠 BLOCAGE : {ip} ({failures} échecs → {cfg.BLOCK_DURATION_SEC}s)")
            return {"allowed": False, "status": "blocked",
                    "delay": cfg.BLOCK_DURATION_SEC, "failures": failures,
                    "expires": time.time() + cfg.BLOCK_DURATION_SEC,
                    "message": f"Trop de tentatives. Réessayez dans {cfg.BLOCK_DURATION_SEC}s."}

        # 6. Délai progressif
        delay = 0
        for threshold in sorted(cfg.PROGRESSIVE_DELAYS.keys(), reverse=True):
            if failures >= threshold:
                delay = cfg.PROGRESSIVE_DELAYS[threshold]
                break

        # 7. Déterminer le statut
        if failures >= cfg.SLOWDOWN_THRESHOLD:
            status = "slowdown"
        elif failures >= cfg.WARN_THRESHOLD:
            status = "warn"
            self.logger.info(f"🟡 AVERTISSEMENT : {ip} — {failures} échecs sur {endpoint}")
        else:
            status = "ok"

        return {
            "allowed":  True,
            "status":   status,
            "delay":    delay,
            "failures": failures,
        }

    def _block_ip(self, ip: str, duration: int, attempts: int,
                  permanent: bool = False):
        """Enregistre un bloc en base de données."""
        now = time.time()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO blocks
                   (ip, reason, blocked_at, expires_at, attempts, is_permanent)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ip, "brute_force", now, now + duration, attempts, int(permanent))
            )
            conn.commit()

    def _get_block(self, ip: str) -> Optional[dict]:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT * FROM blocks WHERE ip = ?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    def _remove_block(self, ip: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM blocks WHERE ip = ?", (ip,))
            conn.commit()

    def _create_alert(self, ip: str, alert_type: str, details: str):
        """Crée une alerte (en production : envoi email/Slack/SIEM)."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """INSERT INTO alerts (ip, alert_type, details, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (ip, alert_type, details, time.time())
            )
            conn.commit()

    def get_stats(self) -> dict:
        """Tableau de bord en temps réel."""
        cutoff = time.time() - self.config.WINDOW_SECONDS
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            total_attempts = conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE timestamp > ?", (cutoff,)
            ).fetchone()[0]

            failed = conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE timestamp > ? AND success = 0",
                (cutoff,)
            ).fetchone()[0]

            blocked_ips = conn.execute(
                "SELECT COUNT(*) FROM blocks WHERE expires_at > ?",
                (time.time(),)
            ).fetchone()[0]

            top_offenders = conn.execute(
                """SELECT ip, COUNT(*) as cnt FROM attempts
                   WHERE timestamp > ? AND success = 0
                   GROUP BY ip ORDER BY cnt DESC LIMIT 5""",
                (cutoff,)
            ).fetchall()

            recent_alerts = conn.execute(
                """SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10"""
            ).fetchall()

        return {
            "window_minutes":   self.config.WINDOW_SECONDS // 60,
            "total_attempts":   total_attempts,
            "failed_attempts":  failed,
            "success_rate":     f"{((total_attempts - failed) / max(total_attempts, 1)) * 100:.1f}%",
            "blocked_ips":      blocked_ips,
            "top_offenders":    [{"ip": r["ip"], "failures": r["cnt"]}
                                  for r in top_offenders],
            "recent_alerts":    [{"type": r["alert_type"], "ip": r["ip"],
                                   "details": r["details"]}
                                  for r in recent_alerts],
        }

    def unblock_ip(self, ip: str):
        """Débloque manuellement une IP (pour l'admin)."""
        self._remove_block(ip)
        self.logger.info(f"✅ IP débloquée manuellement : {ip}")


# ─── Décorateur Flask ─────────────────────────────────────────────

_limiter_instance = None

def get_limiter() -> RateLimiter:
    global _limiter_instance
    if _limiter_instance is None:
        _limiter_instance = RateLimiter()
    return _limiter_instance


def rate_limit(endpoint_name: str = None):
    """
    Décorateur Flask pour protéger une route.

    Usage :
        @app.route("/login", methods=["POST"])
        @rate_limit("login")
        def login():
            ...
    """
    def decorator(f: Callable):
        @wraps(f)
        def wrapped(*args, **kwargs):
            limiter  = get_limiter()
            ip       = request.headers.get("X-Forwarded-For",
                                           request.remote_addr or "0.0.0.0").split(",")[0].strip()
            endpoint = endpoint_name or request.endpoint or f.__name__
            ua       = request.headers.get("User-Agent", "")

            result = limiter.check_ip(ip, endpoint)

            if not result["allowed"]:
                # Log de sécurité structuré (compatible SIEM)
                security_event = {
                    "event":    "ACCESS_DENIED",
                    "ip":       ip,
                    "endpoint": endpoint,
                    "status":   result["status"],
                    "failures": result.get("failures", 0),
                    "time":     datetime.utcnow().isoformat(),
                }
                print(f"🚫 SECURITY: {json.dumps(security_event)}")

                return jsonify({
                    "error":   result.get("message", "Accès refusé"),
                    "status":  result["status"],
                    "retry_after": result.get("delay", 0),
                }), 429

            # Délai artificiel si nécessaire (anti-timing)
            if result.get("delay", 0) > 0:
                time.sleep(min(result["delay"], 10))  # Plafonner à 10s côté serveur

            # Exécuter la vraie fonction
            response = f(*args, **kwargs)

            # Enregistrer la tentative après la réponse
            success = response[1] == 200 if isinstance(response, tuple) else True
            username = request.json.get("username", "") if request.json else ""
            limiter.record_attempt(ip, endpoint, username, success=success, user_agent=ua)

            return response
        return wrapped
    return decorator


# ════════════════════════════════════════════════════════════════
# APPLICATION FLASK DE DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.urandom(32)

    # Faux "base de données" utilisateurs
    USERS = {
        "alice":  hashlib.sha256(b"SecretAlice!").hexdigest(),
        "bob":    hashlib.sha256(b"BobSecure#2024").hexdigest(),
        "admin":  hashlib.sha256(b"Admin@Vault999").hexdigest(),
    }

    @app.route("/login", methods=["POST"])
    @rate_limit("login")
    def login():
        data     = request.json or {}
        username = data.get("username", "")
        password = data.get("password", "")

        stored = USERS.get(username)
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()

        if stored and hmac_compare(pwd_hash, stored):
            return jsonify({"status": "ok", "message": f"Bienvenue {username}"}), 200
        else:
            return jsonify({"error": "Identifiants incorrects"}), 401

    @app.route("/api/data", methods=["GET"])
    @rate_limit("api")
    def api_data():
        return jsonify({"data": "Données sensibles de l'API"}), 200

    @app.route("/admin/stats", methods=["GET"])
    def admin_stats():
        """Dashboard de sécurité (non protégé pour la démo — à sécuriser en prod)."""
        limiter = get_limiter()
        stats = limiter.get_stats()
        return jsonify(stats), 200

    @app.route("/admin/unblock/<ip>", methods=["POST"])
    def admin_unblock(ip):
        get_limiter().unblock_ip(ip)
        return jsonify({"status": "unblocked", "ip": ip}), 200

    @app.teardown_appcontext
    def close_db(error):
        db = getattr(g, "_db", None)
        if db is not None:
            db.close()

    return app


def hmac_compare(a: str, b: str) -> bool:
    """Comparaison en temps constant (anti-timing attack)."""
    import hmac as _hmac
    return _hmac.compare_digest(a.encode(), b.encode())


# ════════════════════════════════════════════════════════════════
# SIMULATION D'ATTAQUE BRUTE FORCE + DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_simulation():
    """
    Simule une attaque brute force et montre le Rate Limiter en action.
    Utilise directement le moteur sans passer par HTTP.
    """
    SEP = "═" * 62

    print(f"\n{SEP}")
    print("  🎬  SIMULATION — Attaque Brute Force sur /login")
    print(f"{SEP}\n")

    print("""  Scénario : Un attaquant utilise credential stuffing
  (liste de couples login/mot de passe volés) pour tenter
  de compromettre un compte admin d'e-commerce.
  Vitesse réelle des bots : 100-10 000 tentatives/minute.
""")

    limiter = RateLimiter()

    # ── Attaquant 1 : IP fixe ──
    attacker_ip = "203.0.113.42"
    victims     = ["admin", "alice", "root", "administrator", "support"]
    passwords   = ["password", "123456", "admin123", "qwerty", "letmein",
                   "Password1!", "Summer2024", "Company@123", "Welcome1"]

    print(f"  {'─'*60}")
    print(f"  🔴 ATTAQUANT 1 : {attacker_ip} (brute force séquentiel)")
    print(f"  {'─'*60}")

    timeline = []
    attempt  = 0

    for username in victims:
        for password in passwords:
            attempt += 1
            result = limiter.check_ip(attacker_ip, "login")
            limiter.record_attempt(attacker_ip, "login", username,
                                   success=False, user_agent="python-requests/2.28.0")

            ts = f"T+{attempt * 2:03d}s"

            if not result["allowed"]:
                icon = "🚫"
                msg  = f"BLOQUÉ ({result['status']}) — retry dans {result.get('delay', 0)}s"
            elif result["status"] == "slowdown":
                icon = "🐌"
                msg  = f"RALENTI — délai {result['delay']}s ajouté ({result['failures']} échecs)"
            elif result["status"] == "warn":
                icon = "⚠️ "
                msg  = f"Passage en surveillance ({result['failures']} échecs)"
            else:
                icon = "🔓"
                msg  = f"Tentative transmise (échec auth: mauvais pwd)"

            print(f"  {ts}  {icon}  user={username:<15} pwd={password:<15}  → {msg}")
            timeline.append((attempt, result["status"], result["allowed"]))

            if not result["allowed"]:
                print(f"\n  ✅  Attaque stoppée après {attempt} tentatives !")
                break
        else:
            continue
        break

    # ── Attaquant 2 : IP rotation ──
    print(f"\n  {'─'*60}")
    print(f"  🟠 ATTAQUANT 2 : Rotation d'IPs (contournement naïf)")
    print(f"  {'─'*60}")

    rotating_ips = [f"198.51.100.{i}" for i in range(1, 8)]

    for i, ip in enumerate(rotating_ips):
        for _ in range(3):  # 3 tentatives par IP
            result = limiter.check_ip(ip, "login")
            limiter.record_attempt(ip, "login", "admin", success=False)

        failures = limiter._count_recent_failures(ip, "login")
        print(f"  IP {ip}  →  {failures} échecs "
              f"{'⚠️ surveillée' if failures >= 3 else '✓ sous seuil'}")

    print(f"""
  💡 Contre-mesure avancée (non implémentée ici) :
     Analyser le fingerprint HTTP (User-Agent, timing, headers)
     et les patterns comportementaux plutôt que l'IP seule.
     → Outils : fail2ban, Cloudflare Turnstile, CAPTCHA adaptatif.
""")

    # ── Statistiques finales ──
    print(f"  {'─'*60}")
    print(f"  📊  TABLEAU DE BORD SÉCURITÉ")
    print(f"  {'─'*60}")
    stats = limiter.get_stats()
    print(f"\n  Fenêtre d'analyse : {stats['window_minutes']} minutes")
    print(f"  Tentatives totales : {stats['total_attempts']}")
    print(f"  Tentatives échouées : {stats['failed_attempts']}")
    print(f"  IPs actuellement bloquées : {stats['blocked_ips']}")

    if stats["top_offenders"]:
        print(f"\n  Top attaquants :")
        for o in stats["top_offenders"]:
            bar = "█" * min(o["failures"], 20)
            print(f"    {o['ip']:<20} {bar} {o['failures']} échecs")

    if stats["recent_alerts"]:
        print(f"\n  Alertes récentes :")
        for a in stats["recent_alerts"][:5]:
            print(f"    🔔 [{a['type']:<18}] {a['ip']} — {a['details']}")

    # ── Scénario de récupération ──
    print(f"\n  {'─'*60}")
    print(f"  🔧  SCÉNARIO RÉCUPÉRATION : Faux positif")
    print(f"  {'─'*60}")
    legitimate_ip = "10.0.0.50"
    print(f"\n  Simulation : employé en télétravail bloqué par erreur")
    print(f"  IP : {legitimate_ip}")

    # Simuler quelques échecs légitimes (fautes de frappe)
    for _ in range(6):
        limiter.record_attempt(legitimate_ip, "login", "alice", success=False)
    r = limiter.check_ip(legitimate_ip, "login")
    print(f"  Statut : {r['status']} — bloqué ? {'OUI' if not r['allowed'] else 'NON'}")

    print(f"\n  Admin débloque manuellement...")
    limiter.unblock_ip(legitimate_ip)
    r2 = limiter.check_ip(legitimate_ip, "login")
    print(f"  Statut après déblocage : {r2['status']} — accès ? "
          f"{'✅ OUI' if r2['allowed'] else '❌ NON'}")

    # ── Architecture de déploiement ──
    print(f"\n{SEP}")
    print(f"  🏗️   ARCHITECTURE DE DÉPLOIEMENT")
    print(f"{SEP}")
    print(f"""
  ┌────────────────────────────────────────────────────────┐
  │  CLIENT  →  [NGINX rate limit]  →  [Flask @rate_limit] │
  │                                           ↓            │
  │                                    [SQLite / Redis]    │
  │                                           ↓            │
  │                              [Alertes email/Slack/SIEM]│
  └────────────────────────────────────────────────────────┘

  En production, remplacer SQLite par Redis pour :
  • Partage état entre plusieurs instances (load balancing)
  • Expiration automatique des entrées (TTL natif)
  • Performance : 100 000+ opérations/seconde

  Intégration NGINX (couche complémentaire) :
  limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
  limit_req zone=login burst=3 nodelay;

  💡 Règle d'or : Plusieurs couches valent mieux qu'une seule.
  NGINX bloque au niveau réseau, Flask au niveau applicatif.
""")

    print(f"  📋  Lien ISO 27001 — Contrôle A.9.4.2 :")
    print(f"  'Les tentatives de connexion infructueuses doivent être")
    print(f"  limitées et les tentatives répétées doivent déclencher")
    print(f"  un verrouillage de compte ou un délai croissant.'")


# ─── CLI ──────────────────────────────────────────────────────────

USAGE = """
Usage :
  python3 rate_limiter.py demo           Simulation complète (recommandé)
  python3 rate_limiter.py server         Lancer le serveur Flask de démo
  python3 rate_limiter.py stats          Afficher les stats en temps réel
"""

def main():
    print(__doc__)
    args = sys.argv[1:]

    if not args or args[0] == "demo":
        run_simulation()

    elif args[0] == "server":
        print("  🚀  Démarrage du serveur Flask de démo...")
        print("  Endpoints :")
        print("    POST /login           → protégé par rate limiting")
        print("    GET  /api/data        → protégé par rate limiting")
        print("    GET  /admin/stats     → tableau de bord sécurité")
        print("    POST /admin/unblock/<ip> → déblocage manuel")
        print()
        app = create_app()
        app.run(host="127.0.0.1", port=5000, debug=False)

    elif args[0] == "stats":
        limiter = RateLimiter()
        stats   = limiter.get_stats()
        print(json.dumps(stats, indent=2, ensure_ascii=False))

    else:
        print(USAGE)


if __name__ == "__main__":
    main()
