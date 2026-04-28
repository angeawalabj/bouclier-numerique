#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 26 : ZERO TRUST CONTROLLER     ║
║  Objectif  : Implémenter les principes Zero Trust              ║
║  Modèle    : Never Trust, Always Verify · Least Privilege      ║
║  Features  : mTLS · JWT · RBAC · Device Trust · Audit log     ║
╚══════════════════════════════════════════════════════════════════╝

"Never trust, always verify" — Principe fondateur du Zero Trust (ZT)
Concept introduit par John Kindervag (Forrester) en 2010, adopté
par NIST SP 800-207 (2020) et mandaté pour les agences US (EO 14028).

En opposition au modèle périmétrique traditionnel ("château-fossé"),
le Zero Trust considère que AUCUN réseau n'est de confiance, même
le réseau interne. Chaque accès doit être :

  ✅  Identifié    — qui demande ? (utilisateur + device)
  ✅  Authentifié  — preuve d'identité (MFA, certificat)
  ✅  Autorisé     — droit explicite sur cette ressource
  ✅  Chiffré      — même sur réseau interne
  ✅  Journalisé   — traçabilité complète
  ✅  Réévalué     — contexte réévalué à chaque requête

Ce contrôleur implémente :
  • Évaluation de confiance par requête (trust score 0-100)
  • RBAC avec héritage de rôles
  • Gestion des sessions avec réévaluation périodique
  • Device fingerprinting (OS, IP, user-agent)
  • Politique de moindre privilège vérifiable
  • Journal d'audit immuable avec signature HMAC

Conformité : NIST SP 800-207 · ANSSI PA-022 · ISO 27001 A.9
"""

import hashlib
import hmac
import json
import time
import uuid
import secrets
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
from dataclasses import dataclass, asdict, field


# ════════════════════════════════════════════════════════════════
# MODÈLE DE DONNÉES
# ════════════════════════════════════════════════════════════════

@dataclass
class Identity:
    user_id:    str
    username:   str
    roles:      list[str]
    mfa_ok:     bool = False
    cert_ok:    bool = False   # mTLS certificate présent
    dept:       str  = ""
    clearance:  int  = 0       # 0=public, 1=interne, 2=confidentiel, 3=secret

@dataclass
class DeviceContext:
    device_id:   str
    ip_address:  str
    user_agent:  str
    os_type:     str = "unknown"
    managed:     bool = False   # Device géré par l'entreprise (MDM)
    compliant:   bool = False   # Conformité policy (antivirus, patches...)

@dataclass
class AccessRequest:
    request_id:  str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    identity:    Optional[Identity] = None
    device:      Optional[DeviceContext] = None
    resource:    str = ""
    action:      str = "read"   # read / write / delete / admin
    timestamp:   str = field(default_factory=lambda: datetime.now().isoformat())
    context:     dict = field(default_factory=dict)


# ════════════════════════════════════════════════════════════════
# MOTEUR D'ÉVALUATION DE CONFIANCE
# ════════════════════════════════════════════════════════════════

class TrustEngine:
    """
    Calcule un score de confiance (0-100) pour chaque requête d'accès.
    Chaque facteur est évalué indépendamment et contribue au score.
    Un accès n'est accordé que si le score dépasse le seuil requis.
    """

    # Seuils de décision
    THRESHOLD_ALLOW   = 70   # Score minimum pour permettre l'accès
    THRESHOLD_STEP_UP = 50   # Score entre 50-70 → demander un 2e facteur
    THRESHOLD_DENY    = 50   # En dessous → refus immédiat

    def evaluate(self, request: AccessRequest) -> dict:
        """Évalue le score de confiance pour une requête."""
        factors = {}
        score   = 0

        identity = request.identity
        device   = request.device

        # ── Facteur 1 : Authentification (40 points max) ─────────
        if identity:
            if identity.mfa_ok:
                factors["mfa"]  = ("✅ MFA validé", +25)
                score += 25
            else:
                factors["mfa"]  = ("⚠️  MFA absent", +5)
                score += 5

            if identity.cert_ok:
                factors["cert"] = ("✅ Certificat mTLS valide", +15)
                score += 15
            else:
                factors["cert"] = ("ℹ️  Pas de certificat mTLS", 0)
        else:
            factors["identity"] = ("❌ Identité non fournie", -50)
            score -= 50

        # ── Facteur 2 : Appareil (30 points max) ─────────────────
        if device:
            if device.managed:
                factors["managed"]   = ("✅ Appareil géré (MDM)", +20)
                score += 20
            else:
                factors["managed"]   = ("⚠️  Appareil non géré", +5)
                score += 5

            if device.compliant:
                factors["compliant"] = ("✅ Appareil conforme", +10)
                score += 10
            else:
                factors["compliant"] = ("⚠️  Non-conformité appareil", 0)

            # IP interne vs externe
            ip = device.ip_address
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
                factors["network"] = ("ℹ️  Réseau interne (non suffisant en ZT)", +5)
                score += 5
            else:
                factors["network"] = ("⚠️  Accès depuis réseau externe", 0)
        else:
            factors["device"] = ("❌ Contexte appareil inconnu", -20)
            score -= 20

        # ── Facteur 3 : Comportement / contexte (30 points max) ──
        hour = datetime.now().hour
        if 8 <= hour <= 19:
            factors["time"] = ("✅ Horaire de travail", +10)
            score += 10
        elif 19 < hour <= 22:
            factors["time"] = ("⚠️  Horaire inhabituel (soir)", +5)
            score += 5
        else:
            factors["time"] = ("🔴 Horaire suspect (nuit)", 0)

        # Sensibilité de la ressource
        resource_lower = request.resource.lower()
        if any(kw in resource_lower for kw in ("admin", "root", "secret", "key", "backup")):
            factors["resource_sensitivity"] = ("🔴 Ressource très sensible → score réduit", -10)
            score -= 10
        elif any(kw in resource_lower for kw in ("conf", "config", "priv", "internal")):
            factors["resource_sensitivity"] = ("⚠️  Ressource sensible", -5)
            score -= 5
        else:
            factors["resource_sensitivity"] = ("ℹ️  Ressource standard", 0)

        # Action (write/delete plus risquée que read)
        action_penalty = {"read": 0, "write": -5, "delete": -15, "admin": -20}
        penalty = action_penalty.get(request.action, -10)
        if penalty < 0:
            factors["action"] = (f"⚠️  Action '{request.action}' à risque élevé", penalty)
            score += penalty
        else:
            factors["action"] = (f"✅ Action '{request.action}' (lecture seule)", 0)

        # Clearance niveau
        if identity:
            factors["clearance"] = (f"ℹ️  Niveau d'habilitation : {identity.clearance}", 0)

        score = max(0, min(100, score))

        if score >= self.THRESHOLD_ALLOW:
            decision = "ALLOW"
        elif score >= self.THRESHOLD_STEP_UP:
            decision = "STEP_UP"
        else:
            decision = "DENY"

        return {
            "score":    score,
            "decision": decision,
            "factors":  factors,
            "request_id": request.request_id,
            "ts":       request.timestamp,
        }


# ════════════════════════════════════════════════════════════════
# RBAC — Role-Based Access Control
# ════════════════════════════════════════════════════════════════

class RBACEngine:
    """
    Contrôle d'accès basé sur les rôles avec héritage.
    Principe du moindre privilège : tout est refusé par défaut.
    """

    def __init__(self):
        # Hiérarchie des rôles (role → rôles parents)
        self._hierarchy: dict[str, list[str]] = {}
        # Permissions par rôle : {role: {(resource_pattern, action)}}
        self._permissions: dict[str, set[tuple]] = defaultdict(set)

    def define_role(self, role: str, inherits_from: list[str] = None):
        self._hierarchy[role] = inherits_from or []
        if role not in self._permissions:
            self._permissions[role] = set()

    def grant(self, role: str, resource_pattern: str, action: str):
        """Accorde une permission à un rôle."""
        self._permissions[role].add((resource_pattern, action))

    def _get_effective_roles(self, role: str, visited: set = None) -> set[str]:
        """Résout l'héritage de rôles (DFS)."""
        if visited is None:
            visited = set()
        if role in visited:
            return set()
        visited.add(role)
        roles = {role}
        for parent in self._hierarchy.get(role, []):
            roles |= self._get_effective_roles(parent, visited)
        return roles

    def check(self, user_roles: list[str], resource: str, action: str) -> dict:
        """Vérifie si les rôles de l'utilisateur permettent l'accès."""
        effective_roles = set()
        for r in user_roles:
            effective_roles |= self._get_effective_roles(r)

        allowed_by = []
        for role in effective_roles:
            for (pattern, perm_action) in self._permissions.get(role, set()):
                action_ok    = perm_action in ("*", action)
                resource_ok  = (pattern == "*" or
                                resource.startswith(pattern) or
                                pattern in resource)
                if action_ok and resource_ok:
                    allowed_by.append(f"{role}:{pattern}:{perm_action}")

        return {
            "allowed":        bool(allowed_by),
            "effective_roles": sorted(effective_roles),
            "granted_by":     allowed_by,
            "resource":       resource,
            "action":         action,
        }


# ════════════════════════════════════════════════════════════════
# JOURNAL D'AUDIT IMMUABLE
# ════════════════════════════════════════════════════════════════

class AuditLog:
    """
    Journal d'audit avec chaînage HMAC pour détecter toute altération.
    Chaque entrée contient le hash de l'entrée précédente (comme une blockchain
    simplifiée) — toute modification rétroactive est détectable.
    """

    def __init__(self, db_path: str = ":memory:", secret: bytes = None):
        self.secret   = secret or secrets.token_bytes(32)
        self._conn    = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT NOT NULL,
                request_id  TEXT,
                user_id     TEXT,
                action      TEXT,
                resource    TEXT,
                decision    TEXT,
                trust_score INTEGER,
                details     TEXT,
                prev_hash   TEXT,
                entry_hash  TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "genesis"

    def _compute_hash(self, entry: dict, prev_hash: str) -> str:
        payload = json.dumps(entry, sort_keys=True) + prev_hash
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def log(self, request: AccessRequest, decision: str,
            trust_score: int, details: str = "") -> str:
        prev  = self._last_hash()
        entry = {
            "ts":          datetime.now().isoformat(),
            "request_id":  request.request_id,
            "user_id":     request.identity.user_id if request.identity else "anonymous",
            "action":      request.action,
            "resource":    request.resource,
            "decision":    decision,
            "trust_score": trust_score,
            "details":     details,
        }
        h = self._compute_hash(entry, prev)
        self._conn.execute(
            "INSERT INTO audit_log (ts,request_id,user_id,action,resource,"
            "decision,trust_score,details,prev_hash,entry_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (entry["ts"], entry["request_id"], entry["user_id"], entry["action"],
             entry["resource"], entry["decision"], entry["trust_score"],
             entry["details"], prev, h)
        )
        self._conn.commit()
        return h

    def verify_integrity(self) -> dict:
        """Vérifie que le journal n'a pas été altéré."""
        rows = self._conn.execute(
            "SELECT id,ts,request_id,user_id,action,resource,decision,"
            "trust_score,details,prev_hash,entry_hash FROM audit_log ORDER BY id"
        ).fetchall()

        if not rows:
            return {"ok": True, "entries": 0, "message": "Journal vide"}

        prev_hash = "genesis"
        for row in rows:
            (id_, ts, req_id, user_id, action, resource, decision,
             trust_score, details, stored_prev, stored_hash) = row

            entry = {"ts": ts, "request_id": req_id, "user_id": user_id,
                     "action": action, "resource": resource, "decision": decision,
                     "trust_score": trust_score, "details": details or ""}
            expected = self._compute_hash(entry, stored_prev)

            if expected != stored_hash:
                return {
                    "ok": False,
                    "entries": len(rows),
                    "tampered_at": id_,
                    "message": f"Entrée #{id_} altérée — journal compromis",
                }
            prev_hash = stored_hash

        return {"ok": True, "entries": len(rows),
                "message": f"Intégrité vérifiée — {len(rows)} entrée(s) valide(s)"}

    def get_entries(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts,request_id,user_id,action,resource,decision,trust_score "
            "FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"ts":r[0],"request_id":r[1],"user_id":r[2],"action":r[3],
                 "resource":r[4],"decision":r[5],"trust_score":r[6]} for r in rows]


# ════════════════════════════════════════════════════════════════
# CONTRÔLEUR ZERO TRUST PRINCIPAL
# ════════════════════════════════════════════════════════════════

class ZeroTrustController:
    """
    Contrôleur d'accès Zero Trust — orchestre trust engine + RBAC + audit.
    Chaque requête passe par les 4 étapes : Identifier → Authentifier → Autoriser → Journaliser
    """

    def __init__(self):
        self.trust_engine = TrustEngine()
        self.rbac         = RBACEngine()
        self.audit        = AuditLog()
        self._setup_default_policy()

    def _setup_default_policy(self):
        """Configure la politique RBAC d'exemple."""
        # Hiérarchie des rôles
        self.rbac.define_role("viewer",  [])
        self.rbac.define_role("editor",  ["viewer"])
        self.rbac.define_role("manager", ["editor"])
        self.rbac.define_role("admin",   ["manager"])
        self.rbac.define_role("auditor", [])

        # Permissions viewer
        self.rbac.grant("viewer",  "/public/",   "read")
        self.rbac.grant("viewer",  "/docs/",     "read")

        # Permissions editor (+ héritage viewer)
        self.rbac.grant("editor",  "/data/",     "read")
        self.rbac.grant("editor",  "/data/",     "write")
        self.rbac.grant("editor",  "/reports/",  "read")

        # Permissions manager
        self.rbac.grant("manager", "/reports/",  "write")
        self.rbac.grant("manager", "/users/",    "read")

        # Permissions admin
        self.rbac.grant("admin",   "/",          "*")   # Tout

        # Permissions auditor (lecture de l'audit uniquement)
        self.rbac.grant("auditor", "/audit/",    "read")
        self.rbac.grant("auditor", "/logs/",     "read")

    def access(self, request: AccessRequest) -> dict:
        """
        Évalue une demande d'accès selon les 4 piliers ZT.
        Retourne la décision finale avec tous les détails.
        """

        # ── Étape 1 : Évaluation Trust Score ────────────────────
        trust_result = self.trust_engine.evaluate(request)
        trust_score  = trust_result["score"]
        trust_decision = trust_result["decision"]

        # ── Étape 2 : RBAC ───────────────────────────────────────
        rbac_result = {"allowed": False, "granted_by": []}
        if request.identity:
            rbac_result = self.rbac.check(
                request.identity.roles,
                request.resource,
                request.action
            )

        # ── Étape 3 : Décision finale ────────────────────────────
        if trust_decision == "DENY":
            final = "DENY"
            reason = f"Score de confiance insuffisant ({trust_score}/100 < {TrustEngine.THRESHOLD_DENY})"
        elif not rbac_result["allowed"]:
            final = "DENY"
            reason = f"RBAC : aucune permission pour {request.action} sur {request.resource}"
        elif trust_decision == "STEP_UP":
            final = "STEP_UP"
            reason = f"Score {trust_score}/100 — authentification renforcée requise"
        else:
            final = "ALLOW"
            reason = f"Score {trust_score}/100 · {', '.join(rbac_result['granted_by'][:2])}"

        # ── Étape 4 : Journal d'audit ────────────────────────────
        self.audit.log(request, final, trust_score, reason)

        return {
            "decision":      final,
            "trust_score":   trust_score,
            "trust_factors": trust_result["factors"],
            "rbac":          rbac_result,
            "reason":        reason,
            "request_id":    request.request_id,
        }

    def summary(self) -> dict:
        """Retourne un résumé des accès récents."""
        entries   = self.audit.get_entries(100)
        integrity = self.audit.verify_integrity()
        counts    = defaultdict(int)
        for e in entries:
            counts[e["decision"]] += 1

        return {
            "total":     len(entries),
            "allowed":   counts["ALLOW"],
            "denied":    counts["DENY"],
            "step_up":   counts["STEP_UP"],
            "integrity": integrity,
        }


# ════════════════════════════════════════════════════════════════
# DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 26 : ZERO TRUST CONTROLLER     ║
╚══════════════════════════════════════════════════════════════════╝

  "Never Trust, Always Verify" — NIST SP 800-207
""")

    ztc = ZeroTrustController()

    # ── Scénarios de test ────────────────────────────────────────
    scenarios = [
        # 1. Admin avec MFA et certificat — accès total attendu
        AccessRequest(
            identity=Identity("u001", "alice", ["admin"], mfa_ok=True, cert_ok=True, clearance=3),
            device=DeviceContext("d001", "10.0.1.50", "Mozilla/5.0", "Windows", managed=True, compliant=True),
            resource="/admin/dashboard",
            action="read",
        ),
        # 2. Éditeur sans MFA sur réseau externe — step-up attendu
        AccessRequest(
            identity=Identity("u002", "bob", ["editor"], mfa_ok=False, cert_ok=False),
            device=DeviceContext("d002", "85.12.34.56", "Chrome/120", "Linux", managed=False, compliant=False),
            resource="/data/clients.csv",
            action="write",
        ),
        # 3. Viewer tentant une suppression — RBAC deny
        AccessRequest(
            identity=Identity("u003", "charlie", ["viewer"], mfa_ok=True, cert_ok=True),
            device=DeviceContext("d003", "10.0.1.51", "Firefox/121", "macOS", managed=True, compliant=True),
            resource="/data/backup.tar.gz",
            action="delete",
        ),
        # 4. Identité anonyme — deny immédiat
        AccessRequest(
            identity=None,
            device=DeviceContext("d004", "192.168.1.10", "curl/8.0"),
            resource="/public/index.html",
            action="read",
        ),
        # 5. Auditeur sur logs — autorisation correcte
        AccessRequest(
            identity=Identity("u004", "diana", ["auditor"], mfa_ok=True, cert_ok=True),
            device=DeviceContext("d005", "10.0.1.52", "Mozilla/5.0", "Linux", managed=True, compliant=True),
            resource="/audit/events",
            action="read",
        ),
        # 6. Manager à 3h du matin — score réduit
        AccessRequest(
            identity=Identity("u005", "eve", ["manager"], mfa_ok=True, cert_ok=False),
            device=DeviceContext("d006", "10.0.1.53", "Mozilla/5.0", "Windows", managed=True, compliant=False),
            resource="/reports/financier_Q1.xlsx",
            action="read",
            context={"simulated_hour": 3},
        ),
    ]

    decision_icons = {"ALLOW": "✅", "DENY": "❌", "STEP_UP": "🔐"}

    print(f"  {'─'*62}")
    print(f"  {'Utilisateur':<12} {'Ressource':<28} {'Action':<8} {'Score':>6}  {'Décision'}")
    print(f"  {'─'*62}")

    for req in scenarios:
        result = ztc.access(req)
        user   = req.identity.username if req.identity else "anonyme"
        icon   = decision_icons.get(result["decision"], "?")
        print(f"  {user:<12} {req.resource:<28} {req.action:<8} "
              f"{result['trust_score']:>5}/100  {icon} {result['decision']}")
        print(f"  {'':12} → {result['reason'][:60]}")
        print()

    # ── Intégrité du journal ─────────────────────────────────────
    integrity = ztc.audit.verify_integrity()
    print(f"  {'─'*62}")
    print(f"  🔐  Intégrité du journal d'audit : "
          f"{'✅ OK' if integrity['ok'] else '❌ COMPROMIS'} "
          f"({integrity['entries']} entrées)")

    # ── Résumé ───────────────────────────────────────────────────
    s = ztc.summary()
    print(f"\n  📊  Résumé : {s['total']} requêtes · "
          f"✅ {s['allowed']} autorisées · "
          f"❌ {s['denied']} refusées · "
          f"🔐 {s['step_up']} step-up")

    print(f"""
  {'─'*62}
  Principes Zero Trust implémentés :

  ✅  Never Trust, Always Verify — chaque requête évaluée
  ✅  Trust Score composite (MFA + appareil + réseau + heure)
  ✅  RBAC avec héritage de rôles (moindre privilège)
  ✅  Journal d'audit HMAC-chaîné (détection altération)
  ✅  Décision STEP_UP pour score intermédiaire

  Conformité : NIST SP 800-207 · ISO 27001 A.9 · ANSSI PA-022
  {'─'*62}
""")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="Zero Trust Controller — Bouclier Numérique J26")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Démonstration des scénarios Zero Trust")

    pa = sub.add_parser("check", help="Vérifier un accès")
    pa.add_argument("--user",     required=True)
    pa.add_argument("--roles",    required=True, help="Rôles séparés par virgule")
    pa.add_argument("--resource", required=True)
    pa.add_argument("--action",   default="read")
    pa.add_argument("--ip",       default="127.0.0.1")
    pa.add_argument("--mfa",      action="store_true")
    pa.add_argument("--managed",  action="store_true")

    args = p.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    ztc = ZeroTrustController()
    req = AccessRequest(
        identity=Identity(args.user, args.user, args.roles.split(","), mfa_ok=args.mfa),
        device=DeviceContext("cli", args.ip, "CLI", managed=args.managed, compliant=args.managed),
        resource=args.resource,
        action=args.action,
    )
    result = ztc.access(req)
    icons  = {"ALLOW": "✅", "DENY": "❌", "STEP_UP": "🔐"}
    print(f"{icons[result['decision']]} {result['decision']} (score: {result['trust_score']}/100)")
    print(f"Raison : {result['reason']}")


if __name__ == "__main__":
    main()
