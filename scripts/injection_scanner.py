#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 22 : SCANNER INJECTIONS        ║
║  Objectif  : Détecter SQLi, XSS, SSTI, Command Injection      ║
║  Technique : Payloads adaptatifs · Détection de réflexion      ║
║  Légalité  : Usage sur VOS propres applications UNIQUEMENT     ║
╚══════════════════════════════════════════════════════════════════╝

Différence avec le fuzzer d'API (Jour 21) :
  - Jour 21 : protocole API (OWASP API Top 10, endpoints REST)
  - Jour 22 : injections dans les paramètres (OWASP Web Top 10)
              → crawl des formulaires HTML, spider des paramètres GET/POST
              → détection fine SQLi (basée sur erreurs + time-based)
              → XSS réfléchi et stocké, SSTI, Command Injection

Techniques de détection :
  SQLi Error-based  : mots-clés d'erreur DB dans la réponse
  SQLi Time-based   : SLEEP(3)/pg_sleep(3)/WAITFOR DELAY → latence
  XSS Réfléchi      : marqueur unique retrouvé dans le DOM
  XSS Stocké        : vérification post-soumission sur la page cible
  SSTI              : {{7*7}} → "49" dans la réponse
  CMDi              : ; id ; whoami → uid= dans la réponse

Conformité : OWASP Top 10 A03:2021 (Injection) · ISO 27001 A.14.2.8
"""

import urllib.request
import urllib.error
import urllib.parse
import html as html_module
import time
import re
import random
import string
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict
from html.parser import HTMLParser


# ════════════════════════════════════════════════════════════════
# BIBLIOTHÈQUE DE PAYLOADS
# ════════════════════════════════════════════════════════════════

MARKER_PREFIX = "BNUM"   # Marqueur unique pour détecter la réflexion XSS

def gen_marker() -> str:
    """Génère un identifiant unique pour détecter la réflexion."""
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"{MARKER_PREFIX}{suffix}"


SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
    "1 AND 1=2",
    "' OR 1=1--",
    "admin'--",
    "') OR ('1'='1",
]

SQLI_TIME_PAYLOADS = [
    ("mysql",      "' AND SLEEP(3)--",          3.0),
    ("mysql",      "1; SELECT SLEEP(3)--",       3.0),
    ("postgresql", "'; SELECT pg_sleep(3)--",    3.0),
    ("postgresql", "1; SELECT pg_sleep(3)--",    3.0),
    ("mssql",      "'; WAITFOR DELAY '0:0:3'--", 3.0),
    ("sqlite",     "1 AND 1=1",                  0.0),  # Pas de sleep SQLite standard
]

SQLI_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "supplied argument is not a valid mysql",
    "mysql server version",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "postgresql",
    "psql:",
    # MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "sql server",
    "sqlstate",
    # Oracle
    "ora-",
    "oracle error",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    # Générique
    "syntax error",
    "odbc microsoft access driver",
    "jdbc",
    "sql command not properly ended",
    "unexpected token",
]

XSS_PAYLOADS = [
    '<script>alert("{marker}")</script>',
    '<img src=x onerror=\'alert("{marker}")\'>',
    '"><script>alert("{marker}")</script>',
    "'><svg onload='alert(\"{marker}\")'>",
    '<body onload=alert("{marker}")>',
    '{{"{marker}"}}',                          # SSTI Jinja2
    '${"{marker}"}',                           # SSTI EL / Thymeleaf
    "#{\"#{#{#{#{#{\"{marker}\"}}}}}}\"}}}}}",  # SSTI Ruby ERB
]

SSTI_PAYLOADS = [
    ("{{7*7}}",         "49"),    # Jinja2, Twig
    ("${7*7}",          "49"),    # Thymeleaf, EL
    ("<%= 7*7 %>",      "49"),    # ERB (Ruby)
    ("#{7*7}",          "49"),    # Ruby String Interpolation
    ("{{7*'7'}}",       "7777777"), # Jinja2 (multiplication str)
    ("{php}echo 7*7;{/php}", "49"),  # Smarty
]

CMDI_PAYLOADS = [
    ("; id",         r"uid=\d+"),
    ("| id",         r"uid=\d+"),
    ("` id`",        r"uid=\d+"),
    ("$(id)",        r"uid=\d+"),
    ("; whoami",     r"\w+"),
    ("| cat /etc/passwd", r"root:"),
    ("; ping -c1 127.0.0.1", r"1 received|bytes from"),
]


# ════════════════════════════════════════════════════════════════
# PARSEUR HTML — extraction des formulaires et liens
# ════════════════════════════════════════════════════════════════

class FormParser(HTMLParser):
    """Extrait tous les formulaires et champs d'une page HTML."""

    def __init__(self):
        super().__init__()
        self.forms   = []
        self.links   = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name  = attrs.get("name", "")
            itype = attrs.get("type", "text")
            value = attrs.get("value", "test")
            if name and itype not in ("submit", "button", "hidden", "image"):
                self._current_form["inputs"].append({
                    "name": name, "type": itype, "value": value
                })
        elif tag == "a":
            href = attrs.get("href", "")
            if href and href.startswith(("http", "/", "?")):
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ════════════════════════════════════════════════════════════════
# MOTEUR DE SCAN
# ════════════════════════════════════════════════════════════════

class InjectionScanner:

    def __init__(self, base_url: str, timeout: float = 6.0,
                 rate_limit: float = 0.15, max_pages: int = 20):
        self.base_url   = base_url.rstrip("/")
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.max_pages  = max_pages
        self.findings   = []
        self.visited    = set()
        self._lock      = threading.Lock()
        self._req_count = 0

    # ── HTTP helpers ─────────────────────────────────────────────

    def _get(self, url: str, params: dict = None) -> dict:
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return self._do_request("GET", url)

    def _post(self, url: str, data: dict) -> dict:
        body = urllib.parse.urlencode(data).encode()
        return self._do_request("POST", url, body=body,
                                content_type="application/x-www-form-urlencoded")

    def _do_request(self, method: str, url: str,
                    body: bytes = None, content_type: str = None) -> dict:
        headers = {
            "User-Agent": "BouclierNumerique-Scanner/1.0 (Security Audit)",
            "Accept": "text/html,application/json,*/*",
        }
        if content_type:
            headers["Content-Type"] = content_type

        t0 = time.monotonic()
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body_bytes = resp.read(65536)
                body_text  = body_bytes.decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "body": body_text,
                    "headers": dict(resp.headers),
                    "url": url, "error": None,
                    "latency": time.monotonic() - t0,
                }
        except urllib.error.HTTPError as e:
            body_text = e.read(4096).decode("utf-8", errors="replace")
            return {
                "status": e.code, "body": body_text,
                "headers": dict(e.headers) if e.headers else {},
                "url": url, "error": str(e),
                "latency": time.monotonic() - t0,
            }
        except Exception as e:
            return {
                "status": 0, "body": "", "headers": {},
                "url": url, "error": str(e),
                "latency": time.monotonic() - t0,
            }
        finally:
            time.sleep(self.rate_limit)
            with self._lock:
                self._req_count += 1

    def _add(self, vuln_type: str, severity: str, title: str,
             description: str, evidence: str, url: str,
             param: str, payload: str, remediation: str, owasp: str):
        f = {
            "id": len(self.findings) + 1,
            "type": vuln_type,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence[:600],
            "url": url,
            "param": param,
            "payload": payload[:200],
            "remediation": remediation,
            "owasp": owasp,
            "ts": datetime.now().isoformat(),
        }
        with self._lock:
            self.findings.append(f)
        sev_icons = {"CRITIQUE":"🔴","ÉLEVÉE":"🟠","MODÉRÉE":"🟡","FAIBLE":"🟢"}
        print(f"    {sev_icons.get(severity,'⚪')} [{severity}] {title}")

    # ── Crawl ────────────────────────────────────────────────────

    def crawl(self) -> list[dict]:
        """
        Découvre les pages, formulaires et paramètres GET du site.
        Retourne la liste des cibles à tester.
        """
        targets = []
        queue   = [self.base_url]
        visited = set()

        print(f"  🕷️  Crawl de {self.base_url}...")

        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            r = self._get(url)
            if r["status"] == 0 or not r["body"]:
                continue

            # Extraire les paramètres GET de l'URL
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            if params:
                targets.append({
                    "url": url.split("?")[0],
                    "method": "GET",
                    "params": {k: v[0] for k, v in params.items()},
                    "source": "url_params",
                })

            # Extraire les formulaires
            parser = FormParser()
            try:
                parser.feed(r["body"])
            except Exception:
                pass

            for form in parser.forms:
                action = form["action"] or url
                if not action.startswith("http"):
                    action = self.base_url.rstrip("/") + "/" + action.lstrip("/")
                if form["inputs"]:
                    targets.append({
                        "url": action,
                        "method": form["method"],
                        "params": {inp["name"]: inp["value"] for inp in form["inputs"]},
                        "source": "form",
                    })

            # Suivre les liens internes
            for link in parser.links[:15]:
                if link.startswith("/"):
                    link = self.base_url + link
                elif link.startswith("?"):
                    link = url.split("?")[0] + link
                if link.startswith(self.base_url) and link not in visited:
                    queue.append(link)

        print(f"  📄  {len(visited)} page(s) crawlée(s) · {len(targets)} cible(s) trouvée(s)\n")
        return targets

    # ── SQLi Error-based ─────────────────────────────────────────

    def test_sqli_error(self, url: str, method: str, params: dict):
        """Détecte les injections SQL par les messages d'erreur de la BD."""
        for param_name in params:
            for payload in SQLI_ERROR_PAYLOADS:
                test_params = {**params, param_name: payload}
                r = self._get(url, test_params) if method == "GET" else self._post(url, test_params)

                body_lower = r["body"].lower()
                matched = next(
                    (sig for sig in SQLI_ERROR_SIGNATURES if sig in body_lower), None
                )
                if matched:
                    self._add(
                        vuln_type="SQLi — Error-based",
                        severity="CRITIQUE",
                        title=f"Injection SQL (error-based) sur /{url.split('/')[-1]}",
                        description=(
                            f"Le paramètre '{param_name}' n'est pas correctement échappé. "
                            f"Un message d'erreur SQL a été détecté dans la réponse, "
                            "révélant la structure interne de la base de données."
                        ),
                        evidence=f"Signature détectée : '{matched}'\nExtrait : ...{r['body'][max(0,body_lower.find(matched)-50):body_lower.find(matched)+200]}...",
                        url=url,
                        param=param_name,
                        payload=payload,
                        remediation=(
                            "Utiliser des requêtes paramétrées (prepared statements). "
                            "Ne JAMAIS concaténer des entrées utilisateur dans une requête SQL. "
                            "Désactiver l'affichage des erreurs en production."
                        ),
                        owasp="A03:2021 — Injection",
                    )
                    return  # Une vuln confirmée suffit pour ce paramètre

    # ── SQLi Time-based ──────────────────────────────────────────

    def test_sqli_time(self, url: str, method: str, params: dict):
        """
        Détecte les injections SQL aveugles par mesure du temps de réponse.
        Méthode fiable même si les erreurs ne sont pas affichées.
        """
        # Mesure de référence (temps de réponse normal)
        baseline = []
        for _ in range(2):
            r = self._get(url, params) if method == "GET" else self._post(url, params)
            baseline.append(r["latency"])
        baseline_avg = sum(baseline) / len(baseline)

        for db_type, payload, expected_delay in SQLI_TIME_PAYLOADS:
            if expected_delay == 0:
                continue
            for param_name in params:
                test_params = {**params, param_name: payload}
                r = self._get(url, test_params) if method == "GET" else self._post(url, test_params)

                # Si la réponse prend >= expected_delay + marge, injection probable
                if r["latency"] >= expected_delay + 1.0 and r["latency"] > baseline_avg + 2.0:
                    self._add(
                        vuln_type="SQLi — Time-based Blind",
                        severity="CRITIQUE",
                        title=f"Injection SQL aveugle (time-based) sur /{url.split('/')[-1]}",
                        description=(
                            f"Le paramètre '{param_name}' provoque un délai artificiel "
                            f"de {r['latency']:.1f}s (baseline: {baseline_avg:.2f}s) "
                            f"avec un payload {db_type.upper()}. "
                            "La base de données est injectable même sans affichage d'erreur."
                        ),
                        evidence=(
                            f"Payload : {payload}\n"
                            f"Délai mesuré : {r['latency']:.2f}s\n"
                            f"Baseline : {baseline_avg:.2f}s\n"
                            f"DB suspectée : {db_type.upper()}"
                        ),
                        url=url,
                        param=param_name,
                        payload=payload,
                        remediation=(
                            "Requêtes paramétrées obligatoires. "
                            "Un ORM correctement configuré protège contre cette attaque. "
                            "Auditer toutes les requêtes SQL construites dynamiquement."
                        ),
                        owasp="A03:2021 — Injection",
                    )
                    return

    # ── XSS Réfléchi ─────────────────────────────────────────────

    def test_xss_reflected(self, url: str, method: str, params: dict):
        """
        Détecte le XSS réfléchi avec un marqueur unique.
        Si le marqueur apparaît dans la réponse sans échappement HTML,
        le script injecté s'exécuterait dans le navigateur de la victime.
        """
        for param_name in params:
            marker = gen_marker()
            for template in XSS_PAYLOADS[:5]:
                payload = template.replace("{marker}", marker)
                test_params = {**params, param_name: payload}
                r = self._get(url, test_params) if method == "GET" else self._post(url, test_params)

                # Vérifier la réflexion : le marqueur est-il présent sans être encodé HTML ?
                if marker in r["body"]:
                    # Est-il encodé ? (&lt;script&gt; = sécurisé, <script> = vulnérable)
                    body_at_marker = r["body"][
                        max(0, r["body"].find(marker)-100):
                        r["body"].find(marker)+len(payload)+50
                    ]
                    is_encoded = "&lt;" in body_at_marker or "&amp;" in body_at_marker

                    if not is_encoded and "<" in payload and "<" in r["body"]:
                        self._add(
                            vuln_type="XSS Réfléchi",
                            severity="ÉLEVÉE",
                            title=f"XSS réfléchi sur /{url.split('/')[-1]} (param: {param_name})",
                            description=(
                                f"Le contenu du paramètre '{param_name}' est retourné "
                                "dans la page HTML sans encodage. Un attaquant peut injecter "
                                "du JavaScript arbitraire qui s'exécute dans le navigateur "
                                "de la victime (vol de cookie, phishing, keylogger...)"
                            ),
                            evidence=(
                                f"Payload envoyé : {payload[:100]}\n"
                                f"Contexte dans la réponse :\n{body_at_marker[:300]}"
                            ),
                            url=url,
                            param=param_name,
                            payload=payload,
                            remediation=(
                                "Encoder toutes les sorties HTML (htmlspecialchars en PHP, "
                                "{{ var }} en Jinja2/Django, escapeHtml en Java). "
                                "Implémenter Content-Security-Policy. "
                                "Valider et rejeter les entrées contenant des balises HTML."
                            ),
                            owasp="A03:2021 — Injection (XSS)",
                        )
                        return  # Vuln confirmée, passer au paramètre suivant

    # ── SSTI ─────────────────────────────────────────────────────

    def test_ssti(self, url: str, method: str, params: dict):
        """
        Détecte l'injection de templates côté serveur (Server-Side Template Injection).
        SSTI → exécution de code arbitraire sur le serveur.
        """
        for param_name in params:
            for payload, expected in SSTI_PAYLOADS:
                test_params = {**params, param_name: payload}
                r = self._get(url, test_params) if method == "GET" else self._post(url, test_params)

                if expected in r["body"]:
                    self._add(
                        vuln_type="SSTI",
                        severity="CRITIQUE",
                        title=f"Injection de template (SSTI) sur /{url.split('/')[-1]}",
                        description=(
                            f"Le paramètre '{param_name}' est interpolé par le moteur "
                            f"de templates sans échappement. Payload '{payload}' a produit "
                            f"'{expected}' dans la réponse. SSTI permet l'exécution de code "
                            "arbitraire sur le serveur — équivalent à une RCE."
                        ),
                        evidence=f"Payload: {payload}\nRésultat attendu: {expected}\nExtrait réponse: {r['body'][:300]}",
                        url=url,
                        param=param_name,
                        payload=payload,
                        remediation=(
                            "Ne jamais rendre des entrées utilisateur directement dans un template. "
                            "Utiliser le sandboxing (Jinja2 SandboxedEnvironment). "
                            "Valider et rejeter toute entrée contenant {{ }} ${ } #{ }."
                        ),
                        owasp="A03:2021 — Injection (SSTI → RCE)",
                    )
                    return

    # ── Command Injection ────────────────────────────────────────

    def test_cmdi(self, url: str, method: str, params: dict):
        """Détecte les injections de commandes OS."""
        for param_name in params:
            for payload, pattern in CMDI_PAYLOADS:
                test_params = {**params, param_name: payload}
                r = self._get(url, test_params) if method == "GET" else self._post(url, test_params)

                if re.search(pattern, r["body"]):
                    self._add(
                        vuln_type="Command Injection",
                        severity="CRITIQUE",
                        title=f"Injection de commande OS sur /{url.split('/')[-1]}",
                        description=(
                            f"Le paramètre '{param_name}' est passé à un interpréteur "
                            "de commandes sans validation. Un attaquant peut exécuter des "
                            "commandes arbitraires sur le serveur avec les privilèges "
                            "de l'application web."
                        ),
                        evidence=f"Payload: {payload}\nSortie OS: {r['body'][:300]}",
                        url=url,
                        param=param_name,
                        payload=payload,
                        remediation=(
                            "Ne jamais passer des entrées utilisateur à subprocess/os.system/exec. "
                            "Utiliser des APIs dédiées plutôt que des appels shell. "
                            "Si inévitable : liste blanche stricte des caractères autorisés."
                        ),
                        owasp="A03:2021 — Injection (OS Command)",
                    )
                    return

    # ── Scan complet ─────────────────────────────────────────────

    def scan(self, targets: list[dict] = None):
        """Lance tous les tests sur les cibles découvertes ou fournies."""
        if targets is None:
            targets = self.crawl()

        if not targets:
            print("  ⚠️  Aucune cible trouvée — vérifier l'URL de base.\n")
            return

        total = len(targets)
        for i, t in enumerate(targets, 1):
            url    = t["url"]
            method = t.get("method", "GET")
            params = t.get("params", {})
            if not params:
                continue

            print(f"  [{i:02d}/{total}] {method} {url}")
            self.test_sqli_error(url, method, params)
            self.test_sqli_time(url, method, params)
            self.test_xss_reflected(url, method, params)
            self.test_ssti(url, method, params)
            self.test_cmdi(url, method, params)

    # ── Rapport HTML ─────────────────────────────────────────────

    def generate_report(self, output_path: Optional[Path] = None) -> str:
        sev_order  = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MODÉRÉE": 2, "FAIBLE": 3}
        sev_colors = {"CRITIQUE": "#e74c3c", "ÉLEVÉE": "#e67e22",
                      "MODÉRÉE": "#f39c12",  "FAIBLE": "#27ae60"}
        sev_icons  = {"CRITIQUE": "🔴", "ÉLEVÉE": "🟠", "MODÉRÉE": "🟡", "FAIBLE": "🟢"}

        sorted_f = sorted(self.findings, key=lambda x: sev_order.get(x["severity"], 9))
        counts   = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1

        score = max(0, 100 - (
            counts.get("CRITIQUE", 0) * 30 +
            counts.get("ÉLEVÉE",   0) * 15 +
            counts.get("MODÉRÉE",  0) *  5 +
            counts.get("FAIBLE",   0) *  2
        ))
        score_color = "#e74c3c" if score < 50 else "#e67e22" if score < 75 else "#27ae60"

        cards_html = ""
        for f in sorted_f:
            c = sev_colors.get(f["severity"], "#666")
            i = sev_icons.get(f["severity"], "⚪")
            owasp_short = f["owasp"].split("—")[0].strip()
            cards_html += f"""
        <div class="card" style="border-left:4px solid {c}">
          <div class="card-header">
            <span class="badge" style="background:{c}">{i} {html_module.escape(f['severity'])}</span>
            <span class="tag">{html_module.escape(owasp_short)}</span>
            <span class="tag tag-type">{html_module.escape(f['type'])}</span>
            <strong>{html_module.escape(f['title'])}</strong>
          </div>
          <p>{html_module.escape(f['description'])}</p>
          <div class="two-col">
            <div>
              <div class="label">Paramètre vulnérable</div>
              <code>{html_module.escape(f['param'])}</code>
            </div>
            <div>
              <div class="label">Payload utilisé</div>
              <code>{html_module.escape(f['payload'][:80])}</code>
            </div>
          </div>
          <details>
            <summary>📋 Preuve technique</summary>
            <pre>{html_module.escape(f['evidence'])}</pre>
          </details>
          <div class="fix">✅ <strong>Remédiation :</strong> {html_module.escape(f['remediation'])}</div>
          <div class="meta">🔗 {html_module.escape(f['url'])} · {f['ts'][:19]}</div>
        </div>"""

        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        report = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>🛡️ Rapport Injections — {html_module.escape(self.base_url)}</title>
  <style>
    :root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem;max-width:1100px;margin:auto}}
    h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}
    .meta{{color:var(--muted);font-size:.82rem;margin-bottom:2rem}}
    .score-row{{display:flex;align-items:center;gap:2rem;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:2rem;flex-wrap:wrap}}
    .score-num{{font-size:3.5rem;font-weight:900;color:{score_color}}}
    .score-sub{{color:var(--muted);font-size:.85rem}}
    .chips{{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:.5rem}}
    .chip{{padding:.3rem .8rem;border-radius:20px;font-weight:700;font-size:.82rem}}
    .section{{color:var(--accent);font-size:1.1rem;margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.4rem}}
    .card{{background:var(--card);border-radius:8px;padding:1.2rem;margin-bottom:1rem;border:1px solid var(--border)}}
    .card-header{{display:flex;align-items:center;gap:.6rem;margin-bottom:.8rem;flex-wrap:wrap}}
    .badge{{color:#fff;padding:.2rem .6rem;border-radius:4px;font-size:.78rem;font-weight:700}}
    .tag{{background:#1e3a5f;color:#7eb8f7;padding:.2rem .6rem;border-radius:4px;font-size:.78rem}}
    .tag-type{{background:#1a3a1a;color:#7ef77e}}
    p{{color:var(--muted);font-size:.9rem;line-height:1.5;margin:.4rem 0}}
    .two-col{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin:.8rem 0}}
    .label{{font-size:.75rem;color:var(--muted);margin-bottom:.2rem}}
    code{{background:#0a0c14;padding:.2rem .5rem;border-radius:4px;font-size:.82rem;color:#a8b2d8;display:inline-block;word-break:break-all}}
    details{{margin:.6rem 0}}
    summary{{cursor:pointer;color:var(--accent);font-size:.83rem}}
    pre{{background:#0a0c14;padding:.8rem;border-radius:6px;overflow-x:auto;font-size:.78rem;margin-top:.4rem;color:#a8b2d8;white-space:pre-wrap;word-break:break-word}}
    .fix{{background:rgba(100,255,218,.06);border-radius:6px;padding:.7rem;margin-top:.7rem;font-size:.86rem}}
    .meta{{color:var(--muted);font-size:.76rem;margin-top:.5rem}}
  </style>
</head>
<body>
  <h1>🛡️ Rapport d'Analyse — Injections Web</h1>
  <div class="meta">Cible : {html_module.escape(self.base_url)} · {now} · {self._req_count} requêtes</div>

  <div class="score-row">
    <div><div class="score-num">{score}</div><div class="score-sub">Score sécurité /100</div></div>
    <div>
      <div class="chips">
        <span class="chip" style="background:#e74c3c22;color:#e74c3c">🔴 {counts.get('CRITIQUE',0)} Critique(s)</span>
        <span class="chip" style="background:#e67e2222;color:#e67e22">🟠 {counts.get('ÉLEVÉE',0)} Élevée(s)</span>
        <span class="chip" style="background:#f39c1222;color:#f39c12">🟡 {counts.get('MODÉRÉE',0)} Modérée(s)</span>
        <span class="chip" style="background:#27ae6022;color:#27ae60">🟢 {counts.get('FAIBLE',0)} Faible(s)</span>
      </div>
      <div style="color:var(--muted);font-size:.83rem;margin-top:.5rem">{len(self.findings)} vulnérabilité(s) · OWASP A03:2021 — Injection</div>
    </div>
  </div>

  <div class="section">💉 Vulnérabilités détectées</div>
  {cards_html if cards_html else '<p style="color:#27ae60;padding:1rem;font-size:1rem">✅ Aucune injection détectée lors de ce scan.</p>'}

  <div style="color:var(--muted);font-size:.76rem;text-align:center;margin-top:2rem">
    Généré par <strong>Le Bouclier Numérique — Jour 22</strong> · OWASP A03:2021 · Usage légal uniquement
  </div>
</body>
</html>"""

        if output_path:
            output_path.write_text(report, encoding="utf-8")
            print(f"\n  📄  Rapport → {output_path}")
        return report


# ════════════════════════════════════════════════════════════════
# API VULNÉRABLE LOCALE POUR LA DÉMO
# ════════════════════════════════════════════════════════════════

def create_vulnerable_demo_app():
    """Application web volontairement vulnérable pour la démonstration."""
    try:
        from flask import Flask, request, render_template_string, g
        import sqlite3 as sq3

        app = Flask(__name__)
        DB  = ":memory:"

        def get_db():
            if "db" not in g:
                g.db = sq3.connect(DB)
                g.db.execute(
                    "CREATE TABLE IF NOT EXISTS users "
                    "(id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)"
                )
                g.db.execute("INSERT OR IGNORE INTO users VALUES (1,'alice','alice@corp.fr','secret123')")
                g.db.execute("INSERT OR IGNORE INTO users VALUES (2,'bob','bob@corp.fr','pass456')")
                g.db.commit()
            return g.db

        @app.teardown_appcontext
        def close_db(e=None):
            db = g.pop("db", None)
            if db:
                db.close()

        # Page d'accueil avec formulaire de recherche (vulnérable SQLi + XSS)
        INDEX = """<!DOCTYPE html><html><body>
        <h1>DemoApp</h1>
        <form method="get" action="/search">
          <input name="q" value="{{ q }}">
          <button type="submit">Chercher</button>
        </form>
        <form method="post" action="/login">
          <input name="username" placeholder="Login">
          <input name="password" type="password" placeholder="Mot de passe">
          <button type="submit">Connexion</button>
        </form>
        <a href="/greet?name=Visiteur">Saluer</a>
        </body></html>"""

        @app.route("/")
        def index():
            return render_template_string(INDEX, q="")

        # ⚠️ SQLi + XSS : concaténation directe dans la requête ET dans le template
        @app.route("/search")
        def search():
            q = request.args.get("q", "")
            try:
                db   = get_db()
                rows = db.execute(
                    f"SELECT username, email FROM users WHERE username LIKE '%{q}%'"  # ⚠️ SQLi
                ).fetchall()
                results = [{"username": r[0], "email": r[1]} for r in rows]
            except Exception as e:
                return f"<p>Erreur SQL : {e}</p>", 500  # ⚠️ Erreur SQL exposée

            tpl = """<!DOCTYPE html><html><body>
            <p>Résultats pour : {{ q|safe }}</p>  <!-- ⚠️ |safe = XSS -->
            {% for r in rows %}<p>{{ r.username }} — {{ r.email }}</p>{% endfor %}
            <a href="/">Retour</a>
            </body></html>"""
            return render_template_string(tpl, q=q, rows=results)

        # ⚠️ SSTI : paramètre rendu directement dans le template
        @app.route("/greet")
        def greet():
            name = request.args.get("name", "Monde")
            return render_template_string(
                f"<html><body><h2>Bonjour {name} !</h2></body></html>"  # ⚠️ SSTI
            )

        # ⚠️ SQLi POST
        @app.route("/login", methods=["POST"])
        def login():
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            try:
                db  = get_db()
                row = db.execute(
                    f"SELECT id FROM users WHERE username='{u}' AND password='{p}'"  # ⚠️ SQLi
                ).fetchone()
                if row:
                    return "<p>Connexion réussie !</p><a href='/'>Retour</a>"
                return "<p>Identifiants incorrects.</p><a href='/'>Retour</a>", 401
            except Exception as e:
                return f"<p>SQL Error: {e}</p>", 500

        return app
    except ImportError:
        return None


# ════════════════════════════════════════════════════════════════
# DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 22 : SCANNER INJECTIONS        ║
╚══════════════════════════════════════════════════════════════════╝

  ⚠️  RAPPEL LÉGAL : Utilisation sur VOS propres applications
  uniquement. Voir Art. L323-1 Code pénal.
""")

    demo_port = 7172
    demo_url  = f"http://localhost:{demo_port}"

    app = create_vulnerable_demo_app()
    if app:
        import threading
        t = threading.Thread(
            target=lambda: app.run(port=demo_port, debug=False, use_reloader=False),
            daemon=True
        )
        t.start()
        time.sleep(1.0)
        print(f"  🚀  Application vulnérable démarrée sur {demo_url}\n")
    else:
        print("  ⚠️  Flask non installé — démo simplifiée\n")
        demo_url = "http://httpbin.org"

    scanner = InjectionScanner(
        base_url=demo_url,
        timeout=4.0,
        rate_limit=0.05,
        max_pages=10,
    )

    print("  ─────────────────────────────────────────────────────────")
    print("  🔍  SCAN EN COURS")
    print("  ─────────────────────────────────────────────────────────\n")

    scanner.scan()

    # Résumé
    counts = defaultdict(int)
    for f in scanner.findings:
        counts[f["severity"]] += 1

    score = max(0, 100 - (
        counts.get("CRITIQUE", 0) * 30 + counts.get("ÉLEVÉE", 0) * 15
    ))

    print(f"\n  ─────────────────────────────────────────────────────────")
    print(f"  📊  BILAN : {len(scanner.findings)} vulnérabilité(s) · Score {score}/100")
    print(f"  🔴 Critique : {counts['CRITIQUE']}  🟠 Élevée : {counts['ÉLEVÉE']}  "
          f"🟡 Modérée : {counts['MODÉRÉE']}  🟢 Faible : {counts['FAIBLE']}")
    print(f"  📡 Requêtes : {scanner._req_count}")

    report_path = Path("/tmp/rapport_injections.html")
    scanner.generate_report(report_path)

    print(f"""
  ─────────────────────────────────────────────────────────
  Ce scan a trouvé des injections typiques dans une app
  de développement non sécurisée :

  🔴  SQLi error-based  → erreur MySQL/SQLite exposée
  🔴  SQLi time-based   → SLEEP() accepté en aveugle
  🔴  XSS réfléchi      → payload retourné sans encodage
  🔴  SSTI              → {{{{7*7}}}} → 49 dans la réponse

  Impact réel :
  - SQLi = accès à toute la base de données
  - XSS  = vol de session, phishing ciblé
  - SSTI = exécution de code sur le serveur (RCE)

  Ouvrir {report_path} dans votre navigateur.
  ─────────────────────────────────────────────────────────
""")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="Scanner d'injections Web — Bouclier Numérique J22")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Démonstration sur app vulnérable locale")

    ps = sub.add_parser("scan", help="Scanner une application web")
    ps.add_argument("url",         help="URL de base (ex: https://www.monapp.com)")
    ps.add_argument("--output",    help="Rapport HTML (défaut: rapport_injections.html)")
    ps.add_argument("--rate",      type=float, default=0.2, help="Délai inter-requêtes (s)")
    ps.add_argument("--max-pages", type=int,   default=20,  help="Nombre max de pages à crawler")
    ps.add_argument("--param",     action="append",
                    help="Param URL à tester : --param 'https://app.com/search?q=test'")

    args = p.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    scanner = InjectionScanner(
        base_url=args.url,
        rate_limit=args.rate,
        max_pages=args.max_pages,
    )

    if args.param:
        # Targets manuelles
        targets = []
        for raw in args.param:
            parsed = urllib.parse.urlparse(raw)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            if params:
                targets.append({"url": raw.split("?")[0], "method": "GET", "params": params})
        scanner.scan(targets)
    else:
        scanner.scan()

    out = Path(args.output or "rapport_injections.html")
    scanner.generate_report(out)
    print(f"\n  ✅  Scan terminé · {len(scanner.findings)} finding(s) · Rapport : {out}")


if __name__ == "__main__":
    main()
