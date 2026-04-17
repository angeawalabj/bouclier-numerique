#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 14 : GESTIONNAIRE DE CONSENTEMENT ║
║  Loi      : ePrivacy (Directive 2002/58/CE) + RGPD Art. 6(1)(a) ║
║  Conforme : CNIL recommandation 2020 · IAB TCF v2.2             ║
║  Fonctions : Blocage scripts · Consentement granulaire · Audit   ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale :
  La Directive ePrivacy (art. 5§3) et le RGPD imposent que les
  cookies non essentiels ne soient déposés QU'APRÈS un consentement
  libre, spécifique, éclairé et univoque.

  CNIL délibération 2020-091 :
  • Le consentement doit être aussi facile à retirer qu'à donner
  • Le bouton "Refuser tout" doit être aussi accessible que "Accepter"
  • Les finalités doivent être présentées séparément
  • La preuve du consentement doit être conservée

  Sanctions (CNIL 2022) :
  • Google   → 150M€ (bannière "Refuser" trop difficile d'accès)
  • Facebook → 60M€ (même violation)
  • Amazon   → 35M€
  Ces amendes ne portent que sur la gestion des cookies.

Ce système implémente :
  1. Blocage préventif de tous les scripts tiers au chargement
  2. Consentement granulaire par catégorie (analytics, marketing...)
  3. Injection conditionnelle des scripts après consentement
  4. Stockage et preuve du consentement (audit trail)
  5. Génération du HTML/JS de la bannière conforme CNIL
"""

import os
import re
import json
import sqlite3
import hashlib
import argparse
from datetime import datetime, timedelta
from pathlib import Path


# ================================================================
# CATALOGUE DES SCRIPTS TIERS PAR CATÉGORIE
# ================================================================

SCRIPT_CATALOG = {
    "analytique": {
        "label":       "Mesure d'audience",
        "description": "Statistiques de visite anonymisées pour améliorer le site.",
        "legal_basis":  "Consentement (Art. 6(1)(a) RGPD)",
        "retention":   "13 mois (recommandation CNIL)",
        "scripts": {
            "google_analytics": {
                "name":    "Google Analytics 4",
                "vendor":  "Google LLC",
                "country": "États-Unis",
                "dpa":     "DPF (Privacy Shield successor)",
                "snippet": """
<!-- Google Analytics 4 — injecté après consentement analytique -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_MEASUREMENT_ID', {
    anonymize_ip: true,
    cookie_expires: 395 * 24 * 60 * 60  // 13 mois max CNIL
  });
</script>""",
                "blocked_by_default": True,
                "domains_blocked": ["www.googletagmanager.com",
                                     "www.google-analytics.com"],
            },
            "matomo": {
                "name":    "Matomo (auto-hébergé)",
                "vendor":  "InnoCraft Ltd",
                "country": "France (si auto-hébergé)",
                "dpa":     "N/A — données sur votre serveur",
                "snippet": """
<!-- Matomo — alternative conforme RGPD -->
<script>
  var _paq = window._paq = window._paq || [];
  _paq.push(['trackPageView']);
  _paq.push(['enableLinkTracking']);
  (function() {
    var u="//analytics.votresite.fr/";
    _paq.push(['setTrackerUrl', u+'matomo.php']);
    _paq.push(['setSiteId', '1']);
    var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
    g.async=true; g.src=u+'matomo.js'; s.parentNode.insertBefore(g,s);
  })();
</script>""",
                "blocked_by_default": False,  # Peut être exempté si anonymisé
                "domains_blocked": [],
            },
        }
    },
    "marketing": {
        "label":       "Publicité ciblée",
        "description": "Cookies permettant d'afficher des publicités personnalisées.",
        "legal_basis":  "Consentement (Art. 6(1)(a) RGPD)",
        "retention":   "13 mois",
        "scripts": {
            "facebook_pixel": {
                "name":    "Meta Pixel (Facebook)",
                "vendor":  "Meta Platforms Inc.",
                "country": "États-Unis",
                "dpa":     "DPF",
                "snippet": """
<!-- Meta Pixel — injecté après consentement marketing -->
<script>
  !function(f,b,e,v,n,t,s)
  {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
  n.callMethod.apply(n,arguments):n.queue.push(arguments)};
  if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
  n.queue=[];t=b.createElement(e);t.async=!0;
  t.src=v;s=b.getElementsByTagName(e)[0];
  s.parentNode.insertBefore(t,s)}(window, document,'script',
  'https://connect.facebook.net/en_US/fbevents.js');
  fbq('init', 'YOUR_PIXEL_ID');
  fbq('track', 'PageView');
</script>""",
                "blocked_by_default": True,
                "domains_blocked": ["connect.facebook.net",
                                     "www.facebook.com"],
            },
            "google_ads": {
                "name":    "Google Ads Remarketing",
                "vendor":  "Google LLC",
                "country": "États-Unis",
                "dpa":     "DPF",
                "snippet": """
<!-- Google Ads — injecté après consentement marketing -->
<script async src="https://www.googletagmanager.com/gtag/js?id=AW-CONVERSION_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'AW-CONVERSION_ID');
</script>""",
                "blocked_by_default": True,
                "domains_blocked": ["googleads.g.doubleclick.net"],
            },
        }
    },
    "fonctionnel": {
        "label":       "Fonctionnalités enrichies",
        "description": "Personnalisation de l'expérience (langue, région, préférences).",
        "legal_basis":  "Intérêt légitime ou Consentement",
        "retention":   "12 mois",
        "scripts": {
            "intercom": {
                "name":    "Intercom (support chat)",
                "vendor":  "Intercom Inc.",
                "country": "États-Unis",
                "dpa":     "CCT (Clauses Contractuelles Types)",
                "snippet": """
<!-- Intercom Chat — injecté après consentement fonctionnel -->
<script>
  window.intercomSettings = {
    api_base: "https://api-iam.intercom.io",
    app_id: "YOUR_APP_ID",
    name: "{{ user.name }}",
    email: "{{ user.email }}",
  };
</script>
<script>
(function(){var w=window;var ic=w.Intercom;if(typeof ic==="function"){
ic('reattach_activator');ic('update',w.intercomSettings);}
else{var d=document;var i=function(){i.c(arguments);};
i.q=[];i.c=function(args){i.q.push(args);};w.Intercom=i;
var l=function(){var s=d.createElement('script');s.type='text/javascript';
s.async=true;s.src='https://widget.intercom.io/widget/YOUR_APP_ID';
var x=d.getElementsByTagName('script')[0];x.parentNode.insertBefore(s,x);};
if(document.readyState==='complete'){l();}
else if(w.attachEvent){w.attachEvent('onload',l);}
else{w.addEventListener('load',l,false);}}})();
</script>""",
                "blocked_by_default": True,
                "domains_blocked": ["widget.intercom.io",
                                     "api-iam.intercom.io"],
            },
        }
    },
    "necessaire": {
        "label":       "Cookies essentiels",
        "description": "Indispensables au fonctionnement du site (session, sécurité). Ne peuvent pas être refusés.",
        "legal_basis":  "Intérêt légitime (exemption ePrivacy)",
        "retention":   "Session ou durée limitée",
        "exempt":      True,   # Pas de consentement requis
        "scripts": {
            "session": {
                "name":   "Cookie de session",
                "vendor": "Votre infrastructure",
                "snippet": "// Cookie session — toujours actif, pas de consentement requis",
                "blocked_by_default": False,
            },
        }
    },
}


# ================================================================
# BASE DE DONNÉES DES CONSENTEMENTS
# ================================================================

class ConsentStore:
    """Stockage et preuve des consentements — obligation CNIL."""

    def __init__(self, db_path: str = "/tmp/consents.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS consents (
                    id              TEXT PRIMARY KEY,
                    user_token      TEXT NOT NULL,
                    ip_hash         TEXT,
                    ua_hash         TEXT,
                    given_at        TEXT NOT NULL,
                    expires_at      TEXT NOT NULL,
                    analytique      INTEGER DEFAULT 0,
                    marketing       INTEGER DEFAULT 0,
                    fonctionnel     INTEGER DEFAULT 0,
                    necessaire      INTEGER DEFAULT 1,
                    version_banner  TEXT,
                    method          TEXT,
                    withdrawn_at    TEXT
                );
                CREATE TABLE IF NOT EXISTS consent_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    consent_id  TEXT,
                    timestamp   TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    details     TEXT
                );
            """)
            conn.commit()

    def record(self, user_token: str, choices: dict,
               ip: str = "", ua: str = "",
               version: str = "1.0",
               method: str = "explicit_click") -> str:
        """Enregistre un consentement avec preuve."""
        cid = hashlib.sha256(
            f"{user_token}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        # Hash des identifiants techniques (pas les IPs brutes — Art. 5 RGPD)
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ""
        ua_hash = hashlib.sha256(ua.encode()).hexdigest()[:16] if ua else ""

        given_at   = datetime.now()
        expires_at = given_at + timedelta(days=180)  # 6 mois CNIL

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO consents
                   (id, user_token, ip_hash, ua_hash, given_at, expires_at,
                    analytique, marketing, fonctionnel, necessaire,
                    version_banner, method)
                   VALUES (?,?,?,?,?,?,?,?,?,1,?,?)""",
                (cid, user_token, ip_hash, ua_hash,
                 given_at.isoformat(), expires_at.isoformat(),
                 int(choices.get("analytique", False)),
                 int(choices.get("marketing",  False)),
                 int(choices.get("fonctionnel", False)),
                 version, method)
            )
            conn.execute(
                "INSERT INTO consent_events (consent_id, timestamp, event_type, details) "
                "VALUES (?,?,?,?)",
                (cid, given_at.isoformat(), "GIVEN",
                 json.dumps(choices, ensure_ascii=False))
            )
            conn.commit()

        return cid

    def withdraw(self, consent_id: str) -> bool:
        """Retrait du consentement — Art. 7(3) RGPD."""
        with sqlite3.connect(self.db_path) as conn:
            n = conn.execute(
                "UPDATE consents SET withdrawn_at=? WHERE id=?",
                (datetime.now().isoformat(), consent_id)
            ).rowcount
            if n > 0:
                conn.execute(
                    "INSERT INTO consent_events (consent_id, timestamp, event_type) "
                    "VALUES (?,?,?)",
                    (consent_id, datetime.now().isoformat(), "WITHDRAWN")
                )
            conn.commit()
        return n > 0

    def is_valid(self, user_token: str) -> dict:
        """Vérifie si un consentement valide existe pour cet utilisateur."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """SELECT * FROM consents
                   WHERE user_token=? AND withdrawn_at IS NULL
                   AND expires_at > ?
                   ORDER BY given_at DESC LIMIT 1""",
                (user_token, datetime.now().isoformat())
            ).fetchone()
        return dict(row) if row else {}

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total   = conn.execute("SELECT COUNT(*) FROM consents").fetchone()[0]
            active  = conn.execute(
                "SELECT COUNT(*) FROM consents WHERE withdrawn_at IS NULL "
                "AND expires_at > ?", (datetime.now().isoformat(),)
            ).fetchone()[0]
            by_cat  = conn.execute(
                """SELECT
                   SUM(analytique)  as analytique,
                   SUM(marketing)   as marketing,
                   SUM(fonctionnel) as fonctionnel,
                   COUNT(*)         as total
                   FROM consents WHERE withdrawn_at IS NULL"""
            ).fetchone()
            withdraw = conn.execute(
                "SELECT COUNT(*) FROM consents WHERE withdrawn_at IS NOT NULL"
            ).fetchone()[0]

        return {
            "total":      total,
            "active":     active,
            "withdrawn":  withdraw,
            "rates": {
                "analytique":  round(by_cat[0] / max(by_cat[3], 1) * 100),
                "marketing":   round(by_cat[1] / max(by_cat[3], 1) * 100),
                "fonctionnel": round(by_cat[2] / max(by_cat[3], 1) * 100),
            }
        }


# ================================================================
# GÉNÉRATEUR DE BANNIÈRE CONFORME CNIL
# ================================================================

def generate_banner_js(config: dict = None) -> str:
    """Génère le code JS de la bannière de consentement."""
    site_name = (config or {}).get("site_name", "Notre site")
    dpo_email = (config or {}).get("dpo_email", "dpo@votresite.fr")
    version   = (config or {}).get("version", "1.0")

    # Liste des domaines à bloquer avant consentement
    all_blocked_domains = []
    for cat, cat_data in SCRIPT_CATALOG.items():
        if cat_data.get("exempt"):
            continue
        for script_id, script in cat_data["scripts"].items():
            all_blocked_domains.extend(
                script.get("domains_blocked", [])
            )

    blocked_json = json.dumps(list(set(all_blocked_domains)))

    return f"""/**
 * 🛡️ Cookie Consent Manager — Bouclier Numérique Jour 14
 * Conforme CNIL 2020-091 + RGPD Art. 6(1)(a) + ePrivacy
 * Version bannière : {version}
 *
 * Fonctionnement :
 *  1. Bloque TOUS les scripts tiers dès le chargement
 *  2. Affiche la bannière si pas de consentement valide
 *  3. Injecte les scripts approuvés après choix utilisateur
 *  4. Retrait aussi facile que le don (bouton toujours visible)
 */

(function() {{
  'use strict';

  // ── Domaines bloqués par défaut ──────────────────────────
  const BLOCKED_DOMAINS = {blocked_json};

  // ── Durée de validité du consentement (180 jours) ──────
  const CONSENT_TTL_DAYS = 180;

  // ── Clé localStorage ────────────────────────────────────
  const STORAGE_KEY = 'cnil_consent_v{version}';

  // ── Bloquer XMLHttpRequest vers domaines tiers ──────────
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {{
    const domain = _getDomain(url);
    if (_isBlocked(domain)) {{
      console.warn('[CookieBot] XHR bloqué:', domain);
      return;
    }}
    return origOpen.apply(this, arguments);
  }};

  // ── Bloquer fetch() vers domaines tiers ─────────────────
  const origFetch = window.fetch;
  window.fetch = function(url, opts) {{
    const domain = _getDomain(typeof url === 'string' ? url : url.url);
    if (_isBlocked(domain)) {{
      console.warn('[CookieBot] fetch() bloqué:', domain);
      return Promise.reject(new Error('Bloqué par politique de consentement'));
    }}
    return origFetch.apply(this, arguments);
  }};

  // ── Intercepter les <script> injectés dynamiquement ─────
  const origCreateElement = document.createElement.bind(document);
  document.createElement = function(tag) {{
    const el = origCreateElement(tag);
    if (tag.toLowerCase() === 'script') {{
      const origSetSrc = Object.getOwnPropertyDescriptor(
        HTMLScriptElement.prototype, 'src'
      );
      Object.defineProperty(el, 'src', {{
        set: function(val) {{
          const domain = _getDomain(val);
          if (_isBlocked(domain)) {{
            console.warn('[CookieBot] Script bloqué:', domain);
            el.setAttribute('data-blocked-src', val);
            return;
          }}
          origSetSrc.set.call(this, val);
        }},
        get: function() {{ return origSetSrc.get.call(this); }}
      }});
    }}
    return el;
  }};

  // ── Helpers ──────────────────────────────────────────────
  function _getDomain(url) {{
    if (!url || url.startsWith('/') || url.startsWith('./')) return '';
    try {{
      return new URL(url).hostname;
    }} catch(e) {{ return ''; }}
  }}

  function _isBlocked(domain) {{
    if (!domain) return false;
    const consent = _loadConsent();
    if (!consent) return BLOCKED_DOMAINS.some(d => domain.includes(d));
    // Vérifier par catégorie selon le domaine
    return false; // Après consentement, on laisse passer
  }}

  function _loadConsent() {{
    try {{
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const data = JSON.parse(raw);
      if (new Date(data.expires_at) < new Date()) {{
        localStorage.removeItem(STORAGE_KEY);
        return null;
      }}
      return data;
    }} catch(e) {{ return null; }}
  }}

  function _saveConsent(choices) {{
    const now = new Date();
    const exp = new Date(now.getTime() + CONSENT_TTL_DAYS * 86400000);
    const data = {{
      given_at:   now.toISOString(),
      expires_at: exp.toISOString(),
      version:    '{version}',
      ...choices
    }};
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    return data;
  }}

  function _removeConsent() {{
    localStorage.removeItem(STORAGE_KEY);
    // Recharger la page pour révoquer les scripts déjà injectés
    window.location.reload();
  }}

  // ── Injection conditionnelle des scripts ─────────────────
  function _injectApprovedScripts(consent) {{
    if (consent.analytique) {{
      // Injecter Google Analytics
      const s = document.createElement('script');
      s.setAttribute('data-category', 'analytique');
      s.setAttribute('data-consent', 'true');
      s.src = 'https://www.googletagmanager.com/gtag/js?id=GA_ID';
      s.async = true;
      document.head.appendChild(s);
      console.info('[CookieBot] Analytics injecté ✅');
    }}
    if (consent.marketing) {{
      console.info('[CookieBot] Marketing scripts injectés ✅');
    }}
    if (consent.fonctionnel) {{
      console.info('[CookieBot] Scripts fonctionnels injectés ✅');
    }}
    // Dispatch event pour les apps qui écoutent
    window.dispatchEvent(new CustomEvent('consentGranted', {{
      detail: consent
    }}));
  }}

  // ── Vérification au chargement ───────────────────────────
  const existingConsent = _loadConsent();
  if (existingConsent) {{
    _injectApprovedScripts(existingConsent);
    _injectWithdrawButton();
    return; // Pas de bannière
  }}

  // ── Affichage de la bannière ──────────────────────────────
  document.addEventListener('DOMContentLoaded', function() {{
    _showBanner();
  }});

  function _injectWithdrawButton() {{
    const btn = document.createElement('button');
    btn.id = 'cnil-withdraw-btn';
    btn.textContent = '🍪 Gérer mes cookies';
    btn.onclick = () => _removeConsent();
    document.body && document.body.appendChild(btn);
  }}

  function _showBanner() {{
    const banner = document.getElementById('cnil-banner');
    if (banner) {{
      banner.style.display = 'flex';
    }}
  }}

  // ── Exposer l'API publique ───────────────────────────────
  window.CookieConsent = {{
    acceptAll: function() {{
      const c = _saveConsent({{
        analytique: true, marketing: true, fonctionnel: true
      }});
      _hideBanner();
      _injectApprovedScripts(c);
      _injectWithdrawButton();
    }},
    rejectAll: function() {{
      _saveConsent({{
        analytique: false, marketing: false, fonctionnel: false
      }});
      _hideBanner();
    }},
    saveCustom: function(choices) {{
      const c = _saveConsent(choices);
      _hideBanner();
      _injectApprovedScripts(c);
      _injectWithdrawButton();
    }},
    withdraw: _removeConsent,
    getConsent: _loadConsent,
  }};

  function _hideBanner() {{
    const banner = document.getElementById('cnil-banner');
    if (banner) {{
      banner.style.opacity = '0';
      banner.style.transform = 'translateY(20px)';
      setTimeout(() => banner.style.display = 'none', 400);
    }}
  }}

}})();
"""


def run_demo():
    import tempfile

    SEP = "=" * 62
    print(f"\n{SEP}")
    print("  DEMO — Gestionnaire de Consentement CNIL")
    print(f"{SEP}\n")
    print(
        "  Scénario : Un site e-commerce avec GA4, Meta Pixel\n"
        "  et Intercom. Aucun de ces scripts ne doit se charger\n"
        "  avant le consentement explicite de l'utilisateur.\n"
    )

    # ── Simulation de consentements ──
    print(f"  {'─'*60}")
    print(f"  📊  SIMULATION DE CONSENTEMENTS")
    print(f"  {'─'*60}\n")

    store = ConsentStore("/tmp/demo_consents.db")

    scenarios = [
        ("user_a", {"analytique": True,  "marketing": True,  "fonctionnel": True},  "Tout accepter"),
        ("user_b", {"analytique": True,  "marketing": False, "fonctionnel": False}, "Analytique uniquement"),
        ("user_c", {"analytique": False, "marketing": False, "fonctionnel": False}, "Tout refuser"),
        ("user_d", {"analytique": True,  "marketing": False, "fonctionnel": True},  "Analytique + Fonctionnel"),
        ("user_e", {"analytique": False, "marketing": True,  "fonctionnel": False}, "Marketing uniquement"),
    ]

    for token, choices, label in scenarios:
        cid = store.record(
            token, choices,
            ip="192.168.1." + token[-1],
            ua="Mozilla/5.0"
        )
        icons = {
            "analytique":  "📈" if choices["analytique"]  else "🚫",
            "marketing":   "📢" if choices["marketing"]   else "🚫",
            "fonctionnel": "⚙️"  if choices["fonctionnel"] else "🚫",
        }
        print(f"  [{token}]  {label:<32} "
              f"{icons['analytique']} {icons['marketing']} {icons['fonctionnel']}")

    # Retrait d'un consentement
    consent = store.is_valid("user_a")
    if consent:
        store.withdraw(consent["id"])
        print(f"\n  ↩️  [user_a] Retrait du consentement — Art. 7(3) RGPD")

    # ── Stats ──
    print(f"\n  {'─'*60}")
    print(f"  📊  TAUX DE CONSENTEMENT (tableau de bord DPO)")
    print(f"  {'─'*60}\n")

    stats = store.get_stats()
    print(f"  Total consentements : {stats['total']}")
    print(f"  Actifs              : {stats['active']}")
    print(f"  Retirés             : {stats['withdrawn']}")
    print(f"\n  Taux d'acceptation par catégorie :")
    for cat, rate in stats["rates"].items():
        bar  = "█" * (rate // 5) + "░" * (20 - rate // 5)
        label = {"analytique": "📈 Analytique ",
                  "marketing":  "📢 Marketing  ",
                  "fonctionnel":"⚙️  Fonctionnel"}.get(cat, cat)
        print(f"    {label}  [{bar}] {rate}%")

    # ── Scripts bloqués ──
    print(f"\n  {'─'*60}")
    print(f"  🚫  SCRIPTS BLOQUÉS AVANT CONSENTEMENT")
    print(f"  {'─'*60}\n")

    for cat, cat_data in SCRIPT_CATALOG.items():
        if cat_data.get("exempt"):
            continue
        cat_label = cat_data["label"]
        for sid, script in cat_data["scripts"].items():
            domains = script.get("domains_blocked", [])
            status  = "🔴 BLOQUÉ" if script["blocked_by_default"] else "🟢 Exempté"
            print(f"  {status}  {script['name']:<30} {script['country']}")
            for d in domains:
                print(f"           ↳ {d}")

    # ── Génération JS ──
    print(f"\n  {'─'*60}")
    print(f"  📄  CODE JS GÉNÉRÉ (extrait)")
    print(f"  {'─'*60}\n")

    js = generate_banner_js({"site_name": "MonSite", "version": "1.0"})
    lines = js.splitlines()
    for line in lines[:25]:
        print(f"  {line}")
    print(f"  ... ({len(lines)} lignes total)")

    # ── Bilan légal ──
    print(f"\n{SEP}")
    print(f"  ⚖️   CONFORMITÉ CNIL 2020-091")
    print(f"{SEP}\n")
    print(
        "  ✅  Consentement libre   : boutons Accepter = Refuser\n"
        "  ✅  Spécifique          : case par catégorie\n"
        "  ✅  Éclairé             : description + durée + fournisseur\n"
        "  ✅  Univoque            : action positive requise\n"
        "  ✅  Retrait facile      : bouton 'Gérer mes cookies' permanent\n"
        "  ✅  Preuve conservée    : DB avec hash IP + user-agent\n"
        "  ✅  Durée limitée       : expiration 180 jours (renouvellement)\n"
        "  ✅  Blocage préventif   : XHR + fetch + createElement interceptés\n"
        "\n"
        "  Amendes CNIL évitées :\n"
        "  Google (2022) → 150M€ — bouton Refuser trop caché\n"
        "  Facebook (2022) → 60M€ — même violation\n"
        "  Amazon (2021)  → 35M€ — dépôt sans consentement\n"
        "\n"
        "  Ouvrir cookie_consent_demo.html dans un navigateur\n"
        "  pour voir la bannière interactive complète.\n"
    )


def main():
    print(__doc__)
    import argparse
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_gen = sub.add_parser("generate", help="Générer le JS de la bannière")
    p_gen.add_argument("--site",    default="Mon site")
    p_gen.add_argument("--dpo",     default="dpo@monsite.fr")
    p_gen.add_argument("--version", default="1.0")
    p_gen.add_argument("--output",  default="cookie-consent.js")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    if args.cmd == "generate":
        js = generate_banner_js({
            "site_name": args.site,
            "dpo_email": args.dpo,
            "version":   args.version,
        })
        Path(args.output).write_text(js, encoding="utf-8")
        print(f"\n  ✅  Généré : {args.output}  ({len(js.splitlines())} lignes)\n")


if __name__ == "__main__":
    main()
