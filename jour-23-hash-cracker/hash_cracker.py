#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 23 : CRAQUEUR DE HACHAGES      ║
║  Objectif  : Tester la résistance de vos hachages              ║
║  Techniques: Dictionnaire · Bruteforce · Rainbow · Hybride     ║
║  Légalité  : VOS hachages uniquement — audit interne           ║
╚══════════════════════════════════════════════════════════════════╝

Pourquoi un défenseur a besoin de savoir craquer des hachages :

  1. Auditer une base de données compromise (savoir combien de mots
     de passe sont récupérables AVANT que les attaquants le fassent)
  2. Tester sa politique de mots de passe ("combien de comptes
     auraient été compromis par une attaque dictionnaire en 10min ?")
  3. Valider que l'algorithme de hachage choisi résiste aux attaques
     (MD5/SHA1 en < 1s vs bcrypt/scrypt en > 1h)

Ce script est intentionnellement limité en puissance (pas de GPU,
pas de cluster) pour rester purement éducatif et démontrer le
principe. En production, les attaquants utilisent hashcat avec GPU.

Algorithmes supportés :
  MD5, SHA1, SHA224, SHA256, SHA384, SHA512 (stdlib)
  bcrypt, scrypt, PBKDF2, Argon2 (si installés)

Conformité : OWASP ASVS 2.4 · ANSSI RGS · NIST SP 800-63B
"""

import hashlib
import hmac
import itertools
import string
import time
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# ════════════════════════════════════════════════════════════════
# IDENTIFICATION D'ALGORITHME
# ════════════════════════════════════════════════════════════════

HASH_SIGNATURES = {
    32:  ["md5"],
    40:  ["sha1"],
    56:  ["sha224"],
    64:  ["sha256"],
    96:  ["sha384"],
    128: ["sha512"],
    60:  ["bcrypt"],   # $2b$xx$...
    86:  ["scrypt"],   # $scrypt$...
}

HASH_SECURITY = {
    "md5":    ("CRITIQUE", "Cassable en quelques secondes sur GPU, ne jamais utiliser pour les mots de passe"),
    "sha1":   ("CRITIQUE", "Cassable en secondes, déprécié depuis 2011, interdit par NIST"),
    "sha256": ("MODÉRÉE",  "Sans sel ni itérations, 1 milliard de tentatives/sec sur GPU moderne"),
    "sha512": ("MODÉRÉE",  "Plus résistant que SHA256 mais toujours trop rapide sans KDF"),
    "bcrypt": ("BON",      "Résistant — work factor adaptatif, recommandé OWASP"),
    "scrypt": ("EXCELLENT","Résistant mémoire — recommandé ANSSI pour nouveaux projets"),
    "pbkdf2": ("BON",      "Acceptable avec 600 000+ itérations (NIST SP 800-132)"),
    "argon2": ("EXCELLENT","Gagnant PHC 2015 — résistant CPU et mémoire, standard actuel"),
}


def identify_hash(hash_str: str) -> list[str]:
    """Identifie le(s) algorithme(s) possible(s) à partir du format du hachage."""
    h = hash_str.strip().lower()

    # Préfixes spéciaux
    if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        return ["bcrypt"]
    if h.startswith("$scrypt$"):
        return ["scrypt"]
    if h.startswith("$argon2"):
        return ["argon2id", "argon2i"]
    if h.startswith("pbkdf2:"):
        return ["pbkdf2"]
    if h.startswith("{sha}") or h.startswith("{ssha}"):
        return ["sha1_ldap"]

    # Longueur hexadécimale
    if all(c in "0123456789abcdef" for c in h):
        length = len(h)
        return HASH_SIGNATURES.get(length, [f"inconnu({length} chars)"])

    return ["inconnu"]


# ════════════════════════════════════════════════════════════════
# FONCTIONS DE HACHAGE
# ════════════════════════════════════════════════════════════════

def hash_md5(password: str, salt: str = "") -> str:
    return hashlib.md5((salt + password).encode()).hexdigest()

def hash_sha1(password: str, salt: str = "") -> str:
    return hashlib.sha1((salt + password).encode()).hexdigest()

def hash_sha256(password: str, salt: str = "") -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

def hash_sha512(password: str, salt: str = "") -> str:
    return hashlib.sha512((salt + password).encode()).hexdigest()

def hash_bcrypt(password: str, stored_hash: str) -> bool:
    """Vérifie un hash bcrypt — retourne True si match."""
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except ImportError:
        return False

def hash_pbkdf2(password: str, salt: str, iterations: int = 600_000,
                algo: str = "sha256") -> str:
    dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), iterations)
    return dk.hex()


HASH_FUNCTIONS = {
    "md5":    lambda pwd, h, salt: hash_md5(pwd, salt) == h,
    "sha1":   lambda pwd, h, salt: hash_sha1(pwd, salt) == h,
    "sha224": lambda pwd, h, salt: hashlib.sha224((salt+pwd).encode()).hexdigest() == h,
    "sha256": lambda pwd, h, salt: hash_sha256(pwd, salt) == h,
    "sha384": lambda pwd, h, salt: hashlib.sha384((salt+pwd).encode()).hexdigest() == h,
    "sha512": lambda pwd, h, salt: hash_sha512(pwd, salt) == h,
    "bcrypt": lambda pwd, h, salt: hash_bcrypt(pwd, h),
}


# ════════════════════════════════════════════════════════════════
# ATTAQUES
# ════════════════════════════════════════════════════════════════

class HashCracker:

    def __init__(self, algorithm: str = "auto", salt: str = "",
                 max_workers: int = 4, verbose: bool = True):
        self.algorithm   = algorithm
        self.salt        = salt
        self.max_workers = max_workers
        self.verbose     = verbose
        self.stats       = defaultdict(int)

    def _check(self, password: str, target_hash: str) -> bool:
        """Vérifie si un mot de passe correspond au hachage cible."""
        algo = self.algorithm
        self.stats["attempts"] += 1

        check_fn = HASH_FUNCTIONS.get(algo)
        if check_fn:
            try:
                return check_fn(password, target_hash.lower(), self.salt)
            except Exception:
                return False
        return False

    # ── Attaque par dictionnaire ─────────────────────────────────

    def attack_dictionary(self, target_hash: str,
                          wordlist: list[str],
                          rules: bool = True) -> Optional[str]:
        """
        Attaque par dictionnaire avec règles de transformation.

        Règles appliquées (si rules=True) :
          - Mot original
          - MAJUSCULES, Capitalisée
          - Leet speak : a→@, e→3, i→1, o→0, s→$
          - Ajout de suffixes communs : 123, !, 2024, 2025, 01
          - Ajout de préfixes : !, @, 1
        """
        if self.verbose:
            print(f"  📖  Dictionnaire : {len(wordlist)} mots", end="", flush=True)
            if rules:
                print(f" × règles (×8 ≈ {len(wordlist)*8:,} candidats)", flush=True)
            else:
                print(flush=True)

        def gen_candidates(word: str):
            yield word
            if not rules:
                return
            yield word.upper()
            yield word.capitalize()
            yield word.lower()
            # Leet speak
            leet = word.replace("a","@").replace("e","3").replace("i","1")\
                       .replace("o","0").replace("s","$")
            if leet != word:
                yield leet
            # Suffixes courants
            for suffix in ("123", "!", "1", "2024", "2025", "01", "#"):
                yield word + suffix
            # Préfixe
            for prefix in ("!", "1"):
                yield prefix + word

        t0 = time.monotonic()
        for word in wordlist:
            for candidate in gen_candidates(word):
                if self._check(candidate, target_hash):
                    elapsed = time.monotonic() - t0
                    if self.verbose:
                        print(f"\n  ✅  Trouvé en {elapsed:.2f}s "
                              f"({self.stats['attempts']:,} tentatives) : "
                              f"\033[92m{candidate}\033[0m")
                    return candidate

        if self.verbose:
            elapsed = time.monotonic() - t0
            print(f"  ❌  Non trouvé ({self.stats['attempts']:,} tentatives en {elapsed:.1f}s)")
        return None

    # ── Attaque par bruteforce ───────────────────────────────────

    def attack_bruteforce(self, target_hash: str,
                          charset: str = None,
                          min_len: int = 1,
                          max_len: int = 6) -> Optional[str]:
        """
        Bruteforce pur — explore systématiquement toutes les combinaisons.

        Complexité indicative (charset alphanum = 62 chars) :
          longueur 4 →     14 millions  ≈  < 1 min   (MD5)
          longueur 6 →  56 milliards    ≈  15 min     (MD5 CPU)
          longueur 8 →  218 trillions   ≈  impraticable CPU
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits

        if self.verbose:
            total = sum(len(charset)**l for l in range(min_len, max_len + 1))
            print(f"  💪  Bruteforce : charset={len(charset)} chars · "
                  f"longueur {min_len}–{max_len} · ~{total:,} combinaisons")

        t0 = time.monotonic()
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                candidate = "".join(combo)
                if self._check(candidate, target_hash):
                    elapsed = time.monotonic() - t0
                    if self.verbose:
                        print(f"\n  ✅  Trouvé [{length} chars] en {elapsed:.2f}s "
                              f"({self.stats['attempts']:,} tentatives) : "
                              f"\033[92m{candidate}\033[0m")
                    return candidate
                # Affichage progression toutes les 100k tentatives
                if self.verbose and self.stats["attempts"] % 500_000 == 0:
                    speed = self.stats["attempts"] / max(0.001, time.monotonic() - t0)
                    print(f"\r  ⏳  {self.stats['attempts']:,} tentatives "
                          f"({speed/1000:.0f}k/s) — dernier: {candidate}  ", end="", flush=True)

        if self.verbose:
            elapsed = time.monotonic() - t0
            print(f"\n  ❌  Non trouvé ({self.stats['attempts']:,} tentatives en {elapsed:.1f}s)")
        return None

    # ── Attaque hybride ──────────────────────────────────────────

    def attack_hybrid(self, target_hash: str,
                      wordlist: list[str],
                      append_digits: int = 4) -> Optional[str]:
        """
        Hybride : mot du dictionnaire + suffixe numérique.
        Très efficace contre "motdepasse2024", "admin1234" etc.
        """
        if self.verbose:
            total = len(wordlist) * (10 ** append_digits)
            print(f"  🔀  Hybride : {len(wordlist)} mots × 10^{append_digits} = {total:,} candidats")

        t0 = time.monotonic()
        fmt = f"{{:0{append_digits}d}}"
        for word in wordlist:
            for n in range(10 ** append_digits):
                candidate = word + fmt.format(n)
                if self._check(candidate, target_hash):
                    elapsed = time.monotonic() - t0
                    if self.verbose:
                        print(f"\n  ✅  Trouvé (hybride) en {elapsed:.2f}s : "
                              f"\033[92m{candidate}\033[0m")
                    return candidate

        if self.verbose:
            elapsed = time.monotonic() - t0
            print(f"\n  ❌  Non trouvé ({self.stats['attempts']:,} tentatives en {elapsed:.1f}s)")
        return None


# ════════════════════════════════════════════════════════════════
# AUDIT DE BASE DE DONNÉES
# ════════════════════════════════════════════════════════════════

class PasswordAuditor:
    """
    Audite une liste de hachages (ex: dump de base de données)
    et produit un rapport de résistance.
    """

    # Wordlist intégrée — top mots de passe courants
    BUILTIN_WORDLIST = [
        "password", "123456", "password1", "12345678", "qwerty",
        "abc123", "letmein", "monkey", "1234567", "dragon",
        "111111", "baseball", "iloveyou", "trustno1", "sunshine",
        "princess", "welcome", "shadow", "superman", "michael",
        "batman", "admin", "root", "test", "guest", "pass",
        "master", "hello", "login", "admin123", "root123",
        "azerty", "motdepasse", "bonjour", "soleil", "france",
        "paris", "marseille", "football", "arsenal", "chelsea",
        "password2024", "password2025", "Passw0rd", "P@ssword",
        "qwerty123", "1q2w3e", "qazwsx", "zxcvbn", "asdfgh",
    ]

    def __init__(self, algorithm: str = "md5", salt: str = ""):
        self.algorithm  = algorithm
        self.salt       = salt
        self.cracker    = HashCracker(algorithm=algorithm, salt=salt, verbose=False)
        self.results    = []

    def audit(self, hashes: list[dict],
              wordlist: list[str] = None,
              max_bf_len: int = 5) -> dict:
        """
        hashes : liste de {'user': 'alice', 'hash': 'abc123...'}
        wordlist : liste de mots à tester (BUILTIN_WORDLIST si None)
        """
        wordlist = wordlist or self.BUILTIN_WORDLIST
        total    = len(hashes)

        print(f"\n  🔍  Audit de {total} hachage(s) "
              f"(algorithme: {self.algorithm.upper()})\n")

        cracked     = 0
        weak_count  = 0
        findings    = []

        for i, entry in enumerate(hashes, 1):
            user        = entry.get("user", f"user_{i}")
            target_hash = entry.get("hash", "")
            t0          = time.monotonic()

            # 1. Essai dictionnaire rapide
            found = self.cracker.attack_dictionary(
                target_hash, wordlist, rules=True
            )
            method = "dictionnaire"

            # 2. Si non trouvé, bruteforce court
            if not found:
                self.cracker.stats["attempts"] = 0
                found = self.cracker.attack_bruteforce(
                    target_hash, min_len=1, max_len=max_bf_len
                )
                method = "bruteforce"

            elapsed = time.monotonic() - t0

            if found:
                cracked += 1
                is_weak = len(found) < 8 or found.isdigit() or found.isalpha()
                if is_weak:
                    weak_count += 1

                findings.append({
                    "user": user,
                    "hash": target_hash[:20] + "…",
                    "password": found,
                    "method": method,
                    "time_s": round(elapsed, 2),
                    "cracked": True,
                    "weak": is_weak,
                })
                strength = "💀 FAIBLE" if is_weak else "⚠️  MOYEN"
                print(f"  [{i:02d}/{total}] {user:<20} {strength}  → \033[91m{found}\033[0m  ({method}, {elapsed:.2f}s)")
            else:
                findings.append({
                    "user": user,
                    "hash": target_hash[:20] + "…",
                    "password": None,
                    "method": None,
                    "time_s": round(elapsed, 2),
                    "cracked": False,
                    "weak": False,
                })
                print(f"  [{i:02d}/{total}] {user:<20} ✅ Résistant   (non craqué en {elapsed:.2f}s)")

        rate = cracked / total * 100 if total else 0
        report = {
            "total":          total,
            "cracked":        cracked,
            "cracked_rate":   round(rate, 1),
            "weak":           weak_count,
            "algorithm":      self.algorithm,
            "findings":       findings,
            "ts":             datetime.now().isoformat(),
        }

        self.results = findings
        return report

    def generate_report(self, audit_result: dict,
                        output_path: Optional[Path] = None) -> str:
        """Génère un rapport HTML de l'audit de mots de passe."""
        total   = audit_result["total"]
        cracked = audit_result["cracked"]
        rate    = audit_result["cracked_rate"]
        algo    = audit_result["algorithm"].upper()
        weak    = audit_result["weak"]

        score = max(0, 100 - int(rate * 1.2) - weak * 5)
        score_color = "#e74c3c" if score < 50 else "#e67e22" if score < 75 else "#27ae60"

        sev, msg = HASH_SECURITY.get(audit_result["algorithm"].lower(),
                                     ("?", "Algorithme inconnu"))

        rows_html = ""
        for f in audit_result["findings"]:
            if f["cracked"]:
                pwd_cell = f'<span style="color:#e74c3c;font-weight:700">{f["password"]}</span>'
                icon = "💀" if f["weak"] else "⚠️"
                status = f'{icon} Craqué ({f["method"]})'
            else:
                pwd_cell = '<span style="color:#27ae60">—</span>'
                status   = "✅ Résistant"

            rows_html += f"""<tr>
              <td>{f['user']}</td>
              <td><code style="font-size:.78rem">{f['hash']}</code></td>
              <td>{pwd_cell}</td>
              <td>{status}</td>
              <td>{f['time_s']}s</td>
            </tr>"""

        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        report = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>🔑 Audit Mots de Passe</title>
  <style>
    :root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem;max-width:1000px;margin:auto}}
    h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}
    .meta{{color:var(--muted);font-size:.82rem;margin-bottom:2rem}}
    .score-row{{display:flex;align-items:center;gap:2rem;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;flex-wrap:wrap}}
    .score-num{{font-size:3.5rem;font-weight:900;color:{score_color}}}
    .score-sub{{color:var(--muted);font-size:.85rem}}
    .algo-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:1.5rem}}
    .algo-title{{color:var(--accent);font-weight:700;margin-bottom:.4rem}}
    .chips{{display:flex;gap:.7rem;flex-wrap:wrap;margin:.8rem 0}}
    .chip{{padding:.3rem .8rem;border-radius:20px;font-weight:700;font-size:.82rem}}
    table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;border:1px solid var(--border)}}
    th{{background:#0a0c14;color:var(--accent);padding:.7rem 1rem;text-align:left;font-size:.82rem}}
    td{{padding:.65rem 1rem;border-top:1px solid var(--border);font-size:.85rem;color:var(--muted)}}
    tr:hover td{{background:#1e2235}}
    code{{background:#0a0c14;padding:.2rem .4rem;border-radius:3px;font-size:.78rem}}
    .section{{color:var(--accent);font-size:1.1rem;margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.4rem}}
    .reco{{background:rgba(100,255,218,.06);border-radius:8px;padding:1rem;margin-top:1.5rem;font-size:.88rem;line-height:1.7}}
  </style>
</head>
<body>
  <h1>🔑 Audit de Résistance — Mots de Passe</h1>
  <div class="meta">Algorithme : {algo} · {now} · {total} compte(s) audité(s)</div>

  <div class="score-row">
    <div><div class="score-num">{score}</div><div class="score-sub">Score sécurité /100</div></div>
    <div>
      <div class="chips">
        <span class="chip" style="background:#e74c3c22;color:#e74c3c">💀 {cracked}/{total} craqués ({rate}%)</span>
        <span class="chip" style="background:#e67e2222;color:#e67e22">⚠️ {weak} mots de passe faibles</span>
        <span class="chip" style="background:#27ae6022;color:#27ae60">✅ {total-cracked} résistants</span>
      </div>
    </div>
  </div>

  <div class="algo-card">
    <div class="algo-title">⚗️ Évaluation de l'algorithme : {algo}</div>
    <div style="color:{'#e74c3c' if sev in ('CRITIQUE','MODÉRÉE') else '#27ae60'};font-weight:700">{sev}</div>
    <div style="color:var(--muted);margin-top:.3rem;font-size:.88rem">{msg}</div>
  </div>

  <div class="section">👥 Résultats par compte</div>
  <table>
    <thead><tr><th>Utilisateur</th><th>Hash (tronqué)</th><th>Mot de passe</th><th>Statut</th><th>Temps</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>

  <div class="reco">
    <strong style="color:var(--accent)">📋 Recommandations</strong><br><br>
    ✅ Migrer vers <strong>bcrypt</strong> (work factor ≥ 12) ou <strong>Argon2id</strong> (recommandation OWASP 2024)<br>
    ✅ Imposer une politique : 12 caractères minimum, majuscule + chiffre + symbole<br>
    ✅ Activer la vérification contre les listes de mots de passe compromis (HIBP)<br>
    ✅ Forcer la réinitialisation des comptes dont le mot de passe a été craqué<br>
    ✅ Activer le MFA sur tous les comptes, en particulier les admins<br><br>
    <strong>Référentiels :</strong> OWASP ASVS 2.4.1 · NIST SP 800-63B Section 5.1.1 · ANSSI RGS B3
  </div>

  <div style="color:var(--muted);font-size:.76rem;text-align:center;margin-top:2rem">
    Généré par <strong>Le Bouclier Numérique — Jour 23</strong> · Usage légal uniquement
  </div>
</body>
</html>"""

        if output_path:
            output_path.write_text(report, encoding="utf-8")
            print(f"\n  📄  Rapport → {output_path}")
        return report


# ════════════════════════════════════════════════════════════════
# UTILITAIRES
# ════════════════════════════════════════════════════════════════

def hash_password(password: str, algorithm: str = "sha256",
                  salt: str = "") -> str:
    """Génère un hachage pour les tests."""
    algo = algorithm.lower()
    if algo == "md5":
        return hashlib.md5((salt + password).encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1((salt + password).encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256((salt + password).encode()).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512((salt + password).encode()).hexdigest()
    elif algo == "bcrypt":
        try:
            import bcrypt as bc
            return bc.hashpw(password.encode(), bc.gensalt(12)).decode()
        except ImportError:
            return "bcrypt_non_disponible"
    return ""


def benchmark_algorithms(password: str = "test123") -> dict:
    """
    Benchmark la vitesse de chaque algorithme.
    Illustre pourquoi MD5/SHA sont dangereux pour les mots de passe.
    """
    results = {}
    n_iterations = 100_000

    for algo in ("md5", "sha1", "sha256", "sha512"):
        t0 = time.monotonic()
        h = getattr(hashlib, algo)
        for _ in range(n_iterations):
            h(password.encode()).hexdigest()
        elapsed = time.monotonic() - t0
        rate    = n_iterations / elapsed
        results[algo] = {
            "time_100k": round(elapsed, 3),
            "per_second": int(rate),
            "estimated_gpu_x100": f"~{int(rate*100):,}/s",
        }

    # bcrypt (1 seule itération, c'est son but)
    try:
        import bcrypt as bc
        t0 = time.monotonic()
        h  = bc.hashpw(password.encode(), bc.gensalt(12))
        elapsed = time.monotonic() - t0
        results["bcrypt(12)"] = {
            "time_100k": f"{elapsed:.3f}s × 100000 = théoriquement {elapsed*100_000:.0f}s",
            "per_second": round(1 / elapsed),
            "estimated_gpu_x100": f"~{round(100/elapsed):,}/s (GPU limité par design)",
        }
    except ImportError:
        results["bcrypt"] = {"note": "Non installé — pip install bcrypt"}

    return results


# ════════════════════════════════════════════════════════════════
# DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 23 : CRAQUEUR ÉTHIQUE          ║
╚══════════════════════════════════════════════════════════════════╝
""")

    SEP = "  " + "─" * 60

    # ── Phase 1 : Identification de hachages ────────────────────
    print("  ─────────────────────────────────────────────────────────")
    print("  🔍  PHASE 1 : IDENTIFICATION")
    print("  ─────────────────────────────────────────────────────────\n")

    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",          # MD5("password")
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",   # SHA1("")
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256("")
        "$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234",     # bcrypt simulé
    ]

    for h in test_hashes:
        algos = identify_hash(h)
        short = h[:32] + ("…" if len(h) > 32 else "")
        print(f"  {short}")
        print(f"  → Algorithme probable : {', '.join(algos)}")
        sev, msg = HASH_SECURITY.get(algos[0], ("?", ""))
        if msg:
            print(f"  → Sécurité : [{sev}] {msg[:70]}")
        print()

    # ── Phase 2 : Craquage MD5 ───────────────────────────────────
    print(SEP)
    print("  💀  PHASE 2 : CRAQUAGE MD5 (démonstration)")
    print(SEP + "\n")

    # Créer des hachages MD5 de mots de passe connus
    test_cases = [
        ("alice",   hash_password("password",   "md5")),
        ("bob",     hash_password("azerty123",  "md5")),
        ("charlie", hash_password("x7K#mP9$qL", "md5")),  # Fort — ne sera pas craqué
        ("diana",   hash_password("123456",     "md5")),
    ]

    cracker = HashCracker(algorithm="md5", verbose=True)
    for user, h in test_cases:
        print(f"\n  👤  {user} — MD5: {h}")
        cracker.stats["attempts"] = 0
        result = cracker.attack_dictionary(h, PasswordAuditor.BUILTIN_WORDLIST)
        if not result:
            cracker.stats["attempts"] = 0
            result = cracker.attack_bruteforce(h, min_len=1, max_len=4)

    # ── Phase 3 : Audit de base de données ──────────────────────
    print(f"\n{SEP}")
    print("  📊  PHASE 3 : AUDIT D'UNE BASE MD5 (5 comptes)")
    print(SEP)

    db_dump = [
        {"user": "admin",   "hash": hash_password("admin",      "md5")},
        {"user": "alice",   "hash": hash_password("sunshine",   "md5")},
        {"user": "bob",     "hash": hash_password("bob2024",    "md5")},
        {"user": "carol",   "hash": hash_password("Tr0ub4dor&3","md5")},
        {"user": "dave",    "hash": hash_password("123456",     "md5")},
    ]

    auditor = PasswordAuditor(algorithm="md5")
    audit_result = auditor.audit(db_dump)

    # ── Phase 4 : Benchmark ──────────────────────────────────────
    print(f"\n{SEP}")
    print("  ⚡  PHASE 4 : BENCHMARK — POURQUOI MD5 EST DANGEREUX")
    print(SEP + "\n")

    benchmarks = benchmark_algorithms()
    print(f"  {'Algorithme':<18} {'100k itér.':<14} {'Hash/sec (CPU)':<18} {'GPU ×100 (estimé)'}")
    print(f"  {'─'*70}")
    for algo, stats in benchmarks.items():
        if isinstance(stats.get("time_100k"), float):
            print(f"  {algo:<18} {stats['time_100k']:.3f}s         "
                  f"{stats['per_second']:>12,}     {stats['estimated_gpu_x100']}")
        elif "note" in stats:
            print(f"  {algo:<18} {stats['note']}")
        else:
            print(f"  {algo:<18} {str(stats.get('time_100k',''))[:40]}")
            print(f"  {'':18} → {stats.get('per_second','')} hash/sec")

    report_path = Path("/tmp/rapport_audit_mdp.html")
    auditor.generate_report(audit_result, report_path)

    rate = audit_result["cracked_rate"]
    print(f"""
{SEP}
  📋  BILAN

  Sur 5 comptes audités avec hachage MD5 :
  → {audit_result['cracked']}/5 mots de passe craqués ({rate}%)
  → Méthode : dictionnaire + règles simples, quelques secondes CPU

  Conclusion concrète pour votre RSSI :
  Si votre base de données est volée et que vous utilisez MD5,
  les attaquants récupèrent les mots de passe en quelques heures
  avec un simple GPU (hashcat : >10 milliards de MD5/s sur RTX 4090)

  Solution : bcrypt / Argon2id avec work factor ≥ 12
  → Même GPU : quelques dizaines de hash/s → attaque impraticable

  Ouvrir {report_path} pour le rapport complet.
{SEP}
""")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Craqueur éthique de hachages — Bouclier Numérique Jour 23"
    )
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Démonstration complète")

    ph = sub.add_parser("crack", help="Craquer un hachage")
    ph.add_argument("hash",      help="Hachage cible")
    ph.add_argument("--algo",    default="auto", help="Algorithme (md5/sha1/sha256/...)")
    ph.add_argument("--salt",    default="",     help="Sel")
    ph.add_argument("--wordlist",help="Fichier dictionnaire (un mot par ligne)")
    ph.add_argument("--bruteforce", action="store_true", help="Activer le bruteforce")
    ph.add_argument("--maxlen",  type=int, default=5, help="Longueur max bruteforce")

    pa = sub.add_parser("audit", help="Auditer un fichier JSON de hachages")
    pa.add_argument("file",      help="Fichier JSON [{user, hash}...]")
    pa.add_argument("--algo",    default="md5")
    pa.add_argument("--output",  help="Rapport HTML")

    pb = sub.add_parser("benchmark", help="Comparer la vitesse des algorithmes")
    pb.add_argument("--password", default="test123")

    pi = sub.add_parser("identify", help="Identifier un hachage")
    pi.add_argument("hash")

    args = p.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    if args.cmd == "identify":
        algos = identify_hash(args.hash)
        print(f"Algorithme probable : {', '.join(algos)}")
        for a in algos:
            sev, msg = HASH_SECURITY.get(a, ("?", ""))
            if msg:
                print(f"Sécurité [{sev}] : {msg}")
        return

    if args.cmd == "benchmark":
        results = benchmark_algorithms(args.password)
        for algo, stats in results.items():
            print(f"{algo}: {stats}")
        return

    if args.cmd == "crack":
        algo = args.algo
        if algo == "auto":
            algos = identify_hash(args.hash)
            algo  = algos[0] if algos else "sha256"
            print(f"Algorithme détecté : {algo}")

        wordlist = PasswordAuditor.BUILTIN_WORDLIST
        if args.wordlist:
            wl_path = Path(args.wordlist)
            if wl_path.exists():
                wordlist = wl_path.read_text().splitlines()

        cracker = HashCracker(algorithm=algo, salt=args.salt)
        result  = cracker.attack_dictionary(args.hash, wordlist)
        if not result and args.bruteforce:
            cracker.stats["attempts"] = 0
            result = cracker.attack_bruteforce(args.hash, max_len=args.maxlen)
        if not result:
            print("Non trouvé.")
        return

    if args.cmd == "audit":
        data = json.loads(Path(args.file).read_text())
        auditor = PasswordAuditor(algorithm=args.algo)
        result  = auditor.audit(data)
        out     = Path(args.output or "rapport_audit.html")
        auditor.generate_report(result, out)
        print(f"Craqués : {result['cracked']}/{result['total']} ({result['cracked_rate']}%)")


if __name__ == "__main__":
    main()
