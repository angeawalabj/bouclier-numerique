#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 23 : CRAQUEUR DE HACHAGES     ║
║  Objectif  : Tester la robustesse de vos propres hachages      ║
║  Techniques: Dictionnaire · Bruteforce · Règles transformation  ║
║  Éthique   : Vos propres hachages UNIQUEMENT                   ║
╚══════════════════════════════════════════════════════════════════╝

Utilité défensive : Un attaquant qui vole votre base de données
obtient des hachages. Ce script simule exactement ce qu'il ferait
pour récupérer les mots de passe en clair — AVANT lui.

Algorithmes : MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, scrypt, PBKDF2
Conformité  : ANSSI RGS · RGPD Art. 32 · ISO 27001 A.10.1.1
"""

import hashlib, hmac, time, itertools, string, os, sys, json
from pathlib import Path
from typing import Optional
from datetime import datetime
from collections import defaultdict

TOP_PASSWORDS = [
    "123456","password","123456789","12345678","12345","1234567","qwerty","abc123",
    "000000","1234","iloveyou","password1","123","123321","654321","qwertyuiop",
    "qwerty123","1q2w3e4r","666666","987654321","princess","sunshine","master",
    "welcome","shadow","superman","michael","football","baseball","dragon",
    "monkey","letmein","login","hello","charlie","donald","password2","qwerty1",
    "1q2w3e4r5t","123qwe","zxcvbnm","trustno1","1qaz2wsx","passw0rd","admin",
    "root","test","guest","user","default","azerty","motdepasse","bonjour",
    "soleil","marseille","paris","france","lapin","chaton","amour","admin123",
    "root123","pass123","test123","Passw0rd!","P@ssword","P@ssw0rd","Password1",
]

RULES = [
    lambda w: w,
    lambda w: w.lower(),
    lambda w: w.upper(),
    lambda w: w.capitalize(),
    lambda w: w + "1",
    lambda w: w + "123",
    lambda w: w + "!",
    lambda w: w + "2024",
    lambda w: w + "2025",
    lambda w: w + "@",
    lambda w: "1" + w,
    lambda w: w.replace("a","@").replace("e","3").replace("o","0"),
    lambda w: w.replace("e","3"),
    lambda w: w.replace("i","1"),
    lambda w: w.replace("o","0"),
    lambda w: w.replace("s","$"),
    lambda w: w[::-1],
]

CHARSETS = {
    "digits":         string.digits,
    "lower":          string.ascii_lowercase,
    "alphanum_lower": string.ascii_lowercase + string.digits,
    "alphanum":       string.ascii_letters + string.digits,
    "common":         string.ascii_letters + string.digits + "!@#$%",
}

ALGO_SECURITY = {
    "md5":    {"rating":"CRITIQUE", "note":"Obsolète — 10 milliards hash/s sur GPU"},
    "sha1":   {"rating":"CRITIQUE", "note":"Obsolète — SHAttered collision prouvée"},
    "sha256": {"rating":"FAIBLE",   "note":"Trop rapide — 200M hash/s sur GPU"},
    "sha512": {"rating":"FAIBLE",   "note":"Trop rapide — sans sel = rainbow table"},
    "ntlm":   {"rating":"CRITIQUE", "note":"MD4 non salé — Pass-the-Hash trivial"},
    "bcrypt": {"rating":"BON",      "note":"Lent par design — 100ms/tentative"},
    "scrypt": {"rating":"EXCELLENT","note":"Résistant GPU — best practice 2024"},
    "pbkdf2": {"rating":"BON",      "note":"NIST SP 800-132 — 600k itérations min"},
}


def hash_password(password: str, algo: str, salt: str = "") -> str:
    pwd = password.encode("utf-8")
    if algo == "md5":
        return hashlib.md5(salt.encode() + pwd).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(salt.encode() + pwd).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(salt.encode() + pwd).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(salt.encode() + pwd).hexdigest()
    elif algo == "ntlm":
        # NTLM = MD4(UTF-16LE) — MD4 peut ne pas être disponible sur certains systèmes
        try:
            return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
        except Exception:
            # Fallback simulation (démo uniquement — ne pas utiliser en prod)
            return hashlib.sha256(password.encode("utf-16-le")).hexdigest()[:32]
    elif algo == "scrypt":
        sb = salt.encode()[:16].ljust(16,b"\x00") if salt else os.urandom(16)
        h  = hashlib.scrypt(pwd, salt=sb, n=2**14, r=8, p=1)
        return sb.hex() + ":" + h.hex()
    elif algo == "pbkdf2":
        sb = salt.encode()[:16].ljust(16,b"\x00") if salt else os.urandom(16)
        h  = hashlib.pbkdf2_hmac("sha256", pwd, sb, 600_000)
        return sb.hex() + ":" + h.hex()
    else:
        raise ValueError(f"Algorithme inconnu : {algo}")


def detect_algo(h: str) -> str:
    h = h.strip()
    if h.startswith(("$2b$","$2a$","$2y$")): return "bcrypt"
    if ":" in h and len(h.split(":")[0]) == 32: return "pbkdf2"
    if len(h) == 32:  return "md5"
    if len(h) == 40:  return "sha1"
    if len(h) == 64:  return "sha256"
    if len(h) == 128: return "sha512"
    return "md5"


def verify(password: str, hash_str: str, algo: str, salt: str = "") -> bool:
    h = hash_str.strip()
    if algo == "bcrypt":
        try:
            import bcrypt as _b
            return _b.checkpw(password.encode(), h.encode())
        except Exception:
            return False
    if algo in ("scrypt","pbkdf2"):
        try:
            sb_hex, expected = h.split(":")
            sb = bytes.fromhex(sb_hex)
            if algo == "scrypt":
                computed = hashlib.scrypt(password.encode(), salt=sb, n=2**14, r=8, p=1)
            else:
                computed = hashlib.pbkdf2_hmac("sha256", password.encode(), sb, 600_000)
            return computed.hex() == expected
        except Exception:
            return False
    computed = hash_password(password, algo, salt)
    return hmac.compare_digest(computed.lower(), h.lower())


class HashCracker:
    def __init__(self, hash_str: str, algo: str = "auto", salt: str = "", verbose: bool = True):
        self.hash_str = hash_str.strip()
        self.salt     = salt
        self.verbose  = verbose
        self.attempts = 0
        self.t_start  = time.monotonic()
        self.algo     = detect_algo(self.hash_str) if algo == "auto" else algo

        if verbose:
            sec  = ALGO_SECURITY.get(self.algo, {})
            icon = {"CRITIQUE":"🔴","FAIBLE":"🟠","BON":"🟢","EXCELLENT":"✨"}.get(sec.get("rating",""),"⚪")
            print(f"  {icon} [{sec.get('rating','?')}] {self.algo.upper()} — {sec.get('note','')}")

    def _try(self, candidate: str) -> bool:
        self.attempts += 1
        return verify(candidate, self.hash_str, self.algo, self.salt)

    def attack_dict(self, wordlist=None, apply_rules=True) -> Optional[str]:
        words = wordlist or TOP_PASSWORDS
        rules = RULES if apply_rules else [lambda w: w]
        if self.verbose:
            print(f"\n  📖  Dictionnaire : {len(words)} mots × {len(rules)} règles = {len(words)*len(rules):,} candidats")
        for word in words:
            for rule in rules:
                try:
                    c = rule(word)
                except Exception:
                    c = word
                if self._try(c):
                    return c
        return None

    def attack_brute(self, charset="alphanum_lower", min_len=1, max_len=5, max_attempts=500_000) -> Optional[str]:
        chars = CHARSETS.get(charset, CHARSETS["alphanum_lower"])
        if self.verbose:
            total = sum(len(chars)**l for l in range(min_len, max_len+1))
            print(f"\n  💪  Bruteforce : '{charset}' len {min_len}–{max_len} = {total:,} combinaisons")
        for length in range(min_len, max_len+1):
            for combo in itertools.product(chars, repeat=length):
                if self._try("".join(combo)):
                    return "".join(combo)
                if self.attempts >= max_attempts:
                    return None
        return None

    def crack(self, wordlist_file=None, brute_max_len=4) -> dict:
        self.t_start = time.monotonic()
        found = self.attack_dict(apply_rules=True)
        method = "dictionnaire + règles"

        if not found and wordlist_file and Path(wordlist_file).exists():
            with open(wordlist_file, "r", encoding="latin-1", errors="replace") as f:
                words = [l.rstrip() for l in f if l.strip()]
            found = self.attack_dict(words, apply_rules=False)
            method = f"wordlist {Path(wordlist_file).name}"

        if not found and brute_max_len > 0:
            found = self.attack_brute(max_len=brute_max_len)
            method = "bruteforce"

        elapsed = time.monotonic() - self.t_start
        result = {
            "hash": self.hash_str, "algo": self.algo,
            "cracked": found is not None, "plaintext": found,
            "attempts": self.attempts, "duration_s": round(elapsed, 3),
            "method": method if found else None,
            "security": ALGO_SECURITY.get(self.algo, {}),
        }

        if self.verbose:
            SEP = "─" * 56
            print(f"\n  {SEP}")
            if found:
                speed = f"{self.attempts/elapsed:,.0f} hash/s" if elapsed > 0 else "N/A"
                print(f"  🔓  CRACKÉ → \"{found}\"")
                print(f"  📊  {self.attempts:,} tentatives · {elapsed:.3f}s · {speed}")
                print(f"  ⚔️   Méthode : {method}")
            else:
                print(f"  🔒  NON CRACKÉ après {self.attempts:,} tentatives ({elapsed:.2f}s)")
                r = result["security"].get("rating","")
                if r in ("BON","EXCELLENT"):
                    print(f"  ✅  Normal — {self.algo} est conçu pour résister")
            print(f"  {SEP}")

        return result


def benchmark_algos(password="MotDePasse123!"):
    print(f"\n  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║  ⏱️   BENCHMARK ALGORITHMES — \"{password}\"")
    print(f"  ╚══════════════════════════════════════════════════════╝\n")

    algos = [("MD5","md5"),("SHA-1","sha1"),("SHA-256","sha256"),
             ("SHA-512","sha512"),("NTLM","ntlm"),("PBKDF2","pbkdf2"),("scrypt","scrypt")]

    for name, algo in algos:
        try:
            N = 50 if algo in ("pbkdf2","scrypt") else 5_000
            t0 = time.monotonic()
            for _ in range(N):
                hash_password(password, algo)
            elapsed  = time.monotonic() - t0
            ms_each  = elapsed / N * 1000
            per_sec  = N / elapsed
            days_1M  = 1_000_000 * ms_each / 1000 / 86400

            crack_time = (f"{1_000_000*ms_each/1000:.0f}s" if ms_each < 1
                          else f"{days_1M:.1f} jours" if days_1M > 1
                          else f"{1_000_000*ms_each/3600:.0f}h")

            sec  = ALGO_SECURITY.get(algo, {})
            icon = {"CRITIQUE":"🔴","FAIBLE":"🟠","BON":"🟢","EXCELLENT":"✨"}.get(sec.get("rating",""),"⚪")
            print(f"  {icon} {name:<10} {ms_each:>8.3f} ms/hash  {per_sec:>12,.0f} hash/s  "
                  f"| 1M essais → {crack_time}")
        except Exception as e:
            print(f"  ⚠️  {name:<10} — {e}")

    print(f"""
  ──────────────────────────────────────────────────────
  Recommandations ANSSI / OWASP 2024 :
    ✅  bcrypt   (cost ≥ 12)      ✅  scrypt (N=2^17)
    ✅  argon2id (m=65536, t=3)   ✅  PBKDF2 (≥600k iter)
    ❌  MD5 · SHA-1 · SHA-256 · NTLM — INTERDITS pour les mdp
  ──────────────────────────────────────────────────────
""")


def audit_hash_database(hashes: list) -> dict:
    cracked, total_time = 0, 0.0
    results = []
    print(f"\n  🔍  Audit de {len(hashes)} hachage(s)...\n")
    for entry in hashes:
        u = entry.get("username","?")
        h = entry.get("hash","")
        a = entry.get("algo","auto")
        print(f"  👤  {u} ({a}) : {h[:24]}...")
        c = HashCracker(h, a, verbose=False)
        r = c.crack(brute_max_len=3)
        r["username"] = u
        results.append(r)
        if r["cracked"]:
            cracked += 1
            total_time += r["duration_s"]
            print(f"      🔓  CRACKÉ en {r['duration_s']:.3f}s → \"{r['plaintext']}\"")
        else:
            print(f"      🔒  Résistant ({r['attempts']:,} tentatives)")

    pct = int(cracked / len(hashes) * 100) if hashes else 0
    avg = round(total_time / cracked, 3) if cracked else 0
    verdict = ("🔴 CRITIQUE" if pct > 50 else "🟠 ÉLEVÉE" if pct > 20
               else "🟡 MODÉRÉE" if pct > 0 else "🟢 ACCEPTABLE")

    print(f"""
  ══════════════════════════════════════════════════════════
  📊  RAPPORT D'AUDIT
  Hachages analysés : {len(hashes)} · Craqués : {cracked} ({pct}%)
  Temps moyen       : {avg:.3f}s par mot de passe cracké
  Sévérité          : {verdict}
  Recommandation    : Migrer vers bcrypt(12) ou scrypt/argon2id
  ══════════════════════════════════════════════════════════
""")
    return {"total": len(hashes), "cracked": cracked, "pct": pct, "results": results}


def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 23 : CRAQUEUR DE HACHAGES     ║
╚══════════════════════════════════════════════════════════════════╝
""")
    benchmark_algos()

    cases = [
        ("MD5 brut — 'password'",            hashlib.md5(b"password").hexdigest(), "md5"),
        ("MD5 — 'Passw0rd!' (transformé)",   hashlib.md5(b"Passw0rd!").hexdigest(), "md5"),
        ("SHA-256 — '123456'",               hashlib.sha256(b"123456").hexdigest(), "sha256"),
    ]

    for title, h, algo in cases:
        print(f"  ══════════════════════════════════════════════════════════")
        print(f"  CAS : {title}")
        print(f"  ══════════════════════════════════════════════════════════\n")
        print(f"  Hachage : {h}")
        cracker = HashCracker(h, algo)
        cracker.crack()
        print()

    print("  ══════════════════════════════════════════════════════════")
    print("  CAS : scrypt(N=2^14) — résistant par design")
    print("  ══════════════════════════════════════════════════════════\n")
    sb = os.urandom(16)
    sh = sb.hex() + ":" + hashlib.scrypt(b"password", salt=sb, n=2**14, r=8, p=1).hex()
    print(f"  Hachage : {sh[:48]}...")
    c = HashCracker(sh, "scrypt")
    r = c.crack(brute_max_len=0)
    ms_each = r["duration_s"] / max(r["attempts"],1) * 1000
    print(f"  ✅  {ms_each:.1f}ms/tentative → 1M essais = {ms_each*1_000_000/3600/1000:.0f}h")

    print("  ══════════════════════════════════════════════════════════")
    print("  AUDIT BASE DE DONNÉES SIMULÉE")
    print("  ══════════════════════════════════════════════════════════")
    db = [
        {"username":"alice.martin",  "hash":hashlib.md5(b"sunshine").hexdigest(),    "algo":"md5"},
        {"username":"bob.dupont",    "hash":hashlib.md5(b"bonjour123").hexdigest(),  "algo":"md5"},
        {"username":"claire.dubois", "hash":hashlib.sha256(b"123456").hexdigest(),   "algo":"sha256"},
        {"username":"david.moreau",  "hash":hashlib.md5(b"Tr0ub4dor").hexdigest(),   "algo":"md5"},
    ]
    audit_hash_database(db)

    print("""  CONCLUSIONS
  ──────────────────────────────────────────────────────────
  1. MD5/SHA1/SHA256 → craqués en millisecondes à partir
     d'un dictionnaire de 60 mots seulement
  2. L'ajout de règles (Passw0rd!) donne une fausse sécurité
  3. scrypt/bcrypt/argon2id rendent le bruteforce inviable

  RGPD Art. 32 : "mesures techniques appropriées"
  → MD5 pour les mots de passe = mesure NON appropriée
  → Amende possible en cas de fuite + hachages insuffisants
  ──────────────────────────────────────────────────────────
""")


def main():
    import argparse
    p   = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    sub.add_parser("benchmark")
    pc = sub.add_parser("crack")
    pc.add_argument("hash")
    pc.add_argument("--algo", "-a", default="auto")
    pc.add_argument("--salt", "-s", default="")
    pc.add_argument("--wordlist", "-w")
    pc.add_argument("--brute", "-b", type=int, default=4)
    ph = sub.add_parser("hash")
    ph.add_argument("password")
    ph.add_argument("--algo", "-a", default="sha256")
    pa = sub.add_parser("audit")
    pa.add_argument("file")

    args = p.parse_args()
    if not args.cmd or args.cmd == "demo":
        run_demo()
    elif args.cmd == "benchmark":
        benchmark_algos()
    elif args.cmd == "crack":
        HashCracker(args.hash, args.algo, args.salt).crack(args.wordlist, args.brute)
    elif args.cmd == "hash":
        print(f"  {args.algo} : {hash_password(args.password, args.algo)}")
    elif args.cmd == "audit":
        audit_hash_database(json.loads(Path(args.file).read_text()))


if __name__ == "__main__":
    main()
