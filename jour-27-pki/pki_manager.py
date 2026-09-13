#!/usr/bin/env python3
"""Construit une PKI interne à trois niveaux (CA root, CA intermédiaire, certificats leaf) en pilotant openssl.

Ce script ne réimplémente aucune primitive cryptographique : il orchestre
la CLI `openssl`, qui reste la référence pour générer des clés RSA, des
CSR et signer des certificats X.509 dans le bon ordre. L'intérêt d'une
CA intermédiaire plutôt que de signer les certificats serveur/client
directement avec la CA root est opérationnel autant que sécuritaire :
la clé root peut rester hors ligne en production (elle ne sert qu'une
fois, pour signer l'intermédiaire), alors que l'intermédiaire, exposée
aux opérations courantes de signature, peut être révoquée et renouvelée
sans invalider toute la chaîne de confiance. Chaque certificat généré
porte un SAN (Subject Alternative Name) explicite : le CN seul est
déprécié depuis la RFC 6125, et les clients TLS modernes l'ignorent.
Les commandes openssl sont exécutées comme des listes d'arguments
(pas de `shell=True`) pour éviter qu'un chemin de sortie contrôlé par
l'appelant ne soit interprété par un shell.

Référence : RFC 5280 (X.509), ANSSI RGS, eIDAS.
"""

import subprocess, json, os, sys, datetime
from pathlib import Path

def run(cmd, capture=True):
    """Exécute une commande openssl passée sous forme de liste d'arguments (pas de shell)."""
    r = subprocess.run(cmd, capture_output=capture, text=True)
    return r.stdout.strip(), r.returncode

def create_pki(base_dir: Path):
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "ca").mkdir(exist_ok=True)
    (base_dir / "intermediate").mkdir(exist_ok=True)
    (base_dir / "certs").mkdir(exist_ok=True)

    # Extension files (process substitution not available in Python subprocess)
    Path("/tmp/int_ext.cnf").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")
    Path("/tmp/san_ext.cnf").write_text("subjectAltName=DNS:localhost,DNS:app.local,IP:127.0.0.1")
    Path("/tmp/client_ext.cnf").write_text("extendedKeyUsage=clientAuth\nsubjectAltName=email:alice@techcorp.fr")

    # ── CA Root ──────────────────────────────────────────────────
    print("  [1/4] Génération CA Root (RSA 4096)...")
    run(["openssl", "genrsa", "-out", str(base_dir / "ca/ca.key"), "4096"])
    run([
        "openssl", "req", "-new", "-x509", "-days", "3650",
        "-key", str(base_dir / "ca/ca.key"),
        "-out", str(base_dir / "ca/ca.crt"),
        "-subj", "/C=FR/ST=IDF/O=Bouclier Numerique/CN=Bouclier Root CA",
        "-extensions", "v3_ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ])
    print("  CA Root créée")

    # ── CA Intermédiaire ─────────────────────────────────────────
    print("  [2/4] Génération CA Intermédiaire (RSA 2048)...")
    run(["openssl", "genrsa", "-out", str(base_dir / "intermediate/int.key"), "2048"])
    run([
        "openssl", "req", "-new",
        "-key", str(base_dir / "intermediate/int.key"),
        "-out", str(base_dir / "intermediate/int.csr"),
        "-subj", "/C=FR/ST=IDF/O=Bouclier Numerique/CN=Bouclier Intermediate CA",
    ])
    run([
        "openssl", "x509", "-req", "-days", "1825",
        "-in", str(base_dir / "intermediate/int.csr"),
        "-CA", str(base_dir / "ca/ca.crt"), "-CAkey", str(base_dir / "ca/ca.key"),
        "-CAcreateserial", "-out", str(base_dir / "intermediate/int.crt"),
        "-extfile", "/tmp/int_ext.cnf",
    ])
    print("  CA Intermédiaire créée")

    # ── Certificat serveur TLS ───────────────────────────────────
    print("  [3/4] Certificat TLS serveur (localhost + SAN)...")
    run(["openssl", "genrsa", "-out", str(base_dir / "certs/server.key"), "2048"])
    san_ext = f"""[req]
distinguished_name=dn
[dn]
[SAN]
subjectAltName=DNS:localhost,DNS:app.local,IP:127.0.0.1"""
    san_file = base_dir / "certs/san.cnf"
    san_file.write_text(san_ext)
    run([
        "openssl", "req", "-new",
        "-key", str(base_dir / "certs/server.key"),
        "-out", str(base_dir / "certs/server.csr"),
        "-subj", "/C=FR/O=TechCorp/CN=localhost",
        "-reqexts", "SAN", "-config", str(san_file),
    ])
    run([
        "openssl", "x509", "-req", "-days", "365",
        "-in", str(base_dir / "certs/server.csr"),
        "-CA", str(base_dir / "intermediate/int.crt"),
        "-CAkey", str(base_dir / "intermediate/int.key"),
        "-CAcreateserial", "-out", str(base_dir / "certs/server.crt"),
        "-extfile", "/tmp/san_ext.cnf",
    ])
    print("  Certificat TLS serveur créé")

    # ── Certificat client mTLS ───────────────────────────────────
    print("  [4/4] Certificat client mTLS (alice@techcorp.fr)...")
    run(["openssl", "genrsa", "-out", str(base_dir / "certs/client_alice.key"), "2048"])
    run([
        "openssl", "req", "-new",
        "-key", str(base_dir / "certs/client_alice.key"),
        "-out", str(base_dir / "certs/client_alice.csr"),
        "-subj", "/C=FR/O=TechCorp/CN=alice/emailAddress=alice@techcorp.fr",
    ])
    run([
        "openssl", "x509", "-req", "-days", "365",
        "-in", str(base_dir / "certs/client_alice.csr"),
        "-CA", str(base_dir / "intermediate/int.crt"),
        "-CAkey", str(base_dir / "intermediate/int.key"),
        "-CAcreateserial", "-out", str(base_dir / "certs/client_alice.crt"),
        "-extfile", "/tmp/client_ext.cnf",
    ])
    print("  Certificat client mTLS créé\n")

    # ── Chaîne de confiance ──────────────────────────────────────
    chain_path = base_dir / "certs/chain.crt"
    chain_path.write_bytes(
        (base_dir / "intermediate/int.crt").read_bytes() +
        (base_dir / "ca/ca.crt").read_bytes()
    )

    # Vérification
    out, rc = run([
        "openssl", "verify",
        "-CAfile", str(base_dir / "ca/ca.crt"),
        "-untrusted", str(base_dir / "intermediate/int.crt"),
        str(base_dir / "certs/server.crt"),
    ])
    server_ok = rc == 0

    out2, rc2 = run([
        "openssl", "verify",
        "-CAfile", str(base_dir / "ca/ca.crt"),
        "-untrusted", str(base_dir / "intermediate/int.crt"),
        str(base_dir / "certs/client_alice.crt"),
    ])
    client_ok = rc2 == 0

    # Rapport
    report = {
        "pki_root": str(base_dir),
        "ca_root":          str(base_dir / "ca/ca.crt"),
        "ca_intermediate":  str(base_dir / "intermediate/int.crt"),
        "server_cert":      str(base_dir / "certs/server.crt"),
        "client_cert":      str(base_dir / "certs/client_alice.crt"),
        "chain":            str(chain_path),
        "server_chain_ok":  server_ok,
        "client_chain_ok":  client_ok,
        "generated_at":     datetime.datetime.now().isoformat(),
    }

    (base_dir / "pki_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    print(f"  {'─'*56}")
    print(f"  PKI créée dans {base_dir}/")
    print(f"  Chaîne serveur  : {'valide' if server_ok else 'invalide'}")
    print(f"  Chaîne cliente  : {'valide' if client_ok else 'invalide'}")
    print(f"  Usage mTLS      : -cert {base_dir}/certs/client_alice.crt")
    print(f"                    -key  {base_dir}/certs/client_alice.key")
    print(f"                    -cacert {base_dir}/ca/ca.crt")
    print(f"  {'─'*56}")
    return report

def show_cert_info(cert_path: str):
    out, _ = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-text", "-nameopt", "utf8"])
    subject = next((l.strip() for l in out.splitlines() if "Subject:" in l), "?")
    issuer  = next((l.strip() for l in out.splitlines() if "Issuer:" in l), "?")
    dates   = [l.strip() for l in out.splitlines() if "Not " in l]
    sans    = next((l.strip() for l in out.splitlines() if "DNS:" in l or "IP:" in l), "")
    print(f"  {subject}")
    print(f"  {issuer}")
    for d in dates: print(f"  {d}")
    if sans: print(f"  SAN: {sans}")

def run_demo():
    print("""
  PKI & Certificats — Jour 27
""")
    out, rc = run(["openssl", "version"])
    if rc != 0:
        print("  OpenSSL non disponible"); return

    print(f"  OpenSSL : {out}\n")
    pki_dir = Path("/tmp/bouclier_pki")
    report  = create_pki(pki_dir)

    print("\n  Informations des certificats créés :\n")
    for label, path in [
        ("CA Root",          report["ca_root"]),
        ("CA Intermédiaire", report["ca_intermediate"]),
        ("Serveur TLS",      report["server_cert"]),
        ("Client mTLS",      report["client_cert"]),
    ]:
        print(f"  {label}")
        show_cert_info(path)
        print()

    print(f"""  Points clés PKI Zero Trust :

  - CA Root hors ligne (air-gapped en prod)
  - CA Intermédiaire pour signer les leaf certs
  - SAN obligatoire (CN seul déprécié RFC 6125)
  - mTLS : client ET serveur s'authentifient
  - Chaîne de confiance vérifiable

  Conformité : RFC 5280 · ANSSI RGS · ISO 27001 A.10.1
""")

def main():
    import argparse
    p = argparse.ArgumentParser(description="PKI Manager — Bouclier J27")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    pc = sub.add_parser("create"); pc.add_argument("--dir", default="/tmp/my_pki")
    pi = sub.add_parser("info");   pi.add_argument("cert")
    args = p.parse_args()
    if not args.cmd or args.cmd == "demo": run_demo()
    elif args.cmd == "create": create_pki(Path(args.dir))
    elif args.cmd == "info":   show_cert_info(args.cert)

if __name__ == "__main__":
    main()
