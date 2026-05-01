#!/usr/bin/env python3
"""Bouclier Numerique - Jour 29 : Threat Intelligence Feed"""
import json, time, hashlib, sqlite3, threading
import urllib.request, csv, io, re
from pathlib import Path
from datetime import datetime
from typing import Optional
from html import escape


class IoC:
    def __init__(self, ioc_type, value, source, confidence=50,
                 severity="MODEREE", tags=None, description="", tlp="WHITE"):
        self.id         = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:12]
        self.type       = ioc_type
        self.value      = value.strip()
        self.source     = source
        self.confidence = min(100, max(0, confidence))
        self.severity   = severity
        self.tags       = tags or []
        self.description= description
        self.tlp        = tlp
        self.first_seen = datetime.now().isoformat()
        self.last_seen  = self.first_seen
        self.hit_count  = 1

    def to_stix(self):
        type_map = {"ip":"ipv4-addr","domain":"domain-name","url":"url","email":"email-addr"}
        if self.type in ("hash_md5","hash_sha256"):
            k = "MD5" if self.type=="hash_md5" else "SHA-256"
            return {"type":"file","spec_version":"2.1","id":f"file--{self.id}","hashes":{k:self.value}}
        st = type_map.get(self.type, "indicator")
        return {"type":st,"spec_version":"2.1","id":f"{st}--{self.id}","value":self.value}


class IoCDatabase:
    SCHEMA = (
        "CREATE TABLE IF NOT EXISTS iocs ("
        "id TEXT PRIMARY KEY, type TEXT, value TEXT UNIQUE, "
        "source TEXT, confidence INTEGER, severity TEXT, "
        "tags TEXT, description TEXT, tlp TEXT, "
        "first_seen TEXT, last_seen TEXT, hit_count INTEGER DEFAULT 1);"
        "CREATE INDEX IF NOT EXISTS idx_t ON iocs(type);"
        "CREATE INDEX IF NOT EXISTS idx_s ON iocs(severity);"
    )

    def __init__(self, db_path=":memory:"):
        self.conn  = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()


    def upsert(self, ioc):
        with self._lock:
            if self.conn.execute("SELECT id FROM iocs WHERE value=?",(ioc.value,)).fetchone():
                self.conn.execute(
                    "UPDATE iocs SET hit_count=hit_count+1,last_seen=?,"
                    "confidence=MIN(100,confidence+5) WHERE value=?",
                    (datetime.now().isoformat(), ioc.value))
                self.conn.commit()
                return False
            self.conn.execute("INSERT INTO iocs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ioc.id,ioc.type,ioc.value,ioc.source,ioc.confidence,ioc.severity,
                 json.dumps(ioc.tags),ioc.description,ioc.tlp,
                 ioc.first_seen,ioc.last_seen,ioc.hit_count))
            self.conn.commit()
            return True

    def lookup(self, value):
        row = self.conn.execute("SELECT * FROM iocs WHERE value=?",(value,)).fetchone()
        if not row: return None
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    def stats(self):
        return {
            "total":      self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
            "by_type":    dict(self.conn.execute("SELECT type,COUNT(*) FROM iocs GROUP BY type").fetchall()),
            "by_severity":dict(self.conn.execute("SELECT severity,COUNT(*) FROM iocs GROUP BY severity").fetchall()),
        }

    def get_all(self, limit=500):
        rows = self.conn.execute(
            "SELECT * FROM iocs ORDER BY hit_count DESC,confidence DESC LIMIT ?",(limit,)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["tags"] = json.loads(d.get("tags") or "[]")
            result.append(d)
        return result

    def export_csv(self):
        rows = self.conn.execute(
            "SELECT type,value,severity,confidence,source,description "
            "FROM iocs ORDER BY severity,confidence DESC").fetchall()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type","value","severity","confidence","source","description"])
        w.writerows(rows)
        return buf.getvalue()

    def export_stix_bundle(self):
        objects = [IoC(d["type"],d["value"],d["source"],d["confidence"],d["severity"]).to_stix()
                   for d in self.get_all()]
        return {
            "type":"bundle",
            "id":f"bundle--{hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:32]}",
            "spec_version":"2.1","created":datetime.now().isoformat(),"objects":objects
        }


class FeedCollector:
    def __init__(self, db, timeout=8.0, rate_limit=0.4):
        self.db,self.timeout,self.rate_limit = db,timeout,rate_limit

    def _get(self, url, headers=None):
        h = {"User-Agent":"BouclierNumerique-TI/1.0","Accept":"text/plain,application/json,*/*"}
        if headers: h.update(headers)
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(5_000_000).decode("utf-8", errors="replace")
        except Exception as e:
            print(f"    Err {url[:50]}: {e}")
            return None
        finally:
            time.sleep(self.rate_limit)

    def collect_feodo_ips(self):
        print("  [Feodo]    IPs C2 botnets...", flush=True)
        data = self._get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
        if not data: return 0
        n = 0
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("#") or not line: continue
            parts = [p.strip().strip('"') for p in line.split(",")]
            ip = parts[0] if parts else ""
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip): continue
            malware = parts[2] if len(parts) > 2 else "botnet"
            if self.db.upsert(IoC("ip",ip,"AbuseCH/Feodo",90,"CRITIQUE",
                                  ["c2","botnet",malware.lower()],f"C2 {malware}")):
                n += 1
        print(f"  [Feodo]    {n} nouvelles IPs")
        return n

    def collect_urlhaus(self):
        print("  [URLhaus]  URLs malveillantes...", flush=True)
        data = self._get("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                         {"Content-Type":"application/json"})
        if not data: return 0
        n = 0
        try:
            for e in json.loads(data).get("urls",[])[:150]:
                if e.get("url_status")!="online" or not e.get("url"): continue
                tags = [e["tags"]] if e.get("tags") else []
                if self.db.upsert(IoC("url",e["url"],"AbuseCH/URLhaus",85,"ELEVEE",
                                      tags+["malware_distribution"],
                                      f"Malware:{e.get('threat','?')}")):
                    n += 1
        except Exception: pass
        print(f"  [URLhaus]  {n} nouvelles URLs")
        return n

    def collect_openphish(self):
        print("  [OpenPhish] URLs phishing...", flush=True)
        data = self._get("https://openphish.com/feed.txt")
        if not data: return 0
        n = 0
        for line in data.splitlines()[:300]:
            line = line.strip()
            if line.startswith("http"):
                if self.db.upsert(IoC("url",line,"OpenPhish",80,"ELEVEE",
                                      ["phishing"],"URL phishing")): n += 1
        print(f"  [OpenPhish] {n} nouvelles URLs")
        return n

    def collect_cves(self, n_last=30):
        print(f"  [CVE]      {n_last} CVE recentes...", flush=True)
        data = self._get(f"https://cve.circl.lu/api/last/{n_last}")
        if not data: return 0
        n = 0
        try:
            for cve in json.loads(data):
                cve_id = cve.get("id","")
                if not cve_id.startswith("CVE-"): continue
                cvss = 0.0
                for k in ("cvss","cvss3"):
                    try:
                        cvss = float(cve.get(k) or 0)
                        if cvss: break
                    except (TypeError,ValueError): pass
                sev = ("CRITIQUE" if cvss>=9.0 else "ELEVEE" if cvss>=7.0
                       else "MODEREE" if cvss>=4.0 else "FAIBLE")
                desc = cve.get("summary","")[:200]
                if self.db.upsert(IoC("cve",cve_id,"CIRCL CVE",
                                      int(min(100,cvss*10)),sev,
                                      ["cve",f"cvss_{cvss:.1f}"],desc)):
                    n += 1
        except Exception: pass
        print(f"  [CVE]      {n} nouvelles CVE")
        return n

    def collect_all(self):
        results = {}
        threads = [
            threading.Thread(target=lambda: results.update({"feodo":self.collect_feodo_ips()})),
            threading.Thread(target=lambda: results.update({"urlhaus":self.collect_urlhaus()})),
            threading.Thread(target=lambda: results.update({"phish":self.collect_openphish()})),
            threading.Thread(target=lambda: results.update({"cves":self.collect_cves()})),
        ]
        for t in threads: t.start()
        for t in threads: t.join(timeout=25)
        return results


def generate_report(db, output_path=None):
    stats = db.stats(); iocs = db.get_all(150)
    now   = datetime.now().strftime("%d/%m/%Y %H:%M")
    SC    = {"CRITIQUE":"#e74c3c","ELEVEE":"#e67e22","MODEREE":"#f39c12","FAIBLE":"#27ae60"}
    rows  = "".join(
        f'<tr><td><span style="background:{SC.get(i["severity"],"#888")};color:#fff;'
        f'padding:.1rem .3rem;border-radius:2px;font-size:.73rem">{escape(i["severity"])}</span></td>'
        f'<td><code style="font-size:.77rem">{escape(i["value"][:70])}</code></td>'
        f'<td style="font-size:.78rem">{escape(i["type"])}</td>'
        f'<td>{i["confidence"]}%</td><td style="font-size:.76rem">{escape(i["source"])}</td>'
        f'<td>{i.get("hit_count",1)}</td></tr>'
        for i in iocs[:100]
    )
    html = (f'<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">'
            f'<title>Threat Intelligence</title><style>'
            f'body{{background:#0f1117;color:#e2e8f0;font-family:sans-serif;padding:2rem;max-width:1100px;margin:auto}}'
            f'h1{{color:#64ffda}}table{{width:100%;border-collapse:collapse;background:#1a1d27;border:1px solid #2d3148}}'
            f'th{{background:#0a0c14;color:#64ffda;padding:.55rem;text-align:left;font-size:.77rem}}'
            f'td{{padding:.48rem;border-top:1px solid #2d3148;color:#8892b0}}code{{background:#0a0c14;padding:.12rem .35rem;border-radius:3px}}</style></head>'
            f'<body><h1>Threat Intelligence Feed</h1><p style="color:#8892b0">{now} | {stats["total"]} IoC | TLP:WHITE</p>'
            f'<table><thead><tr><th>Severite</th><th>Valeur</th><th>Type</th><th>Confiance</th><th>Source</th><th>Hits</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></body></html>')
    if output_path:
        output_path.write_text(html, encoding="utf-8")
        print(f"  Rapport -> {output_path}")
    return html


DEMO_IOCS = [
    IoC("ip",     "185.234.219.47","Feodo",    92,"CRITIQUE",["c2","emotet"],"C2 Emotet"),
    IoC("ip",     "45.77.120.81",  "Feodo",    88,"CRITIQUE",["c2","trickbot"],"C2 TrickBot"),
    IoC("ip",     "91.108.56.12",  "OSINT",    78,"ELEVEE",  ["scanner"],"Scanner masscan"),
    IoC("url",    "http://corp-login.ru/payload.exe","URLhaus",85,"ELEVEE",["malware"],"Dropper"),
    IoC("url",    "http://microsofft-auth.com/login","OpenPhish",80,"ELEVEE",["phishing"],"Phishing MS"),
    IoC("domain", "microsofft-auth.com","OSINT",85,"CRITIQUE",["phishing"],"Phishing Microsoft"),
    IoC("hash_sha256","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "MISP",75,"CRITIQUE",["ransomware","lockbit"],"LockBit 3.0"),
    IoC("cve","CVE-2024-21413","CIRCL",95,"CRITIQUE",["rce","outlook"],"RCE Outlook CVSS 9.8"),
    IoC("cve","CVE-2024-0519","CIRCL",90,"CRITIQUE",["chrome","0day"],"Chrome V8 0-day"),
    IoC("cve","CVE-2023-44487","CIRCL",80,"ELEVEE",["http2","dos"],"HTTP/2 Rapid Reset"),
]


def run_demo():
    print("\n=== BOUCLIER NUMERIQUE - JOUR 29 : THREAT INTELLIGENCE ===\n")
    db = IoCDatabase(":memory:")
    FeedCollector(db, timeout=7.0, rate_limit=0.3).collect_all()
    if db.stats()["total"] < 5:
        print("\n  Feeds indisponibles - demo IoC charges\n")
        for ioc in DEMO_IOCS: db.upsert(ioc)
    stats = db.stats()
    iocs  = db.get_all(20)
    SI    = {"CRITIQUE":"[CRIT]","ELEVEE":"[ELEV]","MODEREE":"[MOD]","FAIBLE":"[OK  ]"}
    print(f"  {stats['total']} IoC | Critiques:{stats['by_severity'].get('CRITIQUE',0)} | Eleves:{stats['by_severity'].get('ELEVEE',0)}\n")
    for ioc in iocs[:12]:
        val = ioc["value"][:62]+("..." if len(ioc["value"])>62 else "")
        print(f"  {SI.get(ioc['severity'],'[ ? ]'):8} [{ioc['type']:<12}] {val}")
    stix_path = Path("/tmp/threat_intel.stix.json")
    csv_path  = Path("/tmp/threat_intel.csv")
    html_path = Path("/tmp/threat_intel.html")
    stix_path.write_text(json.dumps(db.export_stix_bundle(),indent=2,ensure_ascii=False))
    csv_path.write_text(db.export_csv(), encoding="utf-8")
    generate_report(db, html_path)
    found = db.lookup("185.234.219.47")
    label = f"MALVEILLANT [{found['severity']}]" if found else "Non liste"
    print(f"\n  Lookup 185.234.219.47 -> {label}")
    print(f"\n  Exports: {stix_path} | {csv_path} | {html_path}\n")


def main():
    import argparse
    p   = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    pc = sub.add_parser("collect")
    pc.add_argument("--db",default="/tmp/ti.db"); pc.add_argument("--output",default="/tmp/ti.html")
    pl = sub.add_parser("lookup")
    pl.add_argument("value"); pl.add_argument("--db",default="/tmp/ti.db")
    args = p.parse_args()
    if not args.cmd or args.cmd=="demo": run_demo()
    elif args.cmd=="collect":
        db=IoCDatabase(args.db); FeedCollector(db).collect_all()
        print(f"OK - {db.stats()['total']} IoC"); generate_report(db,Path(args.output))
    elif args.cmd=="lookup":
        db=IoCDatabase(args.db); found=db.lookup(args.value)
        print("MALVEILLANT\n"+json.dumps(found,indent=2,ensure_ascii=False) if found else f"Non liste: {args.value}")

if __name__=="__main__": main()
