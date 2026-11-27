"""Local collection, immutable publications and console HTTP entry point."""
import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sqlite3
import socket
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
FEEDS = ("unified", "central", "ua", "ip")
MODES = ("demo", "live")
DEFAULT_CONFIG = ROOT / "config.example.json"
CONFIG_PATH = Path(os.environ.get("OJAN_CONFIG") or ROOT / "config.json")
if not CONFIG_PATH.exists() and not os.environ.get("OJAN_CONFIG"):
    CONFIG_PATH = DEFAULT_CONFIG
CONFIG = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    DATA.mkdir(exist_ok=True)
    c = sqlite3.connect(DATA / "state.db", timeout=30)
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE IF NOT EXISTS attempts(mode,feed,id PRIMARY KEY,started,parsed,stage,error,inputs INTEGER);
    CREATE TABLE IF NOT EXISTS publications(mode,feed,version PRIMARY KEY,published);
    """)
    return c


def latest(c, table, mode, feed):
    row = c.execute(f"SELECT * FROM {table} WHERE mode=? AND feed=? ORDER BY rowid DESC LIMIT 1", (mode,feed)).fetchone()
    return dict(row) if row else {}


def folder(mode, feed, version):
    return DATA / mode / feed / version


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def date(value):
    parsed = datetime.fromisoformat(str(value).replace("Z","+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires an offset")
    return parsed.astimezone(timezone.utc)


def canonical(row, cfg):
    value = row["value"].strip()
    typ = row["type"].lower()
    reason = ""
    if not value or not row["source"] or not row["raw"]:
        raise ValueError("missing value or evidence")
    if typ in ("md5","sha1","sha256","hash"):
        typ = {32:"md5",40:"sha1",64:"sha256"}.get(len(value),"invalid")
        if typ == "invalid" or not re.fullmatch("[a-fA-F0-9]+",value) or row["type"].lower() not in (typ,"hash"):
            raise ValueError("invalid hash")
        value = value.lower()
    elif typ in ("ip","ipv4","ipv6","cidr","ip:port","ip_port","ip-port"):
        endpoint = typ in ("ip:port","ip_port","ip-port")
        host, port = value, None
        if endpoint:
            host, port = value.rsplit(":",1)
            if ":" in host and not (host.startswith("[") and host.endswith("]")):
                raise ValueError("IPv6 endpoint requires brackets")
            host = host.strip("[]")
            port = int(port)
            if not 0 < port < 65536:
                raise ValueError("invalid port")
        net = ipaddress.ip_network(host,strict=False)
        addr = net.network_address
        if any(net.overlaps(a) for a in map(ipaddress.ip_network,cfg["allowlist"]) if a.version == net.version):
            reason = "Allowlisted network"
        elif not addr.is_global or addr.is_multicast or not net.broadcast_address.is_global or any(net.overlaps(n) for n in SPECIAL if n.version==net.version):
            reason = "Private or reserved address space"
        if endpoint:
            typ,value = "ip:port", f"[{addr}]:{port}" if addr.version==6 else f"{addr}:{port}"
        elif "/" in host:
            typ,value = "cidr",str(net)
        else:
            typ,value = f"ipv{addr.version}",str(addr)
    elif typ in ("domain","hostname"):
        typ,value = "domain",value.rstrip(".").encode("idna").decode().lower()
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",p) for p in value.split(".")):
            raise ValueError("invalid domain")
    return typ,value,reason


SPECIAL = list(map(ipaddress.ip_network, ["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","192.0.0.0/24","192.0.2.0/24","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4","fc00::/7","fe80::/10","ff00::/8","2001:db8::/32","::1/128","::/128"]))


def csvbytes(columns,rows):
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf,columns,extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


@contextmanager
def collection_lock(path):
    # Closing the descriptor also releases the lock after process failure.
    with path.open("a+b") as lock:
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError(f"Cannot acquire collection lock: {path.name}") from exc
        yield


def run(feed, mode, empty=False):
    from sources import collect,legacy
    cfg = CONFIG | CONFIG.get("feeds",{}).get(feed,{})
    version = uuid.uuid4().hex
    started = now()
    with closing(db()) as c, collection_lock(DATA / f"{mode}-{feed}.lock"):
        c.execute("UPDATE attempts SET error='Interrupted before publication' WHERE mode=? AND feed=? AND stage!='published' AND error IS NULL",(mode,feed))
        c.execute("INSERT INTO attempts VALUES(?,?,?,?,NULL,'fetch',NULL,0)",(mode,feed,version,started))
        c.commit()
        def stage(name):
            c.execute("UPDATE attempts SET stage=? WHERE id=?",(name,version))
            c.commit()
        try:
            previous = latest(c,"publications",mode,feed)
            old = read(folder(mode,feed,previous["version"])/"feed.json") if previous else []
            rows = [] if empty else collect(feed,mode,cfg,stage)
            if not isinstance(rows,list) or not rows:
                raise ValueError("Collection returned zero parsed rows")
            c.execute("UPDATE attempts SET inputs=? WHERE id=?",(len(rows),version))
            stage("parse")
            for row in rows:
                if not all(row.get(k) for k in ("source","type","value","raw")):
                    raise ValueError("Incomplete source evidence")
            c.execute("UPDATE attempts SET parsed=? WHERE id=?",(now(),version))
            stage("normalize")
            groups = {}
            for row in rows:
                typ,value,excluded = canonical(row,cfg)
                expiry = (date(row["expires"]) if row.get("expires") else date(row.get("provider_time") or started)+timedelta(hours=cfg["ttl_hours"])).isoformat()
                r = groups.setdefault((typ,value),dict(type=typ,value=value,observations=[],expires=expiry,reason=excluded))
                r["expires"] = max(expiry,r["expires"])
                r["observations"].append(dict(row,provider_time=row.get("provider_time"),ingested=started,expires=expiry))
            stage("merge")
            prior = {(r["type"],r["value"]):r for r in old}
            for k,r in groups.items():
                r["status"] = "excluded" if r["reason"] else "expired" if date(r["expires"])<=date(started) else "active"
                r["reason"] = r["reason"] or ("Validity window elapsed" if r["status"]=="expired" else r["observations"][0].get("reason") or "Within source validity window")
                history = prior.get(k,{}).get("history",[])[:]
                if not history or (history[-1]["status"],history[-1]["reason"])!=(r["status"],r["reason"]):
                    history.append(dict(at=started,status=r["status"],reason=r["reason"]))
                r["history"] = history
            stage("quality")
            records = [groups[k] for k in sorted(groups)]
            if len(records)<max(cfg["minimum"], len(old)*cfg["min_fraction"]):
                raise ValueError("Parsed record count below quality threshold")
            if not any(r["status"]=="active" for r in records):
                raise ValueError("No currently usable lookup rows")
            stage("publish")
            path = folder(mode,feed,version)
            path.mkdir(parents=True)
            def dump(name,obj):
                (path/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding="utf-8")
            dump("feed.json",records)
            active = [r for r in records if r["status"]=="active"]
            dump("lookup.json",active)
            cols = ["value","type","source","expires","version","mode"]
            (path/"lookup.csv").write_bytes(csvbytes(cols,[dict(r,source="|".join(sorted({o["source"] for o in r["observations"]})),version=version,mode=mode) for r in active]))
            lc,lr = legacy(feed,active,mode)
            (path/"compat.csv").write_bytes(csvbytes(lc,lr))
            changes = dict(added=sorted(groups.keys()-prior.keys()),removed=sorted(prior.keys()-groups.keys()),expired=sorted(k for k,r in groups.items() if r["status"]=="expired" and prior.get(k,{}).get("status")!="expired"))
            pub = now()
            manifest = dict(mode=mode,feed=feed,version=version,previous=previous.get("version"),published=pub,inputs=len(rows),records=len(records),outputs=len(active),expires=(date(pub)+timedelta(hours=cfg["fresh_hours"])).isoformat(),changes=changes,sha256={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in path.iterdir()})
            dump("manifest.json",manifest)
            c.execute("INSERT INTO publications VALUES(?,?,?,?)",(mode,feed,version,pub))
            c.execute("UPDATE attempts SET stage='published' WHERE id=?",(version,))
            c.commit()
            print(feed,mode,version,len(active),"published")
        except Exception as exc:
            c.rollback()
            c.execute("UPDATE attempts SET error=? WHERE id=?",(str(exc),version))
            c.commit()
            raise


def state(mode):
    result = {}
    with closing(db()) as c:
        for feed in FEEDS:
            attempt = latest(c,"attempts",mode,feed)
            pub = latest(c,"publications",mode,feed)
            m = read(folder(mode,feed,pub["version"])/"manifest.json") if pub else {}
            parsed = c.execute("SELECT max(parsed) FROM attempts WHERE mode=? AND feed=?",(mode,feed)).fetchone()[0]
            result[feed] = dict(attempt=attempt,manifest=m,parsed=parsed)
    return result


class LocalServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        mode = parse_qs(url.query).get("mode",["demo"])[0]
        parts = url.path.strip("/").split("/")
        if mode not in MODES:
            return self.send_error(400)
        aliases = {"/threat_intel_latest.csv":"central", "/useragent-intel/suspicious_useragents.csv":"ua"}
        if url.path in aliases:
            feed = aliases[url.path]
            with closing(db()) as c:
                pub = latest(c,"publications","live",feed)
            if not pub:
                return self.send_error(503,"No live publication")
            p = folder("live",feed,pub["version"])/"compat.csv"
        elif url.path.rstrip("/") in ["",*("/"+f for f in FEEDS)]:
            p = ROOT/"index.html"
        elif url.path in ("/app.js","/style.css"):
            p = ROOT/url.path[1:]
        elif url.path=="/api/state":
            return self.reply(json.dumps(state(mode)).encode(),"application/json")
        elif url.path=="/api/enrichment":
            from sources import enrichment
            return self.reply(json.dumps(enrichment(parse_qs(url.query).get("value",[""])[0],mode)).encode(),"application/json")
        elif len(parts)==5 and parts[0]=="exports" and parts[1] in MODES and parts[2] in FEEDS and re.fullmatch("[0-9a-f]{32}",parts[3]) and parts[4] in ("lookup.csv","compat.csv","feed.json","lookup.json","manifest.json"):
            with closing(db()) as c:
                if not c.execute("SELECT 1 FROM publications WHERE mode=? AND feed=? AND version=?",parts[1:4]).fetchone():
                    return self.send_error(404)
            p = folder(*parts[1:4])/parts[4]
        else:
            return self.send_error(404)
        self.reply(p.read_bytes(),{".html":"text/html",".js":"text/javascript",".css":"text/css",".json":"application/json",".csv":"text/csv"}[p.suffix]+"; charset=utf-8")

    def reply(self,body,mime):
        self.send_response(200)
        self.send_header("Content-Type",mime)
        self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=["run","serve","status"])
    parser.add_argument("--mode",choices=MODES,default="demo")
    parser.add_argument("--feed",choices=FEEDS)
    parser.add_argument("--empty",action="store_true")
    parser.add_argument("--port",type=int,default=18746)
    parser.add_argument("--api-port",type=int,default=18747)
    a=parser.parse_args()
    if a.action=="serve":
        from api_v1 import Machine
        from threading import Thread
        with LocalServer(("127.0.0.1",a.port),Handler) as ui, LocalServer(("127.0.0.1",a.api_port),Machine) as api:
            Thread(target=api.serve_forever,daemon=True).start()
            ui.serve_forever()
    elif a.action=="status":
        print(json.dumps(state(a.mode),indent=2))
    else:
        failed=False
        for f in [a.feed] if a.feed else FEEDS:
            try:
                run(f,a.mode,a.empty)
            except Exception as exc:
                failed=True
                print(f,"FAILED",exc)
        raise SystemExit(int(failed))
