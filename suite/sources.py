"""Read-only source adapters and compatibility CSV projections."""
import hashlib
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener, urlopen

ROOT = Path(__file__).resolve().parent
NETWORK = "https://www.spamhaus.org/drop/drop_v4.json"
HASHES = "https://threatview.io/Downloads/SHA-HASH-FEED.txt"
AGENTS = "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json"
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


def observation(value, kind, source, raw, **fields):
    return dict(value=value, type=kind, source=source, raw=raw, upstream=source, **fields)


def fixture(feed):
    rows = []
    def add(value, kind, source, **fields):
        raw = json.dumps(dict(indicator=value, **fields), ensure_ascii=False)
        item = observation(value, kind, source, raw)
        item.update(fields)
        rows.append(item)
    if feed == "unified":
        for name in ("relay", "telemetry", "beacon", "assets", "update"):
            add(f"{name}.example.test", "domain", "Relay watch", reason="Simulated sinkhole observation")
        add("RELAY.EXAMPLE.TEST", "domain", "DNS sensor", reason="Simulated passive DNS sighting")
        add("https://portal.example.test/login", "url", "URL monitor", reason="Simulated phishing submission")
        add("203.0.113.19:443", "ip:port", "Edge sensor", reason="Simulated TLS endpoint")
        add("retired.example.test", "domain", "Relay watch", expires="2020-01-01T00:00:00+00:00")
    elif feed == "central":
        for i, alg in enumerate(["sha256", "md5", "sha1", "sha256", "sha256", "md5"]):
            value = hashlib.new(alg, f"ojan fixture {i}".encode()).hexdigest()
            add(value, alg, "Sample registry", reason="Synthetic sample digest")
            if i == 0:
                add(value.upper(), alg, "Sandbox ledger", reason="Independent fixture observation")
    elif feed == "ua":
        add("AtlasBot", "ua", "Crawler index", category="bot", match="token")
        add("AtlasBot", "ua", "Index mirror", upstream="Crawler index", category="bot", match="token")
        add("AtlasBot", "ua", "Edge telemetry", category="bot", match="token")
        add("FieldCrawler/2.1", "ua", "Crawler index", category="crawler", match="exact")
        add(r"SurveyScan/\d+", "ua", "Edge telemetry", category="scanner", match="pattern")
        add("ArchiveSpider", "ua", "Crawler index", category="crawler", match="token")
        add("BeaconProbe/1.0", "ua", "Edge telemetry", category="scanner", match="exact")
    elif feed == "ip":
        for value, kind in [("45.33.32.156","ipv4"), ("45.33.32.156:8443","ip:port"),
                            ("2600:3c01::a","ipv6"), ("45.33.32.0/28","cidr"),
                            ("10.12.0.4","ipv4"), ("192.0.2.4","ipv4"), ("1.1.1.1","ipv4")]:
            add(value, kind, "Network ledger", reason="Synthetic network observation for policy review")
    else:
        raise ValueError("Unknown workflow")
    return rows


def parse(feed, body):
    rows = []
    if feed in ("ip", "unified"):
        meta = None
        for line in body.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if "cidr" in row:
                rows.append(observation(row["cidr"], "cidr", "Spamhaus DROP", line,
                                        reason="Prefix listed on Spamhaus DROP", source_url=NETWORK))
            elif "timestamp" in row and "copyright" in row:
                meta = row
            else:
                raise ValueError("Unexpected Spamhaus row")
        if meta is None:
            raise ValueError("Missing DROP publisher metadata")
        stamp = int(meta["timestamp"])
        for item in rows:
            item.update(provider_time=datetime.fromtimestamp(stamp, timezone.utc).isoformat(),
                        expires=datetime.fromtimestamp(stamp+93600, timezone.utc).isoformat(),
                        publisher_metadata=meta)
    elif feed == "central":
        for line in body.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if len(value) not in HASH_TYPES or not re.fullmatch("[0-9a-fA-F]+", value):
                raise ValueError("Malformed ThreatView hash")
            rows.append(observation(value, HASH_TYPES[len(value)], "ThreatView", line, source_url=HASHES))
    elif feed == "ua":
        for row in json.loads(body):
            pattern = row["pattern"]
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError("Empty crawler pattern")
            rows.append(observation(pattern, "ua", "Crawler User Agents", json.dumps(row, ensure_ascii=False),
                                    category="crawler", match="pattern", source_url=AGENTS,
                                    reason="Crawler signature for analyst review"))
    return rows


def open_provider(request, timeout):
    """Honor an explicit operator choice to connect directly with default TLS."""
    if os.getenv("OJAN_PROVIDER_DIRECT") == "1":
        return build_opener(ProxyHandler({})).open(request, timeout=timeout)
    return urlopen(request, timeout=timeout)


def download(endpoint, timeout):
    req = Request(endpoint, headers={"User-Agent": "Ojan-Threat-Intelligence/1.0"})
    with open_provider(req, timeout) as response:
        payload = response.read(20_000_001)
    if len(payload) > 20_000_000:
        raise ValueError("Source exceeded 20 MB response limit")
    return payload.decode("utf-8-sig")


def cached_drop(timeout):
    directory = ROOT / "data" / "live"
    directory.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(directory / "source-cache.db", timeout=30)) as db:
        db.execute("create table if not exists cache (url primary key, attempted real, body text)")
        with db:
            db.execute("begin immediate")
            row = db.execute("select attempted,body from cache where url=?", (NETWORK,)).fetchone()
            if row and time.time()-row[0] < 3600:
                if row[1] is None:
                    raise ValueError("DROP fetch pending or failed; hourly source cooldown")
                return row[1]
            db.execute("insert or replace into cache values (?,?,NULL)", (NETWORK,time.time()))
        body = download(NETWORK, timeout)
        with db:
            db.execute("update cache set body=? where url=?", (body,NETWORK))
        return body


def collect(feed, mode, config, stage=None):
    if mode == "demo":
        rows = fixture(feed)
        if stage:
            stage("validate")
            stage("parse")
        return rows
    if mode != "live":
        raise ValueError("Unknown source mode")
    endpoint = {"ip": NETWORK, "unified": NETWORK, "central": HASHES, "ua": AGENTS}[feed]
    timeout = config.get("timeout", 20)
    body = cached_drop(timeout) if endpoint == NETWORK else download(endpoint, timeout)
    if stage:
        stage("validate")
    if not body.strip() or body.lstrip().startswith("<"):
        raise ValueError("Expected provider dataset; received empty or markup response")
    if stage:
        stage("parse")
    return parse(feed, body)


COLUMNS = {
    "unified": "ioc normalized_ioc ioc_type threat_score severity confidence category tags first_seen last_seen is_active sources updated_at",
    "central": "hash hash_type source first_seen malicious_score confidence threat_type tags last_updated enrichment_status",
    "ua": "http_useragent threat_category tool_name severity_level sources",
    "ip": "value type reason expires"
}


def enrichment(value, mode):
    from vt import lookup
    if mode == "demo":
        fixture_states = [
            ("sha256", {"status":"detections", "malicious":6, "suspicious":1, "detection_percent":10}),
            ("md5", {"status":"no detections", "malicious":0, "suspicious":0, "detection_percent":0}),
            ("sha1", {"status":"provider error", "http_status":503}),
            ("sha256", {"status":"not found", "http_status":404}),
        ]
        for i, (algorithm, result) in enumerate(fixture_states):
            if value == hashlib.new(algorithm, f"ojan fixture {i}".encode()).hexdigest():
                return dict(result, provider="Simulated VirusTotal response", fixture=True)
    return lookup(value, mode)


def legacy(feed, records, mode="demo"):
    columns = COLUMNS[feed].split()
    rows = []
    for record in records:
        obs = record["observations"]
        dates = sorted(o["provider_time"] for o in obs if o.get("provider_time"))
        sources = ";".join(sorted({o["source"] for o in obs}))
        value = record["value"]
        row = dict(record)
        row.update(ioc=obs[0]["value"], normalized_ioc=value, ioc_type=record["type"],
                   sources=sources, source=sources, hash=value, hash_type=record["type"],
                   first_seen=dates[0] if dates else "", last_seen=dates[-1] if dates else "",
                   is_active=record["status"] in ("active", "usable"), http_useragent=value,
                   threat_category=obs[0].get("category"), updated_at=max((o.get("ingested","") for o in obs), default=""),
                   confidence=obs[0].get("confidence"), category=obs[0].get("category"))
        if row["ioc_type"] in ("ipv4", "ipv6"):
            row["ioc_type"] = "ip"
        if feed == "central":
            result = enrichment(value, mode)
            successful = result["status"] in ("detections", "no detections")
            row.update(malicious_score=result.get("malicious"), confidence=result.get("detection_percent"),
                       tags=";".join(result.get("tags", [])), last_updated=result.get("checked_at"),
                       enrichment_status="success" if successful else result["status"])
        rows.append({k: row.get(k) for k in columns})
    return columns, rows

