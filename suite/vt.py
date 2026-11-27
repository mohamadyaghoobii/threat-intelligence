"""Optional, bounded VirusTotal file-report worker. Run separately from collection."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
import json
import os
import re
import sqlite3
import time
from urllib.error import HTTPError
from urllib.request import Request

from sources import open_provider

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / "data" / "vt.db"


def lookup(value, mode):
    if mode == "live" and CACHE.exists():
        with closing(sqlite3.connect(CACHE)) as db:
            if db.execute("select 1 from sqlite_master where name='results'").fetchone():
                row = db.execute("select result from results where hash=?", (value,)).fetchone()
                if row:
                    return json.loads(row[0])
    return {"status": "missing"}


def reserve(db, rpm, daily, monthly):
    now = time.time()
    with db:
        db.execute("begin immediate")
        until = db.execute("select max(until) from cooldown").fetchone()[0] or 0
        if until > now:
            return False
        for window, budget in [(60, rpm), (86400, daily), (31 * 86400, monthly)]:
            count = db.execute("select count(*) from requests where at>?", (now-window,)).fetchone()[0]
            if count >= budget:
                return False
        db.execute("delete from requests where at<?", (now-31*86400,))
        db.execute("insert into requests values (?)", (now,))
    return True


def retrieve(value, key, timeout):
    request = Request("https://www.virustotal.com/api/v3/files/"+value, headers={"x-apikey": key})
    with open_provider(request, timeout) as res:
        attrs = json.load(res)["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    malicious, suspicious = stats["malicious"], stats["suspicious"]
    if not all(isinstance(n, int) and n >= 0 for n in (malicious, suspicious)):
        raise ValueError("Invalid analysis counts")
    engines = sum(stats.values())
    return {"status": "detections" if malicious+suspicious else "no detections" if engines else "no analysis",
            "malicious": malicious, "detection_percent": int(100 * malicious / engines) if engines else None,
            "suspicious": suspicious, "tags": attrs.get("tags", []), "analysis_time": attrs.get("last_analysis_date")}


def retry_seconds(value):
    try:
        return max(60, int(value))
    except (ValueError, TypeError):
        try:
            return max(60, parsedate_to_datetime(value).timestamp()-time.time())
        except (ValueError, TypeError):
            return 86400


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=4)
    args = parser.parse_args()
    key = os.getenv("VT_API_KEY")
    if not key:
        raise SystemExit("Set VT_API_KEY to run enrichment.")
    state = ROOT / "data" / "state.db"
    if not state.exists():
        raise SystemExit("Publish live Central first.")
    with closing(sqlite3.connect(state)) as state_db:
        row = state_db.execute("select version from publications where mode='live' and feed='central' order by rowid desc limit 1").fetchone()
    if not row:
        raise SystemExit("Publish live Central first.")
    records = json.loads((ROOT/"data"/"live"/"central"/row[0]/"feed.json").read_text(encoding="utf-8"))
    with closing(sqlite3.connect(CACHE, timeout=20)) as db:
        db.executescript("""create table if not exists results(hash primary key, at real, result);
            create table if not exists requests(at real);
            create table if not exists cooldown(until real);""")
        attempted = 0
        for record in records:
            if attempted >= args.limit:
                break
            value = record["value"]
            if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
                raise ValueError("Unexpected canonical hash")
            cached = db.execute("select at from results where hash=?", (value,)).fetchone()
            if cached and cached[0] > time.time()-86400:
                continue
            if not reserve(db, int(os.getenv("VT_RPM", 4)), int(os.getenv("VT_DAILY", 500)), int(os.getenv("VT_MONTHLY", 15500))):
                print("Provider budget or cooldown reached")
                break
            stop = False
            try:
                result = retrieve(value, key, int(os.getenv("VT_TIMEOUT", 15)))
            except HTTPError as exc:
                result = {"status": "not found" if exc.code == 404 else "provider error", "http_status": exc.code}
                stop = exc.code in (401, 403, 429)
                if exc.code == 429:
                    with db:
                        db.execute("delete from cooldown")
                        db.execute("insert into cooldown values (?)", (time.time()+retry_seconds(exc.headers.get("Retry-After")),))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                result = {"status": "provider error", "error": type(exc).__name__}
                stop = True
            result.update(checked_at=datetime.now(timezone.utc).isoformat(), provider="VirusTotal", version=row[0])
            with db:
                db.execute("insert or replace into results values (?,?,?)", (value,time.time(),json.dumps(result)))
            attempted += 1
            if stop:
                break
        print(f"{attempted} canonical live hashes checked")


if __name__ == "__main__":
    main()

