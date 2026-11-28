"""Compare actual HTTP bytes across an intentionally failed fixture run."""
import csv
import hashlib
import io
import json
import subprocess
import sys
from urllib.request import urlopen

BASE = "http://127.0.0.1:18746"
def fetch(path):
    with urlopen(BASE+path,timeout=10) as response:
        return response.read()

def check():
    state = json.loads(fetch("/api/state"))
    downloads = {}
    for feed, info in state.items():
        assert b'id="body"' in fetch("/"+feed)
        m = info["manifest"]
        prefix = f"/exports/demo/{feed}/{m['version']}/"
        files = {name:fetch(prefix+name) for name in [*m["sha256"],"manifest.json"]}
        assert json.loads(files["manifest.json"]) == m
        for name, digest in m["sha256"].items():
            assert hashlib.sha256(files[name]).hexdigest() == digest
        rows = list(csv.DictReader(io.StringIO(files["lookup.csv"].decode())))
        records = json.loads(files["lookup.json"])
        assert len(rows)==len(records)==m["outputs"]
        assert [(r["type"],r["value"]) for r in rows]==[(r["type"],r["value"]) for r in records]
        assert all(r["version"]==m["version"] for r in rows)
        downloads[feed] = (m["version"],files)
        print(feed,m["version"],len(rows))
    return downloads

if __name__=="__main__":
    before=check()
    assert subprocess.run([sys.executable,"suite.py","run","--feed","unified","--empty"]).returncode==1
    assert before==check()
    assert json.loads(fetch("/api/state"))["unified"]["attempt"]["error"]
    print("Retained versions and all served bytes verified")
