"""Exercise the running local console using an isolated Chrome test profile."""
import csv
import hashlib
import io
import json
import subprocess
import sys
from verify_publication import check
from urllib.request import urlopen
from playwright.sync_api import sync_playwright, expect

URL = "http://127.0.0.1:18746"

def state():
    return json.load(urlopen(URL+"/api/state"))

with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="chrome",headless=True)
    page = browser.new_page()
    errors = []
    page.on("pageerror",lambda error: errors.append(str(error)))
    for feed,s in state().items():
        page.goto(URL+"/"+feed)
        first = page.get_by_role("button", name="Inspect").first
        first.click()
        expect(page.get_by_text("Source observations",exact=True)).to_be_visible()
        page.get_by_role("button",name="Close").click()
        page.get_by_role("textbox",name="Search records").fill("no-such-fixture-xyz")
        expect(page.get_by_text("No matching records.")).to_be_visible()
        page.get_by_role("button",name="Compare versions").click()
        expect(page.get_by_role("dialog")).to_be_visible()
        m=s["manifest"]
        prefix=URL+"/exports/demo/"+feed+"/"+m["version"]+"/"
        manifest=json.load(urlopen(prefix+"manifest.json"))
        payload=urlopen(prefix+"lookup.csv").read()
        assert hashlib.sha256(payload).hexdigest()==manifest["sha256"]["lookup.csv"]
        rows=list(csv.DictReader(io.StringIO(payload.decode())))
        assert len(rows)==manifest["outputs"] and all(r["version"]==manifest["version"] for r in rows)
        print(feed,m["version"],len(rows),"CSV, manifest, search, evidence and comparison verified")
    before=state()["unified"]["manifest"]
    previous_bytes=check()
    assert subprocess.run([sys.executable,"suite.py","run","--feed","unified","--empty"]).returncode==1
    assert state()["unified"]["manifest"]==before
    assert check()==previous_bytes
    page.goto(URL+"/unified")
    expect(page.get_by_text("Degraded · Collection returned zero parsed rows",exact=False)).to_be_visible()
    expect(page.get_by_role("button",name="Inspect").first).to_be_visible()
    page.goto(URL)
    expect(page.get_by_text("Collection returned zero parsed rows")).to_be_visible()
    assert not errors,errors
    print("Zero-row failure visible. Retained immutable publication",before["version"])
    browser.close()
