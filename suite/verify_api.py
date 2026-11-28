"""Integration checks for the running local machine interface (demo and unpublished live)."""
import hashlib
import json
import os
from urllib.error import HTTPError
from urllib.request import Request,urlopen

BASE="http://127.0.0.1:18747/api/v1"
KEY=os.environ["OJAN_SIEM_TOKEN"]
def request(path,status=200,token=KEY,method="GET"):
    headers={"Authorization":"Bearer "+token} if token else {}
    try:
        response=urlopen(Request(BASE+path,headers=headers,method=method),timeout=5)
    except HTTPError as e:
        response=e
    with response:
        body=response.read()
        assert response.status==status,(path,response.status,status)
        if status>=400:
            assert json.loads(body)["error"]["code"]
        return body

def obj(*args,**kwargs):
    return json.loads(request(*args,**kwargs))

assert obj("/livez",token=None)["alive"]
assert obj("/openapi.json",token=None)["openapi"]=="3.1.0"
for token in ("", "wrong"):
    request("/feeds",401,token)
request("/feeds",405,method="POST")
assert len(obj("/feeds?mode=demo")["feeds"])==4
request("/readyz",503)
root="/feeds/unified/snapshots/"
assert obj(root+"latest",503)["error"]["code"]=="no_publication"
m=obj(root+"latest?mode=demo")
ref=root+m["version"]
for name,digest in m["sha256"].items():
    old=request(ref+"/downloads/"+name+"?mode=demo")
    assert hashlib.sha256(old).hexdigest()==digest
    assert old==request(root+"latest/downloads/"+name+"?mode=demo")
page=ref+"/records?mode=demo&type=domain&source=Relay%20watch&limit=1"
a=obj(page)
b=obj(page+"&offset=1")
assert a["total"]>1 and a["items"][0]["id"]!=b["items"][0]["id"]
r=obj(page+"&q=relay&status=active")["items"][0]
assert len(obj(ref+"/records/"+r["id"]+"/provenance?mode=demo")["observations"])==2
request(page+"&limit=0",400)
request(ref+"/records?limit=0&mode=demo",400)
request(root+"missing?mode=demo",404)
assert obj("/feeds/unified/health?mode=demo")["readable"]
print("API checks passed: authorization, method, readiness, no live fallback, filters, pagination, provenance, latest and immutable checksums.")

