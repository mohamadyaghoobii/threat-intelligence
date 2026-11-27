"""Machine read API, mounted on a separate loopback listener."""
import hashlib
import hmac
import json
import os
import re
from contextlib import closing
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

import suite

FILES = ("manifest.json","lookup.csv","compat.csv","lookup.json","feed.json")
PREFIX = "/api/v1"


def health(info):
    m=info["manifest"]
    stale=bool(m and suite.date(m["expires"])<=suite.date(suite.now()))
    error=info["attempt"].get("error")
    ready=bool(m and not stale and not error)
    return dict(version=m.get("version"), published=m.get("published"), expires=m.get("expires"),
                stale=stale, readable=bool(m), ready=ready, last_attempt=info["attempt"],
                last_successful_parse=info["parsed"], inputs=m.get("inputs"), outputs=m.get("outputs"))


class Problem(Exception):
    def __init__(self,status,code,message):
        self.status,self.code,self.message=status,code,message


class Machine(BaseHTTPRequestHandler):
    def respond(self,status,body,mime="application/json",version=None):
        if not isinstance(body,bytes):
            body=json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type",mime)
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-store")
        if status==401:
            self.send_header("WWW-Authenticate",'Bearer realm="Ojan SIEM"')
        if version:
            self.send_header("X-Publication-Version",version)
        self.end_headers()
        self.wfile.write(body)

    def send_error(self,code,message=None,explain=None):
        self.respond(405,{"error":{"code":"method_not_allowed","message":"Use GET"}})

    def do_GET(self):
        try:
            self.dispatch()
        except Problem as e:
            self.respond(e.status,{"error":{"code":e.code,"message":e.message}})
        except (OSError,suite.sqlite3.Error,json.JSONDecodeError):
            self.respond(503,{"error":{"code":"storage_unavailable","message":"Publication storage unavailable"}})

    def dispatch(self):
        url=urlsplit(self.path)
        if url.path==PREFIX+"/livez":
            return self.respond(200,{"alive":True})
        if url.path==PREFIX+"/openapi.json":
            return self.respond(200,(suite.ROOT/"openapi.json").read_bytes())
        key=os.getenv("OJAN_SIEM_TOKEN","")
        auth=self.headers.get("Authorization","").encode()
        if not key or not hmac.compare_digest(auth,("Bearer "+key).encode()):
            raise Problem(401,"unauthorized","SIEM bearer token required")
        if not url.path.startswith(PREFIX+"/"):
            raise Problem(404,"not_found","Unknown machine route")
        parts=url.path[len(PREFIX)+1:].split("/")
        params=parse_qs(url.query,keep_blank_values=True)
        if any(len(v)!=1 for v in params.values()):
            raise Problem(400,"invalid_query","Duplicate query parameter")
        q={k:v[0] for k,v in params.items()}
        mode=q.pop("mode","live")
        if mode not in suite.MODES:
            raise Problem(400,"invalid_mode","Expected live or demo")
        allowed={"q","type","source","status","limit","offset"} if parts[-1]=="records" else set()
        if q.keys()-allowed:
            raise Problem(400,"invalid_query","Unknown query parameter")
        if parts in (["readyz"],["feeds"]):
            feeds={f:health(v) for f,v in suite.state(mode).items()}
            ready=all(v["ready"] for v in feeds.values())
            if parts==["readyz"] and not ready:
                return self.respond(503,dict(mode=mode,ready=False,feeds=feeds,error=dict(code="not_ready",message="Review feed health")))
            return self.respond(200,dict(mode=mode,ready=ready,feeds=feeds))
        if len(parts)<3 or parts[0]!="feeds" or parts[1] not in suite.FEEDS:
            raise Problem(404,"not_found","Unknown feed or route")
        feed=parts[1]
        if parts[2:]==["health"]:
            return self.respond(200,dict(mode=mode,feed=feed,**health(suite.state(mode)[feed])))
        if len(parts)<4 or parts[2]!="snapshots":
            raise Problem(404,"not_found","Unknown snapshot route")
        ref=parts[3]
        with closing(suite.db()) as c:
            if ref=="latest":
                pub=suite.latest(c,"publications",mode,feed)
                if not pub:
                    raise Problem(503,"no_publication","No published snapshot in selected environment")
                version=pub["version"]
            else:
                if not re.fullmatch("[0-9a-f]{32}",ref) or not c.execute("SELECT 1 FROM publications WHERE mode=? AND feed=? AND version=?",(mode,feed,ref)).fetchone():
                    raise Problem(404,"unknown_version","Snapshot not found")
                version=ref
        path=suite.folder(mode,feed,version)
        tail=parts[4:]
        if not tail:
            return self.respond(200,(path/"manifest.json").read_bytes(),version=version)
        if len(tail)==2 and tail[0]=="downloads" and tail[1] in FILES:
            mime="text/csv" if tail[1].endswith(".csv") else "application/json"
            return self.respond(200,(path/tail[1]).read_bytes(),mime,version)
        detail=len(tail)==3 and tail[0]=="records" and tail[2]=="provenance"
        if tail!=["records"] and not detail:
            raise Problem(404,"not_found","Unknown snapshot operation")
        try:
            limit=int(q.get("limit",50))
            offset=int(q.get("offset",0))
            if not 1<=limit<=200 or offset<0:
                raise ValueError
        except ValueError:
            raise Problem(400,"invalid_page","Expected limit 1..200 and nonnegative offset")
        rows=[]
        for r in suite.read(path/"feed.json"):
            rid=hashlib.sha256((r["type"]+"\0"+r["value"]).encode()).hexdigest()
            if detail:
                if rid==tail[1]:
                    return self.respond(200,dict(mode=mode,feed=feed,version=version,id=rid,**r),version=version)
                continue
            if q.get("type",r["type"])!=r["type"] or q.get("status",r["status"])!=r["status"]:
                continue
            if q.get("q","").casefold() not in r["value"].casefold():
                continue
            sources=sorted({o["source"] for o in r["observations"]})
            if "source" in q and q["source"] not in sources:
                continue
            rows.append(dict(id=rid,type=r["type"],value=r["value"],expires=r["expires"],status=r["status"],sources=sources))
        if detail:
            raise Problem(404,"unknown_record","Record not found in snapshot")
        return self.respond(200,dict(mode=mode,feed=feed,version=version,offset=offset,limit=limit,total=len(rows),items=rows[offset:offset+limit]),version=version)

