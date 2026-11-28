"""Use temporary publication storage and a real loopback HTTP listener."""
import json
import os
import uuid
from pathlib import Path
from threading import Thread
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from http.server import ThreadingHTTPServer

import suite
from api_v1 import Machine

isolated=suite.ROOT/"data"/("qa-"+uuid.uuid4().hex)
with patch.object(suite,"DATA",isolated), patch.dict(suite.CONFIG,fresh_hours=-1), patch.dict(os.environ,OJAN_SIEM_TOKEN="isolated-test-only"):
    suite.run("unified","demo")
    with ThreadingHTTPServer(("127.0.0.1",0),Machine) as server:
        Thread(target=server.serve_forever,daemon=True).start()
        def get(path):
            req=Request(f"http://127.0.0.1:{server.server_port}/api/v1/"+path,headers={"Authorization":"Bearer isolated-test-only"})
            try:
                response=urlopen(req,timeout=5)
            except HTTPError as exc:
                response=exc
            with response:
                return response.status,response.read()

        try:
            health=json.loads(get("feeds/unified/health?mode=demo")[1])
            assert health["stale"] and health["readable"] and not health["ready"]
            assert get("readyz?mode=demo")[0]==503
            path="feeds/unified/snapshots/latest/downloads/lookup.csv?mode=demo"
            before=get(path)
            assert before[0]==200
            with patch("sources.collect",side_effect=OSError("Upstream disconnected")):
                try:
                    suite.run("unified","demo")
                except OSError:
                    pass
            after=json.loads(get("feeds/unified/health?mode=demo")[1])
            assert after["version"]==health["version"] and after["last_attempt"]["error"]=="Upstream disconnected"
            assert before==get(path)
            print("Stale read, failed fetch and byte retention verified over HTTP")
        finally:
            server.shutdown()

