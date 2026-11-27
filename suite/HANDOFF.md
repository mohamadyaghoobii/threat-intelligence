# Ojan local handoff · 27 November 2026

Open the [operations console](http://127.0.0.1:18746/). The uploaded Windows build served both loopback listeners at handoff. The default UI shows fixtures. Unified intentionally shows a failed attempt beside its retained publication. Production was untouched.

## Operator commands

Run from this directory with Windows PowerShell and Python 3.12. On a fresh start the launcher seeds missing demo feeds. The background option leaves the terminal available. It inherits OJAN_SIEM_TOKEN or generates an ephemeral secret in the launching PowerShell environment. For a service, provision the same secret to its process and the importer. The currently running demo uses an ephemeral token from the verification shell. For a fresh operator session with your own token, stop the verified Ojan process first after confirming its identity and listener ports, then start from that session.

```powershell
.\Start-Ojan.ps1 -Background
.\Get-OjanFeed.ps1 -Feed central -Mode demo -OutFile .\central-demo.csv
python suite.py run --mode demo
python suite.py status --mode demo
$env:OJAN_PROVIDER_DIRECT = '1'
python suite.py run --mode live --feed central
python vt.py --limit 4
```

The importer reads the latest manifest, pins the version, verifies SHA-256 and replaces its destination on the same volume. Its default mode is live. Keep a separate path for fixtures. Schedule collection and enrichment off the Search Head. For production, compare manifest versions, transfer a changed verified lookup once, and distribute through the existing Splunk lookup deployment mechanism. Given lookup definition ojan_hashes over the Central lookup.csv export:

```spl
index=endpoint | lookup ojan_hashes value AS file_hash OUTPUT source AS ti_source expires AS ti_expires
| where isnotnull(ti_source)
```

## Route and consumer inventory

| Listener | GET routes | Known consumer and behavior |
|---|---|---|
| UI 18746 | /, /unified, /central, /ua, /ip (including trailing slash) | Analyst overview and four workflow pages. Query mode=demo or live. |
| UI | /app.js, /style.css | Browser application assets |
| UI | /api/state | Browser, prior local verifier. Per-feed latest attempt, successful parse and current manifest. Defaults to demo. |
| UI | /api/enrichment?value=…&mode=… | Central record detail. Independent local enrichment cache or labeled fixture evidence. |
| UI | /exports/{mode}/{feed}/{version}/{file} | Browser details, analyst downloads, prior verifier. Immutable published versions only. |
| UI | /threat_intel_latest.csv, /useragent-intel/suspicious_useragents.csv | Prior documented Central and UA consumers. Latest live compatibility CSV or HTTP 503. Actual production consumers and nginx locations require inspection. |
| SIEM 18747 | /api/v1/livez, /api/v1/openapi.json | Unauthenticated process probe and [OpenAPI contract](http://127.0.0.1:18747/api/v1/openapi.json) |
| SIEM | /api/v1/readyz, /api/v1/feeds, /api/v1/feeds/{feed}/health | Authenticated monitoring. Readiness requires all four feeds published, fresh and free of latest-attempt errors. Inspect stale and readable independently. |
| SIEM | /api/v1/feeds/{feed}/snapshots/{ref} | Manifest. Resolve latest once, then use its version for consistent reads. |
| SIEM | /api/v1/feeds/{feed}/snapshots/{ref}/records | Canonical records in publication order. Filter q (case-insensitive value substring), exact type/source/status, offset and limit (1–200). Status is as published. Use expires for current validity. |
| SIEM | /api/v1/feeds/{feed}/snapshots/{ref}/records/{id}/provenance | Canonical record, raw observations and disposition history. Get ID from records. |
| SIEM | /api/v1/feeds/{feed}/snapshots/{ref}/downloads/{file} | Versioned or latest-reference bytes with X-Publication-Version. |
| Local command | suite.py run/status, vt.py | Operator collection, inspection and enrichment. No HTTP mutation endpoint. |

Machine routes default to live. Supply mode=demo for synthetic evidence. Authenticated requests use Authorization: Bearer from OJAN_SIEM_TOKEN. The machine listener exposes no browser routes. Existing browser and legacy routes remain locally accessible on the UI listener; loopback users share that trust boundary. Do not expose the whole UI listener as a SIEM service. Known callers here are based on local code and repository evidence. See [source contracts](SOURCES.md) for the observed 13/10/5 legacy columns and uncertain IP contract.

Valid files are feed.json (all canonical records), lookup.json and lookup.csv (usable at publication), compat.csv and manifest.json. All files belong to the manifest directory. Only committed versions are routable. The SQLite transaction switches one feed at a time, after immutable files are closed. Interrupted writes can leave an unreachable directory. A subsequent run flags the abandoned attempt. Keep the filesystem and SQLite database together.

## Verification performed

- Four UI page entry points returned their HTML. All four fixture publications passed CSV identity, JSON record correspondence, row counts, version pinning and SHA-256 checks for every manifest-listed file. Active output counts were Unified 6, Central 6, UA 5 and IP 4.
- `python verify_publication.py` induced an empty collection. Unified retained e7b6fa0a3a1b4b40b7d1ffc8795a5e5c. The HTTP verifier compared every file, including manifest bytes, before and after. The attempt error appeared in /api/state.
- `python verify_api.py` passed with the server token. Checked two unauthorized cases, POST denial, liveness, readiness, missing live snapshot, invalid paging, combined filters, nonoverlapping pages, two-source provenance and latest-versus-versioned download hashes.
- `python verify_stale.py` used isolated storage and an expired freshness threshold. Readiness returned 503, the lookup returned 200, and an injected upstream disconnect preserved the version and exact bytes.
- The PowerShell importer installed and replaced the verified Central demo lookup at data/verified-central.csv for version 012486f5ab1f42e1b726b5b5743caf8a.
- Visible Edge verified Unified, live Central, UA and IP. Unified search for relay.example.test returned one match. Inspect showed Relay watch and DNS sensor observations. Its rendered degraded banner matched the zero-row error in /api/state and the retained publication ID. Live Central showed ThreatView, 4,541 records and version cdefe5fda1c9.
- Live Central publication cdefe5fda1c9456ab97633a12e434d76 passed HTTP artifact checksums, live/version/source CSV identity, and byte equality with the Central compatibility route. Unpublished UA's legacy download returned 503. A temporary authenticated v1 listener using the same database verified default live mode, explicit demo isolation, rejection of a demo version in live mode, and missing live UA.
- The Splunk staging command produced and installed a 4,541-row live sample in data/splunk. Tampered and stale packages were rejected with the installed lookup byte-identical. Explicit rollback restored exact supplied bytes at an isolated local path. See [SPLUNK.md](SPLUNK.md) for schema, commands, exact isolated-test SPL, drilldown, health panels and rollout/rollback. The adjacent reporting portal has no Splunk telemetry mapping or ES configuration. Existing Splunk panels, ingestion, event matching and search costs need approved access.

## Source diagnostics and Saturday checks

Python discovered the dead HTTP_PROXY and HTTPS_PROXY from its process environment at 127.0.0.1:10808. ALL_PROXY also pointed to loopback port 9. Python's Windows registry discovery returned no proxy and the app config had no proxy entry. Set OJAN_PROVIDER_DIRECT=1 on the collector or enrichment process to use direct connections with default TLS verification. Other processes and Windows proxy settings were untouched.

| Provider | Direct Windows result |
|---|---|
| Spamhaus DROP | HTTP success and 1,737 parsed network rows. Unified and IP publication pending. |
| ThreatView | HTTP success and 4,541 parsed hashes. Published all 4,541 through the normal live Central flow. |
| GitHub crawler-user-agents | HTTP success and 1,519 parsed UA rules. UA publication pending. |
| VirusTotal | HTTP 401 / auth on an unkeyed probe. VT_API_KEY absent. Keyed enrichment and quota validation pending. |

1. Inspect actual nginx locations, trailing slashes, redirects, auth, access logs and Splunk lookup definitions on Saturday. Confirm exact machine paths and real column order, especially Unified and IP. Compare existing consumers against SOURCES.md.
2. Verify outbound provider access and organizational quotas. Run collection off the Search Head, inspect positive parsed counts, timestamps, changes and actual expiry. Set explicit thresholds in config.json and VT account limits in the environment. Test with actual feed sizes; the local UI loads a complete snapshot and the v1 record query scans it in memory.
3. Confirm service identities, TLS, proxy ACLs, filesystem permissions, scheduler and backup/retention strategy. Collection uses OS file locking on Windows and POSIX. Production service identities and listener configuration require validation.
4. Back up nginx, current lookup bytes and the existing service configuration. Stage the new live downloads beside them, compare hashes and headers, then switch one consumer at a time. Roll back by routing consumers to their saved prior endpoint or verified immutable publication and restoring the previous lookup. Preserve the failing attempt and SQLite state for diagnosis. Production cutover and rollback have not been exercised.

