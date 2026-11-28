# Splunk ES integration handoff

The adjacent soc-reporting-portal dashboard renders reporting and system status. Its source contains no Splunk telemetry query or deployment configuration. The TI workspace documents the historical Central CSV and the v1 read-only API. The actual Splunk dashboard definition, lookup definitions, ES version, ingestion jobs and telemetry fields require deployment access. Preserve all existing panels, lookup names and consumers.

## Feed package and install

Use a separate validated exact-match lookup for the initial Central rollout. Native ES file intelligence supports hash indicators. Confirm the installed ES version, file_intel field mapping, distribution and expiry behavior before enabling a native source. Keep UA in a separate context-only view and dataset. The Central export contains hash indicators only. [Splunk supported intelligence types](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/threat-intelligence/supported-types-of-threat-intelligence-in-splunk-enterprise-security)

The tested sample is in data/splunk/cdefe5fda1c9456ab97633a12e434d76/. It holds 4,541 real ThreatView hashes and has manifest SHA-256 for the CSV of `940925fbe116afaedac042c2e7360640075a967f5ae54b4d89043fadd7028afa`.

| CSV field | Contract |
|---|---|
| indicator_type, indicator_value | md5, sha1 or sha256 and the lowercase validated hex hash. Unique exact-match key is indicator_value. |
| source | Source name. Multiple source names are delimited by a pipe. |
| provider_confidence | Optional confidence reported by a single source. Blank for missing, mixed or ambiguous confidence. Additional enrichment stays separate. |
| provider_observed_at, ingested_at | Offset timestamps for latest known observation and latest local ingestion. Unknown observations are blank. |
| expires, expires_epoch | Canonical validity end in ISO 8601 and epoch seconds. |
| publication_id, published_epoch, fresh_until_epoch, mode | Immutable Central version, publication and freshness timestamps in epoch seconds, and constant live. |

Run stage and health on the collector side. Transfer the entire versioned directory and the independent health CSV via the approved deployment channel. Verify and install in staging first. The destination below simulates the Splunk-side path. Production distribution must follow the deployment's standalone or clustered app workflow.

```powershell
$bundle = python splunk_feed.py stage data\splunk
if ($LASTEXITCODE) { throw 'Ojan staging failed' }
python splunk_feed.py verify $bundle
if ($LASTEXITCODE) { throw 'Ojan verification failed' }
python splunk_feed.py install $bundle data\splunk\ojan_live_hashes.csv
if ($LASTEXITCODE) { throw 'Ojan installation failed' }
python splunk_feed.py health data\splunk\ojan_feed_health.csv
```

The installer checks identity, hash, row schema and freshness before a same-directory atomic replacement. Failed validation preserves last-good bytes. Each lookup row carries the installed snapshot age inputs. Health CSV rows describe collector state, which can be newer than the installed version. Refresh health independently and compare the two publication IDs during rollout. Use the staged filenames in a new dashboard section. Save the existing dashboard definition, lookup ACLs and last-good package before publishing. Roll back by restoring the prior dashboard revision and installing the saved package with the same command plus `--rollback`. An expired rollback remains visibly stale and the match panel suppresses it. Verify the resulting version on every Search Head.

## Dashboard searches for staging

Use these exact searches with the stated lookup filenames in the SOC app. These searches were prepared locally. Actual Splunk execution requires the approved environment.

**Feed freshness and source health**

```spl
| inputlookup ojan_feed_health.csv
| eval age_seconds=if(isnotnull(published_epoch) AND published_epoch!="",now()-published_epoch,null())
| eval source_health=case(source_error!="","collection failed",isnull(age_seconds),"unpublished",fresh_until_epoch<=now(),"stale",true(),"current")
| eval health_age_seconds=now()-exported_epoch
| table feed publication_id source_health age_seconds health_age_seconds stage last_attempt last_successful_parse source_error
```

Show an absent health CSV as unavailable via the dashboard's search error state. Display the health age alongside feed age so an old health export is visible.

**Active Central indicators by type**

```spl
| inputlookup ojan_live_hashes.csv
| where mode="live" AND expires_epoch>now()
| stats count AS active_indicators max(published_epoch) AS published_epoch max(fresh_until_epoch) AS fresh_until_epoch BY indicator_type publication_id
| eval age_seconds=now()-published_epoch, lookup_status=if(fresh_until_epoch<=now(),"stale","current")
| table indicator_type active_indicators publication_id age_seconds lookup_status
```

**Isolated telemetry contract for rollout**

In an authorized test index, ingest a known matching `file_hash` from the validated lookup and a known nonmatch. Use timestamps inside the 15-minute window and three extracted fields `file_hash`, `event_id` (unique per test event), and Splunk's standard `host`. Use example event ID `ojan-test-match-001` and sourcetype `ojan:ti:test`. Check the imported events in Splunk before using these searches. Keep this section labelled test telemetry.

```spl
index=ojan_ti_test sourcetype="ojan:ti:test" earliest=-15m latest=now file_hash=* event_id=*
| fields _time host file_hash event_id
| eval indicator=lower(trim(file_hash))
| where match(indicator,"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
| lookup ojan_live_hashes.csv indicator_value AS indicator OUTPUT indicator_type source AS indicator_source provider_confidence publication_id expires_epoch fresh_until_epoch
| where isnotnull(publication_id) AND expires_epoch>now() AND fresh_until_epoch>now()
| fillnull value="unknown" provider_confidence
| table _time host indicator indicator_type indicator_source provider_confidence publication_id event_id
```

Drill down to the supporting event using a token set from the clicked row's event_id. Quote with the Simple XML `|s` filter and use the same panel time bounds so the row remains reproducible.

```spl
index=ojan_ti_test sourcetype="ojan:ti:test" earliest=$match_earliest$ latest=$match_latest$ event_id=$match_event_id|s$
| table _time host event_id file_hash _raw
```

Use a coverage panel with the identical bounded base search. A missing or unverified index/role, an absent lookup, or a search error must be surfaced as unavailable. Show zero matches only when lookup freshness and telemetry coverage are positive.

```spl
index=ojan_ti_test sourcetype="ojan:ti:test" earliest=-15m latest=now
| eval mapped=if(isnotnull(event_id) AND isnotnull(host) AND match(lower(trim(file_hash)),"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$"),1,0)
| stats count AS observed_events sum(mapped) AS mapped_events
| eval telemetry_status=case(observed_events=0,"no telemetry in window",coalesce(mapped_events,0)=0,"telemetry lacks required fields",true(),"mapped telemetry present")
```

## Approved rollout

1. Export the existing dashboard and confirm current ES source and lookup definitions with their owners. Verify the index, sourcetype, timestamp, host, hash format and stable drilldown ID against real recent events for each candidate source. Inspect candidate endpoint indexes only where a targeted sample shows the required fields. Replace the isolated test mapping only after those checks.
2. Install the new lookup and record its publication ID, row count and SHA-256. Prove ingestion with inputlookup and verify the test match, expected nonmatch, drilldown, and states for stale data and missing telemetry.
3. Add views to the existing dashboard after staging review. Use narrow source selectors and short time ranges. Prefer a scheduled summary if repeated dashboard dispatch is expensive. Baseline and compare scanCount, runDuration and lookup execution cost in Job Inspector, plus Search Head I/O wait over the same test period. Record these results before expanding coverage. [Splunk Job Inspector](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.2/manage-jobs/view-search-job-properties)
4. Keep the legacy lookup and panels available for rollback. Production ingestion, SPL execution, telemetry mappings, search cost, and dashboard results remain pending approved access.


## IP and CIDR lookup

Stage the IP feed independently of Central. The exporter reads a published live IP snapshot, validates its checksum and emits `ojan_live_networks.csv`. An unpublished live feed cannot use demo data as a substitute. Host IPs become /32 or /128 for matching. Port-qualified indicators are excluded to avoid turning an IP:port observation into a host-wide match. Identical host networks are deduplicated. Range rows are ordered with more specific prefixes first.

```powershell
$bundle = python splunk_feed.py stage data\splunk --feed ip
if ($LASTEXITCODE) { throw 'IP staging failed' }
python splunk_feed.py verify $bundle
if ($LASTEXITCODE) { throw 'IP verification failed' }
python splunk_feed.py install $bundle data\splunk\ojan_live_networks.csv
```

Use a lookup definition in the intended Splunk app context:

```ini
[ojan_live_networks]
filename = ojan_live_networks.csv
match_type = CIDR(network)
max_matches = 1
```

Check precedence with an overlapping network pair on the installed Splunk version. With one result, an expired more-specific match can suppress a broader current match until the next verified refresh. Validate matching and expiry with isolated events before enabling any dashboard panel. Run the lookup against a bounded search that already exposes a verified network address as `verified_ip`:

```spl
| lookup ojan_live_networks network AS verified_ip OUTPUT network AS ti_network source AS ti_source publication_id AS ti_version expires_epoch AS ti_expires fresh_until_epoch AS ti_fresh_until
| where isnotnull(ti_network) AND ti_expires>now() AND ti_fresh_until>now()
```

[Splunk lookup matching configuration](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.6/configuration-file-reference/10.6.1-configuration-file-reference/transforms.conf)

### Next Splunk IP smoke test

Tonight's Windows run parsed 1,737 Spamhaus DROP rows. Publisher time was 2026-11-26 08:56:44 UTC and validity ended 2026-11-27 10:56:44 UTC. Collection rejected the snapshot with `No currently usable lookup rows`. There is no live IP artifact to import. Run `python verify_splunk_ip.py` for an isolated export and matching model. The verifier checks duplicate host equivalence, IPv4 and IPv6 overlap precedence, excluded ranges, port-qualified observations, expiry and demo isolation. Its controlled package is temporary.

**Refresh, transfer and install.** From the branch's `suite/` directory, run the following in PowerShell on the collector. Set the optional direct switch only where required by that process's proxy environment.

```powershell
$env:OJAN_PROVIDER_DIRECT = '1'
python suite.py run --mode live --feed ip
if ($LASTEXITCODE) { throw 'Live IP publication failed; retain the installed lookup' }
$bundle = python splunk_feed.py stage data\splunk --feed ip
if ($LASTEXITCODE) { throw 'IP package staging failed' }
python splunk_feed.py verify $bundle
if ($LASTEXITCODE) { throw 'IP package validation failed' }
```

Transfer `data/splunk/<publication_id>/manifest.json` and `ojan_live_networks.csv` together. In the approved staging app's deployment workspace, run `python splunk_feed.py install <received_package_directory> <staging_app_lookup_directory>/ojan_live_networks.csv`. Deploy via the existing app distribution workflow and create the `ojan_live_networks` definition above. Record the applied version, output count and sha256 on each Search Head. If IP still lacks a fresh live publication, exercise the existing Central hash smoke test after restaging and validating fresh Central. The Windows Central preflight package lives under `data/splunk-preflight/cdefe5fda1c9456ab97633a12e434d76/` and expires at 2026-11-28 19:52:31 UTC.

**Check lookup freshness first.**

```spl
| inputlookup strict=true ojan_live_networks.csv
| stats count AS lookup_rows dc(publication_id) AS versions values(publication_id) AS publication_id max(published_epoch) AS published_epoch min(fresh_until_epoch) AS fresh_until_epoch count(eval(mode="live" AND expires_epoch>now())) AS active_rows
| eval lookup_age_seconds=now()-published_epoch
| eval state=case(lookup_rows=0 OR versions!=1,"unavailable",fresh_until_epoch<=now() OR active_rows=0,"stale",true(),"current")
```

An inputlookup error means unavailable. Proceed only when the state is current. Keep this status and mapped telemetry coverage visible alongside the match table.

**Create two isolated events.** Select a row using `| inputlookup strict=true ojan_live_networks.csv | where expires_epoch>now() AND fresh_until_epoch>now() | head 1 | table network publication_id`. Use the address portion before the slash as the match and use `192.0.2.1` as the nonmatch. Confirm the selected address currently yields a row through the CIDR definition. Via the approved test ingestion route, write two fresh events to `ojan_ti_test` with sourcetype `ojan:ti:ip:test`, host `ojan-ip-smoke`, extracted field `verified_ip` and event IDs `ojan-ip-hit-001` and `ojan-ip-miss-001`. Verify extraction with this bounded query:

```spl
index=ojan_ti_test sourcetype="ojan:ti:ip:test" host=ojan-ip-smoke earliest=-15m latest=now (event_id=ojan-ip-hit-001 OR event_id=ojan-ip-miss-001)
| eval mapped=if(isnotnull(verified_ip) AND (cidrmatch("0.0.0.0/0",verified_ip) OR cidrmatch("::/0",verified_ip)),1,0)
| stats count AS observed_events dc(event_id) AS event_ids sum(mapped) AS mapped_events
| eval coverage=if(observed_events=2 AND event_ids=2 AND mapped_events=2,"ready","missing or unmapped test telemetry")
```

**Observe the match and the negative control.** Run only with current lookup and ready coverage. The table should report one match and one nonmatch. An expired overlapping candidate is a separate outcome and may mask a broader range with `max_matches=1`. Repeat an overlap test in the installed version before rollout. Count only results explicitly classified as matches.

```spl
index=ojan_ti_test sourcetype="ojan:ti:ip:test" host=ojan-ip-smoke earliest=-15m latest=now (event_id=ojan-ip-hit-001 OR event_id=ojan-ip-miss-001)
| lookup ojan_live_networks network AS verified_ip OUTPUT network AS ti_network source AS ti_source provider_confidence AS ti_confidence publication_id AS ti_version expires_epoch AS ti_expires fresh_until_epoch AS ti_fresh_until
| eval outcome=case(isnull(ti_network),"nonmatch",ti_fresh_until<=now(),"stale lookup",ti_expires<=now(),"expired candidate",true(),"match")
| table _time host event_id verified_ip ti_network ti_source ti_confidence ti_version outcome
```

Use the selected row's event ID and the panel's fixed dispatch bounds for drilldown. With Simple XML token quoting, the detail search is:

```spl
index=ojan_ti_test sourcetype="ojan:ti:ip:test" host=ojan-ip-smoke earliest=$match_earliest$ latest=$match_latest$ event_id=$match_event_id|s$
| table _time host event_id verified_ip _raw
```

Keep the previous verified package, lookup definition, ACLs and dashboard revision. Roll back using the previous package with `install ... --rollback` and redistribute through the same app workflow. Compare equivalent bounded searches in Job Inspector using scanCount, runDuration and lookup phase costs. Compare Search Head I/O wait against the same workload and time window. The production index, sourcetype, IP field, event ID, installed overlap behavior and SOC dashboard integration require server verification.
