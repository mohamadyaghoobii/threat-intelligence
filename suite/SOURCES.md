# Source and compatibility evidence

## Legacy contracts inspected through GitHub

| Workflow | Repository evidence | Local mapping |
| --- | --- | --- |
| Unified | [Builder and CSV order](https://github.com/mohamadyaghoobii/Ioc-intel/blob/main/app/build_feeds.py) | All 13 headers in builder order. The first observation supplies the original value, the canonical value supplies normalized_ioc, and source names use semicolons. Missing scoring fields stay blank. The repository establishes the filename unified_ioc.csv. Verify its nginx URL on Saturday. |
| Central | [Published artifact](https://github.com/mohamadyaghoobii/threat-intelligence-csv/blob/f14deb4afdc1e99e198922f8b8ba86c683f6ae85/threat_intel_latest.csv), [producer](https://github.com/mohamadyaghoobii/threat-intelligence/blob/master/bin/smart_enricher.py) | Inspected blob 3f2fb2189d62406c287c2e933d1d3555757a4dc5. All ten actual headers in order. Successful enrichment maps malicious detections and the percentage of reporting engines detecting the sample to the historical malicious_score and confidence columns. Missing fields stay blank. The older README describes a different enriched CSV. Its documented filename returned 404 in the distribution repo. |
| UA | [Published CSV](https://github.com/mohamadyaghoobii/useragent-intel-feed/blob/main/public/suspicious_useragents.csv), [application](https://github.com/mohamadyaghoobii/useragent-intel/blob/main/README.md) | All five published headers in order. Unknown tools and severity stay blank. Pattern semantics and upstream relationships are available in the canonical record. Inspect nginx for the documented /useragent-intel/suspicious_useragents.csv mapping. |
| IP | No IP export contract found in supplied repository documentation | Local compatibility file carries value, type, reason, expires. Confirm actual production filename and column order. |

The [Central nginx example](https://github.com/mohamadyaghoobii/threat-intelligence/blob/master/README.md) uses /threat_intel_latest.csv. Confirm the active virtual host, auth and location prefixes before rollout. No production endpoint was contacted.

## Collectors and verification

- Unified and IP share the [Spamhaus Project DROP IPv4 dataset](https://www.spamhaus.org/drop/drop_v4.json). The adapter parses NDJSON, retains listing text and publisher metadata, and caches the download across both feeds for one hour. The publisher's example assigns a 26-hour expiry from its dataset timestamp. [DROP documentation](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/)
- Central parses one validated hexadecimal digest per non-comment line in the [ThreatView SHA feed](https://threatview.io/Downloads/SHA-HASH-FEED.txt). The feed lacks per-indicator dates.
- UA preserves each provider pattern and its complete source object from [Crawler User Agents](https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json). The list includes legitimate crawlers. A catalog addition date remains raw metadata. Demo rules exercise exact, pattern and token semantics, plus a known mirror and an independent sensor.
- The Python runtime attempted all three distinct endpoints. Outbound connections failed with WinError 10061 against the configured proxy. Web and GitHub research established formats only. There was no successful live adapter run. Fixtures are generated locally and selected explicitly by mode.
- Optional enrichment reads the latest published live Central feed. Set VT_API_KEY through the environment, then run `python vt.py --limit 4` in the repo or schedule that command outside Splunk. Repeated invocations share local quota reservations, TTL and HTTP 429 cooldown. Configure VT_RPM, VT_DAILY, VT_MONTHLY and VT_TIMEOUT for the account. Defaults are 4 per rolling minute, 500 per rolling day and 15,500 per rolling 31 days. UI detail reads the independent cache. Compatibility exports capture enrichment at publication. No keyed request was made in this workspace. [VirusTotal file-report endpoint](https://docs.virustotal.com/reference/file-info)

