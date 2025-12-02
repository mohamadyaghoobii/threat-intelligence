# 🚀 Enterprise Threat Intelligence Platform

A fully automated, production‑grade system for **collecting, enriching, distributing, and monitoring** threat intelligence across enterprise environments.

---

## 🧠 Overview

This platform delivers a complete, automated **Threat Intelligence Lifecycle**, enabling continuous data ingestion, enrichment, synchronization, and SIEM-based detection.

```
Threat Feeds → Hash Collection → Pre‑processing → VT Enrichment
→ GitHub Sync → Splunk Dashboards & Alerts
```

---

## 🔍 Threat Collection

The collection engine aggregates IOCs from multiple high‑fidelity sources:

- MalwareBazaar  
- ThreatFox  
- ThreatView (SHA + MD5 feeds)  
- Optional manual hash injection  
- Automatic deduplication & timestamped tracking  

---

## 🧬 VirusTotal Enrichment Engine

The enrichment pipeline adds critical malware intelligence:

- Detection statistics (malicious, suspicious, undetected)  
- File type, MIME, size, structural metadata  
- Threat labels, Yara hits, family classifications  
- Sandbox submission timestamps  
- VT key rotation + throttling  
- Local result caching for performance  

---

## 📤 GitHub Distribution Layer

A fully automated distribution system providing:

- Secure GitHub token-based authentication  
- Automated commits with timestamps  
- Version history of all intelligence  
- Public & private raw CSV endpoints  
- Guaranteed 24/7 TI availability  

---

## 📊 Splunk Integration

Created for SOC and DFIR teams:

- Real-time matching of hashes against endpoint logs  
- Custom dashboards for malware visibility  
- Severity-driven alerting  
- Historical intelligence analytics  
- Instant deployment via `$SPLUNK_HOME/etc/apps/`  

---

## 🏗️ Architecture Diagram

![TI Architecture](https://i.imgur.com/H2U5t9L.png)

---

## 📦 Quick Deployment Guide

### 1) Download Latest TI Snapshot
```
wget -O threat_intel_enriched.csv https://raw.githubusercontent.com/mohamadyaghoobii/threat-intelligence/master/threat_intel_latest.csv
```

### 2) Deploy Into Splunk
```
cp threat_intel_enriched.csv /opt/splunk/etc/apps/hash-threat-intelligent/lookups/
```

### 3) Restart Splunk
```
/opt/splunk/bin/splunk restart
```

---

## ⚙️ Configuration

### `local/vt_keys.conf` — VirusTotal Keys
```
VIRUSTOTAL_API_KEYS=your_key_1,your_key_2,your_key_3
REQUESTS_PER_MINUTE=4
CACHE_TTL_HOURS=24
MAX_RETRIES=3
RETRY_DELAY=30
```

### `local/ti_sources.conf` — TI Feeds
```
MALWAREBAZAAR_TXT=https://bazaar.abuse.ch/export/txt/sha256/recent/
THREATFOX_SHA256_URL=https://threatfox.abuse.ch/export/csv/sha256/recent/
THREATVIEW_SHA_URL=https://threatview.io/Downloads/SHA-HASH-FEED.txt
THREATVIEW_MD5_URL=https://threatview.io/Downloads/MD5-HASH-ALL.txt
MAX_DOCS=5000
```

---

## 🧩 Core Components

### `update_ti.py`
Collects & processes all threat feeds.

### `smart_enricher.py`
Runs VirusTotal enrichment + caching + key rotation.

### `github_ti_sync.sh`
Handles GitHub synchronization.

### `check_ti_health.py`
Validates system health and feed integrity.

---

## 📁 Folder Structure
```
hash-threat-intelligent/
 ├── bin/
 │   ├── update_ti.py
 │   ├── smart_enricher.py
 │   ├── github_ti_sync.sh
 │   └── check_ti_health.py
 ├── lookups/
 │   ├── threat_intel_enriched.csv
 │   └── intel_bad_hashes.csv
 ├── local/
 │   ├── vt_keys.conf
 │   └── ti_sources.conf
 ├── default/
 │   ├── transforms.conf
 │   └── app.conf
 └── var/logs/
     ├── ti_collection.log
     └── smart_enrichment.log
```

---

## 🩺 Health Monitoring

### Complete health scan:
```
python3 bin/check_ti_health.py
```

### Validate feed ingestion:
```
python3 bin/update_ti.py --validate
```

---

## 🛠️ Manual Execution

### Run the full pipeline:
```
python3 bin/update_ti.py
python3 bin/smart_enricher.py
./bin/github_ti_sync.sh
```

### Live logs:
```
tail -f var/logs/ti_collection.log
tail -f var/logs/smart_enrichment.log
tail -f var/logs/github_sync.log
```

---

## 🔒 Security Considerations

- API keys are stored locally and never committed.  
- GitHub sync uses secure PAT authentication.  
- No sensitive user data is collected or transmitted.  
- Full operational logging for auditing.  

---

## 🛡️ Enterprise Maintenance

Recommended operational best practices:

- Routine VirusTotal API key rotation  
- Feed quality assessment  
- Disk monitoring  
- Backup schedule  
- GitHub sync validation  

---

## ⭐ About the Project

Developed for professional SOC teams, malware analysts, and threat intelligence engineers requiring scalable, automated, and continuously updated intelligence pipelines.

---

