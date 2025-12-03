# 🚀 Enterprise Threat Intelligence Platform

A fully automated, production‑grade system for **collecting, enriching, distributing, and monitoring** threat intelligence across enterprise environments.

![Central Threat Intelligence Feed](central-ti-dashboard.png)

This screenshot shows the Splunk dashboard consuming the centralized malware hash feed.

---

## 🧠 Overview

This platform delivers a complete, automated **Threat Intelligence Lifecycle**, enabling continuous data ingestion, enrichment, synchronization, and SIEM-based detection.

```
Threat Feeds → Hash Collection → Pre‑processing → VT Enrichment
→ GitHub Sync → Nginx TI Endpoint → Splunk Dashboards & Alerts
```

---

## 🔍 Threat Collection

The collection engine aggregates IOCs from multiple high‑fidelity sources:

- MalwareBazaar  
- ThreatFox  
- ThreatView (SHA and MD5 feeds)  
- Optional manual hash injection  
- Automatic deduplication and timestamped tracking  

---

## 🧬 VirusTotal Enrichment Engine

The enrichment pipeline adds critical malware intelligence:

- Detection statistics (malicious, suspicious, undetected)  
- File type, MIME, size, structural metadata  
- Threat labels, Yara hits, family classifications  
- Sandbox submission timestamps  
- VirusTotal API key rotation and throttling  
- Local result caching for performance  

---

## 📤 GitHub Distribution Layer

A fully automated distribution system providing:

- Secure GitHub token-based authentication  
- Automated commits with timestamps  
- Version history of all intelligence  
- Public and private raw CSV endpoints  
- Guaranteed 24/7 TI availability  

---

## 📊 Splunk Integration

Designed for SOC and DFIR teams:

- Real-time matching of hashes against endpoint logs  
- Custom dashboards for malware visibility  
- Severity-driven alerting  
- Historical intelligence analytics  
- Instant deployment via `$SPLUNK_HOME/etc/apps/`  

---

## 🌐 Self‑Hosted TI Endpoint (Nginx)

In addition to GitHub raw URLs, the platform can expose the latest enriched CSV through a hardened Nginx virtual host.

### Example Nginx site configuration

Save this as `/etc/nginx/sites-available/central-ti` and enable it with a symlink in `sites-enabled`:

```nginx
server {
    listen 80;
    server_name your-ti-host;

    root /var/www/central-ti;

    location / {
        index index.html;
        auth_basic "Threat Intelligence Feed";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    location /threat_intel_latest.csv {
        auth_basic "Threat Intelligence Feed";
        auth_basic_user_file /etc/nginx/.htpasswd;
        types { text/csv csv; }
        default_type text/csv;
    }
}
```

Create the basic authentication file and user:

```bash
htpasswd -c /etc/nginx/.htpasswd ti-user
nginx -t
systemctl reload nginx
```

Place `index.html` and the `threat_intel_latest.csv` symlink in `/var/www/central-ti`. Splunk or any other consumer can now pull the feed from:

```bash
wget --user=ti-user --password='your_password' \
  http://your-ti-host/threat_intel_latest.csv \
  -O threat_intel_latest.csv
```

---

## 📦 Quick Deployment Guide

### 1) Download Latest TI Snapshot

```bash
wget -O threat_intel_enriched.csv \
  https://raw.githubusercontent.com/mohamadyaghoobii/threat-intelligence/master/threat_intel_latest.csv
```

### 2) Deploy Into Splunk

```bash
cp threat_intel_enriched.csv \
  /opt/splunk/etc/apps/hash-threat-intelligent/lookups/
```

### 3) Restart Splunk

```bash
/opt/splunk/bin/splunk restart
```

---

## ⚙️ Configuration

### `local/vt_keys.conf` — VirusTotal Keys

```ini
VIRUSTOTAL_API_KEYS=your_key_1,your_key_2,your_key_3
REQUESTS_PER_MINUTE=4
CACHE_TTL_HOURS=24
MAX_RETRIES=3
RETRY_DELAY=30
```

### `local/ti_sources.conf` — TI Feeds

```ini
MALWAREBAZAAR_TXT=https://bazaar.abuse.ch/export/txt/sha256/recent/
THREATFOX_SHA256_URL=https://threatfox.abuse.ch/export/csv/sha256/recent/
THREATVIEW_SHA_URL=https://threatview.io/Downloads/SHA-HASH-FEED.txt
THREATVIEW_MD5_URL=https://threatview.io/Downloads/MD5-HASH-ALL.txt
MAX_DOCS=5000
```

---

## 🧩 Core Components

### `update_ti.py`

Collects and processes all threat feeds.

### `smart_enricher.py`

Runs VirusTotal enrichment, caching, and key rotation.

### `web_ready_manager.sh`

Prepares the latest consolidated `threat_intel_latest.csv` for web delivery.  
This script normalizes the most recent `threat_intel_YYYYMMDD_HHMMSS.csv` snapshot and updates the `threat_intel_latest.csv` file that is consumed by both:

- GitHub raw endpoints  
- The local Nginx site at `/var/www/central-ti/threat_intel_latest.csv`  

Adjust paths inside this script if your repository or web root is different.

### `github_ti_sync.sh`

Handles GitHub synchronization of the latest CSV and metadata.

### `central_ti_manager.py`

Single entrypoint used by cron. Orchestrates the full pipeline:

1. Collection and enrichment  
2. Web-ready export for Nginx  
3. GitHub synchronization  
4. Pipeline status updates  

### `check_ti_health.py`

Validates system health, feed integrity, and recent run status.

### `test_dashboard.sh`

Helper script for testing the Splunk dashboard and lookup integration.

---

## ⏱️ Automation and Cron

Recommended cron entry to run the full pipeline every 15 minutes:

```bash
*/15 * * * * /usr/bin/python3 /opt/central-ti-repository/bin/central_ti_manager.py >> /opt/central-ti-repository/var/logs/central_ti_manager.log 2>&1
```

Key artifacts produced on each run:

- `threat_intel_YYYYMMDD_HHMMSS.csv` raw snapshots  
- `threat_intel_latest.csv` consolidated view  
- `.last_sync` and `pipeline_status.txt` with the last successful run time and state  

---

## 📁 Folder Structure

```text
threat-intelligence/
 ├── bin/
 │   ├── update_ti.py
 │   ├── smart_enricher.py
 │   ├── github_ti_sync.sh
 │   ├── web_ready_manager.sh
 │   ├── central_ti_manager.py
 │   └── check_ti_health.py
 ├── default/
 │   ├── transforms.conf
 │   └── app.conf
 ├── local/
 │   ├── vt_keys.conf
 │   └── ti_sources.conf
 ├── metadata/
 │   ├── pipeline_status.txt
 │   └── .last_sync
 ├── threat_intel_latest.csv
 └── var/logs/
     ├── ti_collection.log
     ├── smart_enrichment.log
     └── github_sync.log
```

---

## 🩺 Health Monitoring

### Complete health scan

```bash
python3 bin/check_ti_health.py
```

### Validate feed ingestion

```bash
python3 bin/update_ti.py --validate
```

Check `metadata/pipeline_status.txt` and `.last_sync` for information about the last successful run.

---

## 🛠️ Manual Execution

### Run the full pipeline end‑to‑end

```bash
python3 bin/update_ti.py
python3 bin/smart_enricher.py
./bin/web_ready_manager.sh
./bin/github_ti_sync.sh
```

### Live logs

```bash
tail -f var/logs/ti_collection.log
tail -f var/logs/smart_enrichment.log
tail -f var/logs/github_sync.log
```

---

## 🔒 Security Considerations

- API keys are stored locally on the server and never committed to Git.  
- GitHub synchronization uses secure personal access tokens.  
- Nginx endpoint is protected with HTTP basic authentication using `/etc/nginx/.htpasswd`.  
- No sensitive user data is collected or transmitted.  
- Full operational logging is available for auditing.  

---

## 🛡️ Enterprise Maintenance

Recommended operational best practices:

- Routine VirusTotal API key rotation  
- Regular feed quality assessment  
- Disk and log volume monitoring  
- Backup schedule for the repository and Splunk configs  
- Periodic verification of GitHub and Nginx synchronization  

---


## ⭐ About the Project

Developed for professional SOC teams, malware analysts, and threat intelligence engineers who need a scalable, automated, and continuously updated threat intelligence pipeline that can feed both GitHub and internal web endpoints such as Nginx.
