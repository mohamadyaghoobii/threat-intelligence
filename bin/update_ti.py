#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final Optimized TI Collector - Only hash-based sources
"""
import os, sys, csv, subprocess, json, time
from datetime import datetime
from pathlib import Path

TIMEOUT = 45
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
APP = "hash-threat-intelligent"
APP_DIR = Path(SPLUNK_HOME) / "etc/apps" / APP
LOOKUPS = APP_DIR / "lookups"
CSV_OUT = str(LOOKUPS / "intel_bad_hashes.csv")
LOG_FILE = APP_DIR / "var" / "logs" / "ti_collection.log"

HEX = set("0123456789abcdef")

# Ensure log directory exists
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def structured_log(message, level="INFO", **extra):
    """Enhanced structured logging"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "module": "ti_collector",
        "message": message,
        **extra
    }

    try:
        with LOG_FILE.open('a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except:
        pass

    print(json.dumps(log_entry), flush=True)

def http_get(url: str) -> str:
    """Enhanced HTTP client with metrics"""
    start_time = time.time()
    ca = "/etc/ssl/certs/ca-certificates.crt"
    env = dict(os.environ)
    env.setdefault("SSL_CERT_FILE", ca)
    env.setdefault("CURL_CA_BUNDLE", ca)

    try:
        out = subprocess.check_output(
            ["curl", "-fsSL", "-A", "SplunkTI-Final", "--max-time", str(TIMEOUT),
             "--retry", "2", "--location", "--cacert", ca, url],
            text=True, env=env
        )
        duration = time.time() - start_time
        structured_log("HTTP request successful", url=url, duration_seconds=round(duration, 2))
        return out.replace("\r", "")
    except subprocess.CalledProcessError as e:
        structured_log("HTTP request failed", url=url, error=str(e), level="ERROR")
        raise

def hash_type(h: str):
    """Determine hash type with validation"""
    l = len(h)
    if l == 64 and all(c in HEX for c in h):
        return "sha256"
    elif l == 40 and all(c in HEX for c in h):
        return "sha1"
    elif l == 32 and all(c in HEX for c in h):
        return "md5"
    return ""

def is_hex(h: str):
    """Check if string is hexadecimal"""
    return all(c in HEX for c in h.lower())

def parse_threatfox_csv(text: str):
    """ThreatFox CSV parser"""
    start_time = time.time()
    raw = text.splitlines()
    header_line = None
    data_lines = []

    for ln in raw:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            sl = s.lstrip("#").strip()
            if 'ioc_value' in sl.lower() and 'ioc_type' in sl.lower():
                header_line = sl
            continue
        data_lines.append(s)

    lines = []
    if header_line:
        lines = [header_line] + data_lines
    else:
        synth_header = '"first_seen_utc","ioc_id","ioc_value","ioc_type"'
        lines = [synth_header] + data_lines

    reader = csv.reader(lines, skipinitialspace=True)
    header = next(reader, []) or []
    header = [h.strip().strip('"').lower() for h in header]
    idx = {h: i for i, h in enumerate(header)}

    def col(name, row, default=""):
        i = idx.get(name)
        return (row[i].strip().strip('"') if i is not None and i < len(row) else default)

    out = []
    valid_hashes = 0

    for row in reader:
        val = (col("ioc_value", row) or "").lower().strip()
        if not val:
            continue

        t = hash_type(val) if is_hex(val) else ""
        if t:
            fs = col("first_seen_utc", row) or col("first_seen", row) or ""
            out.append({
                "hash": val,
                "hash_type": t,
                "source": "threatfox",
                "first_seen": fs,
                "last_seen": ""
            })
            valid_hashes += 1

    duration = time.time() - start_time
    structured_log("Parsed ThreatFox CSV",
                  valid_hashes=valid_hashes,
                  duration_seconds=round(duration, 2))

    return out

def parse_plain_hashes(text: str, source_name: str):
    """Plain hash parser (accepts one token per line or first CSV token)"""
    out = []
    valid_hashes = 0

    for raw in text.splitlines():
        s = raw.strip().strip('"').lower()
        if not s or s.startswith("#"):
            continue

        token = s.split(",")[0].strip()
        t = hash_type(token)
        if t and is_hex(token):
            out.append({
                "hash": token,
                "hash_type": t,
                "source": source_name,
                "first_seen": "",
                "last_seen": ""
            })
            valid_hashes += 1

    structured_log("Parsed plain hashes", source=source_name, valid_hashes=valid_hashes)
    return out

def write_csv(path: str, rows):
    """CSV writer with backup"""
    path_str = str(path)

    # Create backup
    if os.path.exists(path_str):
        backup_path = path_str + ".bak"
        try:
            subprocess.run(["cp", path_str, backup_path], check=True)
            structured_log("Created backup", backup_path=backup_path)
        except Exception as e:
            structured_log("Backup failed", error=str(e), level="WARN")

    # Write new file
    os.makedirs(os.path.dirname(path_str), exist_ok=True)
    start_time = time.time()

    try:
        with open(path_str, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["hash", "hash_type", "source", "first_seen", "last_seen"])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)

        duration = time.time() - start_time
        structured_log("CSV write completed",
                      output_path=path_str,
                      row_count=len(rows),
                      duration_seconds=round(duration, 2))

    except Exception as e:
        structured_log("CSV write failed", error=str(e), level="ERROR")
        raise

def read_conf():
    """Configuration reader"""
    conf = {}
    conf_path = APP_DIR / "local" / "ti_sources.conf"

    if conf_path.exists():
        try:
            with conf_path.open("r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#") or "=" not in ln:
                        continue
                    k, v = ln.split("=", 1)
                    conf[k.strip()] = v.strip()

            structured_log("Configuration loaded", source_count=len(conf))
        except Exception as e:
            structured_log("Config read failed", error=str(e), level="ERROR")

    return conf

def read_file(path: str) -> str:
    """File reader"""
    path_str = str(path)
    try:
        with open(path_str, "r", encoding="utf-8") as f:
            content = f.read()
        structured_log("File read successful", path=path_str, size_bytes=len(content))
        return content
    except FileNotFoundError:
        structured_log("File not found", path=path_str, level="WARN")
        return ""
    except Exception as e:
        structured_log("File read failed", path=path_str, error=str(e), level="ERROR")
        return ""

def collect_ti_data(conf):
    """Main TI data collection"""
    all_rows = []
    collection_stats = {}

    # ThreatFox collection (hash-only)
    tf_sha = conf.get("THREATFOX_SHA256_URL", "https://threatfox.abuse.ch/export/csv/sha256/recent/")
    tf_all = conf.get("THREATFOX_URL", "https://threatfox.abuse.ch/export/csv/recent/")

    tf_rows = []
    try:
        txt = http_get(tf_sha)
        tf_rows = parse_threatfox_csv(txt)
        collection_stats["threatfox_sha256"] = len(tf_rows)

        if len(tf_rows) == 0:
            structured_log("ThreatFox SHA256 empty, trying fallback")
            txt = http_get(tf_all)
            tf_rows = parse_threatfox_csv(txt)
            collection_stats["threatfox_fallback"] = len(tf_rows)

    except Exception as e:
        structured_log("ThreatFox collection failed", error=str(e), level="ERROR")

    all_rows.extend(tf_rows)

    # MalwareBazaar - hash source
    mb_url = conf.get("MALWAREBAZAAR_TXT")
    if mb_url:
        try:
            structured_log("Collecting from MalwareBazaar", url=mb_url)
            text = http_get(mb_url)
            rows = parse_plain_hashes(text, "malwarebazaar")
            all_rows.extend(rows)
            collection_stats["malwarebazaar"] = len(rows)
        except Exception as e:
            structured_log("MalwareBazaar collection failed", error=str(e), level="WARN")
            collection_stats["malwarebazaar"] = 0

    # ThreatView (SHA + MD5) - hash-only feeds
    tv_sha = conf.get("THREATVIEW_SHA_URL")
    if tv_sha:
        try:
            structured_log("Collecting from ThreatView (SHA feed)", url=tv_sha)
            text = http_get(tv_sha)
            rows = parse_plain_hashes(text, "threatview")
            all_rows.extend(rows)
            collection_stats["threatview_sha"] = len(rows)
        except Exception as e:
            structured_log("ThreatView SHA collection failed", error=str(e), level="WARN")
            collection_stats["threatview_sha"] = 0

    tv_md5 = conf.get("THREATVIEW_MD5_URL")
    if tv_md5:
        try:
            structured_log("Collecting from ThreatView (MD5 feed)", url=tv_md5)
            text = http_get(tv_md5)
            rows = parse_plain_hashes(text, "threatview")
            all_rows.extend(rows)
            collection_stats["threatview_md5"] = len(rows)
        except Exception as e:
            structured_log("ThreatView MD5 collection failed", error=str(e), level="WARN")
            collection_stats["threatview_md5"] = 0

    # Manual hashes
    manual_path = conf.get("LOCAL_HASHES_FILE", str(APP_DIR / "local" / "manual_hashes.txt"))
    if os.path.exists(manual_path):
        try:
            text = read_file(manual_path)
            rows = parse_plain_hashes(text, "manual")
            all_rows.extend(rows)
            collection_stats["manual"] = len(rows)
        except Exception as e:
            structured_log("Manual hashes failed", error=str(e), level="WARN")

    return all_rows, collection_stats

def deduplicate_rows(rows):
    """Deduplication with source merging"""
    dedup = {}
    duplicate_count = 0

    for r in rows:
        h = r["hash"]
        cur = dedup.get(h)

        if not cur:
            dedup[h] = dict(r)
        else:
            s0 = set((cur.get("source") or "").split(";")) - {""}
            s1 = set((r.get("source") or "").split(";")) - {""}
            cur["source"] = ";".join(sorted(s0 | s1))
            duplicate_count += 1

    structured_log("Deduplication completed",
                  unique_hashes=len(dedup),
                  duplicates_merged=duplicate_count)

    return list(dedup.values())

def apply_max_docs_limit(rows, max_docs):
    """Apply MAX_DOCS limit"""
    if not max_docs or len(rows) <= max_docs:
        return rows

    # Prioritize rows with first_seen dates
    dated_rows = [r for r in rows if r.get("first_seen")]
    undated_rows = [r for r in rows if not r.get("first_seen")]

    dated_rows.sort(key=lambda x: x.get("first_seen", ""), reverse=True)

    final_rows = dated_rows[:max_docs]
    remaining_slots = max_docs - len(final_rows)

    if remaining_slots > 0 and undated_rows:
        final_rows.extend(undated_rows[:remaining_slots])

    structured_log("Applied MAX_DOCS limit",
                  original_count=len(rows),
                  final_count=len(final_rows),
                  max_docs=max_docs)

    return final_rows

def main():
    """Main function"""
    start_time = time.time()
    structured_log("Starting final TI collection")

    try:
        # Read configuration
        conf = read_conf()
        max_docs = int(conf.get("MAX_DOCS", "0")) or None

        # Collect data
        all_rows, collection_stats = collect_ti_data(conf)

        # Process data
        unique_rows = deduplicate_rows(all_rows)

        if max_docs:
            final_rows = apply_max_docs_limit(unique_rows, max_docs)
        else:
            final_rows = unique_rows

        # Write output
        write_csv(CSV_OUT, final_rows)

        # Calculate duration
        duration = time.time() - start_time

        # Final summary
        structured_log("TI collection completed successfully",
                      total_sources=len(collection_stats),
                      total_hashes=len(final_rows),
                      total_duration=round(duration, 2),
                      **collection_stats)

        return 0

    except Exception as e:
        duration = time.time() - start_time
        structured_log("TI collection failed",
                      error=str(e),
                      total_duration=round(duration, 2),
                      level="ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())
