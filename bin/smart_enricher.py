#!/usr/bin/env python3
"""
Smart VT Enricher - Avoids re-enriching existing hashes, only processes new ones
"""
import os, csv, time, json, subprocess
from pathlib import Path
from datetime import datetime

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
APP_DIR = Path(SPLUNK_HOME) / "etc/apps/hash-threat-intelligent"
LOOKUPS = APP_DIR / "lookups"
OUTPUT_FILE = LOOKUPS / "threat_intel_enriched.csv"
CONF = APP_DIR / "local" / "vt_keys.conf"
LOG_FILE = APP_DIR / "var" / "logs" / "smart_enrichment.log"

def log(message, level="INFO"):
    timestamp = datetime.now().isoformat()
    log_entry = f"{timestamp} - {level} - {message}"
    print(log_entry)
    try:
        with LOG_FILE.open('a') as f:
            f.write(log_entry + '\n')
    except:
        pass

def load_keys():
    """Load VT API keys"""
    keys = []
    if CONF.exists():
        try:
            with CONF.open('r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("VIRUSTOTAL_API_KEYS="):
                        key_str = line.split('=', 1)[1]
                        keys = [k.strip() for k in key_str.split(',') if k.strip() and len(k.strip()) == 64]
                        break
        except Exception as e:
            log(f"Failed to load VT keys: {e}", "ERROR")

    return keys

def get_existing_enriched_hashes():
    """Get hashes that are already enriched to avoid duplicates"""
    existing_hashes = set()
    if OUTPUT_FILE.exists():
        try:
            with OUTPUT_FILE.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('hash') and row.get('vt_enrichment_status') == 'success':
                        existing_hashes.add(row['hash'])
            log(f"Found {len(existing_hashes)} already enriched hashes")
        except Exception as e:
            log(f"Error reading existing enriched file: {e}", "ERROR")

    return existing_hashes

def get_fresh_hashes_from_malwarebazaar():
    """Get fresh hashes from MalwareBazaar, excluding already enriched ones"""
    log("Fetching fresh hashes from MalwareBazaar")
    try:
        result = subprocess.run([
            "curl", "-fsSL", "--max-time", "30",
            "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        ], capture_output=True, text=True, timeout=35)

        all_hashes = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith("#") and len(line) == 64:
                if all(c in '0123456789abcdef' for c in line.lower()):
                    all_hashes.append(line.lower())

        log(f"Fetched {len(all_hashes)} total SHA256 hashes from MalwareBazaar")
        return all_hashes

    except Exception as e:
        log(f"Error fetching MalwareBazaar hashes: {e}", "ERROR")
        return []

def query_virustotal_smart(hash_value, api_key):
    """Smart VT query with comprehensive fields"""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    try:
        cmd = [
            "curl", "-fsSL", "--max-time", "10",
            "-H", f"X-Apikey: {api_key}",
            "-H", "User-Agent: SplunkTI-Smart/1.0",
            url
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            data = json.loads(result.stdout)
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            names = attributes.get('names', [])
            tags = attributes.get('tags', [])

            return {
                'hash': hash_value,
                'hash_type': 'sha256',
                'source': 'malwarebazaar',
                'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                # VT Analysis
                'vt_malicious': str(stats.get('malicious', 0)),
                'vt_suspicious': str(stats.get('suspicious', 0)),
                'vt_undetected': str(stats.get('undetected', 0)),
                'vt_harmless': str(stats.get('harmless', 0)),
                'vt_reputation': str(attributes.get('reputation', 0)),
                'vt_times_submitted': str(attributes.get('times_submitted', 0)),

                # Timeline
                'vt_first_submission': str(attributes.get('first_submission_date', '')),
                'vt_last_analysis': str(attributes.get('last_analysis_date', '')),

                # Threat Intelligence
                'vt_suggested_threat_label': attributes.get('popular_threat_classification', {}).get('suggested_threat_label', ''),
                'vt_tags': ';'.join(tags[:10]) if tags else '',
                'vt_names': ';'.join(names[:5]) if names else '',

                # File Info
                'vt_sha256': attributes.get('sha256', ''),
                'vt_md5': attributes.get('md5', ''),
                'vt_sha1': attributes.get('sha1', ''),
                'vt_file_size': str(attributes.get('size', '')),
                'vt_file_type': attributes.get('type_description', ''),

                'vt_enrichment_status': 'success',
                'vt_last_updated': datetime.now().isoformat()
            }
        else:
            return create_error_result(hash_value, f'http_error_{result.returncode}')

    except subprocess.TimeoutExpired:
        return create_error_result(hash_value, 'timeout')
    except Exception as e:
        return create_error_result(hash_value, f'exception_{str(e)}')

def create_error_result(hash_value, error_type):
    """Create result for failed queries"""
    return {
        'hash': hash_value,
        'hash_type': 'sha256',
        'source': 'malwarebazaar',
        'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        'vt_malicious': '', 'vt_suspicious': '', 'vt_undetected': '', 'vt_harmless': '',
        'vt_reputation': '', 'vt_times_submitted': '',
        'vt_first_submission': '', 'vt_last_analysis': '',
        'vt_suggested_threat_label': '', 'vt_tags': '', 'vt_names': '',
        'vt_sha256': '', 'vt_md5': '', 'vt_sha1': '', 'vt_file_size': '', 'vt_file_type': '',

        'vt_enrichment_status': error_type,
        'vt_last_updated': datetime.now().isoformat()
    }

def load_existing_enriched_data():
    """Load existing enriched data to append new results"""
    existing_data = []
    if OUTPUT_FILE.exists():
        try:
            with OUTPUT_FILE.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                existing_data = list(reader)
            log(f"Loaded {len(existing_data)} existing enriched records")
        except Exception as e:
            log(f"Error loading existing enriched data: {e}", "ERROR")

    return existing_data

def main():
    start_time = time.time()
    log("Starting smart VT enrichment - avoiding duplicates")

    # Load API keys
    api_keys = load_keys()
    if not api_keys:
        log("No API keys available - cannot proceed", "ERROR")
        return 1

    log(f"Loaded {len(api_keys)} API keys")

    # Get existing enriched hashes to avoid duplicates
    existing_enriched_hashes = get_existing_enriched_hashes()

    # Get fresh hashes from MalwareBazaar
    all_fresh_hashes = get_fresh_hashes_from_malwarebazaar()
    if not all_fresh_hashes:
        log("No fresh hashes available - stopping", "ERROR")
        return 1

    # Filter out already enriched hashes
    new_hashes = [h for h in all_fresh_hashes if h not in existing_enriched_hashes]

    if not new_hashes:
        log("No new hashes to enrich - all hashes already processed", "INFO")
        return 0

    # Limit to 30 new hashes per run to respect VT API limits
    hashes_to_enrich = new_hashes[:30]

    log(f"Found {len(new_hashes)} new hashes, will enrich {len(hashes_to_enrich)}")

    # Load existing data to append new results
    all_enriched_data = load_existing_enriched_data()

    # Enrich new hashes
    key_index = 0
    new_enriched_count = 0

    for i, hash_value in enumerate(hashes_to_enrich):
        api_key = api_keys[key_index]
        result = query_virustotal_smart(hash_value, api_key)

        # Add to results
        all_enriched_data.append(result)
        new_enriched_count += 1

        log(f"Enriched {i+1}/{len(hashes_to_enrich)} - {hash_value[:16]} - Malicious: {result['vt_malicious']} - Status: {result['vt_enrichment_status']}")

        # Rotate API key every 8 requests
        if (i + 1) % 8 == 0:
            key_index = (key_index + 1) % len(api_keys)
            log(f"Rotated to API key {key_index + 1}")

        # Rate limiting
        if i < len(hashes_to_enrich) - 1:
            time.sleep(8)

    # Write updated enriched CSV
    fieldnames = [
        'hash', 'hash_type', 'source', 'first_seen',
        'vt_malicious', 'vt_suspicious', 'vt_undetected', 'vt_harmless',
        'vt_reputation', 'vt_times_submitted', 'vt_first_submission', 'vt_last_analysis',
        'vt_suggested_threat_label', 'vt_tags', 'vt_names',
        'vt_sha256', 'vt_md5', 'vt_sha1', 'vt_file_size', 'vt_file_type',
        'vt_enrichment_status', 'vt_last_updated'
    ]

    try:
        with open(OUTPUT_FILE, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in all_enriched_data:
                writer.writerow(result)

        duration = time.time() - start_time
        successful_new = len([r for r in all_enriched_data[-new_enriched_count:] if r['vt_enrichment_status'] == 'success'])

        log("=== SMART ENRICHMENT COMPLETED ===")
        log(f"Output file: {OUTPUT_FILE}")
        log(f"Total records in file: {len(all_enriched_data)}")
        log(f"New hashes processed: {new_enriched_count}")
        log(f"New successful: {successful_new}")
        log(f"Success rate: {(successful_new/new_enriched_count)*100:.1f}%" if new_enriched_count > 0 else "N/A")
        log(f"Duration: {duration:.1f} seconds")

    except Exception as e:
        log(f"Failed to write output file: {e}", "ERROR")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
