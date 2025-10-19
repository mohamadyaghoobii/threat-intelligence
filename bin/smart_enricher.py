#!/usr/bin/env python3
"""
Enhanced Smart VT Enricher - Without suspicious_score
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

# Standard TI Fields - Clean without suspicious_score
STANDARD_FIELDS = [
    'hash', 
    'hash_type', 
    'source',
    'first_seen',
    'malicious_score',
    'confidence',
    'threat_type',
    'tags',
    'last_updated',
    'enrichment_status'
]

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
    """Get hashes that are already successfully enriched"""
    existing_hashes = set()
    if OUTPUT_FILE.exists():
        try:
            with OUTPUT_FILE.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('hash') and row.get('enrichment_status') == 'success':
                        existing_hashes.add(row['hash'])
            log(f"Found {len(existing_hashes)} already enriched hashes")
        except Exception as e:
            log(f"Error reading existing enriched file: {e}", "ERROR")
    return existing_hashes

def get_fresh_hashes_from_malwarebazaar():
    """Get fresh hashes from MalwareBazaar"""
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

def query_virustotal_standardized(hash_value, api_key):
    """Standardized VT query - Clean output format without suspicious_score"""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    try:
        cmd = [
            "curl", "-fsSL", "--max-time", "10",
            "-H", f"X-Apikey: {api_key}",
            "-H", "User-Agent: SplunkTI-Standard/1.0",
            url
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            data = json.loads(result.stdout)
            
            # Check if hash exists in VT
            if 'data' not in data:
                return create_standardized_result(hash_value, 'not_found')
                
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            tags = attributes.get('tags', [])
            
            malicious = stats.get('malicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)
            
            # Calculate confidence score (0-100)
            total_engines = sum(stats.values())
            confidence = int((malicious / total_engines) * 100) if total_engines > 0 else 0
            
            # Determine threat type
            threat_type = determine_threat_type(malicious, tags)

            return {
                'hash': hash_value,
                'hash_type': 'sha256',
                'source': 'malwarebazaar',
                'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'malicious_score': str(malicious),
                'confidence': str(confidence),
                'threat_type': threat_type,
                'tags': ';'.join(tags[:5]) if tags else '',
                'last_updated': datetime.now().isoformat(),
                'enrichment_status': 'success'
            }
        else:
            # Handle HTTP errors specifically
            if result.returncode == 22:  # HTTP 404 - Not Found
                return create_standardized_result(hash_value, 'not_found')
            elif result.returncode == 28:  # Timeout
                return create_standardized_result(hash_value, 'timeout')
            else:
                return create_standardized_result(hash_value, f'http_error_{result.returncode}')

    except subprocess.TimeoutExpired:
        return create_standardized_result(hash_value, 'timeout')
    except Exception as e:
        return create_standardized_result(hash_value, f'error_{str(e)}')

def determine_threat_type(malicious, tags):
    """Determine threat type based on scores and tags"""
    if malicious >= 10:
        return 'malware'
    elif malicious >= 5:
        return 'suspicious'
    elif any(tag in ['trojan', 'ransomware', 'worm'] for tag in tags):
        return 'malware'
    else:
        return 'unknown'

def create_standardized_result(hash_value, status):
    """Create clean standardized result for all cases"""
    base_result = {
        'hash': hash_value,
        'hash_type': 'sha256',
        'source': 'malwarebazaar',
        'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'malicious_score': '',
        'confidence': '',
        'threat_type': '',
        'tags': '',
        'last_updated': datetime.now().isoformat(),
        'enrichment_status': status
    }
    
    # Only include successful results in final output
    return base_result

def load_existing_successful_data():
    """Load only successful enriched data"""
    existing_data = []
    if OUTPUT_FILE.exists():
        try:
            with OUTPUT_FILE.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('enrichment_status') == 'success':
                        existing_data.append(row)
            log(f"Loaded {len(existing_data)} existing SUCCESSFUL records")
        except Exception as e:
            log(f"Error loading existing data: {e}", "ERROR")
    return existing_data

def main():
    start_time = time.time()
    log("Starting CLEAN VT enrichment - no suspicious_score")

    # Load API keys
    api_keys = load_keys()
    if not api_keys:
        log("No API keys available - cannot proceed", "ERROR")
        return 1

    log(f"Loaded {len(api_keys)} API keys")

    # Get existing successful hashes to avoid duplicates
    existing_hashes = get_existing_enriched_hashes()

    # Get fresh hashes
    all_fresh_hashes = get_fresh_hashes_from_malwarebazaar()
    if not all_fresh_hashes:
        log("No fresh hashes available - stopping", "ERROR")
        return 1

    # Filter out already enriched hashes
    new_hashes = [h for h in all_fresh_hashes if h not in existing_hashes]

    if not new_hashes:
        log("No new hashes to enrich - all hashes already processed", "INFO")
        return 0

    # Limit to 30 new hashes per run
    hashes_to_enrich = new_hashes[:30]
    log(f"Found {len(new_hashes)} new hashes, will enrich {len(hashes_to_enrich)}")

    # Load existing SUCCESSFUL data only
    all_enriched_data = load_existing_successful_data()

    # Enrich new hashes - only keep successful ones
    key_index = 0
    successful_count = 0

    for i, hash_value in enumerate(hashes_to_enrich):
        api_key = api_keys[key_index]
        result = query_virustotal_standardized(hash_value, api_key)

        # ONLY add successful results to final output
        if result['enrichment_status'] == 'success':
            all_enriched_data.append(result)
            successful_count += 1
            log(f"✅ Success {i+1}/{len(hashes_to_enrich)} - {hash_value[:16]} - Malicious: {result['malicious_score']} - Type: {result['threat_type']}")
        else:
            log(f"❌ Failed {i+1}/{len(hashes_to_enrich)} - {hash_value[:16]} - Status: {result['enrichment_status']}")

        # Rotate API key every 8 requests
        if (i + 1) % 8 == 0:
            key_index = (key_index + 1) % len(api_keys)
            log(f"🔄 Rotated to API key {key_index + 1}")

        # Rate limiting
        if i < len(hashes_to_enrich) - 1:
            time.sleep(8)

    # Write ONLY successful records to CSV
    try:
        with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=STANDARD_FIELDS)
            writer.writeheader()
            for result in all_enriched_data:
                writer.writerow(result)

        duration = time.time() - start_time

        log("=== CLEAN ENRICHMENT COMPLETED ===")
        log(f"📁 Output file: {OUTPUT_FILE}")
        log(f"📊 Total successful records: {len(all_enriched_data)}")
        log(f"🆕 New successful: {successful_count}")
        log(f"📈 Success rate: {(successful_count/len(hashes_to_enrich))*100:.1f}%")
        log(f"⏱️ Duration: {duration:.1f} seconds")

    except Exception as e:
        log(f"❌ Failed to write output file: {e}", "ERROR")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
