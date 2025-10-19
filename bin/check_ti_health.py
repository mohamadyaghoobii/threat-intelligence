#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fixed Threat Intelligence Health Monitoring
- Better error handling for network issues
- Improved timeout handling
- More resilient source checking
"""
import os, csv, json, time, socket
from pathlib import Path
from datetime import datetime, timedelta
import subprocess

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
APP = "hash-threat-intelligent"
APP_DIR = Path(SPLUNK_HOME) / "etc/apps" / APP
LOOKUPS = APP_DIR / "lookups"
HEALTH_FILE = APP_DIR / "var" / "health_status.json"

# TI Sources with fallback options
TI_SOURCES = {
    "threatfox_sha256": "https://threatfox.abuse.ch/export/csv/sha256/recent/",
    "threatfox_all": "https://threatfox.abuse.ch/export/csv/recent/", 
    "malwarebazaar": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
}

def log(message, level="INFO", **extra):
    """Structured logging"""
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "module": "ti_health",
        "message": message,
        **extra
    }
    print(json.dumps(log_data), flush=True)

def check_network_connectivity():
    """Check basic network connectivity"""
    test_hosts = [
        "threatfox.abuse.ch",
        "bazaar.abuse.ch", 
        "sslbl.abuse.ch",
        "google.com"  # Control test
    ]
    
    results = {}
    for host in test_hosts:
        try:
            socket.setdefaulttimeout(10)
            socket.gethostbyname(host)
            results[host] = {"status": "reachable", "error": ""}
        except Exception as e:
            results[host] = {"status": "unreachable", "error": str(e)}
    
    return results

def check_ti_source(source_name, url):
    """Enhanced TI source checking with better error handling"""
    try:
        # First test DNS resolution
        hostname = url.split('/')[2]
        try:
            socket.gethostbyname(hostname)
        except Exception as e:
            return {
                "status": "dns_error",
                "error": f"DNS resolution failed: {str(e)}",
                "last_checked": datetime.now().isoformat()
            }

        # Use curl with comprehensive error handling
        cmd = [
            "curl", "-fsSL", "--max-time", "45", "--retry", "1",
            "--connect-timeout", "10", "-A", "SplunkTI-HealthCheck/1.0",
            "-w", "%{http_code}", url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
        
        if result.returncode == 0:
            # Extract HTTP code from end of output
            output = result.stdout
            if len(output) > 3:
                http_code = output[-3:]
                content = output[:-3]
            else:
                http_code = "000"
                content = output
                
            if http_code.startswith("2"):
                lines = content.strip().split('\n')
                data_lines = [l for l in lines if l and not l.startswith('#') and l.strip()]
                return {
                    "status": "healthy",
                    "http_code": http_code,
                    "response_lines": len(data_lines),
                    "last_checked": datetime.now().isoformat()
                }
            else:
                return {
                    "status": "http_error",
                    "http_code": http_code,
                    "error": f"HTTP error: {http_code}",
                    "last_checked": datetime.now().isoformat()
                }
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return {
                "status": "curl_error",
                "error": f"curl failed: {error_msg}",
                "last_checked": datetime.now().isoformat()
            }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "error": "Request timed out after 45 seconds",
            "last_checked": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "last_checked": datetime.now().isoformat()
        }

def check_data_freshness():
    """Check freshness of local TI data with enhanced checks"""
    freshness_checks = {}
    
    # Check main hash lookup
    hash_file = LOOKUPS / "intel_bad_hashes.csv"
    if hash_file.exists():
        file_time = datetime.fromtimestamp(hash_file.stat().st_mtime)
        age_hours = (datetime.now() - file_time).total_seconds() / 3600
        
        # Count rows and analyze content
        try:
            with hash_file.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                row_count = len(rows)
                
                # Analyze sources
                sources = {}
                for row in rows:
                    source = row.get('source', 'unknown')
                    sources[source] = sources.get(source, 0) + 1
                    
        except Exception as e:
            row_count = 0
            sources = {}
            
        freshness_checks["intel_bad_hashes"] = {
            "file_age_hours": round(age_hours, 2),
            "row_count": row_count,
            "sources": sources,
            "status": "fresh" if age_hours < 12 else "stale"
        }
    
    # Check enriched data
    enriched_file = LOOKUPS / "intel_bad_hashes_enriched.csv"
    if enriched_file.exists():
        file_time = datetime.fromtimestamp(enriched_file.stat().st_mtime)
        age_hours = (datetime.now() - file_time).total_seconds() / 3600
        
        # Analyze VT enrichment status
        try:
            with enriched_file.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                vt_stats = {
                    "total": 0,
                    "with_malicious": 0,
                    "with_suspicious": 0,
                    "errors": 0
                }
                
                for row in reader:
                    vt_stats["total"] += 1
                    if row.get("vt_malicious") and int(row.get("vt_malicious", 0)) > 0:
                        vt_stats["with_malicious"] += 1
                    if row.get("vt_suspicious") and int(row.get("vt_suspicious", 0)) > 0:
                        vt_stats["with_suspicious"] += 1
                    if row.get("vt_error_type") and row.get("vt_error_type") not in ["", "success", "not_found"]:
                        vt_stats["errors"] += 1
                        
        except Exception as e:
            vt_stats = {"total": 0, "with_malicious": 0, "with_suspicious": 0, "errors": 0}
            
        freshness_checks["intel_bad_hashes_enriched"] = {
            "file_age_hours": round(age_hours, 2),
            "vt_stats": vt_stats,
            "status": "fresh" if age_hours < 24 else "stale"
        }
    
    return freshness_checks

def check_vt_cache_health():
    """Check VT cache health"""
    cache_dir = APP_DIR / "var" / "vt_cache"
    if not cache_dir.exists():
        return {"status": "not_configured", "cache_files": 0}
    
    cache_files = list(cache_dir.glob("*.json"))
    valid_cache = 0
    total_size = 0
    cache_ages = []
    
    for cache_file in cache_files:
        try:
            total_size += cache_file.stat().st_size
            with cache_file.open('r') as f:
                data = json.load(f)
            if data.get('cache_time'):
                cache_time = datetime.fromisoformat(data['cache_time'])
                age_hours = (datetime.now() - cache_time).total_seconds() / 3600
                cache_ages.append(age_hours)
                valid_cache += 1
        except:
            continue
    
    avg_age = sum(cache_ages) / len(cache_ages) if cache_ages else 0
    
    return {
        "status": "healthy" if len(cache_files) > 0 else "empty",
        "cache_files": len(cache_files),
        "valid_cache_files": valid_cache,
        "total_cache_size_mb": round(total_size / (1024 * 1024), 2),
        "average_age_hours": round(avg_age, 2)
    }

def check_system_resources():
    """Check system resource usage"""
    try:
        # Check disk space for Splunk directory
        result = subprocess.run([
            "df", "-h", SPLUNK_HOME
        ], capture_output=True, text=True)
        
        disk_info = {"status": "unknown"}
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 5:
                    usage_pct = int(parts[4].strip('%'))
                    disk_info = {
                        "disk_usage": parts[4],
                        "available": parts[3],
                        "used": parts[2],
                        "total": parts[1],
                        "status": "healthy" if usage_pct < 85 else "warning" if usage_pct < 95 else "critical"
                    }
        
        # Check memory usage
        mem_result = subprocess.run([
            "free", "-m"
        ], capture_output=True, text=True)
        
        mem_info = {"status": "unknown"}
        if mem_result.returncode == 0:
            lines = mem_result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 7:
                    total_mem = int(parts[1])
                    used_mem = int(parts[2])
                    mem_pct = (used_mem / total_mem) * 100
                    mem_info = {
                        "total_mb": total_mem,
                        "used_mb": used_mem,
                        "usage_percent": round(mem_pct, 1),
                        "status": "healthy" if mem_pct < 80 else "warning" if mem_pct < 90 else "critical"
                    }
        
        return {
            "disk": disk_info,
            "memory": mem_info
        }
        
    except Exception as e:
        return {"status": "check_failed", "error": str(e)}

def calculate_overall_health(network_checks, source_checks, freshness_checks, cache_health):
    """Calculate overall system health status with weighted scoring"""
    scores = {
        "network": 0.3,
        "sources": 0.3, 
        "freshness": 0.2,
        "cache": 0.1,
        "resources": 0.1
    }
    
    component_status = {}
    
    # Network health (30%)
    reachable_hosts = sum(1 for check in network_checks.values() if check["status"] == "reachable")
    network_score = reachable_hosts / len(network_checks) if network_checks else 0
    component_status["network"] = {
        "score": network_score,
        "status": "healthy" if network_score >= 0.8 else "warning" if network_score >= 0.5 else "critical"
    }
    
    # Source health (30%)
    healthy_sources = sum(1 for check in source_checks.values() if check["status"] == "healthy")
    source_score = healthy_sources / len(source_checks) if source_checks else 0
    component_status["sources"] = {
        "score": source_score, 
        "status": "healthy" if source_score >= 0.8 else "warning" if source_score >= 0.5 else "critical"
    }
    
    # Data freshness (20%)
    fresh_data = sum(1 for check in freshness_checks.values() if check["status"] == "fresh")
    freshness_score = fresh_data / len(freshness_checks) if freshness_checks else 0
    component_status["freshness"] = {
        "score": freshness_score,
        "status": "healthy" if freshness_score >= 0.8 else "warning" if freshness_score >= 0.5 else "critical"
    }
    
    # Cache health (10%)
    cache_score = 1.0 if cache_health["status"] in ["healthy", "not_configured"] else 0.5 if cache_health["status"] == "empty" else 0
    component_status["cache"] = {
        "score": cache_score,
        "status": cache_health["status"]
    }
    
    # Calculate weighted overall score
    overall_score = (
        network_score * scores["network"] +
        source_score * scores["sources"] + 
        freshness_score * scores["freshness"] +
        cache_score * scores["cache"]
    )
    
    if overall_score >= 0.8:
        overall_status = "healthy"
    elif overall_score >= 0.6:
        overall_status = "warning" 
    else:
        overall_status = "critical"
    
    return overall_status, component_status, overall_score

def main():
    """Main health check execution"""
    log("Starting enhanced Threat Intelligence health check")
    
    # Ensure directories exist
    HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    health_report = {
        "timestamp": datetime.now().isoformat(),
        "overall_status": "unknown",
        "components": {}
    }
    
    # Check network connectivity first
    log("Checking network connectivity")
    network_checks = check_network_connectivity()
    health_report["components"]["network"] = network_checks
    
    # Check TI sources
    log("Checking TI source availability")
    source_checks = {}
    for source_name, url in TI_SOURCES.items():
        log(f"Checking {source_name}", url=url)
        source_checks[source_name] = check_ti_source(source_name, url)
        time.sleep(2)  # Be nice to the TI sources
    
    health_report["components"]["ti_sources"] = source_checks
    
    # Check data freshness
    log("Checking data freshness")
    freshness_checks = check_data_freshness()
    health_report["components"]["data_freshness"] = freshness_checks
    
    # Check VT cache
    log("Checking VT cache health")
    cache_health = check_vt_cache_health()
    health_report["components"]["vt_cache"] = cache_health
    
    # Check system resources
    log("Checking system resources")
    system_health = check_system_resources()
    health_report["components"]["system_resources"] = system_health
    
    # Calculate overall health
    overall_status, component_status, overall_score = calculate_overall_health(
        network_checks, source_checks, freshness_checks, cache_health
    )
    health_report["overall_status"] = overall_status
    health_report["component_status"] = component_status
    health_report["overall_score"] = round(overall_score, 3)
    
    # Write health report
    try:
        with HEALTH_FILE.open('w') as f:
            json.dump(health_report, f, indent=2)
        log("Health report written successfully", report_path=str(HEALTH_FILE))
    except Exception as e:
        log("Failed to write health report", error=str(e), level="ERROR")
    
    # Log summary
    healthy_sources = sum(1 for s in source_checks.values() if s["status"] == "healthy")
    total_sources = len(source_checks)
    
    reachable_hosts = sum(1 for n in network_checks.values() if n["status"] == "reachable")
    total_hosts = len(network_checks)
    
    log("Health check completed", 
        overall_status=overall_status,
        overall_score=round(overall_score, 3),
        network_reachable=f"{reachable_hosts}/{total_hosts}",
        healthy_sources=f"{healthy_sources}/{total_sources}",
        ti_data_rows=freshness_checks.get("intel_bad_hashes", {}).get("row_count", 0),
        vt_enriched_rows=freshness_checks.get("intel_bad_hashes_enriched", {}).get("vt_stats", {}).get("total", 0)
    )
    
    # Provide actionable recommendations
    if overall_status == "critical":
        log("ACTION REQUIRED: System health is critical. Check network connectivity and TI source availability.", level="ERROR")
    elif overall_status == "warning":
        log("ACTION RECOMMENDED: System health needs attention. Review component status details.", level="WARNING")
    else:
        log("System health is good. No immediate action required.", level="INFO")
    
    return 0 if overall_status in ["healthy", "warning"] else 1

if __name__ == "__main__":
    exit(main())
