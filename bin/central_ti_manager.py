#!/usr/bin/env python3
"""
Central TI Manager - Simple File Based
"""
import os, csv, shutil
from datetime import datetime
from pathlib import Path

# Paths
SPLUNK_HOME = "/opt/splunk"
APP_DIR = Path(SPLUNK_HOME) / "etc/apps/hash-threat-intelligent"
CENTRAL_REPO = Path("/opt/central-ti-repository")
LOOKUPS = APP_DIR / "lookups"

def export_to_central():
    """Export current TI data to central repository"""
    source_file = LOOKUPS / "threat_intel_enriched.csv"
    
    if not source_file.exists():
        print("❌ No enriched data found")
        return False
    
    # Ensure central directory exists
    CENTRAL_REPO.mkdir(exist_ok=True)
    
    # Create timestamped copy
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamped_file = CENTRAL_REPO / f"threat_intel_{timestamp}.csv"
    latest_file = CENTRAL_REPO / "threat_intel_latest.csv"
    
    try:
        # Copy to central with timestamp
        shutil.copy2(source_file, timestamped_file)
        shutil.copy2(source_file, latest_file)
        
        # Count records
        with source_file.open('r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            record_count = sum(1 for _ in reader)
        
        print(f"✅ Exported {record_count} records to central repository")
        print(f"📁 Files: {timestamped_file}")
        print(f"📁 Latest: {latest_file}")
        return True
        
    except Exception as e:
        print(f"❌ Export failed: {str(e)}")
        return False

def import_from_central():
    """Import TI data from central repository"""
    latest_file = CENTRAL_REPO / "threat_intel_latest.csv"
    target_file = LOOKUPS / "threat_intel_enriched.csv"
    
    if not latest_file.exists():
        print("❌ No central TI data found")
        return False
    
    try:
        # Backup current file
        if target_file.exists():
            backup_file = LOOKUPS / f"threat_intel_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            shutil.copy2(target_file, backup_file)
            print(f"📦 Backup created: {backup_file}")
        
        # Import from central
        shutil.copy2(latest_file, target_file)
        
        # Count records
        with target_file.open('r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            record_count = sum(1 for _ in reader)
        
        print(f"✅ Imported {record_count} records from central repository")
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {str(e)}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "export":
        export_to_central()
    elif len(sys.argv) > 1 and sys.argv[1] == "import":
        import_from_central()
    else:
        print("Usage: central_ti_manager.py [export|import]")
        print("Export: Copy current TI data to central repository")
        print("Import: Copy from central repository to current app")
