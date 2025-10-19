#!/bin/bash
echo "🛡️ HASH THREAT INTELLIGENCE - PRODUCTION MANAGER"
echo "================================================"

echo "📥 Step 1: Collecting threat intelligence..."
sudo -u splunk python3 /opt/splunk/etc/apps/hash-threat-intelligent/bin/update_ti.py

echo ""
echo "🔍 Step 2: Enriching with VirusTotal..."
sudo -u splunk python3 /opt/splunk/etc/apps/hash-threat-intelligent/bin/smart_enricher.py

echo ""
echo "✅ Step 3: Verification..."
/opt/splunk/bin/splunk search "| inputlookup final_threat_intel_enriched | stats count by vt_enrichment_status"   2>/dev/null

echo ""
echo "🎯 PRODUCTION READY!"
echo "💡 Run this daily for updated threat intelligence"
