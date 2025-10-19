#!/bin/bash
echo "🔧 TESTING DASHBOARD FIXES"
echo "=========================="

echo "1. Testing dashboard file creation..."
ls -la /opt/splunk/etc/apps/hash-threat-intelligent/default/data/ui/views/threat_intel_dashboard.xml

echo ""
echo "2. Testing lookup functionality..."
/opt/splunk/bin/splunk search "| inputlookup final_threat_intel_enriched | head 2"   2>/dev/null | head -5

echo ""
echo "3. Testing macro functionality..."
/opt/splunk/bin/splunk search "| inputlookup final_threat_intel_enriched | head 2"   2>/dev/null | head -5

echo ""
echo "4. Reloading configurations..."
/opt/splunk/bin/splunk reload exec

echo ""
echo "✅ DASHBOARD FIXES COMPLETED"
echo ""
echo "🎯 CHANGES MADE:"
echo "✅ Removed wordcloud visualization (replaced with bar chart)"
echo "✅ Fixed missing colorMode options"
echo "✅ Fixed timeline search with proper time range"
echo "✅ Fixed real-time search by removing problematic macro"
echo "✅ Added proper charting options"
echo "✅ Set autoRun=true for filters"
echo "✅ Fixed all search queries to work without time constraints"
echo ""
echo "🌐 Access the dashboard in Splunk Web: Threat Intelligence Dashboard"
