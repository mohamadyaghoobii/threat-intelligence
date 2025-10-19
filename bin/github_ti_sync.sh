#!/bin/bash
# GitHub Threat Intelligence Sync

echo "🔄 Syncing Threat Intelligence to GitHub..."

cd /opt/central-ti-repository

# Copy latest enriched data
cp /opt/splunk/etc/apps/hash-threat-intelligent/lookups/threat_intel_enriched.csv threat_intel_latest.csv

# Git operations
git add threat_intel_latest.csv
git commit -m "TI Update $(date +%Y%m%d_%H%M%S)" > /dev/null 2>&1

# Push to GitHub (using master branch)
git push origin master

if [ $? -eq 0 ]; then
    RECORD_COUNT=$(wc -l < threat_intel_latest.csv)
    echo "✅ Successfully pushed to GitHub"
    echo "📊 Records: $((RECORD_COUNT - 1))"
    echo "🌐 URL: https://github.com/mohamadyaghoobii/threat-intelligence-repo"
else
    echo "❌ Push failed."
    echo "💡 Run manually: cd /opt/central-ti-repository && git push origin master"
fi
