#!/bin/bash

echo "🔄 Syncing Threat Intelligence to GitHub + Nginx..."

# Paths
REPO_PATH="/opt/central-ti-repository"
SPLUNK_LOOKUP="/opt/splunk/etc/apps/hash-threat-intelligent/lookups/threat_intel_enriched.csv"
NGINX_PATH="/var/www/central-ti/threat_intel_latest.csv"

cd "$REPO_PATH"

echo "📁 Copying latest TI CSV from Splunk..."
cp "$SPLUNK_LOOKUP" "$REPO_PATH/threat_intel_latest.csv"

echo "🌐 Updating Nginx web root..."
ln -sf "$REPO_PATH/threat_intel_latest.csv" "$NGINX_PATH"

# Git operations
git add threat_intel_latest.csv
git commit -m "TI Update $(date +%Y%m%d_%H%M%S)" > /dev/null 2>&1

echo "⬆️ Pushing to GitHub..."
git push origin master
PUSH_STATUS=$?

if [ $PUSH_STATUS -eq 0 ]; then
    RECORD_COUNT=$(wc -l < threat_intel_latest.csv)
    echo "✅ GitHub Push OK"
    echo "📊 Records: $((RECORD_COUNT - 1))"
    echo "🌐 GitHub URL: https://github.com/mohamadyaghoobii/threat-intelligence"
    echo "🌍 Nginx URL:   http://YOUR_SERVER_IP/threat_intel_latest.csv"
else
    echo "❌ GitHub Push FAILED"
    echo "💡 Try manually: cd /opt/central-ti-repository && git push origin master"
fi

echo "✔ Sync complete."
