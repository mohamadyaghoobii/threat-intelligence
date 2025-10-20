#!/bin/bash
echo "🔄 Syncing to repositories and remote server..."

# Load configuration
source /opt/secure/ti_sync/remote_config.conf

# 1. Update main repository
cd /opt/central-ti-repository
cp /opt/splunk/etc/apps/hash-threat-intelligent/lookups/threat_intel_enriched.csv threat_intel_latest.csv
git add threat_intel_latest.csv
git commit -m "TI data update $(date +%Y%m%d_%H%M%S)" > /dev/null 2>&1
git push origin master > /dev/null 2>&1
echo "✅ Main repo updated"

# 2. Update CSV repository
cd /opt/threat-intelligence-csv
cp /opt/central-ti-repository/threat_intel_latest.csv threat_intel_enriched.csv
git add threat_intel_enriched.csv
git commit -m "Enterprise CSV $(date +%Y%m%d_%H%M%S)" > /dev/null 2>&1
git push origin master > /dev/null 2>&1
echo "✅ CSV repo updated"

# 3. Sync to remote server
echo "🔄 Syncing to remote server $REMOTE_HOST..."

# Create remote directory
sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "mkdir -p $REMOTE_PATH && chmod 755 $REMOTE_PATH"

# Upload file with full path including filename
if sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no \
   /opt/central-ti-repository/threat_intel_latest.csv \
   $REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/threat_intel_latest.csv; then
    echo "✅ File uploaded to remote server"

    # Verify file transfer
    if sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "test -f $REMOTE_PATH/threat_intel_latest.csv && echo 'exists'"; then
        echo "✅ File verification successful - file exists on remote server"

        # Get file sizes for comparison
        LOCAL_SIZE=$(stat -c%s /opt/central-ti-repository/threat_intel_latest.csv 2>/dev/null || echo 0)
        REMOTE_SIZE=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "stat -c%s $REMOTE_PATH/threat_intel_latest.csv 2>/dev/null || echo 0")

        echo "📊 File sizes - Local: $LOCAL_SIZE bytes, Remote: $REMOTE_SIZE bytes"
        
        # Success notification
        echo "🎉 Data successfully distributed to:"
        echo "   📦 GitHub Main Repo"
        echo "   📊 GitHub CSV Repo" 
        echo "   🌐 Remote Server ($REMOTE_HOST)"
    else
        echo "❌ File verification failed"
    fi
else
    echo "❌ Failed to upload to remote server"
fi

echo "🎯 ALL TARGETS SYNCED SUCCESSFULLY!"
