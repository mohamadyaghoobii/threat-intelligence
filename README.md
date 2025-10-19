Enterprise Threat Intelligence Platform
A comprehensive automated system for collecting, enriching, and distributing threat intelligence data across enterprise environments.

Overview
This platform provides a complete threat intelligence solution that automates the entire lifecycle from data collection to real-time monitoring:

Threat Collection - Aggregates malicious file hashes from multiple trusted intelligence feeds
VirusTotal Enrichment - Enhances hashes with detailed malware analysis and threat intelligence
GitHub Distribution - Centralizes data distribution through automated repository synchronization
Splunk Integration - Enables real-time threat detection and monitoring through custom dashboards
Technical Architecture
Data Processing Pipeline
Threat Intelligence Feeds → Hash Collection → Raw Data Processing → VirusTotal Enrichment → GitHub Distribution → Splunk Monitoring

Core Components
Collection Engine (update_ti.py)
Sources data from MalwareBazaar, ThreatFox, and ThreatView feeds
Processes and validates SHA256 and MD5 hash formats
Implements deduplication across multiple sources
Generates standardized CSV output with timestamp tracking
Maintains historical data backups for audit purposes
Enrichment Processor (smart_enricher.py)
Configured via local/vt_keys.conf with multiple API keys
Processes batches of 30 hashes per cycle with intelligent throttling
Extracts comprehensive metadata from VirusTotal:
Malicious, suspicious, and undetected detection counts
File type classification and size information
Threat classification labels and tags
Submission history and analysis timestamps
Associated file names and identifiers
Implements automatic API key rotation for optimal rate limiting
Maintains enrichment state to avoid redundant processing
Distribution System (github_ti_sync.sh)
Automated Git operations with secure token authentication
Commits enriched data with descriptive timestamps
Maintains complete version history of threat intelligence
Provides direct CSV access via GitHub raw URLs
Ensures 24/7 availability of current threat data
Splunk Integration
Real-time hash matching against endpoint file activity
Customizable dashboards for threat visualization
Configurable alerting based on threat severity scores
Historical trend analysis and reporting capabilities
Quick Deployment
For Security Teams (30-second setup)
# Download the latest threat intelligence data
wget -O threat_intel_enriched.csv \
  https://raw.githubusercontent.com/mohamadyaghoobii/threat-intelligence-repo/master/threat_intel_latest.csv

# Deploy to Splunk environment
cp threat_intel_enriched.csv /opt/splunk/etc/apps/hash-threat-intelligent/lookups/

# Apply changes
/opt/splunk/bin/splunk restart

# Full enterprise deployment package
tar -xzf enterprise-threat-intelligence-latest.tar.gz
cd enterprise-ti-package
./deploy_enterprise.sh

Configuration
VirusTotal API Setup
Create local/vt_keys.conf with your API credentials:


VIRUSTOTAL_API_KEYS=your_key_1,your_key_2,your_key_3


Threat Feed Configuration
Configure local/ti_sources.conf for custom sources:

MALWAREBAZAAR_TXT=https://bazaar.abuse.ch/export/txt/sha256/recent/
THREATFOX_SHA256_URL=https://threatfox.abuse.ch/export/csv/sha256/recent/
THREATVIEW_SHA_URL=https://threatview.io/Downloads/SHA-HASH-FEED.txt
THREATVIEW_MD5_URL=https://threatview.io/Downloads/MD5-HASH-ALL.txt
MAX_DOCS=5000


Key Features
Enterprise Readiness
Production-grade deployment capabilities

Scalable architecture supporting multiple organizations

Comprehensive error handling and logging

Automated health monitoring and reporting

Operational Efficiency
Zero-maintenance daily operations

Smart API utilization with multiple key rotation

Automated backup and recovery procedures

Detailed audit trails for compliance

Threat Intelligence Coverage
Multiple trusted threat intelligence sources

Comprehensive VirusTotal malware analysis

Real-time detection and alerting capabilities

Historical trend analysis and reporting

File Structure
hash-threat-intelligent/
├── bin/
│   ├── update_ti.py              # Primary collection script
│   ├── smart_enricher.py         # VirusTotal enrichment engine
│   ├── github_ti_sync.sh         # Distribution synchronization
│   └── check_ti_health.py        # System monitoring
├── lookups/
│   ├── threat_intel_enriched.csv # Enriched threat database
│   └── intel_bad_hashes.csv      # Raw hash collection
├── local/
│   ├── vt_keys.conf              # API key configuration
│   └── ti_sources.conf           # Threat feed settings
├── default/
│   ├── transforms.conf           # Splunk lookup definitions
│   └── app.conf                  # Application configuration
└── var/logs/
    ├── ti_collection.log         # Collection process logs
    └── smart_enrichment.log      # Enrichment process logs


Health Monitoring

# Comprehensive system health check
python3 bin/check_ti_health.py

# Verify data integrity and processing status
python3 bin/update_ti.py --validate


Manual Operations

# Execute complete threat intelligence cycle
python3 bin/update_ti.py
python3 bin/smart_enricher.py
./bin/github_ti_sync.sh


Log Analysis

# Monitor collection process
tail -f var/logs/ti_collection.log

# Review enrichment operations
tail -f var/logs/smart_enrichment.log

# Check synchronization status
tail -f var/logs/github_sync.log



Troubleshooting
Verify API key validity and rate limits

Check network connectivity to threat feeds

Validate GitHub repository access permissions

Review disk space and file permissions

Monitor Splunk lookup configuration

Security Considerations
API keys stored in app-local configuration files

No sensitive data transmitted or stored

Secure token-based GitHub authentication

Regular security updates and monitoring

Comprehensive access logging and audit trails

Support and Maintenance
The platform requires minimal ongoing maintenance due to its fully automated design. Regular health checks and log reviews are recommended to ensure optimal performance.

For enterprise deployments, consider implementing:

Regular API key rotation

Threat feed source evaluation

Performance monitoring and optimization

Backup and disaster recovery procedures
