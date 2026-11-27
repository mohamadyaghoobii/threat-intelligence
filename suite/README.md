# Ojan Threat Intelligence Suite
The suite collects and publishes versioned threat intelligence for analyst review and Splunk. This directory can run alongside the legacy integration in the repository root.

## Local evaluation
Use Python 3.12. In PowerShell run `./Start-Ojan.ps1`. On Linux run `python3 suite.py run --mode demo`, set `OJAN_SIEM_TOKEN` in the server environment if using the authenticated API, then run `python3 suite.py serve`.
The console binds to 127.0.0.1:18746 and the SIEM API to 127.0.0.1:18747. The console defaults to demo; machine endpoints default to live.

Copy `config.example.json` to the ignored `config.json` for site-specific settings, or pass a config path in `OJAN_CONFIG`. Generated snapshots, credentials, and database files belong outside Git.

See [SPLUNK.md](SPLUNK.md) for staging, lookup validation, and isolated matching. See [HANDOFF.md](HANDOFF.md) for the API inventory and rollout checks. Establish a verified production event-field mapping before connecting the lookup to an existing dashboard.
