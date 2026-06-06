# Release Notes

## Summary
This release improves threat ingestion, observability, enforcement, and security hygiene for the Advanced Threat Intelligence Platform.

## Highlights
- **Threat ingestion** from OSINT feeds including VirusTotal, AlienVault OTX, and AbuseIPDB.
- **Kibana dashboards** for threat discovery and Elasticsearch index visibility.
- **Monitoring daemon** support for periodic policy enforcement and health checks.
- **Firewall rollback** support for safe remediation of false positives.
- **Security improvements** through secure configuration guidance and placeholder-only credential handling.

## Details
- Added or clarified README sections for project overview, architecture, installation, configuration, running instructions, screenshots, and future improvements.
- Included a visual architecture diagram for the ingestion-to-enforcement flow.
- Reinforced `.env` configuration guidance to keep credentials out of source control.
- Documented security considerations to encourage secret management, least privilege, and audit logging.
