# Advanced Threat Intelligence Platform (TIP) & Dynamic Policy Enforcer

## Executive Summary

This repository implements an enterprise-grade Financial Services Threat Intelligence Platform with a SOC-oriented automation architecture. The platform ingests free OSINT feeds, normalizes and deduplicates IOCs, applies dynamic risk scoring, stores enriched intelligence in MongoDB, exports SIEM-compatible logs, and enforces high-risk network protection using Linux iptables.

The design supports Banking & Financial cybersecurity by focusing on high-fidelity detection, audit-ready logging, automated controls, operational validation, and analyst-ready dashboards.

---

## Enterprise Architecture Overview

The platform is a modular security automation engine with these responsibilities:

- `data_ingestion/` — feed connectors and API orchestrators
- `core/` — normalization, deduplication, scoring, storage, logging
- `feeds/` — OSINT threat feed integrations
- `policy_enforcer/` — firewall enforcement and rollback
- `logs/` — audit trails and SIEM export files
- `docs/` — architecture, roadmap, SOC workflows

### High-level Flow

1. `main.py` starts the platform in `demo` or `live` mode.
2. Feed collectors query OSINT APIs or generate demo indicators.
3. `core.normalizer` standardizes each IOC and maps it to a schema.
4. `core.deduplicator` checks MongoDB for existing entries.
5. `core.risk_scoring` assigns a normalized 0–100 threat score.
6. Documents are persisted in MongoDB.
7. `core.security_logger` writes SIEM-ready security events.
8. `policy_enforcer.firewall_manager` blocks IPs via `iptables` for risk >= 80.
9. Log shippers move events into Elasticsearch.
10. Kibana dashboards visualize SOC metrics.

### Deployment Pattern

The architecture supports Linux hosts and containerized SIEM labs:

- Python service can run as systemd or a cron-driven task
- MongoDB stores normalized IOC data
- Elasticsearch ingests security event logs
- Kibana visualizes SOC metrics
- iptables enforces host-level blocks

This design fits banking SOC requirements for automated detection and policy enforcement.

---

## Folder Structure and Purpose

```
Advanced-Threat-Intelligence-Platform-Dynamic-Policy-Enforcer/
├── core/                    # Enterprise processing engine
├── feeds/                   # OSINT and reputation connectors
├── data_ingestion/          # feed orchestration and ingestion helpers
├── policy_enforcer/         # firewall automation and rollback
├── scripts/                 # CLI management and rollback utilities
├── logs/                    # runtime logs and SIEM export
├── docs/                    # architecture, plans, dashboards
├── .env.example             # secure configuration template
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
├── README.md                # project overview and quickstart
└── REVIEW.md                # candidate review guide
```

### Folder Responsibilities

- `core/`
  - `pipeline.py` orchestrates ingest → normalize → score → store → enforce.
  - `normalizer.py` defines enterprise IOC schema normalization.
  - `cleaner.py` validates and infers IOC types.
  - `deduplicator.py` prevents duplicate ingestion.
  - `risk_scoring.py` defines weighted scoring logic.
  - `database.py` manages MongoDB persistence and migration.
  - `logger.py` provides application logging.
  - `security_logger.py` writes SIEM-ready audit events.

- `feeds/`
  - `alienvault.py`, `abuseipdb.py`, `virustotal.py` implement free feed connectors.
  - Additional feeds will be added for URLhaus, ThreatFox, Feodo Tracker, CIRCL.

- `data_ingestion/`
  - Contains specialized ingestion scripts and optional helpers for feed orchestration.

- `policy_enforcer/`
  - `firewall_manager.py` implements kernel-level iptables blocking and rollback.
  - `enforcer_daemon.py` monitors MongoDB for high-risk IOCs and enforces policies.

- `scripts/`
  - `policy_cli.py` provides CLI commands for daemon startup and rollback actions.

- `logs/`
  - `ingestion.log` for pipeline audit and error tracking.
  - `security_events.log` for SIEM ingestion.

- `docs/`
  - Architecture design
  - Week 2 and Week 3 project roadmap
  - ELK pipeline and dashboard specifications

---

## Threat Feed Selection and Banking Relevance

The platform uses only free OSINT feeds and open-source tools.

### AlienVault OTX
- Why selected: free community pulses with structured IOC and threat categories.
- Reliability: widely used by enterprises, strong community validation.
- Value: good for early detection of botnet C2s, malware domains, and campaign indicators.
- Banking relevance: financial institutions need community-derived reputation for suspicious IPs/domains.

### AbuseIPDB
- Why selected: free IP reputation and abuse confidence scoring.
- Reliability: purpose-built for IP abuse reporting.
- Value: identifies IPs used for brute force, botnets, fraud, and C2.
- Banking relevance: IP-based attacks are critical for banking perimeter defense and fraud prevention.

### URLhaus
- Why selected: free malware URL repository with active phishing/malware URLs.
- Reliability: maintained by abuse.ch and open-source security community.
- Value: URL intelligence is essential for phishing and web-based intrusion detection.
- Banking relevance: banks must detect phishing/malware domains targeting customers.

### Feodo Tracker
- Why selected: focused free C2 feed for banking trojans.
- Reliability: curated botnet tracker for threat actors.
- Value: useful for identifying malware command-and-control infrastructure.
- Banking relevance: protects financial networks from banking trojans and fraudware.

### ThreatFox
- Why selected: free IOC repository from Abuse.ch with malware context.
- Reliability: community intelligence on malware and threat actor behavior.
- Value: supports correlation across IPs, domains, URLs, and hashes.
- Banking relevance: adds context for targeted attacks and credential theft campaigns.

### VirusTotal (Optional Free Tier)
- Why selected: multi-engine detection and reputation scoring.
- Reliability: strongest reputation feed available in the free tier.
- Value: adds detection count and malware family visibility.
- Banking relevance: helps validate critical IOCs with vendor consensus.

### CIRCL CVE Feed
- Why selected: vulnerability intelligence for exploitation tracking.
- Reliability: CVE feeds are authoritative and open.
- Value: identifies exploited CVEs and vulnerability-related risk.
- Banking relevance: supports vulnerability management and threat hunting.

---

## Week 2 Implementation: Normalization + SIEM Integration

### 1. IOC Normalization Engine

Normalization is essential for SOC operations.

Why normalization matters:
- Feeds use different field names, formats, and metadata.
- Normalized IOCs can be compared, searched, and correlated.
- SIEM systems require a predictable schema for detection and dashboards.
- Analysts depend on consistent fields for fast triage and incident response.

#### Normalized IOC Schema

```json
{
  "indicator": "185.220.101.1",
  "type": "ip",
  "source": "AlienVault OTX",
  "threat_type": "botnet",
  "risk_score": 92,
  "country": "Unknown",
  "status": "malicious",
  "first_seen": "2026-05-29T12:00:00Z",
  "last_seen": "2026-05-29T12:05:00Z",
  "ingestion_time": "2026-05-29T12:10:00Z",
  "tags": ["tor", "c2", "scanner"],
  "details": {
    "feed_id": "pulse-12345",
    "confidence": 85,
    "abuse_confidence": 92,
    "vt_detection_count": 22,
    "cve_related": ["CVE-2024-1234"]
  },
  "blocked": false
}
```

This schema enables:
- deduplication by normalized `indicator`
- IOC classification by `type`
- source attribution for scoring
- correlation by `threat_type`
- blocking decisions from `risk_score`
- dashboard support from `status` and `blocked`
- analyst notes through `tags` and `details`

### 2. Risk Scoring Engine

A weighted scoring model is the backbone of banking risk prioritization.

#### Proposed weighting model

- Feed reliability: 10–30 points
- Threat category: 0–25 points
- Malware/reputation tags: 0–20 points
- Abuse confidence: 0–15 points
- Detection count / engine consensus: 0–15 points
- IOC age / frequency: 0–10 points

Example source weights:
- VirusTotal: +30
- AlienVault OTX: +20
- ThreatFox malware: +25
- AbuseIPDB high confidence: +10
- URLHaus malicious URL: +20
- Feodo Tracker botnet: +15
- CIRCL CVE exploitation: +15

#### Risk score tiers

- 0–39: Low
- 40–69: Medium
- 70–89: High
- 90–100: Critical

#### Firewall threshold

- `>= 80` = automated block candidate

#### Why this model is important

- Reduces false positives by requiring multiple threat signals
- Prioritizes SOC analyst time on critical, highly reliable threats
- Aligns with banking risk management and incident response stages
- Provides deterministic decision support for auto-blocking

### 3. SIEM Integration

The platform must produce structured logs for ingestion by ELK.

#### Security event log schema

```
2026-05-28 20:11:11 | EVENT=IOC_DETECTED | IOC=5.5.5.5 | TYPE=ip | SOURCE=AlienVaultOTX | RISK=95 | ACTION=DETECTED
2026-05-28 20:11:15 | EVENT=FIREWALL_BLOCK | IOC=5.5.5.5 | TYPE=ip | SOURCE=AlienVaultOTX | RISK=95 | ACTION=BLOCKED
2026-05-28 20:12:00 | EVENT=ROLLBACK | IOC=5.5.5.5 | TYPE=ip | SOURCE=AlienVaultOTX | RISK=95 | ACTION=UNBLOCKED
```

This log format supports SIEM parsing, correlation rules, and compliance audits.

### 4. Elasticsearch Integration

Design Elasticsearch as the centralized analytics store.

#### Index mapping example

```json
PUT /threat_intelligence_events
{
  "mappings": {
    "properties": {
      "timestamp": {"type": "date"},
      "event": {"type": "keyword"},
      "ioc": {"type": "keyword"},
      "type": {"type": "keyword"},
      "source": {"type": "keyword"},
      "risk": {"type": "integer"},
      "action": {"type": "keyword"},
      "threat_type": {"type": "keyword"},
      "country": {"type": "keyword"},
      "tags": {"type": "keyword"},
      "details": {"type": "object", "enabled": false}
    }
  }
}
```

### 5. Kibana Dashboard Design

Kibana dashboards provide visibility into threat operations.

#### Recommended visualizations

1. **Top Malicious IPs** — bar chart count by IOC
2. **Threat Feed Sources** — pie chart by `source`
3. **High-Risk Indicators** — table sorted by `risk` descending
4. **Blocked Threat Timeline** — time series of `FIREWALL_BLOCK` events
5. **IOC Type Distribution** — donut chart by `type`
6. **Geolocation of Malicious IPs** — map visualization
7. **Threat Severity Heatmap** — risk vs source/tags matrix
8. **Firewall Enforcement Statistics** — blocked vs failed blocks
9. **Real-Time Threat Stream** — live stream of security events
10. **Top Threat Categories** — bar chart by `threat_type`

#### Why dashboards are critical

- SOC analysts need quick detection of trending threats
- Real-time visibility accelerates containment
- Banking security requires operational metrics for audit and compliance
- Dashboards enable executive reporting and incident review

### 6. Security Event Logging

Every action in the platform is logged with context.

#### Audit log examples

- `IOC_DETECTED`
- `FIREWALL_BLOCK`
- `FIREWALL_BLOCK_FAILED`
- `ROLLBACK`
- `DUPLICATE_IGNORED`
- `FEED_FAILURE`

#### Compliance value

- PCI-DSS and financial regulations require tamper-evident logs
- Audit trails prove that automated enforcement occurred and was reviewed
- Structured logs support SIEM detection rules and reporting

### 7. Threat Categorization and Correlation

The normalization engine tags each IOC with categories such as:
- `botnet`
- `ransomware`
- `phishing`
- `c2`
- `fraud`
- `credential_theft`
- `vulnerability_exploit`

This enables correlation-ready event structure for advanced detection rules.

---

## Week 3 Implementation: Dynamic Policy Enforcement

### 1. Firewall Automation Engine

A production-ready enforcement engine must:
- add DROP rules dynamically for high-risk IPs
- verify rule existence before insertion
- avoid duplicate rules
- log each enforcement action
- support whitelisting for known safe hosts
- perform safe rollback on errors

### 2. Real-Time Monitoring Daemon

Design a daemon that continuously monitors MongoDB and acts when new high-risk IOCs arrive.

#### Requirements
- poll MongoDB at regular intervals or use a change stream
- build a work queue of new/high-risk events
- enforce firewall rules in an idempotent manner
- log enforcement and alert conditions
- maintain state to avoid reprocessing

#### Event-driven architecture
- use MongoDB Change Streams or periodic polling
- process only new `risk_score >= 80` events
- update IOC documents with `blocked: true` and `block_time`
- emit `FIREWALL_BLOCK` or `BLOCK_FAILED`

### 3. Auto Blacklisting

Auto-blacklisting should be gated by policy and threshold.

- enforce only if `risk_score >= 80`
- require `blocked == false` before action
- allow whitelist bypass via `trusted_sources` and `trusted_ips`
- support manual analyst override

### 4. Rollback Mechanism

Rollback is required for banking reliability.

- `unblock_ip(ip)` removes the `iptables` DROP rule
- rollback can be triggered manually or after policy review
- store rollback metadata in MongoDB:
  - `rollback_reason`
  - `rollback_time`
  - `rolled_back_by`

### 5. Rule Validation

Before changing rules:
- validate IP format
- verify `iptables` is available
- confirm permissions for `sudo`
- check existing rules before modification

### 6. Duplicate Rule Prevention

Check `iptables -C INPUT -s <ip> -j DROP` before adding a rule.
If the rule exists, skip insertion and log the result.

### 7. Audit Logging

Log each enforcement decision with:
- timestamp
- indicator
- risk score
- action
- decision source
- operator

This supports SOC review and regulatory audits.

### 8. False Positive Handling

Banking environments cannot tolerate accidental outages.

- use a safe default `auto_block_threshold = 80`
- keep a whitelist of internal and partner IPs
- allow analysts to mark an IOC as `false_positive`
- support rollback commands and `manual_unblock` workflows

### 9. Dynamic Policy Enforcement Workflow

1. Feed ingestion builds normalized IOC documents.
2. Scoring engine assigns risk.
3. MongoDB stores IOCs.
4. Monitoring daemon scans for `risk_score >= 80` and `blocked == false`.
5. Enforcement engine adds iptables rule if safe.
6. Security logger writes event to `security_events.log`.
7. SIEM pipeline ingests the log and reflects enforcement decisions.
8. Analysts review dashboards and rollback if needed.

---

## ELK Stack Integration

### Filebeat Configuration

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /path/to/Advanced-Threat-Intelligence-Platform-Dynamic-Policy-Enforcer/logs/security_events.log
    multiline.pattern: '^\d{4}-\d{2}-\d{2}'
    multiline.negate: true
    multiline.match: after

output.logstash:
  hosts: ["localhost:5044"]
```

### Logstash Pipeline

```conf
input {
  beats {
    port => 5044
  }
}

filter {
  dissect {
    mapping => {
      "message" => "%{timestamp} | EVENT=%{event} | IOC=%{ioc} | TYPE=%{type} | SOURCE=%{source} | RISK=%{risk} | ACTION=%{action}"
    }
  }
  date {
    match => ["timestamp", "ISO8601", "yyyy-MM-dd HH:mm:ss"]
    target => "@timestamp"
  }
  mutate {
    convert => { "risk" => "integer" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "tip-security-events-%{+YYYY.MM.dd}"
    ilm_enabled => false
  }
}
```

### Elasticsearch Index Strategy

Use a time-series index pattern for daily retention and operational search:
- `tip-security-events-YYYY.MM.DD`
- `tip-normalized-iocs` for IOC documents if directly ingested

### Kibana Visualizations

Build dashboards using the index pattern `tip-security-events-*`.

- Table: `Top Malicious IPs`
- Pie: `Threat Feed Sources`
- Metric: `High-Risk Triggers`
- Lens: `Blocked Threat Timeline`
- Map: `Geolocation of Malicious IPs`

---

## MongoDB Design

### Collection: `ioc_data`

Recommended fields:

- `indicator` (keyword)
- `type` (keyword)
- `source` (keyword)
- `threat_type` (keyword)
- `risk_score` (integer)
- `status` (keyword)
- `country` (keyword)
- `first_seen` (date)
- `last_seen` (date)
- `ingestion_time` (date)
- `tags` (array)
- `details` (object)
- `blocked` (boolean)
- `block_time` (date)
- `rollback_time` (date)
- `false_positive` (boolean)
- `analysis_notes` (string)

### Index strategy

- index on `indicator`
- index on `risk_score`
- compound index on `source` + `type`
- TTL or archival pipeline for old IOC versions

### Why MongoDB

- Flexible schema supports different feed metadata
- Document model is ideal for threat intelligence enrichment
- Good fit for rapid prototyping and SOC data models
- Free/community edition is suitable for a student portfolio project

---

## Firewall Automation and Linux Security

### Why `iptables`

- Kernel-level packet filtering provides low-latency blocking
- Readily available on most Linux distros
- Suitable for enterprise perimeter enforcement in a lab environment
- Fits banking-grade requirement for host-level control

### Enforcement logic

- Use `sudo iptables -C` to verify existing rule
- Use `sudo iptables -A INPUT -s <ip> -j DROP` for blocking
- Use `sudo iptables -D INPUT -s <ip> -j DROP` for rollback
- Support `whitelist.txt` or internal trusted IP list

### Why automated defense is critical

- Reduces mean time to contain (MTTC)
- Prevents repeated access from high-risk threat actors
- Strengthens SOC automation posture for financial networks

---

## Security Logging Structure

### Example log lines

```
2026-05-28T20:11:11Z | EVENT=IOC_DETECTED | IOC=5.5.5.5 | TYPE=ip | SOURCE=AlienVaultOTX | RISK=95 | ACTION=DETECTED
2026-05-28T20:11:15Z | EVENT=FIREWALL_BLOCK | IOC=5.5.5.5 | TYPE=ip | SOURCE=AlienVaultOTX | RISK=95 | ACTION=BLOCKED
2026-05-28T20:12:00Z | EVENT=ROLLBACK | IOC=5.5.5.5 | TYPE=ip | SOURCE=AlienVaultOTX | RISK=95 | ACTION=UNBLOCKED
```

### Logging benefits

- Audit trail for compliance (PCI-DSS, ISO 27001)
- Evidence of automated enforcement and review
- Support for security incident investigations
- Enables SIEM alert correlation and analyst response

---

## SOC Operational Workflow

### Threat intelligence operations

1. Ingest free OSINT feeds continuously or on schedule.
2. Normalize indicators and store them centrally.
3. Deduplicate to avoid analyst fatigue.
4. Score and enrich IOCs with contextual details.
5. Automatically enforce critical threats in the network layer.
6. Stream logs into ELK for situational awareness.
7. Review dashboards and investigate high-risk events.
8. Apply rollback or mark false positives as needed.

### Banking alignment

- Supports defense against phishing, fraud, credential theft, botnets, and ransomware.
- Produces operational metrics for SOC reviews.
- Enables audit and compliance reporting for financial regulators.
- Demonstrates advanced automation in a real-world security engineering portfolio.

---

## Week 2 Execution Roadmap

1. Expand `feeds/` with:
   - `urlhaus.py`
   - `feodotracker.py`
   - `threatfox.py`
   - `cve_circl.py`
2. Enhance `core.normalizer` to support:
   - `url`
   - `sha256`
   - `md5`
   - `cve`
3. Build a normalization engine that:
   - auto-detects IOC type
   - maps feed fields to the normalized schema
   - preserves `details` metadata
4. Enhance `core.risk_scoring` with weighted factors:
   - feed reliability
   - abuse confidence
   - detection count
   - IOC category
   - observed frequency
5. Add SIEM-ready event export with consistent field names.
6. Create Logstash pipeline and Elasticsearch index templates.
7. Design Kibana dashboards and document them in `docs/`.

## Week 3 Execution Roadmap

1. Build a daemon service in `policy_enforcer/enforcer_daemon.py`.
2. Implement `block_ip`, `unblock_ip`, and `rule_exists` safely.
3. Add whitelist and blacklist config support.
4. Add rollback metadata to MongoDB IOC documents.
5. Add health monitoring and metrics collection.
6. Add `scripts/` for CLI rollback and enforcement audit.
7. Document manual analyst workflows and SOC triage steps.

---

## Advanced Production-grade Improvements

- IOC caching and feed deduplication across ingestion cycles
- Threat actor grouping using shared tags and TTPs
- Concurrent feed ingestion with `asyncio`
- API rate-limit handling and backoff retry
- Secure configuration with `.env` and environment variables
- API key rotation support in config management
- Docker-based deployment for isolated lab environments
- Health metrics for MongoDB, Elasticsearch, and firewall enforcement
- Scheduled ingestion via cron or systemd timers

---

## Professional Implementation Guidance

### Linux commands for setup

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mongodb iptables
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with API keys before live mode
python3 main.py --mode demo
```

### SIEM pipeline commands

```bash
sudo systemctl start elasticsearch
sudo systemctl start kibana
sudo systemctl start logstash
filebeat -e -c /etc/filebeat/filebeat.yml
```

### MongoDB query examples

```python
from pymongo import MongoClient
client = MongoClient('mongodb://localhost:27017/')
collection = client['threat_intelligence']['ioc_data']
print(collection.find_one({'indicator': '185.220.101.1'}))
```

### iptables verification

```bash
sudo iptables -C INPUT -s 185.220.101.1 -j DROP
sudo iptables -L INPUT -n
```

---

## Conclusion

This platform is built to look and behave like a real enterprise Financial Services Threat Intelligence solution. It combines Python orchestration, MongoDB persistence, Linux firewall enforcement, and ELK stack observability in a SOC-centric workflow. The architecture is modular, scalable, and ready for internship review, portfolio presentation, and practical cybersecurity demonstrations.

Use this document as the authoritative design reference while evolving the repository toward Week 2 and Week 3 production readiness.
