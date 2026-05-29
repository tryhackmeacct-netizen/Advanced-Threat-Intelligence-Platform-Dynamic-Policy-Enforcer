# Advanced Threat Intelligence Platform - Internship Review Guide

## Executive Summary
A production-ready threat intelligence automation platform that ingests malicious IOC data from OSINT feeds, normalizes and deduplicates indicators, stores them in MongoDB with risk scoring, automatically enforces firewall blocking rules via Linux iptables, and generates SIEM-ready audit logs for SOC monitoring and compliance.

## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Platform                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  OSINT Threat Feeds   →  IOC Normalization  →  Deduplication  │
│  • VirusTotal          • IP/Domain/Hash      • MongoDB Query    │
│  • AlienVault OTX      • Indicator Cleaning  • Duplicate Check  │
│  • AbuseIPDB          • Type Inference       • Risk Scoring     │
│                                                                  │
│  ↓                                                              │
│                                                                  │
│  MongoDB Storage      →  Risk Assessment    →  Firewall Policy│
│  • Malicious IOCs       • Risk Calculation    • iptables Rules │
│  • Timestamp Tracking   • 80+ threshold       • Auto-blocking  │
│  • Source Attribution   • By Feed Source      • High-Risk IPs  │
│                                                                  │
│  ↓                                                              │
│                                                                  │
│  SIEM-Ready Logging   →  SOC Monitoring     →  Compliance    │
│  • Security Events      • Audit Trail        • Timestamped    │
│  • Event Types          • Block Events       • Event Details  │
│  • Risk Scores          • Detection Events   • Source Tracking│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Day-by-Day Implementation

### Day 1: Project Initialization & Environment Setup
**Status:** ✅ Complete

What was built:
- Project folder structure created
- GitHub repository initialized
- Python virtual environment configured
- MongoDB connectivity setup
- Initial IOC database workflow
- Basic malicious IOC insertion logic

**Proof:**
```
$ python3 main.py --mode demo --indicators 203.0.113.99
✓ 203.0.113.99 (ip) - Risk: 95 - Source: DemoFeed
```

### Day 2: OSINT Threat Intelligence Ingestion
**Status:** ✅ Complete

What was built:
- OSINT threat feed ingestion pipeline
- Public threat intelligence feeds (VirusTotal, AlienVault, AbuseIPDB)
- Malicious IP extraction logic
- Automated IOC processing workflow
- Ingestion pipeline for MongoDB storage

**Feeds Integrated:**
- **VirusTotal** - Commercial threat intelligence with malware detection
- **AlienVault OTX** - Open threat exchange with pulse data
- **AbuseIPDB** - IP reputation and abuse scoring

**Proof:**
```
$ python3 main.py --mode live
2026-05-27 07:09:20,503 | INFO | tip_ingestion | Feed VirusTotal successful
2026-05-27 07:09:20,504 | INFO | tip_ingestion | Feed AlienVault successful
2026-05-27 07:09:20,505 | INFO | tip_ingestion | Feed AbuseIPDB successful
```

### Day 3: IOC Normalization & Risk Scoring
**Status:** ✅ Complete

What was built:
- IOC cleaning and normalization engine
- Deduplication logic with MongoDB queries
- Risk scoring system for malicious indicators
- Standardized IOC storage format
- Improved threat intelligence processing workflow

**Risk Scoring System:**
| Source | Risk Score |
|--------|-----------|
| DemoFeed | 95 |
| VirusTotal | 90 |
| AlienVault | 85 |
| AbuseIPDB | 80 |
| URLHaus | 88 |
| Default | 60 |

**Proof:**
```
$ python3 main.py --mode demo --indicators 203.0.113.99 198.51.100.99
✓ 203.0.113.99 (ip) - Risk: 95 - Source: DemoFeed
✓ 198.51.100.99 (ip) - Risk: 95 - Source: DemoFeed
```

### Day 4: MongoDB Threat Database Integration
**Status:** ✅ Complete

What was built:
- MongoDB database server configuration
- Python-MongoDB connection with pymongo
- IOC threat intelligence collection
- Malicious IOC insertion and retrieval
- Legacy document migration support
- Database validation

**Database Schema:**
```json
{
  "indicator": "203.0.113.99",
  "type": "ip",
  "source": "DemoFeed",
  "risk_score": 95,
  "status": "malicious",
  "timestamp": "2026-05-27T07:09:29.641000",
  "details": {}
}
```

**Proof:**
```
$ python3 -c "from pymongo import MongoClient; ...collection.count_documents({})"
Total documents: 12
```

### Day 5: Dynamic Firewall Policy Enforcer
**Status:** ✅ Complete

What was built:
- Dynamic firewall automation engine
- Linux iptables policy enforcement
- Automatic malicious IP blocking
- Risk threshold-based enforcement (≥80)
- Security logging for all firewall actions

**Firewall Rules Generated:**
```bash
sudo iptables -A INPUT -s 203.0.113.99 -j DROP
sudo iptables -A INPUT -s 198.51.100.99 -j DROP
sudo iptables -A INPUT -s 192.0.2.99 -j DROP
```

**Proof:**
```
$ sudo iptables -L INPUT -n
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
target     prot opt source        destination
DROP       all  --  203.0.113.99  0.0.0.0/0
DROP       all  --  198.51.100.99 0.0.0.0/0
DROP       all  --  192.0.2.99    0.0.0.0/0
```

### Day 6: Centralized Security Logging & SIEM Preparation
**Status:** ✅ Complete

What was built:
- Centralized security logging engine
- SIEM-ready audit logging system
- Malicious IOC detection events
- Firewall enforcement action logging
- SOC monitoring compatible log structure
- Kibana/ELK Stack integration foundation

**Security Log Format (SIEM-Compatible):**
```
2026-05-27 11:09:29 | EVENT=MALICIOUS_IP_DETECTED | IP=203.0.113.99 | SOURCE=DemoFeed | RISK=95 | ACTION=DETECTED
2026-05-27 11:09:29 | EVENT=FIREWALL_BLOCK | IP=203.0.113.99 | SOURCE=DemoFeed | RISK=95 | ACTION=BLOCKED
```

**Proof:**
```
$ tail -5 logs/security_events.log
2026-05-27 11:09:29 | EVENT=MALICIOUS_IP_DETECTED | IP=203.0.113.99 | SOURCE=DemoFeed | RISK=95 | ACTION=DETECTED
2026-05-27 11:09:29 | EVENT=FIREWALL_BLOCK | IP=203.0.113.99 | SOURCE=DemoFeed | RISK=95 | ACTION=BLOCKED
```
## Day 7: SIEM Integration & Elasticsearch Forwarding

**Status:** ✅ Complete (Architecture + Integration Layer)

### What was built:

* Elasticsearch SIEM forwarding module
* SIEM-compatible JSON event formatting
* IOC forwarding pipeline for centralized monitoring
* Elasticsearch connectivity validation
* Security event transformation engine
* Structured logging architecture for ELK Stack integration

### SIEM Workflow:

```
Threat IOC → Risk Scoring → MongoDB → Elasticsearch Forwarding → SIEM Dashboard
```

### Features Implemented:

* IOC forwarding to Elasticsearch
* JSON-based security event formatting
* Elasticsearch availability checking
* Fail-safe handling when SIEM server is offline
* Logging fallback mechanism
* Modular SIEM integration architecture

### Proof:

```bash
$ python3 main.py --mode demo --indicators 87.87.87.87

2026-05-29 20:40:31,208 | WARNING | tip_ingestion | Elasticsearch server unreachable
2026-05-29 20:40:31,259 | WARNING | tip_ingestion | Skipping SIEM forwarding
2026-05-29 20:40:31,260 | WARNING | tip_ingestion | Failed to forward IOC 87.87.87.87 to Elasticsearch SIEM
```

### Files Added:

* `core/siem_forwarder.py`
* Elasticsearch integration logic
* SIEM event formatting modules

### Security Benefit:

This module prepares the platform for enterprise SOC environments where security teams require centralized monitoring, searchable threat intelligence, and visual dashboards using ELK Stack or SIEM platforms.

---

## Day 8: Dynamic Enforcement Daemon & Rollback System

**Status:** ✅ Complete

### What was built:

* Automated enforcement daemon
* Continuous monitoring engine
* Firewall rollback mechanism
* CLI-based policy management
* Real-time IOC enforcement workflow
* Automated response architecture

### Enforcement Workflow:

```
MongoDB IOC → Risk Evaluation → Enforcement Daemon → iptables Rule Creation
```

### Features Implemented:

* Continuous monitoring of high-risk indicators
* Dynamic firewall rule creation
* Rollback support for false positives
* Automated response handling
* Policy management CLI utilities
* Modular enforcement architecture

### Files Added:

* `policy_enforcer/enforcer_daemon.py`
* `policy_enforcer/rollback.py`
* `scripts/policy_cli.py`

### Example Enforcement Rule:

```bash
sudo iptables -A INPUT -s 87.87.87.87 -j DROP
```

### Rollback Example:

```bash
sudo iptables -D INPUT -s 87.87.87.87 -j DROP
```

### Security Benefit:

The Dynamic Policy Enforcer reduces manual SOC workload by automatically translating threat intelligence into active defensive firewall policies.

---

## Day 9: Project Refactoring, Validation & Production Hardening

**Status:** ✅ Complete

### What was built:

* IOC validation engine
* Codebase refactoring
* Modular architecture improvements
* Improved error handling
* Improved logging consistency
* Duplicate IOC handling enhancements
* Production-ready project structure

### Validation Features:

* IP format validation
* IOC type detection
* Invalid indicator filtering
* Data normalization consistency
* Safer database insertion logic

### New Modules Added:

* `core/validator.py`
* Improved `core/pipeline.py`
* Enhanced `core/database.py`
* Updated `core/config.py`

### Improvements:

* Cleaner module separation
* Improved maintainability
* Better scalability for future integrations
* Enhanced exception handling
* Safer MongoDB interactions
* Better SIEM compatibility

### Proof:

```bash
$ python3 main.py --mode demo --indicators 203.0.113.10 198.51.100.20 87.87.87.87

Duplicate IOC skipped: 203.0.113.10
Duplicate IOC skipped: 198.51.100.20
Stored IOC 87.87.87.87 from DemoFeed
[SUCCESS] Processed 1 IOCs
```

### Security Benefit:

The platform now behaves more like a production-ready cybersecurity automation system with improved reliability, validation, modularity, and operational safety.


## Review Commands

### 1. Test the Complete Pipeline (Demo Mode)
```bash
cd ~/Advanced-Threat-Intelligence-Platform-Dynamic-Policy-Enforcer
source .venv/bin/activate

# Run with demo data (safe, no API keys needed)
python3 main.py --mode demo --indicators 203.0.113.99 198.51.100.99 192.0.2.99
```

**Expected Output:**
```
✓ 203.0.113.99 (ip) - Risk: 95 - Source: DemoFeed
✓ 198.51.100.99 (ip) - Risk: 95 - Source: DemoFeed
✓ 192.0.2.99 (ip) - Risk: 95 - Source: DemoFeed
[SUCCESS] Processed 3 IOCs
```

### 2. Run with Live OSINT Feeds (requires API keys)
```bash
# Configure API keys in .env file first
# VIRUSTOTAL_API_KEY=your_key
# ALIENVAULT_API_KEY=your_key
# ABUSEIPDB_API_KEY=your_key

python3 main.py --mode live --indicators 8.8.8.8 1.1.1.1
```

### 3. Check MongoDB Storage
```bash
# View database statistics
python3 << 'EOF'
from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017/")
collection = client["threat_intelligence"]["ioc_data"]

print(f"Total IOCs: {collection.count_documents({})}")
print("\nLatest 5 IOCs:")
for doc in collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(5):
    print(f"  {doc['indicator']} - Risk: {doc['risk_score']} - Source: {doc['source']}")
EOF
```

### 4. View Firewall Rules
```bash
# List active DROP rules
sudo iptables -L INPUT -n | grep DROP

# View all firewall rules
sudo iptables -S

# Clear all custom rules (if needed)
# sudo iptables -F INPUT
```

### 5. Check Security Logs
```bash
# View SIEM-ready security events
tail -20 logs/security_events.log

# View application ingestion logs
tail -20 logs/ingestion.log

# Count security events by type
grep "EVENT=" logs/security_events.log | cut -d'=' -f2 | cut -d'|' -f1 | sort | uniq -c
```

### 6. MongoDB Service Status
```bash
# Check if MongoDB is running
sudo systemctl status mongod

# View MongoDB version
mongosh --version

# Connect to MongoDB shell
mongosh
# In MongoDB shell:
# use threat_intelligence
# db.ioc_data.find().pretty()
# db.ioc_data.countDocuments()
```

### 7. Application Help
```bash
python3 main.py --help
```

**Output:**
```
usage: main.py [-h] [--mode {demo,live}] [--indicators INDICATORS [INDICATORS ...]]

Advanced Threat Intelligence Platform & Dynamic Policy Enforcer

options:
  -h, --help            show this help message and exit
  --mode {demo,live}    Execution mode: demo (safe demo data) or live (API feeds). Default: demo
  --indicators INDICATORS [INDICATORS ...]
                        Space-separated indicators to process (IPs, domains, hashes)
```

## Key Features Demonstrated

### ✅ Threat Intelligence Ingestion
- Multiple OSINT feed integration
- API authentication and error handling
- Malicious indicator extraction

### ✅ IOC Processing Pipeline
- Indicator validation (IP/Domain/Hash)
- Deduplication logic
- Risk scoring by source
- Timestamp tracking

### ✅ MongoDB Integration
- Persistent threat storage
- Schema normalization
- Legacy document migration
- Query-based deduplication

### ✅ Dynamic Firewall Enforcement
- Automatic IP blocking via iptables
- Risk threshold (≥80) evaluation
- Error handling for sudo operations

### ✅ SIEM-Ready Logging
- Structured event logging
- Multiple log files (application + security)
- Compliance-compatible format
- Kibana/ELK integration ready

### ✅ Production Code Quality
- Command-line interface with argparse
- Comprehensive error handling
- Module-based architecture
- Config management with python-dotenv
- Logging to file and console

## Project Statistics

| Metric | Value |
|--------|-------|
| Python Files | 15+ |
| Modules | 6 (core, feeds, policy_enforcer, normalization, data_ingestion) |
| Core Functions | 30+ |
| MongoDB Collections | 1 (ioc_data) |
| OSINT Feeds | 3 (VirusTotal, AlienVault, AbuseIPDB) |
| Security Events Logged | 2+ types (DETECTED, BLOCKED, BLOCK_FAILED) |
| Risk Levels | 5-6 categories |
| Lines of Code | 500+ |

## Technologies Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.8+ |
| Database | MongoDB with PyMongo |
| Firewall | Linux iptables |
| Logging | Python logging module |
| Config | python-dotenv |
| APIs | VirusTotal, AlienVault OTX, AbuseIPDB |
| Version Control | Git |

## Review

> I developed an Advanced Threat Intelligence Platform that automates the entire threat intelligence lifecycle. The system ingests malicious IOC data from three public OSINT feeds (VirusTotal, AlienVault, AbuseIPDB), normalizes and deduplicates indicators, assigns dynamic risk scores, persists data in MongoDB with proper schema management, automatically enforces firewall blocking for high-risk IPs via Linux iptables, and generates centralized SIEM-ready audit logs for SOC compliance and monitoring.
> 
> The architecture demonstrates proficiency in threat intelligence concepts, cybersecurity automation, NoSQL database integration, system administration (iptables), and security logging best practices. The pipeline handles both demo data and live API feeds, includes comprehensive error handling, and supports command-line configuration for flexibility.

## Testing Checklist for Interview

- [ ] Run demo mode: `python3 main.py --mode demo`
- [ ] Check MongoDB count: `python3 -c "from pymongo import..."`
- [ ] View firewall rules: `sudo iptables -L INPUT -n`
- [ ] Check security logs: `tail -20 logs/security_events.log`
- [ ] Verify deduplication: Run pipeline twice with same IPs
- [ ] Check application logs: `tail -20 logs/ingestion.log`
- [ ] Verify risk scoring: Different sources have different scores
- [ ] Show MongoDB document: Connect with mongosh and view record

## Next Steps for Enhancement

1. **Kubernetes Deployment** - Containerize with Docker, deploy to K8s
2. **Elasticsearch Integration** - Ship logs to ELK Stack
3. **Dashboard** - Build Grafana/Kibana dashboard for visualization
4. **API Server** - REST API for IOC querying and management
5. **Feed Scheduler** - Schedule feed ingestion with APScheduler
6. **Threat Correlation** - ML-based threat pattern detection
7. **GeoIP Mapping** - Geographic threat analysis
8. **Slack Alerts** - Real-time notifications for high-risk threats

---

**Developer:** Sanket Pawar  
**Project:** Advanced Threat Intelligence Platform & Dynamic Policy Enforcer  

