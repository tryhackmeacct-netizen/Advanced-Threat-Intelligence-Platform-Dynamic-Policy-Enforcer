# Verification Guide (How to Run the Project)

This guide demonstrates how to verify the functionality of the Advanced Threat Intelligence Platform and Dynamic Policy Enforcer.

## Prerequisites

Activate the project environment:

```bash
cd ~/Advanced-Threat-Intelligence-Platform-Dynamic-Policy-Enforcer
source .venv/bin/activate
```

---

## Threat Intelligence Ingestion

Process a sample indicator:

```bash
python3 main.py --mode demo --indicators 198.1.1.1
```

Expected outcome:

* IOC is analyzed and enriched
* IOC is stored in MongoDB
* IOC is forwarded to Elasticsearch
* Risk score is calculated

---

## MongoDB Verification

Open MongoDB shell:

```bash
mongosh
```

Select the project database:

```javascript
use threat_intelligence
```

Show available collections:

```javascript
show collections
```

Display total IOC records:

```javascript
db.ioc_data.countDocuments()
```

Display the most recently ingested indicators:

```javascript
db.ioc_data.find().sort({_id:-1}).limit(5).pretty()
```

Search for a specific indicator:

```javascript
db.ioc_data.find({indicator:"198.1.1.1"}).pretty()
```

---

## Elasticsearch Verification

Verify Elasticsearch availability:

```bash
curl -k -u elastic:'<ELASTIC_PASSWORD>' https://localhost:9200
```

Display indexed document count:

```bash
curl -k -u elastic:'<ELASTIC_PASSWORD>' \
https://localhost:9200/threat_intelligence/_count?pretty
```

Display recent threat records:

```bash
curl -k -u elastic:'<ELASTIC_PASSWORD>' \
"https://localhost:9200/threat_intelligence/_search?pretty&size=5"
```

---

## Kibana Dashboard

Verify Kibana service:

```bash
sudo systemctl status kibana
```

Open Kibana:

```text
http://localhost:5601
```

Example dashboard visualizations:

* Threat Source Analysis
* IOC Inventory
* Risk Score Distribution
* Blocked Indicators

---

## Dynamic Firewall Enforcement

Display active firewall rules:

```bash
sudo iptables -L -n -v --line-numbers
```

Block a high-risk indicator:

```bash
sudo .venv/bin/python main.py --mode demo --indicators 198.12.1.2
```

Verify firewall rule creation:

```bash
sudo iptables -L -n -v --line-numbers
```

---

## Firewall Rollback

Remove a previously enforced firewall rule:

```bash
sudo .venv/bin/python main.py --rollback 198.12.1.2
```

Verify firewall rule removal:

```bash
sudo iptables -L -n -v --line-numbers
```

---

## Security Logs

Locate available log files:

```bash
find . -type f | grep -i log
```

View recent security events:

```bash
tail -50 logs/security.log
```

---

## Automated Testing

Run the test suite:

```bash
pytest -v
```

or

```bash
python -m pytest -v
```

---

## Git Development History

Display commit history:

```bash
git log --oneline --graph --all -20
```

Display project branches:

```bash
git branch
```

---

## Service Status Checks

MongoDB:

```bash
sudo systemctl status mongod
```

Elasticsearch:

```bash
sudo systemctl status elasticsearch
```

Kibana:

```bash
sudo systemctl status kibana
```
