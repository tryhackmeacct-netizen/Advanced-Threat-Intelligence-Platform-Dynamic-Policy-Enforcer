# Advanced Threat Intelligence Platform & Dynamic Policy Enforcer

## Project Overview
This project automates threat intelligence collection, IOC normalization, MongoDB storage, risk scoring, and Linux firewall blocking using Python and `iptables`.

## Security Flow
Threat Feed
    ↓
Normalization
    ↓
MongoDB Storage
    ↓
Risk Scoring
    ↓
Automatic Firewall Blocking

## Project Structure
```text
.
├── main.py
├── normalization/
│   ├── cleaner.py
│   ├── deduplicator.py
│   └── risk_scoring.py
├── policy_enforcer/
│   └── firewall_manager.py
├── database/
│   └── mongo_connection.py
├── dashboards/
├── data_ingestion/
│   └── virustotal.py
├── docs/
├── logs/
├── requirements.txt
├── screenshots/
```

### Folder Details
- `main.py` — main entry point for threat processing
- `normalization/` — cleans and validates IOC data
- `policy_enforcer/` — handles Linux firewall blocking
- `database/` — MongoDB connection utilities
- `dashboards/` — dashboard-related files
- `data_ingestion/` — threat feed ingestion scripts
- `docs/` — project documentation
- `logs/` — runtime logs
- `requirements.txt` — Python dependencies
- `screenshots/` — proof screenshots for review

## Main Features
- Clean and normalize malicious IPs
- Detect duplicate IOCs before inserting into MongoDB
- Assign risk scores based on threat source
- Insert IOC records into MongoDB
- Automatically block high-risk IPs using `iptables`

## Run Commands
### Run the project
```bash
python3 main.py
```

### Run with a custom IP
```bash
python3 main.py --ip 1.2.3.4
```

### Check the database using MongoDB shell
```bash
mongosh
use threat_intelligence
db.ioc_data.find().pretty()
```

### Check the MongoDB collection from bash
```bash
python3 - <<'PY'
from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017/")
collection = client["threat_intelligence"]["ioc_data"]
print("count =", collection.count_documents({}))
for doc in collection.find({}, {"_id": 0}):
    print(doc)
PY
```

### Check firewall rules
```bash
sudo iptables -L INPUT -n
sudo iptables -S
```

### Check MongoDB service status
```bash
sudo systemctl status mongod
```

### Check project structure
```bash
tree
```

## Expected Outputs
### First run
```text
[+] IOC inserted successfully
[+] Blocked malicious IP: 8.8.8.8
```

### Second run for the same IP
```text
[-] Duplicate IOC found
```

### MongoDB document example
```json
{
  "ip": "8.8.8.8",
  "source": "VirusTotal",
  "risk_score": 90,
  "status": "malicious"
}
```

### Firewall rule example
```text
DROP       all  --  8.8.8.8              0.0.0.0/0
```

## Review / Demo Commands
These commands are useful during internship review:

```bash
cd /home/sanket/Advanced-Threat-Intelligence-Platform-Dynamic-Policy-Enforcer
python3 main.py
sudo iptables -L INPUT -n
sudo systemctl status mongod
mongosh
use threat_intelligence
db.ioc_data.find().pretty()
```

## Screenshots
Proof artifacts are stored in `screenshots/`:

- `screenshots/python3_main.py.png`
- `screenshots/sudo_iptables_input.png`

These can be used in internship review to show:
- Python automation executed successfully
- The firewall rule was added and is active

## Week 1 Checklist
### Completed
- [x] Python-based project structure created
- [x] MongoDB integration added
- [x] Deduplication logic implemented
- [x] Risk scoring logic implemented
- [x] Firewall blocking implemented
- [x] README and review screenshots added

### Pending
- [ ] Integrate at least 3 public OSINT feeds
- [ ] Add a real feed ingestion pipeline
- [ ] Normalize feed output before storing
- [ ] Add daily commit tracking

## Daily Commit Plan
### Day 1
- Create project structure
- Add MongoDB connectivity
- Add basic IOC insertion logic

### Day 2
- Add cleaning and deduplication logic
- Add risk scoring

### Day 3
- Add firewall automation
- Verify `iptables` rule creation

### Day 4
- Add README and review screenshots
- Update documentation for demo flow

### Day 5
- Add at least 3 feed integrations
- Finalize Week 1 deliverables

## Notes
- `python3 main.py` will show `[-] Duplicate IOC found` when the same IOC is already stored.
- Use `python3 main.py --ip 1.2.3.4` to test a fresh IP without editing the source code.
- The firewall command requires `sudo` privileges in this environment.

## Author
Sanket Pawar
