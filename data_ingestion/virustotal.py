from core.database import get_collection, migrate_legacy_documents
from core.normalizer import normalize_record
from core.risk_scoring import calculate_risk

collection = get_collection()
migrate_legacy_documents(collection)

record = normalize_record(
    {
        "indicator": "185.220.101.1",
        "source": "VirusTotal",
        "risk_score": 90,
        "status": "malicious",
        "details": {},
    }
)
record["risk_score"] = calculate_risk(record["source"])

if collection.find_one({"$or": [{"indicator": record["indicator"]}, {"ip": record["indicator"]}]}) is not None:
    print("Duplicate IOC found")
else:
    collection.insert_one(record)
    print("IOC Data Stored Successfully")
