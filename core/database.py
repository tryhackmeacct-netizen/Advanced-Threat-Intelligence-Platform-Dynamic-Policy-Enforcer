from datetime import datetime, timezone

from pymongo import MongoClient

from core.cleaner import clean_indicator, infer_indicator_type
from core.config import COLLECTION_NAME, DB_NAME, MONGO_URI


def normalize_legacy_document(doc):
    if not doc:
        return None

    indicator = clean_indicator(doc.get("indicator") or doc.get("ip") or doc.get("domain") or "")
    if not indicator:
        return None

    return {
        "indicator": indicator,
        "type": doc.get("type") or infer_indicator_type(indicator),
        "source": doc.get("source", "Unknown"),
        "risk_score": int(doc.get("risk_score", 0)),
        "status": doc.get("status", "malicious"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": doc.get("details", {}),
    }


def migrate_legacy_documents(collection):
    migrated = 0

    for doc in collection.find({"indicator": {"$exists": False}, "ip": {"$exists": True}}):
        normalized = normalize_legacy_document(doc)
        if normalized is None:
            continue

        collection.replace_one({"_id": doc["_id"]}, normalized)
        migrated += 1

    return migrated


def get_collection():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    return db[COLLECTION_NAME]


def insert_ioc(collection, ioc):
    existing = collection.find_one({"indicator": ioc["indicator"]})
    if existing:
        return False
    collection.insert_one(ioc)
    return True
