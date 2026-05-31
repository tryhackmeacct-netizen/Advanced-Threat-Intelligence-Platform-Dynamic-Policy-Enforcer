from datetime import datetime, timezone

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from core.cleaner import clean_indicator, infer_indicator_type
from core.config import COLLECTION_NAME, DB_NAME, MONGO_URI
from core.logger import get_logger

logger = get_logger(__name__)
_indexes_initialized = False


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


def create_indexes(collection):
    try:
        collection.create_index([("indicator", 1)], unique=True)
        collection.create_index([("risk_score", -1)])
        collection.create_index([("source", 1)])
        logger.info("MongoDB indexes ensured for collection '%s'", collection.name)
    except DuplicateKeyError as error:
        logger.warning("Unable to create unique index on indicator due to existing duplicates: %s", error)
    except Exception as error:
        logger.error("Failed to create MongoDB indexes: %s", error, exc_info=True)


def get_collection():
    global _indexes_initialized

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    if not _indexes_initialized:
        create_indexes(collection)
        _indexes_initialized = True

    return collection


def insert_ioc(collection, ioc):
    """Insert IOC with duplicate detection and graceful handling."""
    existing = collection.find_one({"indicator": ioc["indicator"]})
    if existing:
        logger.debug("IOC already exists, skipping: %s", ioc["indicator"])
        return False
    try:
        collection.insert_one(ioc)
        return True
    except DuplicateKeyError:
        logger.warning("Duplicate key error for indicator: %s (race condition)", ioc["indicator"])
        return False


def remove_duplicate_iocs(collection):
    """
    Remove duplicate IOC records from MongoDB.
    Returns tuple: (duplicates_found, duplicates_removed)
    """
    pipeline = [
        {
            "$group": {
                "_id": "$indicator",
                "ids": {"$push": "$_id"},
                "count": {"$sum": 1}
            }
        },
        {
            "$match": {
                "count": {"$gt": 1}
            }
        }
    ]
    
    duplicates_found = 0
    duplicates_removed = 0
    
    try:
        for group in collection.aggregate(pipeline):
            duplicates_found += 1
            indicator = group["_id"]
            ids_to_keep = group["ids"][0]
            ids_to_delete = group["ids"][1:]
            
            deleted = collection.delete_many({"_id": {"$in": ids_to_delete}})
            duplicates_removed += deleted.deleted_count
            
            logger.info(
                "Removed %d duplicate records for indicator: %s",
                deleted.deleted_count,
                indicator
            )
        
        logger.info(
            "Duplicate cleanup complete: %d duplicates found, %d records removed",
            duplicates_found,
            duplicates_removed
        )
        return duplicates_found, duplicates_removed
    except Exception as error:
        logger.error("Failed to remove duplicates: %s", error, exc_info=True)
        return 0, 0


def get_feed_stats(collection):
    return {
        "total_iocs": collection.count_documents({}),
        "high_risk": collection.count_documents({"risk_score": {"$gte": 80}}),
        "sources": collection.distinct("source"),
    }
