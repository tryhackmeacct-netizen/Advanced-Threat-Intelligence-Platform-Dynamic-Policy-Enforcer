#!/usr/bin/env python3

import time
from datetime import datetime, timezone

from pymongo import MongoClient

from core.config import BLOCK_THRESHOLD, COLLECTION_NAME, DB_NAME, MONGO_URI
from core.logger import get_logger
from policy_enforcer.firewall_manager import block_ip, record_blocked_ip

logger = get_logger()


def get_db():
    client = MongoClient(MONGO_URI)
    return client[DB_NAME]


def monitor_enforcement(poll_seconds=15):
    db = get_db()
    collection = db[COLLECTION_NAME]

    logger.info(
        "Starting enforcement daemon [threshold=%s, poll_seconds=%s]",
        BLOCK_THRESHOLD,
        poll_seconds,
    )

    blocked_collection = db["blocked_ips"]

    while True:
        candidates = list(
            collection.find({"risk_score": {"$gte": BLOCK_THRESHOLD}, "blocked": False})
        )

        if candidates:
            logger.info("Found %d candidate IOC(s) for enforcement", len(candidates))

        for doc in candidates:
            ip = doc["indicator"]
            source = doc.get("source", "Unknown")
            risk_score = int(doc.get("risk_score", 0))

            existing = blocked_collection.find_one({"ip": ip})
            if existing:
                logger.info("Already tracked blocked IP in MongoDB: %s", ip)
                continue

            if block_ip(ip):
                collection.update_one(
                    {"_id": doc["_id"]},
                    {
                        "$set": {
                            "blocked": True,
                            "block_time": datetime.now(timezone.utc).isoformat(),
                        }
                    },
                )
                blocked_collection.insert_one({"ip": ip, "status": "active", "source": source, "risk_score": risk_score})
                record_blocked_ip(ip, source, risk_score)
                logger.info("Enforced block for %s", ip)
            else:
                logger.warning("Skipping enforcement for %s", ip)

        time.sleep(poll_seconds)


if __name__ == "__main__":
    monitor_enforcement()
