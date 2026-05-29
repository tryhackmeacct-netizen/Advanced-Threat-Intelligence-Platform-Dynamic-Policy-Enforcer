#!/usr/bin/env python3

from datetime import datetime, timezone

from pymongo import MongoClient

from core.config import BLOCKED_IPS_COLLECTION, COLLECTION_NAME, DB_NAME, MONGO_URI
from core.logger import get_logger
from policy_enforcer.firewall_manager import unblock_ip

logger = get_logger()


def get_db():
    client = MongoClient(MONGO_URI)
    return client[DB_NAME]


def rollback_ip(ip, reason="manual_unblock"):
    if not unblock_ip(ip):
        logger.warning("Rollback failed for %s", ip)
        return False

    now = datetime.now(timezone.utc).isoformat()
    db = get_db()

    db[BLOCKED_IPS_COLLECTION].update_one(
        {"ip": ip},
        {
            "$set": {
                "rule_status": "removed",
                "rollback_reason": reason,
                "rollback_time": now,
            }
        },
        upsert=True,
    )

    db[COLLECTION_NAME].update_one(
        {"indicator": ip},
        {
            "$set": {
                "blocked": False,
                "rollback_reason": reason,
                "rollback_time": now,
            }
        },
    )

    logger.info("Rollback completed for %s", ip)
    return True
