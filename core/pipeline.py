from core.cleaner import clean_indicator, infer_indicator_type
from core.database import get_collection, migrate_legacy_documents
from core.deduplicator import is_duplicate
from core.logger import get_logger
from core.normalizer import normalize_record
from core.risk_scoring import calculate_risk
from core.security_logger import log_security_event
from feeds.abuseipdb import fetch_indicators as fetch_abuseipdb
from feeds.alienvault import fetch_indicators as fetch_alienvault
from feeds.virustotal import fetch_indicators as fetch_virustotal
from policy_enforcer.firewall_manager import block_ip

logger = get_logger()


def build_demo_records(indicators):
    records = []
    for indicator in indicators:
        records.append(
            {
                "indicator": indicator,
                "type": infer_indicator_type(clean_indicator(indicator)),
                "source": "DemoFeed",
                "risk_score": 95,
                "status": "malicious",
            }
        )
    return records


def process_records(records):
    collection = get_collection()
    migrate_legacy_documents(collection)
    inserted = []

    for record in records:
        normalized = normalize_record(record)
        indicator = normalized["indicator"]

        if is_duplicate(collection, indicator):
            logger.info("Duplicate IOC skipped: %s", indicator)
            continue

        normalized["risk_score"] = calculate_risk(normalized["source"])

        collection.insert_one(normalized)
        inserted.append(normalized)

        logger.info("Stored IOC %s from %s", indicator, normalized["source"])
        log_security_event(
            "MALICIOUS_IP_DETECTED",
            indicator,
            normalized["source"],
            normalized["risk_score"],
            "DETECTED",
        )

        if normalized["risk_score"] >= 80:
            blocked = block_ip(indicator)
            if blocked:
                log_security_event(
                    "FIREWALL_BLOCK",
                    indicator,
                    normalized["source"],
                    normalized["risk_score"],
                    "BLOCKED",
                )
            else:
                log_security_event(
                    "FIREWALL_BLOCK",
                    indicator,
                    normalized["source"],
                    normalized["risk_score"],
                    "BLOCK_FAILED",
                )

    return inserted


def fetch_live_records(indicators):
    feed_results = []

    for feed_name, feed_fn in (
        ("VirusTotal", fetch_virustotal),
        ("AlienVault", fetch_alienvault),
        ("AbuseIPDB", fetch_abuseipdb),
    ):
        try:
            feed_results.extend(feed_fn(indicators))
        except Exception as error:
            logger.error("Feed %s failed: %s", feed_name, error)

    return feed_results


def run_demo(indicators):
    records = build_demo_records(indicators)
    return process_records(records)


def run_live(indicators):
    records = fetch_live_records(indicators)

    if not records:
        logger.warning("No live indicators were returned by any feed")
        return []

    return process_records(records)
