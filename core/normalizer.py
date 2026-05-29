from datetime import datetime, timezone

from core.cleaner import clean_indicator, infer_indicator_type


def normalize_record(record):
    indicator = clean_indicator(record.get("indicator") or record.get("ip") or record.get("domain") or "")
    indicator_type = record.get("type") or infer_indicator_type(indicator)
    source = record.get("source", "Unknown")
    now = datetime.now(timezone.utc).isoformat()

    if indicator_type == "unknown":
        raise ValueError(f"Unsupported indicator format: {record}")

    return {
        "indicator": indicator,
        "type": indicator_type,
        "source": source,
        "risk_score": int(record.get("risk_score", 0)),
        "status": record.get("status", "malicious"),
        "country": record.get("country", "Unknown"),
        "confidence": record.get("confidence", "medium"),
        "first_seen": record.get("first_seen", now),
        "last_seen": record.get("last_seen", now),
        "timestamp": now,
        "tags": record.get("tags", []),
        "details": record.get("details", {}),
        "blocked": record.get("blocked", False),
    }
