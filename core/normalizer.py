from datetime import datetime, timezone

from core.cleaner import clean_indicator, infer_indicator_type


def normalize_record(record):
    indicator = clean_indicator(record.get("indicator") or record.get("ip") or record.get("domain") or "")
    indicator_type = record.get("type") or infer_indicator_type(indicator)
    source = record.get("source", "Unknown")

    if indicator_type == "unknown":
        raise ValueError(f"Unsupported indicator format: {record}")

    return {
        "indicator": indicator,
        "type": indicator_type,
        "source": source,
        "risk_score": int(record.get("risk_score", 0)),
        "status": record.get("status", "malicious"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": record.get("details", {}),
    }
