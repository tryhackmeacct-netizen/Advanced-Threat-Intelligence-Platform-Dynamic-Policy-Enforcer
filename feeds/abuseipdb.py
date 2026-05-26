import requests

from core.config import ABUSEIPDB_API_KEY


def fetch_indicators(indicators):
    if not ABUSEIPDB_API_KEY:
        raise RuntimeError("ABUSEIPDB_API_KEY is not configured")

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    results = []

    for indicator in indicators:
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check/{indicator}",
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", {})
        abuse_confidence = data.get("abuseConfidence", 0)

        if abuse_confidence >= 50:
            results.append(
                {
                    "indicator": indicator,
                    "type": "ip",
                    "source": "AbuseIPDB",
                    "risk_score": 80,
                    "details": {"abuse_confidence": abuse_confidence},
                }
            )

    return results
