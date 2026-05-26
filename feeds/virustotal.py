import requests

from core.config import VIRUSTOTAL_API_KEY


def fetch_indicators(indicators):
    if not VIRUSTOTAL_API_KEY:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not configured")

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json",
    }

    results = []

    for indicator in indicators:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()

        payload = response.json()
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        if stats.get("malicious", 0) > 0:
            results.append(
                {
                    "indicator": indicator,
                    "type": "ip",
                    "source": "VirusTotal",
                    "risk_score": 90,
                    "details": {"malicious": stats.get("malicious", 0)},
                }
            )

    return results
