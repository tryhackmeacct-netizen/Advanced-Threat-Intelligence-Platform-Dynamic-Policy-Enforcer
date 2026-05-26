import requests

from core.config import ALIENVAULT_API_KEY


def fetch_indicators(indicators):
    if not ALIENVAULT_API_KEY:
        raise RuntimeError("ALIENVAULT_API_KEY is not configured")

    headers = {
        "X-OTX-API-KEY": ALIENVAULT_API_KEY,
        "accept": "application/json",
    }

    results = []

    for indicator in indicators:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general",
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()

        payload = response.json()
        pulses = payload.get("pulse_info", {}).get("pulses", [])
        malicious = len(pulses) if pulses else 0

        if malicious > 0:
            results.append(
                {
                    "indicator": indicator,
                    "type": "ip",
                    "source": "AlienVault",
                    "risk_score": 85,
                    "details": {"pulse_count": malicious},
                }
            )

    return results
