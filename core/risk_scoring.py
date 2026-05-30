SOURCE_RISK_MAP = {
    "VirusTotal": 90,
    "AlienVault": 85,
    "AbuseIPDB": 80,
    "URLHaus": 88,
    "DemoFeed": 95,
}


def calculate_risk(source):
    return SOURCE_RISK_MAP.get(source, 60)


def calculate_final_score(ioc):
    score = ioc.get("risk_score")

    if not score:
        score = calculate_risk(ioc.get("source"))

    if ioc.get("source") == "VirusTotal":
        score += 10
    elif ioc.get("source") == "AlienVault":
        score += 5

    return min(int(score), 100)
