SOURCE_RISK_MAP = {
    "VirusTotal": 90,
    "AlienVault": 85,
    "AbuseIPDB": 80,
    "URLHaus": 88,
    "DemoFeed": 95,
}


def calculate_risk(source):
    return SOURCE_RISK_MAP.get(source, 60)
