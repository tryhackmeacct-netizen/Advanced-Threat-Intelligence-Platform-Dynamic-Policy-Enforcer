def calculate_risk(source):
    if source == "VirusTotal":
        return 90

    if source == "AlienVault":
        return 85

    if source == "AbuseIPDB":
        return 80

    if source == "URLHaus":
        return 88

    if source == "DemoFeed":
        return 95

    return 60
