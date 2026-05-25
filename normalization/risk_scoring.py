def calculate_risk(source):
    """
    Assign a risk score based on the IOC source.
    """
    if source == "VirusTotal":
        return 90

    if source == "AbuseIPDB":
        return 85

    if source == "AlienVault":
        return 80

    return 40
