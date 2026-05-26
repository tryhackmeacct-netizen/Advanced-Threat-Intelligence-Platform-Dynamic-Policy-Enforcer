import os

from dotenv import load_dotenv


load_dotenv()


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intelligence")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "ioc_data")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

DEFAULT_FEED_INDICATORS = [
    item.strip()
    for item in os.getenv(
        "DEFAULT_FEED_INDICATORS",
        "203.0.113.10,198.51.100.20,192.0.2.20",
    ).split(",")
    if item.strip()
]

ENABLE_DEMO_FALLBACK = os.getenv("ENABLE_DEMO_FALLBACK", "1") == "1"
