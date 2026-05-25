import argparse
from datetime import datetime

from pymongo import MongoClient

from normalization.cleaner import clean_ip
from normalization.deduplicator import is_duplicate
from normalization.risk_scoring import calculate_risk
from policy_enforcer.firewall_manager import block_ip


parser = argparse.ArgumentParser(description="Dynamic Threat Intelligence Policy Enforcer")
parser.add_argument(
    "--ip",
    default="8.8.8.8",
    help="Malicious IP address to process (default: 8.8.8.8)",
)
args = parser.parse_args()

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Select database
db = client["threat_intelligence"]

# Select collection
collection = db["ioc_data"]

# Clean IP address
cleaned_ip = clean_ip(args.ip)

# Check duplicate IOC
if not is_duplicate(collection, cleaned_ip):

    # Calculate risk score
    risk_score = calculate_risk("VirusTotal")

    # Create IOC document
    ioc_document = {
        "ip": cleaned_ip,
        "source": "VirusTotal",
        "risk_score": risk_score,
        "status": "malicious",
        "timestamp": str(datetime.utcnow())
    }

    # Insert into MongoDB
    collection.insert_one(ioc_document)

    print("[+] IOC inserted successfully")

    # Automatically block high-risk IPs
    if risk_score >= 80:
        block_ip(cleaned_ip)

else:
    print("[-] Duplicate IOC found")
