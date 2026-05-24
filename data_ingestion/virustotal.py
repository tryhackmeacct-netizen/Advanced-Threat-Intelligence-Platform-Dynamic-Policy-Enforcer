from pymongo import MongoClient
import datetime

client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intelligence"]
collection = db["ioc_data"]

ioc_data = {
    "ip": "185.220.101.1",
    "source": "VirusTotal",
    "risk_score": 90,
    "status": "malicious",
    "timestamp": str(datetime.datetime.now())
}

collection.insert_one(ioc_data)

print("IOC Data Stored Successfully")
