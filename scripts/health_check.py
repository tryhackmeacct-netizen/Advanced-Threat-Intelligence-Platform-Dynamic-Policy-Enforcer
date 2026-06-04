import os
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load .env from project root
project_root = Path(__file__).resolve().parent.parent
load_dotenv(project_root / ".env")

ES_URL = os.getenv("ELASTICSEARCH_URL", "https://localhost:9200")
ES_USER = os.getenv("ELASTICSEARCH_USER")
ES_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD")

print(f"Testing connection to: {ES_URL}")
print(f"Using user: {ES_USER}")

try:
    response = requests.get(
        ES_URL,
        auth=(ES_USER, ES_PASSWORD),
        verify=False,
        timeout=10,
    )

    if response.status_code == 200:
        data = response.json()

        print("\n✓ Elasticsearch is reachable")
        print(f"Cluster Name : {data.get('cluster_name')}")
        print(f"Node Name    : {data.get('name')}")
        print(f"Version      : {data.get('version', {}).get('number')}")

    elif response.status_code == 401:
        print("\n✗ Authentication failed (401 Unauthorized)")
        print("Check ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD")

    else:
        print(f"\n✗ Elasticsearch returned status code {response.status_code}")
        print(response.text)

except requests.exceptions.ConnectionError:
    print("\n✗ Unable to connect to Elasticsearch")

except requests.exceptions.Timeout:
    print("\n✗ Connection timed out")

except Exception as e:
    print(f"\n✗ Error: {e}")
