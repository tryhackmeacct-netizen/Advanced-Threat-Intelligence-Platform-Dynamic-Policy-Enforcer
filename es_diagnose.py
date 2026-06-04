#!/usr/bin/env python3
"""Elasticsearch TLS connectivity diagnostic script."""

import os
from core.config import (
    ELASTICSEARCH_CA_CERT_PATH,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USER,
    ELASTICSEARCH_PASSWORD,
)
from core.siem_forwarder import diagnose_elasticsearch_connection


def main():
    print("Elasticsearch diagnostics")
    print("========================")
    print("URL:", ELASTICSEARCH_URL)
    print("CA certificate path:", ELASTICSEARCH_CA_CERT_PATH)
    print("CA certificate exists:", os.path.exists(ELASTICSEARCH_CA_CERT_PATH))
    print("CA certificate readable:", os.path.exists(ELASTICSEARCH_CA_CERT_PATH) and os.access(ELASTICSEARCH_CA_CERT_PATH, os.R_OK))
    print("Authentication user:", ELASTICSEARCH_USER or "<unset>")
    print("Authentication configured:", bool(ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD))
    print()
    print("Running Elasticsearch reachability check...")

    reachable = diagnose_elasticsearch_connection()
    print("Elasticsearch reachable:", reachable)

    if not reachable:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
