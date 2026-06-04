import os
from pathlib import Path

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConnectionError as ESConnectionError,
    SSLError,
    TransportError,
)

from core.config import (
    ELASTICSEARCH_CA_CERT_PATH,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_USER,
    ES_INDEX_NAME,
    SIEM_ENABLED,
)
from core.logger import get_logger
from threat_queue.event_queue import save_failed_event, get_queue_size

logger = get_logger("siem_forwarder")


def _is_ca_cert_readable(ca_cert_path):
    if not ca_cert_path:
        logger.error("ELASTICSEARCH_CA_CERT_PATH is not configured")
        return False

    cert_path = Path(ca_cert_path)

    try:
        parent_dir = cert_path.parent
        if not os.access(parent_dir, os.X_OK):
            logger.error(
                "Cannot access Elasticsearch CA certificate directory: %s (missing execute permission)",
                parent_dir,
            )
            return False
    except PermissionError:
        logger.error(
            "Permission denied while checking Elasticsearch CA certificate directory: %s",
            cert_path.parent,
        )
        return False

    try:
        exists = cert_path.exists()
    except PermissionError:
        logger.error(
            "Permission denied while checking Elasticsearch CA certificate path: %s",
            ca_cert_path,
        )
        return False

    if not exists:
        logger.error("Elasticsearch CA certificate does not exist: %s", ca_cert_path)
        return False

    try:
        is_file = cert_path.is_file()
    except PermissionError:
        logger.error(
            "Permission denied while verifying Elasticsearch CA certificate file type: %s",
            ca_cert_path,
        )
        return False

    if not is_file:
        logger.error("Elasticsearch CA certificate path is not a regular file: %s", ca_cert_path)
        return False

    if not os.access(cert_path, os.R_OK):
        logger.error(
            "Elasticsearch CA certificate file is not readable by the current user: %s",
            ca_cert_path,
        )
        return False

    return True


def _build_elasticsearch_client():
    logger.debug(
        "Initializing Elasticsearch client: url=%s ca_cert=%s",
        ELASTICSEARCH_URL,
        ELASTICSEARCH_CA_CERT_PATH,
    )

    if not ELASTICSEARCH_URL.lower().startswith("https://"):
        logger.warning(
            "Elasticsearch URL does not use HTTPS, but verify_certs=True is configured: %s",
            ELASTICSEARCH_URL,
        )

    if not _is_ca_cert_readable(ELASTICSEARCH_CA_CERT_PATH):
        logger.error("Elasticsearch client startup aborted due to CA certificate validation failure")
        return None

    auth = None
    if ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD:
        auth = (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)
    else:
        logger.warning("Elasticsearch authentication is not fully configured; basic_auth will not be provided")

    try:
        client_args = {
            "hosts": [ELASTICSEARCH_URL],
            "verify_certs": True,
            "ca_certs": ELASTICSEARCH_CA_CERT_PATH,
            "request_timeout": 30,
        }

        if auth:
            client_args["basic_auth"] = auth

        es_client = Elasticsearch(**client_args)

        if not es_client.ping():
            logger.error("Elasticsearch ping returned False for %s", ELASTICSEARCH_URL)
            return None

        logger.info("Elasticsearch client initialized successfully")
        return es_client

    except SSLError as error:
        logger.error("TLS/SSL validation failed for %s: %s", ELASTICSEARCH_URL, error)
        return None

    except AuthenticationException as error:
        logger.error("Elasticsearch authentication failed for %s: %s", ELASTICSEARCH_URL, error)
        return None

    except AuthorizationException as error:
        logger.error("Elasticsearch authorization failed for %s: %s", ELASTICSEARCH_URL, error)
        return None

    except ESConnectionError as error:
        logger.error("Elasticsearch connection failed for %s: %s", ELASTICSEARCH_URL, error)
        return None

    except TransportError as error:
        logger.error("Elasticsearch transport error for %s: %s", ELASTICSEARCH_URL, error)
        return None

    except Exception as error:
        logger.error("Unexpected Elasticsearch startup error for %s: %s", ELASTICSEARCH_URL, error)
        return None


def diagnose_elasticsearch_connection():
    """Print diagnostic information about Elasticsearch connectivity."""
    logger.info("Elasticsearch diagnostic: url=%s", ELASTICSEARCH_URL)
    logger.info("Elasticsearch diagnostic: ca_cert_path=%s", ELASTICSEARCH_CA_CERT_PATH)
    logger.info(
        "Elasticsearch diagnostic: ca_cert_exists=%s ca_cert_readable=%s",
        Path(ELASTICSEARCH_CA_CERT_PATH).exists(),
        Path(ELASTICSEARCH_CA_CERT_PATH).is_file() and os.access(ELASTICSEARCH_CA_CERT_PATH, os.R_OK),
    )
    logger.info(
        "Elasticsearch diagnostic: auth_user=%s auth_configured=%s",
        ELASTICSEARCH_USER or "<unset>",
        bool(ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD),
    )

    client = _build_elasticsearch_client()
    if client is None:
        logger.error("Elasticsearch diagnostic: unreachable")
        return False

    logger.info("Elasticsearch diagnostic: reachable")
    return True


es = _build_elasticsearch_client()


def forward_to_siem(ioc):
    """
    Forward IOC to Elasticsearch.
    If unavailable, queue event for later retry.
    """
    if not SIEM_ENABLED:
        logger.debug("Skipping SIEM forwarding because SIEM_ENABLED is false")
        return "SKIPPED"

    if es is None:
        logger.warning(
            "SIEM unavailable, IOC queued for retry | Indicator=%s | Queue size=%d",
            ioc["indicator"],
            get_queue_size() + 1,
        )
        save_failed_event(ioc)
        return "QUEUED"

    try:
        es_doc = dict(ioc)

        # Remove MongoDB _id field before sending to Elasticsearch
        es_doc.pop("_id", None)

        es.index(
            index=ES_INDEX_NAME,
            id=str(ioc["indicator"]),
            document=es_doc,
        )

        logger.info(
            "IOC forwarded to SIEM | Indicator=%s",
            ioc["indicator"],
        )
        return "SUCCESS"

    except Exception as error:
        logger.error(
            f"SIEM forwarding failed, queueing for retry: {error}"
        )
        save_failed_event(ioc)
        return "QUEUED"
