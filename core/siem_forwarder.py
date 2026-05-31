from elasticsearch import Elasticsearch

from core.config import ES_INDEX_NAME, SIEM_ENABLED
from core.logger import get_logger
from threat_queue.event_queue import save_failed_event, get_queue_size

logger = get_logger()

try:
    es = Elasticsearch(
        "https://localhost:9200",
        basic_auth=("elastic", "utU--9H79mHMhK56tXin"),
        verify_certs=False,
        request_timeout=30,
    )

    if not es.ping():
        logger.warning("Elasticsearch server unreachable on startup")
        es = None

except Exception as error:
    logger.error(f"Elasticsearch connection failed: {error}")
    es = None


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
