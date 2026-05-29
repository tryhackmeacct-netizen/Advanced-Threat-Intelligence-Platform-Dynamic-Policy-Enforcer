from elasticsearch import Elasticsearch

from core.config import ELASTICSEARCH_URL, ES_INDEX_NAME, SIEM_ENABLED
from core.logger import get_logger

logger = get_logger()

try:
    es = Elasticsearch(ELASTICSEARCH_URL, request_timeout=30)
    if not es.ping():
        logger.warning("Elasticsearch server unreachable")
        es = None
except Exception as error:
    logger.error(f"Elasticsearch connection failed: {error}")
    es = None


def forward_to_siem(ioc):
    if not SIEM_ENABLED:
        logger.debug("Skipping SIEM forwarding because SIEM_ENABLED is false")
        return False

    if es is None:
        logger.warning("Skipping SIEM forwarding")
        return False

    try:
        es.index(index=ES_INDEX_NAME, document=ioc)
        logger.info("IOC forwarded to SIEM | Indicator=%s", ioc["indicator"])
        return True
    except Exception as error:
        logger.error(f"SIEM forwarding failed: {error}")
        return False
