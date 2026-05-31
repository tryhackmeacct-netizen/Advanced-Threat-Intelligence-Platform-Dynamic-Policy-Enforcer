"""
Event queue manager for failed SIEM forwards.
Provides resilience when Elasticsearch is unavailable.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)

QUEUE_DIR = Path(__file__).resolve().parent
FAILED_EVENTS_FILE = QUEUE_DIR / "failed_events.json"


def load_failed_events():
    """Load previously failed events from queue file."""
    if not FAILED_EVENTS_FILE.exists():
        return []
    
    try:
        with open(FAILED_EVENTS_FILE, 'r') as f:
            events = json.load(f)
            logger.info("Loaded %d queued events from failed_events.json", len(events))
            return events
    except Exception as error:
        logger.error("Failed to load queued events: %s", error)
        return []


def save_failed_event(ioc):
    """Queue a failed event for later forwarding."""
    try:
        events = load_failed_events()
        
        # Add timestamp if not present
        if "queued_at" not in ioc:
            ioc["queued_at"] = datetime.now(timezone.utc).isoformat()
        
        events.append(ioc)
        
        with open(FAILED_EVENTS_FILE, 'w') as f:
            json.dump(events, f, indent=2, default=str)
        
        logger.info(
            "IOC queued for retry | Indicator=%s | Queue size=%d",
            ioc["indicator"],
            len(events)
        )
        return True
    except Exception as error:
        logger.error("Failed to queue event: %s", error, exc_info=True)
        return False


def clear_queued_events():
    """Clear all queued events (after successful forwarding)."""
    try:
        if FAILED_EVENTS_FILE.exists():
            FAILED_EVENTS_FILE.unlink()
            logger.info("Cleared failed_events.json queue")
        return True
    except Exception as error:
        logger.error("Failed to clear queue: %s", error)
        return False


def get_queue_size():
    """Get current size of failed events queue."""
    events = load_failed_events()
    return len(events)
