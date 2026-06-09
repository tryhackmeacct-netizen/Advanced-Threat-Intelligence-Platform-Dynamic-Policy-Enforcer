from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
LOG_DIR.mkdir(exist_ok=True)
SECURITY_LOG_PATH = LOG_DIR / "security_events.log"


def _format_timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def log_security_event(event_type: str, indicator: str, source: str, risk_score: int, action: str) -> None:
    line = (
        f"{_format_timestamp()} | EVENT={event_type} | IP={indicator} | "
        f"SOURCE={source} | RISK={risk_score} | ACTION={action}"
    )

    with SECURITY_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")