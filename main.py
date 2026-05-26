import argparse

from core.cleaner import clean_indicator
from core.config import DEFAULT_FEED_INDICATORS, ENABLE_DEMO_FALLBACK
from core.logger import get_logger
from core.pipeline import run_demo, run_live

logger = get_logger()


def resolve_indicators(ip_values):
    if ip_values:
        return [clean_indicator(ip) for ip in ip_values]

    return [clean_indicator(ip) for ip in DEFAULT_FEED_INDICATORS]


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Threat Intelligence Platform & Dynamic Policy Enforcer"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the demo ingestion pipeline",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run live feed ingestion when API keys are configured",
    )
    parser.add_argument(
        "--ip",
        action="append",
        dest="ip_values",
        help="Override the indicator list for demo or live ingestion",
    )
    args = parser.parse_args()

    if args.live:
        logger.info("Running live ingestion mode")
        indicators = resolve_indicators(args.ip_values)
        run_live(indicators)
        return

    logger.info("Running demo ingestion mode")
    if ENABLE_DEMO_FALLBACK:
        indicators = resolve_indicators(args.ip_values)
        run_demo(indicators)
    else:
        logger.warning("Demo fallback disabled and no live mode selected")


if __name__ == "__main__":
    main()
