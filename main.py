#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform - Main Entry Point
Processes malicious IOCs through normalization, deduplication, risk scoring,
MongoDB storage, and dynamic firewall enforcement with SIEM-ready logging.
"""

import argparse
import sys

from core.config import DEFAULT_FEED_INDICATORS, ENABLE_DEMO_FALLBACK
from core.logger import get_logger
from core.pipeline import run_demo, run_live

logger = get_logger()


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Advanced Threat Intelligence Platform & Dynamic Policy Enforcer"
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "live"],
        default="demo",
        help="Execution mode: demo (safe demo data) or live (API feeds). Default: demo",
    )
    parser.add_argument(
        "--indicators",
        nargs="+",
        help="Space-separated indicators to process (IPs, domains, hashes)",
    )
    return parser.parse_args()


def main():
    """Main entry point for the threat intelligence platform."""
    args = parse_arguments()

    # Determine indicators to process
    indicators = args.indicators if args.indicators else DEFAULT_FEED_INDICATORS

    if not indicators:
        logger.error("No indicators provided. Use --indicators or configure DEFAULT_FEED_INDICATORS")
        sys.exit(1)

    logger.info(
        "Starting Threat Intelligence Platform [MODE=%s, INDICATORS=%d]",
        args.mode.upper(),
        len(indicators),
    )

    try:
        if args.mode == "demo":
            logger.info("Running in DEMO mode with %d indicators", len(indicators))
            inserted = run_demo(indicators)
        else:
            logger.info("Running in LIVE mode - fetching from feeds")
            inserted = run_live(indicators)

        if not inserted:
            logger.warning("No new indicators were processed")
            if args.mode == "live" and ENABLE_DEMO_FALLBACK:
                logger.info("Falling back to DEMO mode")
                inserted = run_demo(indicators)

        logger.info("[SUCCESS] Processed %d IOCs", len(inserted))

        for ioc in inserted:
            print(
                f"✓ {ioc['indicator']} ({ioc['type']}) - "
                f"Risk: {ioc['risk_score']} - Source: {ioc['source']}"
            )

    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user")
        sys.exit(0)
    except Exception as error:
        logger.error("Pipeline failed: %s", error, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()