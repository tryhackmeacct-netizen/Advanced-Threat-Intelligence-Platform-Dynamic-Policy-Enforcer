#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform - Main Entry Point
Processes malicious IOCs through normalization, deduplication, risk scoring,
MongoDB storage, and dynamic firewall enforcement with SIEM-ready logging.
"""

import argparse
import sys
import time

from core.config import DEFAULT_FEED_INDICATORS, ENABLE_DEMO_FALLBACK
from core.logger import get_logger
from core.pipeline import run_demo, run_live
from policy_enforcer.firewall_manager import unblock_ip

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
    parser.add_argument(
        "--rollback",
        metavar="IP",
        help="Remove a previously applied firewall block rule",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Run in continuous and monitor for new threat indicators",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Monitoring interval in seconds while using --monitor.",
    )
    return parser.parse_args()


def format_ioc_output(ioc):
    """Format IOC processing results for display."""
    indicator = ioc['indicator']
    risk_score = ioc.get('risk_score', 0)
    ioc_type = ioc.get('type', 'unknown').upper()
    source = ioc.get('source', 'unknown')

    stored = "YES"
    siem_display = ioc.get("siem_status", "UNKNOWN")
    firewall_status = ioc.get("firewall_status", "SKIPPED")

    output = (
        f"\n✓ IOC: {indicator}\n"
        f"  Type: {ioc_type}\n"
        f"  Risk: {risk_score}/100\n"
        f"  Source: {source}\n"
        f"  Stored: {stored}\n"
        f"  SIEM: {siem_display}\n"
        f"  Firewall: {firewall_status}"
    )

    return output


def main():
    """Main entry point for the threat intelligence platform."""
    args = parse_arguments()
    
    # Rollback mode
    if args.rollback:
        logger.info("Rollback requested for %s", args.rollback)

        success = unblock_ip(args.rollback)

        if success:
            print("\n" + "=" * 70)
            print("FIREWALL ROLLBACK SUCCESS")
            print("=" * 70)
            print(f"\n✓ Removed firewall block for: {args.rollback}\n")
            print("=" * 70 + "\n")
            sys.exit(0)

        print("\n" + "=" * 70)
        print("FIREWALL ROLLBACK FAILED")
        print("=" * 70)
        print(f"\n✗ Unable to remove firewall block for: {args.rollback}\n")
        print("=" * 70 + "\n")
        sys.exit(1)

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
    if args.monitor:
        logger.info(
            "Starting continuous monitoring mode (interval=%s seconds)",
            args.interval,
        )

        while True:
            try:
                logger.info("Monitoring cycle started")

                if args.mode == "demo":
                    inserted = run_demo(indicators)
                else:
                    inserted = run_live(indicators)

                logger.info(
                    "Monitoring cycle complete. Processed %d IOCs",
                    len(inserted),
                )

                logger.info(
                    "Sleeping for %d seconds before next cycle",
                    args.interval,
                )

                time.sleep(args.interval)

            except KeyboardInterrupt:
                logger.warning("Monitoring stopped by user")
                sys.exit(0)

            except Exception as error:
                logger.error(
                    "Monitoring cycle failed: %s",
                    error,
                    exc_info=True,
                )

                time.sleep(args.interval)
    
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
        
        # Display detailed IOC output
        print("\n" + "="*70)
        print("THREAT INTELLIGENCE PLATFORM - IOC PROCESSING RESULTS")
        print("="*70)
        
        for ioc in inserted:
            print(format_ioc_output(ioc))
        
        print("\n" + "="*70)
        print(f"Total IOCs Processed: {len(inserted)}")
        print("="*70 + "\n")

    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user")
        sys.exit(0)
    except Exception as error:
        logger.error("Pipeline failed: %s", error, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
    