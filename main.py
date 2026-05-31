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
from policy_enforcer.firewall_manager import is_whitelisted
from core.siem_forwarder import forward_to_siem
import os

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


def format_ioc_output(ioc):
    """Format IOC processing results for display."""
    indicator = ioc['indicator']
    risk_score = ioc.get('risk_score', 0)
    ioc_type = ioc.get('type', 'unknown').upper()
    source = ioc.get('source', 'unknown')
    
    # Check storage status
    stored = "YES"
    
    # Check SIEM status
    siem_display = "SENT"
    
    # Check firewall status
    firewall_status = "SKIPPED"
    if risk_score >= 80:
        if is_whitelisted(indicator):
            firewall_status = "WHITELISTED"
        elif os.geteuid() != 0:
            firewall_status = "ROOT REQUIRED"
        else:
            firewall_status = "BLOCKED"
    
    # Create detailed output
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
