#!/usr/bin/env python3
"""Command-line rollback utility for blocked IP addresses."""

import argparse
from policy_enforcer.rollback import rollback_ip


def parse_args():
    parser = argparse.ArgumentParser(
        description="Rollback a blocked IP address and remove the corresponding firewall rule."
    )
    parser.add_argument(
        "--ip",
        required=True,
        help="IPv4 or IPv6 address to rollback.",
    )
    parser.add_argument(
        "--reason",
        default="manual_unblock",
        help="Reason for rollback (default: manual_unblock).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    success = rollback_ip(args.ip, reason=args.reason)
    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
