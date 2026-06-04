#!/usr/bin/env python3

import os
import sys
import argparse

# Ensure project root is on sys.path when running this file directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from policy_enforcer.enforcer_daemon import monitor_enforcement
from policy_enforcer.rollback import rollback_ip


def main():
    parser = argparse.ArgumentParser(
        description="Policy enforcement helper for daemon start and rollback actions"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser(
        "start-daemon",
        help="Start the continuous policy enforcement daemon",
    )
    start_parser.add_argument(
        "--interval",
        type=int,
        default=15,
        help="Polling interval in seconds for checking new high-risk IOCs",
    )

    rollback_parser = subparsers.add_parser(
        "rollback",
        help="Rollback a blocked IP and remove its firewall rule",
    )
    rollback_parser.add_argument("ip", help="IP address to unblock")
    rollback_parser.add_argument(
        "--reason",
        default="manual_unblock",
        help="Reason for rollback metadata",
    )

    args = parser.parse_args()

    if args.command == "start-daemon":
        monitor_enforcement(poll_seconds=args.interval)
    elif args.command == "rollback":
        rollback_ip(args.ip, reason=args.reason)


if __name__ == "__main__":
    main()
