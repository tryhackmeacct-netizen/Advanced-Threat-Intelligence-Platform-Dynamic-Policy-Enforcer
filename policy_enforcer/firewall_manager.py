import ipaddress
import os
import shutil
import subprocess
from pathlib import Path

import core.config as config
from core.logger import get_logger

logger = get_logger("firewall")


def load_whitelist():
    whitelist_file = Path(__file__).resolve().parents[1] / "config" / "whitelist.txt"
    entries = []

    if not whitelist_file.exists():
        return entries

    with whitelist_file.open() as f:
        for line in f:
            value = line.strip()
            if not value or value.startswith("#"):
                continue

            try:
                if "/" in value:
                    entries.append(ipaddress.ip_network(value, strict=False))
                else:
                    entries.append(ipaddress.ip_address(value))
            except ValueError:
                entries.append(value.lower())

    return entries


def is_whitelisted(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for item in load_whitelist():
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if address in item:
                return True
        elif isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if address == item:
                return True
        elif isinstance(item, str):
            if ip.lower() == item:
                return True

    return False


def block_ip(ip):
    """
    Block malicious IP using iptables.
    Returns:
        - True: Successfully blocked
        - False: Skipped (whitelisted, disabled, or no root)
    """
    if not config.FIREWALL_ENABLED:
        logger.info("Firewall is disabled, skipping block for %s", ip)
        return False

    if is_whitelisted(ip):
        logger.info("Skipping whitelisted IP: %s", ip)
        return False

    # Check for root privileges
    if os.geteuid() != 0:
        logger.warning(
            "Firewall enforcement skipped for %s. Root privileges required. "
            "Run with 'sudo' or use --firewall-disabled in production.",
            ip
        )
        return False

    command = [find_iptables_command(), "-A", "INPUT", "-s", ip, "-j", "DROP"]
    logger.debug("Applying iptables rule for %s: %s", ip, " ".join(command))

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        logger.info("Blocked malicious IP: %s", ip)
        if result.stdout:
            logger.debug("iptables stdout: %s", result.stdout.strip())
        if result.stderr:
            logger.debug("iptables stderr: %s", result.stderr.strip())
        return True
    except FileNotFoundError:
        logger.error("iptables binary not found. Firewall could not apply rule for %s", ip)
        return False
    except subprocess.CalledProcessError as error:
        logger.error("Firewall update failed for %s: %s", ip, error)
        return False


def unblock_ip(ip):
    """
    Remove a previously blocked IP address from iptables.
    Returns:
        - True: Successfully unblocked
        - False: Skipped or failed
    """
    if not config.FIREWALL_ENABLED:
        logger.info("Firewall is disabled, skipping unblock for %s", ip)
        return False

    if is_whitelisted(ip):
        logger.info("Skipping whitelist removal for %s", ip)
        return False

    if os.geteuid() != 0:
        logger.warning(
            "Firewall rollback skipped for %s. Root privileges required.",
            ip,
        )
        return False

    command = [find_iptables_command(), "-D", "INPUT", "-s", ip, "-j", "DROP"]
    logger.debug("Removing iptables rule for %s: %s", ip, " ".join(command))

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        logger.info("Unblocked IP: %s", ip)
        if result.stdout:
            logger.debug("iptables stdout: %s", result.stdout.strip())
        if result.stderr:
            logger.debug("iptables stderr: %s", result.stderr.strip())
        return True
    except FileNotFoundError:
        logger.error("iptables binary not found. Firewall could not remove rule for %s", ip)
        return False
    except subprocess.CalledProcessError as error:
        logger.warning("No matching firewall rule found for %s or removal failed: %s", ip, error)
        return False


def record_blocked_ip(ip, source, risk_score):
    """Record a blocked IP event for auditing and future rollback.
    This helper currently logs the event and can be extended to persist audit data.
    """
    logger.info("Recording blocked IP: %s source=%s risk_score=%s", ip, source, risk_score)
    return True


def find_iptables_command():
    path = shutil.which("iptables")
    if not path:
        raise FileNotFoundError("iptables command not found")
    return path