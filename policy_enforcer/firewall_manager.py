import platform
import ipaddress
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

from core.config import BLOCKED_IPS_COLLECTION, DB_NAME, FIREWALL_ENABLED, MONGO_URI
from core.logger import get_logger

logger = get_logger()

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


def get_blocked_ips_collection():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    return db[BLOCKED_IPS_COLLECTION]


def record_blocked_ip(ip, source, risk_score):
    blocked_collection = get_blocked_ips_collection()
    blocked_collection.update_one(
        {"ip": ip},
        {
            "$set": {
                "ip": ip,
                "source": source,
                "risk_score": risk_score,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "rule_status": "active",
            }
        },
        upsert=True,
    )


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
        address = None

    for item in load_whitelist():
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if address and address in item:
                return True
        elif isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if address == item:
                return True
        elif isinstance(item, str):
            if ip.lower() == item:
                return True

    return False


def _run_command(command):
    return subprocess.run(command, capture_output=True, text=True)


def _windows_rule_name(ip):
    return f"TIP_BLOCK_{ip}"


def _windows_rule_exists(ip):
    rule_name = _windows_rule_name(ip)
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        f"name={rule_name}",
    ]
    result = _run_command(command)
    return result.returncode == 0 and "No rules match" not in result.stdout


def _windows_block_ip(ip):
    rule_name = _windows_rule_name(ip)
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        "remoteip=" + ip,
        "enable=yes",
        "profile=any",
    ]
    result = _run_command(command)
    if result.returncode != 0:
        logger.error("Windows firewall blocking failed: %s", result.stderr.strip() or result.stdout.strip())
        return False
    logger.info("Blocked malicious IP using Windows firewall: %s", ip)
    return True


def _windows_unblock_ip(ip):
    rule_name = _windows_rule_name(ip)
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}",
    ]
    result = _run_command(command)
    if result.returncode != 0:
        logger.error("Windows firewall unblock failed: %s", result.stderr.strip() or result.stdout.strip())
        return False
    logger.info("Removed Windows firewall rule for %s", ip)
    return True


def _linux_rule_exists(ip):
    command = [
        "iptables",
        "-C",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP",
    ]
    result = _run_command(command)
    return result.returncode == 0


def _linux_block_ip(ip):
    command = [
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP",
    ]
    result = _run_command(command)
    if result.returncode != 0:
        logger.error("Linux firewall blocking failed: %s", result.stderr.strip() or result.stdout.strip())
        return False
    logger.info("Blocked malicious IP using iptables: %s", ip)
    return True


def _linux_unblock_ip(ip):
    command = [
        "iptables",
        "-D",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP",
    ]
    result = _run_command(command)
    if result.returncode != 0:
        logger.error("Linux firewall unblock failed: %s", result.stderr.strip() or result.stdout.strip())
        return False
    logger.info("Removed iptables rule for %s", ip)
    return True


def block_ip(ip):
    if not FIREWALL_ENABLED:
        logger.info("Firewall is disabled, skipping block for %s", ip)
        return False

    if is_whitelisted(ip):
        logger.info("Skipping whitelisted IP: %s", ip)
        return False

    try:
        if IS_WINDOWS:
            if _windows_rule_exists(ip):
                logger.warning("IP already blocked: %s", ip)
                return False
            return _windows_block_ip(ip)

        if IS_LINUX:
            if _linux_rule_exists(ip):
                logger.warning("IP already blocked: %s", ip)
                return False
            return _linux_block_ip(ip)

        logger.error("Firewall blocking is not supported on this platform: %s", platform.system())
        return False
    except FileNotFoundError as error:
        logger.error("Firewall command not found: %s", error)
        return False
    except subprocess.CalledProcessError as error:
        logger.error("Firewall blocking failed: %s", error)
        return False


def unblock_ip(ip):
    try:
        if IS_WINDOWS:
            return _windows_unblock_ip(ip)

        if IS_LINUX:
            return _linux_unblock_ip(ip)

        logger.error("Firewall unblock is not supported on this platform: %s", platform.system())
        return False
    except FileNotFoundError as error:
        logger.error("Firewall command not found: %s", error)
        return False
    except subprocess.CalledProcessError as error:
        logger.error("Firewall unblock failed: %s", error)
        return False
