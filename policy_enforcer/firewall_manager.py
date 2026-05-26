import subprocess


def sudo_available():
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
    return result.returncode == 0


def rule_exists(ip):
    if not sudo_available():
        return False

    command = [
        "sudo",
        "iptables",
        "-C",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP",
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0


def block_ip(ip):
    if not sudo_available():
        print(f"[-] sudo is not available; skipping firewall block for {ip}")
        return False

    if rule_exists(ip):
        print(f"[i] Firewall rule already exists for {ip}")
        return False

    command = [
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP",
    ]

    try:
        subprocess.run(command, check=True)
        print(f"[+] Blocked malicious IP: {ip}")
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Failed to block IP: {ip}")
        return False


def unblock_ip(ip):
    if not sudo_available():
        print(f"[-] sudo is not available; skipping unblock for {ip}")
        return False

    command = [
        "sudo",
        "iptables",
        "-D",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP",
    ]

    try:
        subprocess.run(command, check=True)
        print(f"[+] Removed firewall rule for {ip}")
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Failed to remove firewall rule for {ip}")
        return False
