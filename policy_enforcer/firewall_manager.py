import subprocess


def block_ip(ip):
    """
    Block a malicious IP using iptables.
    """
    command = [
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP"
    ]

    try:
        subprocess.run(command, check=True)
        print(f"[+] Blocked malicious IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[-] Failed to block IP: {ip}")
