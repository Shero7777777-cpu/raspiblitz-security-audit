#!/usr/bin/env python3
"""R8B-05: Read-only listener, bind, process and SSH audit."""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys

ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

MAX_BYTES = 4 * 1024 * 1024

SENSITIVE_PORTS = {
    2222, 5400, 8300, 10000, 50000, 50505,
    9010, 9011, 9012, 9013, 8200,
    5330, 5333, 5334, 5335, 11500,
}

SSH_PATHS = (
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
)

def run(argv, allow_nonzero=False):
    executable = shutil.which(argv[0])
    if not executable:
        return "UNAVAILABLE", "", None

    try:
        proc = subprocess.run(
            [executable, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=ENV,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", None
    except OSError:
        return "ERROR", "", None

    if len(proc.stdout) > MAX_BYTES:
        return "OUTPUT_LIMIT", "", proc.returncode

    if proc.returncode != 0 and not allow_nonzero:
        return "ERROR", "", proc.returncode

    return (
        "OK",
        proc.stdout.decode("utf-8", errors="replace"),
        proc.returncode,
    )

def split_endpoint(value):
    """Extract numeric port without exposing address."""
    if value.startswith("["):
        match = re.fullmatch(r"\[(.+)\]:(\d+)", value)
        if not match:
            return None, None
        return match.group(1), int(match.group(2))

    if ":" not in value:
        return None, None

    address, port = value.rsplit(":", 1)
    if not port.isdecimal():
        return None, None

    return address, int(port)

def bind_class(address):
    if address in {"*", "0.0.0.0", "::"}:
        return "WILDCARD"

    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "UNKNOWN"

    if ip.is_loopback:
        return "LOOPBACK"

    if ip.is_link_local:
        return "LINK_LOCAL"

    if ip.is_unspecified:
        return "WILDCARD"

    return "SPECIFIC_ADDRESS"

def family_of(address):
    if address == "*":
        return "UNKNOWN"

    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        return "UNKNOWN"

def process_metadata(line):
    """Extract only process labels and whether a PID was visible."""
    matches = re.findall(
        r'\("([^"]{1,80})",pid=(\d+)',
        line,
    )
    if not matches:
        return {
            "process_visible": False,
            "process_labels": [],
            "pid_redacted": True,
        }

    labels = sorted({name for name, _ in matches})
    return {
        "process_visible": True,
        "process_labels": labels,
        "pid_redacted": True,
    }

def collect():
    status, raw, _ = run(
        ["ss", "-H", "-l", "-n", "-t", "-u", "-p"]
    )
    if status != "OK":
        return status, []

    entries = []

    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue

        proto = fields[0].lower()
        if proto not in {"tcp", "udp"}:
            continue

        address, port = split_endpoint(fields[4])
        if address is None:
            continue

        metadata = process_metadata(line)

        entries.append({
            "protocol": proto,
            "port": port,
            "address_family": family_of(address),
            "bind_class": bind_class(address),
            "sensitive_port": port in SENSITIVE_PORTS,
            "process": metadata,
            "identity_verified": False,
            "external_reachability_verified": False,
        })

    return "OK", entries

def ssh_status(entries):
    sshd = next(
        (
            path for path in SSH_PATHS
            if os.path.isfile(path) and os.access(path, os.X_OK)
        ),
        None,
    )

    ssh_process_listeners = [
        item for item in entries
        if "sshd" in item["process"]["process_labels"]
    ]

    result = {
        "sshd_binary_available": sshd is not None,
        "sshd_process_listener_count": len(ssh_process_listeners),
        "active_ssh_environment": bool(os.environ.get("SSH_CONNECTION")),
        "configured_port_count": None,
        "configuration_status": "UNAVAILABLE",
        "anti_lockout": "NOT_VERIFIED",
    }

    if sshd:
        status, output, _ = run([sshd, "-T"])
        result["configuration_status"] = status
        if status == "OK":
            result["configured_port_count"] = sum(
                1 for line in output.splitlines()
                if re.fullmatch(r"port\s+\d+", line.strip())
            )

    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true", required=True)
    args = parser.parse_args()

    status, entries = collect()

    counts = {
        "loopback": 0,
        "wildcard": 0,
        "specific_address": 0,
        "link_local": 0,
        "unknown": 0,
        "ipv4": 0,
        "ipv6": 0,
        "family_unknown": 0,
        "sensitive": 0,
        "process_visible": 0,
    }

    for item in entries:
        counts[item["bind_class"].lower()] += 1
        counts[
            item["address_family"].lower()
            if item["address_family"] != "UNKNOWN"
            else "family_unknown"
        ] += 1
        counts["sensitive"] += int(item["sensitive_port"])
        counts["process_visible"] += int(
            item["process"]["process_visible"]
        )

    report = {
        "schema": "R8B-05",
        "mode": "LIVE_READ_ONLY_BIND_AUDIT",
        "listener_status": status,
        "listener_count": len(entries),
        "counts": counts,
        "listeners": entries,
        "ssh": ssh_status(entries),
        "trust": {
            "automatic_lan_trust": False,
            "automatic_vpn_trust": False,
            "automatic_rfc1918_trust": False,
        },
        "firewall_apply": "NOT_IMPLEMENTED",
        "policy_approval": "BLOCKED",
        "raspiblitz_validation": "NOT_PERFORMED",
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
