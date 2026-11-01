#!/usr/bin/env python3
"""R8B-03: Read-only local network/service classification preview."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

PORTS = {
    ("tcp", 22): ("SSH", "PRIVATE_CANDIDATE"),
    ("tcp", 8333): ("BITCOIN_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 18333): ("BITCOIN_TESTNET_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 38333): ("BITCOIN_SIGNET_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 8332): ("BITCOIN_RPC", "PRIVATE_CANDIDATE"),
    ("tcp", 18332): ("BITCOIN_TESTNET_RPC", "PRIVATE_CANDIDATE"),
    ("tcp", 38332): ("BITCOIN_SIGNET_RPC", "PRIVATE_CANDIDATE"),
    ("tcp", 9735): ("LIGHTNING_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 10009): ("LND_GRPC", "PRIVATE_CANDIDATE"),
    ("tcp", 8080): ("LND_REST_OR_OTHER", "UNCLASSIFIED"),
    ("tcp", 50001): ("ELECTRUM_TCP", "PRIVATE_CANDIDATE"),
    ("tcp", 50002): ("ELECTRUM_TLS", "PRIVATE_CANDIDATE"),
    ("tcp", 9050): ("TOR_SOCKS", "PRIVATE_CANDIDATE"),
    ("tcp", 9051): ("TOR_CONTROL", "PRIVATE_CANDIDATE"),
    ("tcp", 8118): ("HTTP_PROXY", "PRIVATE_CANDIDATE"),
    ("tcp", 1194): ("OPENVPN_TCP", "UNCLASSIFIED"),
    ("udp", 1194): ("OPENVPN_UDP", "UNCLASSIFIED"),
    ("tcp", 443): ("HTTPS_OR_VPN", "UNCLASSIFIED"),
    ("udp", 53): ("DNS", "PRIVATE_CANDIDATE"),
    ("tcp", 53): ("DNS", "PRIVATE_CANDIDATE"),
}

def run(argv, accept_nonzero=False):
    executable = shutil.which(argv[0])
    if not executable:
        return "UNAVAILABLE", ""
    try:
        result = subprocess.run(
            [executable, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=ENV,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "ERROR", ""
    if len(result.stdout) > 4 * 1024 * 1024:
        return "OUTPUT_LIMIT", ""
    if result.returncode != 0 and not accept_nonzero:
        return "ERROR", ""
    return "OK", result.stdout.decode("utf-8", errors="replace")

def classify(proto, port):
    return PORTS.get(
        (proto, port),
        ("UNKNOWN", "UNCLASSIFIED"),
    )

def listeners():
    status, raw = run(["ss", "-H", "-l", "-n", "-t", "-u"])
    if status != "OK":
        return {"status": status}

    result = {
        "status": "OK",
        "total": 0,
        "public_candidates": 0,
        "private_candidates": 0,
        "unclassified": 0,
        "candidate_services": [],
        "endpoints_redacted": True,
    }

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in {"tcp", "udp"}:
            continue
        local = parts[4]
        match = re.search(r":(\d+)$", local)
        if not match:
            continue

        port = int(match.group(1))
        name, category = classify(proto, port)
        result["total"] += 1

        if category == "PUBLIC_CANDIDATE":
            result["public_candidates"] += 1
        elif category == "PRIVATE_CANDIDATE":
            result["private_candidates"] += 1
        else:
            result["unclassified"] += 1

        if name != "UNKNOWN":
            result["candidate_services"].append({
                "service": name,
                "category": category,
                "port": port,
                "protocol": proto,
                "identity_verified": False,
                "reachability_verified": False,
            })

    return result

def ssh():
    paths = [
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/sbin/sshd",
    ]
    executable = next(
        (p for p in paths if os.path.isfile(p) and os.access(p, os.X_OK)),
        None,
    )
    if executable is None:
        return {
            "status": "UNAVAILABLE",
            "listener_may_still_exist": True,
        }

    status, raw = run([executable, "-T"])
    if status != "OK":
        return {"status": status}

    ports = []
    for line in raw.splitlines():
        match = re.fullmatch(r"port\s+(\d+)", line.strip())
        if match:
            ports.append(int(match.group(1)))

    return {
        "status": "OK",
        "configured_port_count": len(ports),
        "configured_ports_redacted": True,
        "active_ssh_path_verified": False,
    }

def systemd():
    status, raw = run(
        ["systemctl", "is-system-running"],
        accept_nonzero=True,
    )
    if status != "OK":
        return {"status": status}

    state = raw.strip()
    allowed = {
        "running", "degraded", "maintenance",
        "starting", "stopping", "offline",
        "initializing",
    }
    return {
        "status": "OK",
        "state": state if state in allowed else "UNKNOWN",
        "nonzero_exit_is_not_automatically_error": True,
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit", action="store_true", required=True)
    args = p.parse_args()

    report = {
        "schema": "R8B-03",
        "mode": "LIVE_READ_ONLY_CLASSIFICATION",
        "raspiblitz_compatibility": "UNVERIFIED",
        "trust_policy": "EXPLICIT_ONLY",
        "classification_method": "PORT_HEURISTIC_ONLY",
        "firewall_apply_available": False,
        "policy_rules_generated": False,
        "ssh_anti_lockout_verified": False,
        "checks": {},
    }

    report["checks"]["listeners"] = listeners()
    report["checks"]["ssh"] = ssh()
    report["checks"]["systemd"] = systemd()

    for name, argv in {
        "interfaces": ["ip", "-j", "address", "show"],
        "routes": ["ip", "-j", "route", "show", "table", "all"],
        "ufw": ["ufw", "status"],
        "nftables": ["nft", "-j", "list", "ruleset"],
        "iptables": ["iptables-save"],
        "ip6tables": ["ip6tables-save"],
    }.items():
        status, raw = run(argv)
        report["checks"][name] = {
            "status": status,
            "raw_details_redacted": True,
            "data_read": status == "OK",
        }

    report["checks"]["tailscale"] = {
        "client_available": shutil.which("tailscale") is not None,
        "trusted": False,
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
