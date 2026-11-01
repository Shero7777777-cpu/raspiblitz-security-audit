#!/usr/bin/env python3
"""R8B-06: Local, read-only firewall evidence and regression audit."""

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys

ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

MAX_OUTPUT = 4 * 1024 * 1024

def run(argv):
    exe = shutil.which(argv[0])
    if not exe:
        return "UNAVAILABLE", ""

    try:
        p = subprocess.run(
            [exe, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=ENV,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except OSError:
        return "ERROR", ""

    if len(p.stdout) > MAX_OUTPUT:
        return "OUTPUT_LIMIT", ""

    if p.returncode != 0:
        return "ERROR", ""

    return "OK", p.stdout.decode("utf-8", "replace")

def endpoint(value):
    if value.startswith("["):
        match = re.fullmatch(r"\[(.+)\]:(\d+)", value)
        if match:
            return match.group(1), int(match.group(2))

    if ":" not in value:
        return None, None

    address, port = value.rsplit(":", 1)
    if not port.isdecimal():
        return None, None

    return address, int(port)

def classify_bind(address):
    if address in {"*", "0.0.0.0", "::"}:
        return "WILDCARD"

    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "UNKNOWN"

    if ip.is_unspecified:
        return "WILDCARD"
    if ip.is_loopback:
        return "LOOPBACK"
    if ip.is_link_local:
        return "LINK_LOCAL"

    return "SPECIFIC_ADDRESS"

def trust_decision(address):
    """No address is automatically trusted."""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return "NOT_TRUSTED"

    return "NOT_TRUSTED"

def inspect_family(family, flag):
    status, output = run([
        "ss", flag, "-H", "-l", "-n", "-t", "-u"
    ])

    if status != "OK":
        return {
            "status": status,
            "family": family,
            "listener_count": None,
            "wildcard": None,
            "loopback": None,
            "specific": None,
            "external_reachability": "NOT_VERIFIED",
        }

    entries = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue

        proto = fields[0].lower()
        if proto not in {"tcp", "udp"}:
            continue

        address, port = endpoint(fields[4])
        if address is None:
            continue

        entries.append({
            "protocol": proto,
            "port": port,
            "bind": classify_bind(address),
            "trusted": False,
            "publicly_reachable": "NOT_VERIFIED",
        })

    return {
        "status": "OK",
        "family": family,
        "listener_count": len(entries),
        "wildcard": sum(
            x["bind"] == "WILDCARD" for x in entries
        ),
        "loopback": sum(
            x["bind"] == "LOOPBACK" for x in entries
        ),
        "specific": sum(
            x["bind"] == "SPECIFIC_ADDRESS" for x in entries
        ),
        "external_reachability": "NOT_VERIFIED",
        "listeners": entries,
    }

def firewall_backends():
    commands = {
        "ufw": ["ufw", "status", "verbose"],
        "nftables": ["nft", "-j", "list", "ruleset"],
        "iptables": ["iptables-save"],
        "ip6tables": ["ip6tables-save"],
    }

    result = {}
    for name, command in commands.items():
        status, output = run(command)
        result[name] = {
            "status": status,
            "data_read": status == "OK",
            "raw_rules_redacted": True,
            "output_nonempty": bool(output.strip()) if status == "OK" else None,
            "effective_packet_decision": "NOT_VERIFIED",
        }

    return result

def regressions():
    tests = {
        "ipv4_wildcard": classify_bind("0.0.0.0") == "WILDCARD",
        "ipv6_wildcard": classify_bind("::") == "WILDCARD",
        "star_wildcard": classify_bind("*") == "WILDCARD",
        "ipv4_loopback": classify_bind("127.0.0.1") == "LOOPBACK",
        "ipv6_loopback": classify_bind("::1") == "LOOPBACK",
        "private_ipv4_not_trusted":
            trust_decision("192.0.2.0/24") == "NOT_TRUSTED",
        "private_ipv4_10_not_trusted":
            trust_decision("10.8.0.40") == "NOT_TRUSTED",
        "private_ipv6_not_trusted":
            trust_decision("fd00::1") == "NOT_TRUSTED",
        "public_ipv4_not_trusted":
            trust_decision("8.8.8.8") == "NOT_TRUSTED",
        "unknown_not_trusted":
            trust_decision("not-an-address") == "NOT_TRUSTED",
        "ipv4_endpoint":
            endpoint("127.0.0.1:9010") == ("127.0.0.1", 9010),
        "ipv6_endpoint":
            endpoint("[::1]:9010") == ("::1", 9010),
    }

    return {
        "tests": tests,
        "passed": sum(tests.values()),
        "total": len(tests),
        "result": "PASS" if all(tests.values()) else "FAIL",
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.audit == args.self_test:
        parser.error("Choose exactly one: --audit or --self-test")

    tests = regressions()

    if args.self_test:
        print(json.dumps(tests, indent=2, sort_keys=True))
        return 0 if tests["result"] == "PASS" else 1

    ipv4 = inspect_family("IPv4", "-4")
    ipv6 = inspect_family("IPv6", "-6")
    backends = firewall_backends()

    available = [
        name for name, value in backends.items()
        if value["status"] == "OK"
    ]

    report = {
        "schema": "R8B-06",
        "mode": "LIVE_READ_ONLY_FIREWALL_AUDIT",
        "ipv4": ipv4,
        "ipv6": ipv6,
        "firewall_backends": backends,
        "multiple_backends_readable": len(available) > 1,
        "backend_conflict": "NOT_DETERMINED",
        "effective_firewall_policy": "NOT_VERIFIED",
        "public_reachability": "NOT_VERIFIED",
        "automatic_private_network_trust": False,
        "ssh_anti_lockout": "NOT_VERIFIED",
        "regressions": {
            "result": tests["result"],
            "passed": tests["passed"],
            "total": tests["total"],
        },
        "firewall_apply": "NOT_IMPLEMENTED",
        "policy_approval": "BLOCKED",
        "raspiblitz_validation": "NOT_PERFORMED",
    }

    print(json.dumps(report, indent=2, sort_keys=True))

    return 0 if tests["result"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
