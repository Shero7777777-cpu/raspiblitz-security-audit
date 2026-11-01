#!/usr/bin/env python3
"""R8B-11: Privacy-preserving, read-only firewall condition diagnostics."""

import argparse
import collections
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LIMIT = 4 * 1024 * 1024

OPTIONS = {
    "-p": "protocol", "--protocol": "protocol",
    "-s": "source", "--source": "source",
    "-d": "destination", "--destination": "destination",
    "-i": "in_interface", "--in-interface": "in_interface",
    "-o": "out_interface", "--out-interface": "out_interface",
    "-m": "module", "--match": "module",
    "-j": "target", "--jump": "target",
    "-g": "target", "--goto": "target",
    "--sport": "source_port", "--source-port": "source_port",
    "--dport": "destination_port", "--destination-port": "destination_port",
    "--sports": "source_ports", "--dports": "destination_ports",
    "--ctstate": "states", "--state": "states",
    "--comment": "comment",
    "--limit": "limit", "--limit-burst": "limit_burst",
    "--log-prefix": "log_prefix",
    "--log-level": "log_level",
    "--log-tcp-sequence": "log_flag",
    "--log-tcp-options": "log_flag",
    "--log-ip-options": "log_flag",
    "--log-uid": "log_flag",
    "--icmp-type": "icmp_type",
    "--icmpv6-type": "icmpv6_type",
    "--mark": "mark",
    "--src-type": "src_type", "--dst-type": "dst_type",
}

MODULES = {
    "tcp", "udp", "multiport", "conntrack", "state",
    "comment", "icmp", "icmp6", "ipv6-icmp",
    "addrtype", "limit", "hashlimit", "mark",
}

PROTOCOLS = {
    "tcp", "udp", "icmp", "icmpv6", "ipv6-icmp",
    "esp", "ah", "all",
}

STATES = {
    "NEW", "ESTABLISHED", "RELATED", "INVALID",
    "UNTRACKED", "SNAT", "DNAT",
}

FLAG_OPTIONS = {
    "--log-tcp-sequence", "--log-tcp-options",
    "--log-ip-options", "--log-uid",
}

LOG_OPTIONS = {
    "--log-prefix", "--log-level",
    *FLAG_OPTIONS,
}

PORT_OPTIONS = {
    "source_port", "destination_port",
    "source_ports", "destination_ports",
}

REPEATABLE = {"module"}

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

    if len(p.stdout) > LIMIT:
        return "OUTPUT_LIMIT", ""
    if p.returncode != 0:
        return "ERROR", ""

    return "OK", p.stdout.decode("utf-8", "replace")

def port_ok(value):
    if not re.fullmatch(r"\d+(?::\d+)?", value):
        return False

    numbers = [int(x) for x in value.split(":")]
    return all(0 <= x <= 65535 for x in numbers) and (
        len(numbers) == 1 or numbers[0] <= numbers[1]
    )

def safe_option(token):
    # Never echo arbitrary token values into diagnostic output.
    if token in OPTIONS:
        return token
    return "UNKNOWN_OPTION_REDACTED"

def diagnose(tokens, family):
    findings = []
    seen = collections.Counter()
    protocol = None
    target = None
    modules = set()
    has_ports = False
    index = 0
    pending_negation = False

    def add(category, option="NONE"):
        item = {"category": category, "option": safe_option(option)}
        if item not in findings:
            findings.append(item)

    while index < len(tokens):
        token = tokens[index]

        if token == "!":
            if pending_negation or index + 1 >= len(tokens):
                add("INVALID_NEGATION")
            pending_negation = True
            index += 1
            continue

        kind = OPTIONS.get(token)

        if kind is None:
            add("UNKNOWN_OPTION", token)
            pending_negation = False
            index += 1
            continue

        seen[kind] += 1

        if seen[kind] > 1 and kind not in REPEATABLE:
            add("DUPLICATE_OPTION", token)

        if token in FLAG_OPTIONS:
            if pending_negation:
                add("UNSUPPORTED_NEGATION", token)
            pending_negation = False
            index += 1
            continue

        if index + 1 >= len(tokens):
            add("MISSING_VALUE", token)
            break

        value = tokens[index + 1]

        if value == "!" or value.startswith("-"):
            add("MISSING_VALUE", token)
            pending_negation = False
            index += 1
            continue

        if pending_negation and kind in {
            "target", "module", "comment", "log_prefix",
        }:
            add("UNSUPPORTED_NEGATION", token)

        pending_negation = False

        if kind == "protocol":
            protocol = value.lower()
            if protocol not in PROTOCOLS:
                add("UNSUPPORTED_PROTOCOL", token)

        elif kind in {"source", "destination"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
                expected = 4 if family == "IPv4" else 6
                if network.version != expected:
                    add("ADDRESS_FAMILY_MISMATCH", token)
            except ValueError:
                add("INVALID_CIDR", token)

        elif kind == "module":
            modules.add(value.lower())
            if value.lower() not in MODULES:
                add("UNSUPPORTED_MODULE", token)

        elif kind in PORT_OPTIONS:
            has_ports = True
            values = value.split(",") if kind.endswith("ports") else [value]
            if not values or not all(port_ok(v) for v in values):
                add("INVALID_PORT", token)

        elif kind == "states":
            states = value.upper().split(",")
            if not states or not all(s in STATES for s in states):
                add("UNSUPPORTED_STATE", token)

        elif kind == "target":
            target = value

        elif kind == "log_level":
            if not re.fullmatch(r"[0-7]", value):
                add("UNSUPPORTED_LOG_LEVEL", token)

        elif kind == "log_prefix":
            if len(value) > 29:
                add("INVALID_LOG_PREFIX", token)

        index += 2

    if pending_negation:
        add("INVALID_NEGATION")

    if has_ports and protocol not in {"tcp", "udp"}:
        add("PORT_PROTOCOL_MISMATCH")

    if seen["target"] != 1:
        add("TARGET_COUNT_INVALID")

    if any(token in LOG_OPTIONS for token in tokens) and target != "LOG":
        add("LOG_OPTION_WITHOUT_LOG_TARGET")

    if target == "LOG" and any(
        token in tokens for token in {
            "--log-tcp-sequence", "--log-tcp-options",
        }
    ) and protocol != "tcp":
        add("LOG_TCP_OPTION_PROTOCOL_MISMATCH")

    if not findings:
        status = "NO_DIAGNOSTIC_FINDINGS"
    elif any(item["category"] in {
        "MISSING_VALUE", "INVALID_NEGATION", "TARGET_COUNT_INVALID",
    } for item in findings):
        status = "PARSE_ERROR"
    else:
        status = "UNSUPPORTED"

    return {"status": status, "findings": findings}

def parse_save(raw):
    table = None
    rules = []
    errors = 0
    filter_seen = False
    filter_committed = False

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith("*"):
            if table is not None:
                errors += 1
            table = line[1:]
            if table == "filter":
                filter_seen = True
            continue

        if line == "COMMIT":
            if table == "filter":
                filter_committed = True
            if table is None:
                errors += 1
            table = None
            continue

        if table != "filter" or not line.startswith("-A "):
            continue

        try:
            tokens = shlex.split(line)
        except ValueError:
            errors += 1
            continue

        if len(tokens) < 3:
            errors += 1
            continue

        rules.append((tokens[1], tokens[2:]))

    if table is not None or not filter_seen or not filter_committed:
        errors += 1

    return rules, errors

def inspect(raw, family):
    rules, parse_errors = parse_save(raw)
    findings = []
    counts = collections.Counter()

    positions = collections.Counter()

    for chain, tokens in rules:
        positions[chain] += 1
        result = diagnose(tokens, family)
        counts[result["status"]] += 1

        if result["findings"]:
            findings.append({
                "family": family,
                "chain": chain,
                "position": positions[chain],
                "status": result["status"],
                "findings": result["findings"],
            })

    return {
        "rule_count": len(rules),
        "status_counts": dict(counts),
        "parse_errors": parse_errors,
        "diagnostic_findings": findings,
        "all_rules_verified": False,
        "effective_packet_decision": "NOT_VERIFIED",
        "policy_approval": "BLOCKED",
    }

def self_test():
    def status(tokens):
        return diagnose(tokens, "IPv4")["status"]

    def categories(tokens):
        return {
            x["category"] for x in diagnose(tokens, "IPv4")["findings"]
        }

    checks = {
        "valid_tcp_rule": status(
            ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"]
        ) == "NO_DIAGNOSTIC_FINDINGS",
        "unknown_option": "UNKNOWN_OPTION" in categories(
            ["--mystery", "abc", "-j", "DROP"]
        ),
        "missing_value": "MISSING_VALUE" in categories(
            ["-p"]
        ),
        "duplicate_protocol": "DUPLICATE_OPTION" in categories(
            ["-p", "tcp", "-p", "udp", "-j", "DROP"]
        ),
        "duplicate_target": "DUPLICATE_OPTION" in categories(
            ["-j", "DROP", "-j", "ACCEPT"]
        ),
        "trailing_negation": "INVALID_NEGATION" in categories(
            ["-p", "tcp", "!", "-j", "DROP", "!"]
        ),
        "port_protocol_mismatch": "PORT_PROTOCOL_MISMATCH" in categories(
            ["-p", "icmp", "--dport", "443", "-j", "DROP"]
        ),
        "invalid_port": "INVALID_PORT" in categories(
            ["-p", "tcp", "--dport", "70000", "-j", "DROP"]
        ),
        "log_prefix": status(
            ["-j", "LOG", "--log-prefix", "FW:"]
        ) == "NO_DIAGNOSTIC_FINDINGS",
        "log_level": status(
            ["-j", "LOG", "--log-level", "4"]
        ) == "NO_DIAGNOSTIC_FINDINGS",
        "log_without_target": "LOG_OPTION_WITHOUT_LOG_TARGET" in categories(
            ["-j", "DROP", "--log-level", "4"]
        ),
        "log_tcp_mismatch": "LOG_TCP_OPTION_PROTOCOL_MISMATCH" in categories(
            ["-p", "udp", "-j", "LOG", "--log-tcp-options"]
        ),
        "family_mismatch": "ADDRESS_FAMILY_MISMATCH" in categories(
            ["-s", "2001:db8::/32", "-j", "DROP"]
        ),
        "incomplete_save": parse_save(
            "*filter\n:INPUT ACCEPT [0:0]\n"
        )[1] > 0,
        "fail_closed": inspect(
            "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n",
            "IPv4",
        )["effective_packet_decision"] == "NOT_VERIFIED",
    }

    return {
        "result": "PASS" if all(checks.values()) else "FAIL",
        "passed": sum(checks.values()),
        "total": len(checks),
        "tests": checks,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--audit", action="store_true")
    modes.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    tests = self_test()

    if args.self_test:
        print(json.dumps(tests, indent=2, sort_keys=True))
        return 0 if tests["result"] == "PASS" else 1

    results = {}

    for family, command in (
        ("IPv4", ["iptables-save"]),
        ("IPv6", ["ip6tables-save"]),
    ):
        status, raw = run(command)

        if status != "OK":
            results[family] = {
                "status": status,
                "effective_packet_decision": "NOT_VERIFIED",
            }
            continue

        results[family] = {
            "status": "OK",
            "analysis": inspect(raw, family),
        }

    print(json.dumps({
        "schema": "R8B-11",
        "mode": "LIVE_READ_ONLY_UNSUPPORTED_CONDITION_DIAGNOSTICS",
        "families": results,
        "automatic_private_network_trust": False,
        "effective_firewall_policy": "NOT_VERIFIED",
        "ssh_anti_lockout": "NOT_VERIFIED",
        "public_reachability": "NOT_VERIFIED",
        "firewall_apply": "NOT_IMPLEMENTED",
        "policy_approval": "BLOCKED",
        "raspiblitz_validation": "NOT_PERFORMED",
        "regressions": {
            "result": tests["result"],
            "passed": tests["passed"],
            "total": tests["total"],
        },
    }, indent=2, sort_keys=True))

    return 0 if tests["result"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
