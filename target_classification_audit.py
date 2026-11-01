#!/usr/bin/env python3
"""R8B-09: Read-only firewall target classification and fail-closed audit."""

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LIMIT = 4 * 1024 * 1024

VERDICTS = {"ACCEPT", "DROP", "REJECT", "RETURN"}
EXTENSIONS = {
    "LOG", "NFLOG", "MARK", "CONNMARK",
    "CONNSECMARK", "SECMARK", "TRACE",
    "TCPMSS", "CLASSIFY", "DSCP", "TOS",
    "TTL", "HL", "AUDIT",
}

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

def parse_save(raw):
    table = None
    chains = {}
    policies = {}
    errors = 0

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith("*"):
            table = line[1:]
            continue
        if line == "COMMIT":
            table = None
            continue
        if table != "filter":
            continue

        if line.startswith(":"):
            match = re.match(
                r"^:([A-Za-z0-9_-]+)\s+(\S+)\s+\[",
                line,
            )
            if not match:
                errors += 1
                continue

            name, policy = match.groups()
            chains.setdefault(name, [])
            policies[name] = policy
            continue

        if line.startswith("-A "):
            try:
                tokens = shlex.split(line)
            except ValueError:
                errors += 1
                continue

            if len(tokens) < 3:
                errors += 1
                continue

            chain = tokens[1]
            chains.setdefault(chain, []).append(tokens[2:])

    return chains, policies, errors

def target_info(tokens, chain_names):
    indices = [
        i for i, token in enumerate(tokens)
        if token in {"-j", "--jump", "-g", "--goto"}
    ]

    if len(indices) != 1:
        return {
            "classification": "UNSUPPORTED",
            "target_type": "MISSING_OR_MULTIPLE",
            "flow": "NOT_VERIFIED",
        }

    index = indices[0]

    if index + 1 >= len(tokens):
        return {
            "classification": "PARSE_ERROR",
            "target_type": "MISSING_VALUE",
            "flow": "NOT_VERIFIED",
        }

    target = tokens[index + 1]
    kind = "GOTO" if tokens[index] in {"-g", "--goto"} else "JUMP"

    if target in chain_names:
        classification = "USER_CHAIN"
    elif target in VERDICTS:
        classification = "VERDICT"
    elif target in EXTENSIONS:
        classification = "EXTENSION"
    else:
        classification = "UNSUPPORTED"

    return {
        "classification": classification,
        "target_type": target if classification != "UNSUPPORTED" else "UNKNOWN",
        "flow": kind,
    }

def inspect_rules(chains):
    chain_names = set(chains)
    summaries = []
    counts = {
        "VERDICT": 0,
        "USER_CHAIN": 0,
        "EXTENSION": 0,
        "UNSUPPORTED": 0,
        "PARSE_ERROR": 0,
    }
    negations = 0

    for chain, rules in chains.items():
        for position, tokens in enumerate(rules, 1):
            info = target_info(tokens, chain_names)
            kind = info["classification"]
            counts[kind] += 1

            negated = "!" in tokens
            if negated:
                negations += 1

            summaries.append({
                "chain": chain,
                "position": position,
                "classification": kind,
                "target_type": info["target_type"],
                "flow": info["flow"],
                "negation_present": negated,
                "effective_packet_decision": "NOT_VERIFIED",
            })

    return {
        "rule_count": len(summaries),
        "counts": counts,
        "negated_rule_count": negations,
        "rules": summaries,
        "effective_packet_decision": "NOT_VERIFIED",
        "policy_approval": "BLOCKED",
    }

def self_test():
    chains = {
        "INPUT": [
            ["-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            ["-j", "DROP"],
            ["-j", "LOG"],
            ["-j", "MARK"],
            ["-j", "CONNMARK"],
            ["-j", "CUSTOM"],
            ["-g", "CUSTOM"],
            ["!", "-s", "192.0.2.0/24", "-j", "REJECT"],
            ["-j", "MYSTERY_TARGET"],
            ["-j"],
            ["-j", "ACCEPT", "-j", "DROP"],
        ],
        "CUSTOM": [["-j", "RETURN"]],
    }

    report = inspect_rules(chains)
    rows = report["rules"]

    checks = {
        "accept_verdict": rows[0]["classification"] == "VERDICT",
        "drop_verdict": rows[1]["target_type"] == "DROP",
        "log_extension": rows[2]["classification"] == "EXTENSION",
        "mark_extension": rows[3]["classification"] == "EXTENSION",
        "connmark_extension": rows[4]["classification"] == "EXTENSION",
        "user_chain_jump": rows[5]["classification"] == "USER_CHAIN",
        "user_chain_goto": rows[6]["flow"] == "GOTO",
        "negation_detected": rows[7]["negation_present"],
        "unknown_target": rows[8]["classification"] == "UNSUPPORTED",
        "missing_target": rows[9]["classification"] == "PARSE_ERROR",
        "multiple_targets": rows[10]["classification"] == "UNSUPPORTED",
        "return_verdict": rows[11]["target_type"] == "RETURN",
        "rule_order": rows[0]["position"] == 1 and rows[1]["position"] == 2,
        "fail_closed": all(
            row["effective_packet_decision"] == "NOT_VERIFIED"
            for row in rows
        ),
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

    families = {
        "IPv4": ["iptables-save"],
        "IPv6": ["ip6tables-save"],
    }

    results = {}

    for family, command in families.items():
        status, raw = run(command)

        if status != "OK":
            results[family] = {
                "status": status,
                "effective_packet_decision": "NOT_VERIFIED",
            }
            continue

        chains, policies, errors = parse_save(raw)
        analysis = inspect_rules(chains)

        results[family] = {
            "status": "OK" if errors == 0 else "PARTIAL",
            "parse_errors": errors,
            "input_default_policy": policies.get(
                "INPUT", "NOT_VERIFIED"
            ),
            "analysis": analysis,
        }

    report = {
        "schema": "R8B-09",
        "mode": "LIVE_READ_ONLY_TARGET_CLASSIFICATION",
        "families": results,
        "unknown_constructs_block_approval": True,
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
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if tests["result"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
