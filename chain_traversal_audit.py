#!/usr/bin/env python3
"""R8B-08: Conservative, read-only iptables chain-flow analysis."""

import argparse
import json
import re
import shlex
import os
import stat
import shutil
import selectors
import signal
import subprocess
import time
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LIMIT = 4 * 1024 * 1024
BUILTINS = {"INPUT", "OUTPUT", "FORWARD"}
VERDICTS = {"ACCEPT", "DROP", "REJECT", "RETURN"}
CONDITIONS = {
    "-s": "SOURCE_CIDR",
    "-d": "DESTINATION_CIDR",
    "-i": "INPUT_INTERFACE",
    "-o": "OUTPUT_INTERFACE",
    "--sport": "SOURCE_PORT",
    "--dport": "DESTINATION_PORT",
    "--sports": "SOURCE_PORT_SET",
    "--dports": "DESTINATION_PORT_SET",
    "--state": "CONNECTION_STATE",
    "--ctstate": "CONNECTION_STATE",
    "--tcp-flags": "TCP_FLAGS",
    "--icmp-type": "ICMP_TYPE",
    "--icmpv6-type": "ICMPV6_TYPE",
    "-m": "MATCH_MODULE",
}


_TRUSTED_EXEC_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def _resolve_trusted_executable(command):
    """Fail closed unless the resolved executable path is root-controlled."""
    if not isinstance(command, str) or not command or "\x00" in command:
        return None

    if os.path.isabs(command):
        if os.path.normpath(command) != command:
            return None
        if os.path.dirname(command) not in _TRUSTED_EXEC_DIRS:
            return None
        candidates = (command,)
    elif "/" in command or "\\" in command or command in (".", ".."):
        return None
    else:
        candidates = tuple(
            os.path.join(directory, command)
            for directory in _TRUSTED_EXEC_DIRS
        )

    for candidate in candidates:
        current = candidate
        visited = set()

        for _ in range(40):
            if current in visited:
                break
            visited.add(current)

            parts = current.split("/")[1:]
            cursor = "/"

            try:
                root_info = os.lstat("/")
                if (
                    not stat.S_ISDIR(root_info.st_mode)
                    or root_info.st_uid != 0
                    or root_info.st_mode & 0o022
                ):
                    break

                for index, component in enumerate(parts):
                    cursor = os.path.join(cursor, component)
                    info = os.lstat(cursor)

                    if info.st_uid != 0:
                        raise OSError("untrusted owner")

                    if stat.S_ISLNK(info.st_mode):
                        target = os.readlink(cursor)
                        if any(
                            component in (".", "..")
                            for component in target.split("/")
                        ):
                            raise OSError("unsafe symlink target")
                        remaining = parts[index + 1:]
                        current = os.path.normpath(
                            os.path.join(
                                os.path.dirname(cursor),
                                target,
                                *remaining,
                            )
                        )
                        if not os.path.isabs(current):
                            raise OSError("invalid symlink")
                        break

                    if info.st_mode & 0o022:
                        raise OSError("writable path")

                    if index < len(parts) - 1:
                        if not stat.S_ISDIR(info.st_mode):
                            raise OSError("non-directory component")
                    elif (
                        not stat.S_ISREG(info.st_mode)
                        or not info.st_mode & 0o111
                    ):
                        raise OSError("not executable")
                else:
                    if os.path.dirname(cursor) in _TRUSTED_EXEC_DIRS:
                        return cursor
                    break

            except (OSError, ValueError):
                break

    return None


def _bounded_collect(argv, limit, env):
    deadline = time.monotonic() + 10.0
    proc = None
    selector = None
    completed = False

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            close_fds=True,
            start_new_session=True,
        )

        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)

        output = bytearray()

        while True:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                return "TIMEOUT", b"", None

            events = selector.select(remaining)

            if not events:
                return "TIMEOUT", b"", None

            allowance = limit + 1 - len(output)
            count = min(65536, allowance)

            if count <= 0:
                return "OUTPUT_LIMIT", b"", None

            chunk = os.read(proc.stdout.fileno(), count)

            if not chunk:
                break

            output.extend(chunk)

            if len(output) > limit:
                return "OUTPUT_LIMIT", b"", None

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return "TIMEOUT", b"", None

        try:
            returncode = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            return "TIMEOUT", b"", None

        completed = True
        return "OK", bytes(output), returncode

    except (OSError, ValueError):
        return "ERROR", b"", None

    finally:
        if proc is not None:
            if not completed:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    try:
                        proc.kill()
                    except (OSError, ValueError, RuntimeError):
                        pass

                try:
                    proc.wait(timeout=0.5)
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    subprocess.TimeoutExpired,
                ):
                    pass

            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except (OSError, ValueError, RuntimeError):
                    pass

        if selector is not None:
            try:
                selector.close()
            except (OSError, ValueError, RuntimeError):
                pass


def run(argv):
    exe = _resolve_trusted_executable(argv[0])
    if not exe:
        return "UNAVAILABLE", ""

    status, raw, returncode = _bounded_collect(
        [exe, *argv[1:]],
        LIMIT,
        ENV,
    )

    if status != "OK":
        return status, ""

    if returncode != 0:
        return "ERROR", ""

    return "OK", raw.decode("utf-8", "replace")

def parse_save(raw):
    table = None
    chains = {}
    policies = {}
    parse_errors = 0

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
                parse_errors += 1
                continue

            name, policy = match.groups()
            chains.setdefault(name, [])
            policies[name] = policy
            continue

        if not line.startswith("-A "):
            continue

        try:
            tokens = shlex.split(line)
        except ValueError:
            parse_errors += 1
            continue

        if len(tokens) < 3:
            parse_errors += 1
            continue

        name = tokens[1]
        rule = tokens[2:]
        _, kind = rule_target(rule)
        if kind == "INVALID":
            parse_errors += 1
        chains.setdefault(name, []).append(rule)

    return chains, policies, parse_errors

def rule_target(tokens):
    target = None
    kind = "NONE"
    index = 0
    while index < len(tokens):
        token = tokens[index]
        # LOG prefixes and comments are literal values, not option streams.
        if token in {"--log-prefix", "--comment"}:
            if index + 1 >= len(tokens):
                return None, "INVALID"
            index += 2
            continue
        if token in {"-j", "--jump", "-g", "--goto"}:
            if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                return None, "INVALID"
            if target is not None:
                return None, "INVALID"
            target = tokens[index + 1]
            kind = "GOTO" if token in {"-g", "--goto"} else "JUMP"
            index += 2
            continue
        index += 1
    return target, kind

def conditions(tokens):
    found = set()

    for index, token in enumerate(tokens):
        if token in CONDITIONS:
            found.add(CONDITIONS[token])

        if token in {"--dport", "--sport", "--dports", "--sports"}:
            if index + 1 < len(tokens):
                value = tokens[index + 1]
                if ":" in value:
                    found.add("PORT_RANGE")

        if token in {"--state", "--ctstate"}:
            if index + 1 < len(tokens):
                value = tokens[index + 1].upper()
                if "ESTABLISHED" in value:
                    found.add("ESTABLISHED")
                if "RELATED" in value:
                    found.add("RELATED")

        if token == "!":
            found.add("NEGATION")

    return sorted(found)

def analyze(chains, policies):
    graph = {}
    targets = set()
    condition_types = set()
    rule_count = 0
    unknown_targets = set()
    goto_count = 0
    return_count = 0

    for chain, rules in chains.items():
        graph[chain] = []

        for tokens in rules:
            rule_count += 1
            condition_types.update(conditions(tokens))

            target, kind = rule_target(tokens)
            if target is None:
                continue

            targets.add(target)

            if target == "RETURN":
                return_count += 1

            if kind == "GOTO":
                goto_count += 1

            if target in chains:
                graph[chain].append(target)
            elif target not in VERDICTS:
                unknown_targets.add(target)

    cycles = set()
    visited = set()
    active = set()

    def visit(node):
        if node in active:
            cycles.add(node)
            return

        if node in visited:
            return

        visited.add(node)
        active.add(node)

        for next_node in graph.get(node, []):
            visit(next_node)

        active.remove(node)

    for chain in graph:
        visit(chain)

    reachable = set()

    def walk(node):
        if node in reachable:
            return
        reachable.add(node)
        for next_node in graph.get(node, []):
            walk(next_node)

    if "INPUT" in chains:
        walk("INPUT")

    return {
        "input_default_policy": policies.get(
            "INPUT", "NOT_VERIFIED"
        ),
        "chain_count": len(chains),
        "rule_count": rule_count,
        "input_direct_rule_count": len(chains.get("INPUT", [])),
        "input_reachable_chain_count": len(reachable),
        "input_reachable_chains": sorted(reachable),
        "condition_types": sorted(condition_types),
        "goto_count": goto_count,
        "return_count": return_count,
        "cycle_detected": bool(cycles),
        "cycle_nodes": sorted(cycles),
        "unknown_target_count": len(unknown_targets),
        "target_types": sorted(targets & VERDICTS),
        "effective_packet_decision": "NOT_VERIFIED",
        "rule_order_considered": True,
        "rule_order_fully_evaluated": False,
    }

def self_test():
    sample = """*filter
:INPUT DROP [0:0]
:TEST - [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i eth0 -s 192.0.2.0/24 -p tcp --dport 8000:9000 -j TEST
-A TEST -j RETURN
COMMIT
"""
    chains, policies, errors = parse_save(sample)
    report = analyze(chains, policies)

    cycle_sample = """*filter
:INPUT DROP [0:0]
:A - [0:0]
:B - [0:0]
-A INPUT -j A
-A A -j B
-A B -j A
COMMIT
"""
    c, p, _ = parse_save(cycle_sample)

    ipv6_sample = """*filter
:INPUT DROP [0:0]
-A INPUT -p ipv6-icmp -j ACCEPT
COMMIT
"""
    c6, p6, _ = parse_save(ipv6_sample)

    checks = {
        "parse_no_error": errors == 0,
        "input_policy_drop": report["input_default_policy"] == "DROP",
        "chain_traversal": "TEST" in report["input_reachable_chains"],
        "state_established": "ESTABLISHED" in report["condition_types"],
        "state_related": "RELATED" in report["condition_types"],
        "interface_condition": "INPUT_INTERFACE" in report["condition_types"],
        "source_cidr_condition": "SOURCE_CIDR" in report["condition_types"],
        "port_range": "PORT_RANGE" in report["condition_types"],
        "return_detected": report["return_count"] == 1,
        "cycle_detected": analyze(c, p)["cycle_detected"],
        "ipv6_policy": analyze(c6, p6)["input_default_policy"] == "DROP",
        "no_effective_verdict":
            report["effective_packet_decision"] == "NOT_VERIFIED",
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
        analysis = analyze(chains, policies)
        analysis["parse_errors"] = errors

        results[family] = {
            "status": "OK" if errors == 0 else "PARTIAL",
            "analysis": analysis,
        }

    report = {
        "schema": "R8B-08",
        "mode": "LIVE_READ_ONLY_CHAIN_TRAVERSAL",
        "families": results,
        "nftables_expression_evaluation": "NOT_IMPLEMENTED",
        "ufw_backend": "NOT_DETERMINED",
        "nat_effective_behavior": "NOT_VERIFIED",
        "forwarding_effective_behavior": "NOT_VERIFIED",
        "ipv6_dual_stack_behavior": "NOT_VERIFIED",
        "wsl_host_boundary": "NOT_VERIFIED",
        "ssh_anti_lockout": "NOT_VERIFIED",
        "public_reachability": "NOT_VERIFIED",
        "effective_firewall_policy": "NOT_VERIFIED",
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
