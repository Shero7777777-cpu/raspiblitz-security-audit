#!/usr/bin/env python3
"""R8B-10: Strict, read-only iptables condition validation."""

import argparse
import ipaddress
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

MODULES = {
    "tcp", "udp", "multiport", "conntrack", "state",
    "comment", "icmp", "icmp6", "ipv6-icmp",
    "addrtype", "limit", "hashlimit", "mark",
}

PROTOCOLS = {
    "tcp", "udp", "icmp", "ipv6-icmp",
    "icmpv6", "all", "esp", "ah",
}

STATES = {
    "NEW", "ESTABLISHED", "RELATED", "INVALID",
    "UNTRACKED", "SNAT", "DNAT",
}

VALUE_OPTIONS = {
    "-p": "PROTOCOL",
    "--protocol": "PROTOCOL",
    "-s": "SOURCE_CIDR",
    "--source": "SOURCE_CIDR",
    "-d": "DESTINATION_CIDR",
    "--destination": "DESTINATION_CIDR",
    "-i": "INTERFACE",
    "--in-interface": "INTERFACE",
    "-o": "INTERFACE",
    "--out-interface": "INTERFACE",
    "--sport": "PORT",
    "--source-port": "PORT",
    "--dport": "PORT",
    "--destination-port": "PORT",
    "--sports": "PORT_LIST",
    "--dports": "PORT_LIST",
    "--state": "STATES",
    "--ctstate": "STATES",
    "-m": "MODULE",
    "--match": "MODULE",
    "-j": "TARGET",
    "--jump": "TARGET",
    "-g": "TARGET",
    "--goto": "TARGET",
    "--comment": "COMMENT",
    "--log-prefix": "COMMENT",
    "-c": "COUNTER",
    "--icmp-type": "ICMP_TYPE",
    "--icmpv6-type": "ICMP_TYPE",
    "--limit": "LIMIT",
    "--limit-burst": "INTEGER",
    "--mark": "MARK",
    "--src-type": "ADDRTYPE",
    "--dst-type": "ADDRTYPE",
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
    proc = selector = None
    completed = False
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            close_fds=True, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        output = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "TIMEOUT", b"", None
            if not selector.select(remaining):
                return "TIMEOUT", b"", None
            count = min(65536, limit + 1 - len(output))
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
                    try: proc.kill()
                    except (OSError, ValueError, RuntimeError): pass
                try: proc.wait(timeout=0.5)
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired): pass
            if proc.stdout is not None:
                try: proc.stdout.close()
                except (OSError, ValueError, RuntimeError): pass
        if selector is not None:
            try: selector.close()
            except (OSError, ValueError, RuntimeError): pass


def run(argv):
    exe = _resolve_trusted_executable(argv[0])
    if not exe:
        return "UNAVAILABLE", ""
    status, raw, returncode = _bounded_collect([exe, *argv[1:]], LIMIT, ENV)
    if status != "OK":
        return status, ""
    if returncode != 0:
        return "ERROR", ""
    return "OK", raw.decode("utf-8", "replace")

def valid_port(value):
    if not re.fullmatch(r"\d+(?::\d+)?", value):
        return False

    parts = [int(x) for x in value.split(":")]
    return all(0 <= x <= 65535 for x in parts) and (
        len(parts) == 1 or parts[0] <= parts[1]
    )

def valid_port_list(value):
    parts = value.split(",")
    return bool(parts) and all(valid_port(x) for x in parts)

def valid_interface(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}\+?", value))

def valid_cidr(value, family):
    try:
        address = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False

    return address.version == (4 if family == "IPv4" else 6)

def valid_states(value):
    parts = value.upper().split(",")
    return bool(parts) and all(x in STATES for x in parts)

def validate_value(kind, value, family):
    if kind == "PROTOCOL":
        return value.lower() in PROTOCOLS

    if kind in {"SOURCE_CIDR", "DESTINATION_CIDR"}:
        return valid_cidr(value, family)

    if kind == "INTERFACE":
        return valid_interface(value)

    if kind == "PORT":
        return valid_port(value)

    if kind == "PORT_LIST":
        return valid_port_list(value)

    if kind == "STATES":
        return valid_states(value)

    if kind == "MODULE":
        return value.lower() in MODULES

    if kind == "TARGET":
        return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value))

    if kind == "COMMENT":
        return len(value) <= 256

    if kind == "ICMP_TYPE":
        return bool(re.fullmatch(r"[A-Za-z0-9_/-]{1,64}", value))

    if kind == "LIMIT":
        return bool(re.fullmatch(r"\d+/(second|minute|hour|day)", value))

    if kind == "INTEGER":
        return value.isdecimal()

    if kind == "MARK":
        return bool(re.fullmatch(
            r"(0x[0-9a-fA-F]+|\d+)(/(0x[0-9a-fA-F]+|\d+))?",
            value,
        ))

    if kind == "ADDRTYPE":
        return bool(re.fullmatch(r"[A-Z,]{1,64}", value))

    return False

def validate_rule(tokens, family):
    errors = []
    unsupported = []
    seen = []
    negations = 0
    target_count = 0
    index = 0

    while index < len(tokens):
        token = tokens[index]

        if token == "!":
            negations += 1
            if index + 1 >= len(tokens):
                errors.append("TRAILING_NEGATION")
            index += 1
            continue

        kind = VALUE_OPTIONS.get(token)

        if kind is None:
            unsupported.append("UNKNOWN_OPTION")
            index += 1
            continue

        needed = 2 if kind == "COUNTER" else 1
        if index + needed >= len(tokens):
            errors.append("MISSING_VALUE")
            index += 1
            continue

        values = tokens[index + 1:index + 1 + needed]
        if any(value == "!" or value.startswith("--") for value in values):
            errors.append("MISSING_VALUE")
            index += 1
            continue

        if kind == "COUNTER":
            if not all(re.fullmatch(r"[0-9]+", value) for value in values):
                unsupported.append("UNSUPPORTED_VALUE")
        elif not validate_value(kind, values[0], family):
            unsupported.append("UNSUPPORTED_VALUE")

        seen.append(kind)
        if kind == "TARGET":
            target_count += 1
        index += 1 + needed

    if target_count > 1:
        errors.append("MULTIPLE_TARGETS")

    if errors:
        status = "PARSE_ERROR"
    elif unsupported:
        status = "UNSUPPORTED"
    else:
        status = "SUPPORTED_SYNTAX_ONLY"

    return {
        "status": status,
        "error_count": len(errors),
        "unsupported_count": len(unsupported),
        "negation_count": negations,
        "condition_types": sorted(set(seen)),
        "effective_packet_decision": "NOT_VERIFIED",
    }

def parse_save(raw):
    table = None
    committed = False
    filter_seen = False
    filter_committed = False
    rules = []
    errors = 0

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith("*"):
            if table is not None and not committed:
                errors += 1
            table = line[1:]
            if table == "filter":
                filter_seen = True
            committed = False
            continue

        if line == "COMMIT":
            if table is None or committed:
                errors += 1
                continue
            if table == "filter":
                filter_committed = True
            table = None
            committed = True
            continue

        if line.startswith("-A ") and table != "filter":
            errors += 1
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

    if (
        (table is not None and not committed)
        or not filter_seen
        or not filter_committed
    ):
        errors += 1

    return rules, errors

def inspect(raw, family):
    rules, parse_errors = parse_save(raw)
    counts = {
        "SUPPORTED_SYNTAX_ONLY": 0,
        "UNSUPPORTED": 0,
        "PARSE_ERROR": 0,
    }
    condition_types = set()
    negated = 0

    for chain, tokens in rules:
        result = validate_rule(tokens, family)
        counts[result["status"]] += 1
        condition_types.update(result["condition_types"])
        negated += result["negation_count"]

    return {
        "rule_count": len(rules),
        "counts": counts,
        "parse_errors": parse_errors,
        "negation_count": negated,
        "condition_types": sorted(condition_types),
        "all_conditions_supported": (
            parse_errors == 0
            and counts["UNSUPPORTED"] == 0
            and counts["PARSE_ERROR"] == 0
        ),
        "effective_packet_decision": "NOT_VERIFIED",
        "policy_approval": "BLOCKED",
    }

def self_test():
    checks = {
        "valid_ipv4": valid_cidr("192.0.2.0/24", "IPv4"),
        "reject_ipv6_in_ipv4": not valid_cidr("2001:db8::/32", "IPv4"),
        "valid_ipv6": valid_cidr("2001:db8::/32", "IPv6"),
        "valid_port_range": valid_port("8000:9000"),
        "reject_reverse_range": not valid_port("9000:8000"),
        "valid_multiport": valid_port_list("22,80,8000:9000"),
        "reject_invalid_port": not valid_port("70000"),
        "valid_interface": valid_interface("tailscale0"),
        "valid_states": valid_states("ESTABLISHED,RELATED"),
        "reject_unknown_state": not valid_states("MYSTERY"),
        "reject_unknown_module": not validate_value(
            "MODULE", "mystery", "IPv4"
        ),
        "unknown_option": validate_rule(
            ["--mystery", "1", "-j", "ACCEPT"], "IPv4"
        )["status"] == "UNSUPPORTED",
        "missing_value": validate_rule(
            ["-p"], "IPv4"
        )["status"] == "PARSE_ERROR",
        "trailing_negation": validate_rule(
            ["-p", "tcp", "!"], "IPv4"
        )["status"] == "PARSE_ERROR",
        "supported_tcp_rule": validate_rule(
            ["-p", "tcp", "-m", "tcp",
             "--dport", "443", "-j", "ACCEPT"], "IPv4"
        )["status"] == "SUPPORTED_SYNTAX_ONLY",
        "fail_closed": validate_rule(
            ["-j", "DROP"], "IPv4"
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
                "all_conditions_supported": False,
                "effective_packet_decision": "NOT_VERIFIED",
            }
            continue

        results[family] = {
            "status": "OK",
            "analysis": inspect(raw, family),
        }

    report = {
        "schema": "R8B-10",
        "mode": "LIVE_READ_ONLY_STRICT_CONDITION_VALIDATION",
        "families": results,
        "effective_firewall_policy": "NOT_VERIFIED",
        "automatic_private_network_trust": False,
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
