#!/usr/bin/env python3
"""R8B-12: Privacy-preserving, read-only iptables match-module mapping."""

import argparse
import collections
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

# Static diagnostic schema, not an authorization allowlist.
# Option values are NEVER included in the report.
MODULE_SCHEMA = {
    "tcp": {
        "--sport": "VALUE",
        "--source-port": "VALUE",
        "--dport": "VALUE",
        "--destination-port": "VALUE",
        "--tcp-flags": "TWO_VALUES",
        "--tcp-option": "VALUE",
        "--syn": "FLAG",
    },
    "udp": {
        "--sport": "VALUE",
        "--source-port": "VALUE",
        "--dport": "VALUE",
        "--destination-port": "VALUE",
    },
    "multiport": {
        "--sports": "VALUE",
        "--source-ports": "VALUE",
        "--dports": "VALUE",
        "--destination-ports": "VALUE",
        "--ports": "VALUE",
    },
    "conntrack": {
        "--ctstate": "VALUE",
        "--ctproto": "VALUE",
        "--ctorigsrc": "VALUE",
        "--ctorigdst": "VALUE",
        "--ctreplsrc": "VALUE",
        "--ctrepldst": "VALUE",
        "--ctorigsrcport": "VALUE",
        "--ctorigdstport": "VALUE",
        "--ctreplsrcport": "VALUE",
        "--ctrepldstport": "VALUE",
        "--ctdir": "VALUE",
        "--ctstatus": "VALUE",
        "--ctexpire": "VALUE",
    },
    "state": {
        "--state": "VALUE",
    },
    "comment": {
        "--comment": "VALUE",
    },
    "limit": {
        "--limit": "VALUE",
        "--limit-burst": "VALUE",
    },
    "mark": {
        "--mark": "VALUE",
    },
    "addrtype": {
        "--src-type": "VALUE",
        "--dst-type": "VALUE",
        "--limit-iface-in": "FLAG",
        "--limit-iface-out": "FLAG",
    },
    "icmp": {
        "--icmp-type": "VALUE",
    },
    "icmp6": {
        "--icmpv6-type": "VALUE",
    },
    "ipv6-icmp": {
        "--icmpv6-type": "VALUE",
    },
    "owner": {
        "--uid-owner": "VALUE",
        "--gid-owner": "VALUE",
        "--socket-exists": "FLAG",
        "--suppl-groups": "FLAG",
    },
    "cgroup": {
        "--cgroup": "VALUE",
        "--path": "VALUE",
    },
    "socket": {
        "--transparent": "FLAG",
        "--nowildcard": "FLAG",
        "--restore-skmark": "FLAG",
    },
}

BASE_OPTIONS = {
    "-p": "VALUE",
    "--protocol": "VALUE",
    "-s": "VALUE",
    "--source": "VALUE",
    "-d": "VALUE",
    "--destination": "VALUE",
    "-i": "VALUE",
    "--in-interface": "VALUE",
    "-o": "VALUE",
    "--out-interface": "VALUE",
    "-f": "FLAG",
    "--fragment": "FLAG",
    "-m": "VALUE",
    "--match": "VALUE",
    "-j": "VALUE",
    "--jump": "VALUE",
    "-g": "VALUE",
    "--goto": "VALUE",
}

TARGET_SCHEMA = {
    "LOG": {
        "--log-prefix": "VALUE",
        "--log-level": "VALUE",
        "--log-tcp-sequence": "FLAG",
        "--log-tcp-options": "FLAG",
        "--log-ip-options": "FLAG",
        "--log-uid": "FLAG",
    },
    "REJECT": {
        "--reject-with": "VALUE",
    },
    "MARK": {
        "--set-mark": "VALUE",
        "--set-xmark": "VALUE",
        "--and-mark": "VALUE",
        "--or-mark": "VALUE",
        "--xor-mark": "VALUE",
    },
    "CONNMARK": {
        "--set-mark": "VALUE",
        "--save-mark": "FLAG",
        "--restore-mark": "FLAG",
        "--mask": "VALUE",
        "--nfmask": "VALUE",
        "--ctmask": "VALUE",
    },
}

KNOWN_TARGETS = {
    "ACCEPT", "DROP", "REJECT", "RETURN",
    "LOG", "NFLOG", "MARK", "CONNMARK",
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


def run(command):
    exe = _resolve_trusted_executable(command)
    if not exe:
        return "UNAVAILABLE", ""
    status, raw, returncode = _bounded_collect([exe], LIMIT, ENV)
    if status != "OK": return status, ""
    if returncode != 0: return "ERROR", ""
    return "OK", raw.decode("utf-8", "replace")


def _bounded_collect(argv, limit, env):
    deadline=time.monotonic()+10; proc=selector=None; completed=False
    try:
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,close_fds=True,start_new_session=True)
        selector=selectors.DefaultSelector(); selector.register(proc.stdout,selectors.EVENT_READ); output=bytearray()
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not selector.select(remaining): return "TIMEOUT",b"",None
            count=min(65536,limit+1-len(output))
            if count<=0:return "OUTPUT_LIMIT",b"",None
            chunk=os.read(proc.stdout.fileno(),count)
            if not chunk:break
            output.extend(chunk)
            if len(output)>limit:return "OUTPUT_LIMIT",b"",None
        remaining=deadline-time.monotonic()
        if remaining<=0:return "TIMEOUT",b"",None
        try:returncode=proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:return "TIMEOUT",b"",None
        completed=True;return "OK",bytes(output),returncode
    except (OSError,ValueError):return "ERROR",b"",None
    finally:
        if proc is not None:
            if not completed:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except OSError:
                    try:proc.kill()
                    except (OSError,ValueError,RuntimeError):pass
                try:proc.wait(timeout=.5)
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):pass
            if proc.stdout is not None:
                try:proc.stdout.close()
                except (OSError,ValueError,RuntimeError):pass
        if selector is not None:
            try:selector.close()
            except (OSError,ValueError,RuntimeError):pass

def safe_module(name):
    return name if name in MODULE_SCHEMA else "REDACTED_UNKNOWN_MODULE"

def safe_option(name):
    known = set(BASE_OPTIONS)
    for schema in MODULE_SCHEMA.values():
        known.update(schema)
    for schema in TARGET_SCHEMA.values():
        known.update(schema)
    return name if name in known else "REDACTED_UNKNOWN_OPTION"

def parse_save(raw):
    table = None
    filter_seen = False
    filter_committed = False
    errors = 0
    rules = []

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
            if table is None:
                errors += 1
            if table == "filter":
                filter_committed = True
            table = None
            continue

        if table != "filter" or not line.startswith("-A "):
            continue

        try:
            parts = shlex.split(line)
        except ValueError:
            errors += 1
            continue

        if len(parts) < 3:
            errors += 1
            continue

        rules.append((parts[1], parts[2:]))

    if table is not None or not filter_seen or not filter_committed:
        errors += 1

    return rules, errors

def classify(tokens):
    findings = []
    modules = []
    mapped = []
    index = 0
    target = None
    negation_pending = False
    seen_targets = 0

    def add(category, option="NONE", module="NONE"):
        item = {
            "category": category,
            "option": safe_option(option),
            "module": safe_module(module)
            if module != "NONE" else "NONE",
        }
        if item not in findings:
            findings.append(item)

    # First pass: collect declared match modules and target.
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"-m", "--match"} and i + 1 < len(tokens):
            modules.append(tokens[i + 1].lower())
            i += 2
            continue
        if token in {"--comment", "--log-prefix"} and i + 1 < len(tokens):
            # These values are literal text and may themselves be "-j".
            i += 2
            continue
        if token in {"-j", "--jump", "-g", "--goto"}:
            seen_targets += 1
            if i + 1 < len(tokens):
                target = tokens[i + 1]
                i += 2
                continue
        i += 1

    if seen_targets != 1:
        add("TARGET_COUNT_INVALID")

    for module in modules:
        if module not in MODULE_SCHEMA:
            add("UNKNOWN_MODULE", "-m", module)

    while index < len(tokens):
        token = tokens[index]

        if token == "!":
            if negation_pending or index + 1 >= len(tokens):
                add("INVALID_NEGATION")
            negation_pending = True
            index += 1
            continue

        owners = []
        if token in BASE_OPTIONS:
            owners.append(("BASE", BASE_OPTIONS[token]))

        for module in modules:
            schema = MODULE_SCHEMA.get(module, {})
            if token in schema:
                owners.append((module, schema[token]))

        if target in TARGET_SCHEMA and token in TARGET_SCHEMA[target]:
            owners.append(("TARGET", TARGET_SCHEMA[target][token]))

        if not owners:
            add("UNKNOWN_OPTION", token)
            negation_pending = False
            index += 1
            continue

        # Same option may be owned by more than one module.
        # No packet semantics are inferred from such mappings.
        unique_owners = set(owners)
        if len(unique_owners) > 1:
            add("AMBIGUOUS_OPTION_OWNERSHIP", token)

        arities = {arity for _, arity in unique_owners}
        if len(arities) != 1:
            add("AMBIGUOUS_OPTION_ARITY", token)
            negation_pending = False
            index += 1
            continue

        arity = next(iter(arities))
        needed = {"FLAG": 0, "VALUE": 1, "TWO_VALUES": 2}[arity]

        if index + needed >= len(tokens):
            add("MISSING_VALUE", token)
            break

        values = tokens[index + 1:index + 1 + needed]
        if any(
            value == "!"
            or (
                token not in {"--comment", "--log-prefix"}
                and (
                    value in BASE_OPTIONS
                    or value in {
                        option
                        for schema in MODULE_SCHEMA.values()
                        for option in schema
                    }
                    or value in {
                        option
                        for schema in TARGET_SCHEMA.values()
                        for option in schema
                    }
                    or value.startswith("--")
                )
            )
            for value in values
        ):
            add("MISSING_VALUE", token)
            index += 1
            negation_pending = False
            continue

        if negation_pending and token in {
            "-j", "--jump", "-g", "--goto",
            "-m", "--match",
        }:
            add("UNSUPPORTED_NEGATION", token)

        negation_pending = False

        if token in {"-m", "--match"}:
            pass
        elif token in {"-j", "--jump", "-g", "--goto"}:
            pass
        else:
            mapped.append({
                "option": safe_option(token),
                "owner_count": len(unique_owners),
            })

        index += 1 + needed

    if negation_pending:
        add("INVALID_NEGATION")

    if findings:
        if any(x["category"] in {
            "MISSING_VALUE", "INVALID_NEGATION", "TARGET_COUNT_INVALID",
        } for x in findings):
            status = "PARSE_ERROR"
        elif any(x["category"].startswith("AMBIGUOUS") for x in findings):
            status = "AMBIGUOUS"
        else:
            status = "UNSUPPORTED"
    else:
        status = "KNOWN_MAPPED"

    return {
        "status": status,
        "modules": sorted({safe_module(m) for m in modules}),
        "target": target if target in KNOWN_TARGETS else "REDACTED_TARGET",
        "mapped_options": mapped,
        "findings": findings,
        "effective_packet_decision": "NOT_VERIFIED",
    }

def inspect(raw, family):
    rules, parse_errors = parse_save(raw)
    positions = collections.Counter()
    results = []
    counts = collections.Counter()

    for chain, tokens in rules:
        positions[chain] += 1
        result = classify(tokens)
        counts[result["status"]] += 1

        if result["modules"] or result["findings"]:
            results.append({
                "family": family,
                "chain": chain if re.fullmatch(
                    r"[A-Za-z0-9_-]{1,64}", chain
                ) else "REDACTED_CHAIN",
                "position": positions[chain],
                **result,
            })

    return {
        "rule_count": len(rules),
        "parse_errors": parse_errors,
        "classification_counts": dict(counts),
        "module_diagnostics": results,
        "all_rules_semantically_verified": False,
        "effective_packet_decision": "NOT_VERIFIED",
        "policy_approval": "BLOCKED",
    }

def self_test():
    def status(tokens):
        return classify(tokens)["status"]

    def categories(tokens):
        return {
            item["category"] for item in classify(tokens)["findings"]
        }

    checks = {
        "owner_uid_mapping": status([
            "-m", "owner", "--uid-owner", "1000", "-j", "ACCEPT"
        ]) == "KNOWN_MAPPED",
        "owner_gid_mapping": status([
            "-m", "owner", "--gid-owner", "1000", "-j", "DROP"
        ]) == "KNOWN_MAPPED",
        "owner_socket_flag": status([
            "-m", "owner", "--socket-exists", "-j", "DROP"
        ]) == "KNOWN_MAPPED",
        "cgroup_path_mapping": status([
            "-m", "cgroup", "--path", "system.slice", "-j", "DROP"
        ]) == "KNOWN_MAPPED",
        "unknown_module": "UNKNOWN_MODULE" in categories([
            "-m", "mystery", "--x", "1", "-j", "DROP"
        ]),
        "unknown_option": "UNKNOWN_OPTION" in categories([
            "-m", "owner", "--mystery", "1", "-j", "DROP"
        ]),
        "missing_value": "MISSING_VALUE" in categories([
            "-m", "owner", "--uid-owner", "-j", "DROP"
        ]),
        "missing_value_short_jump": "MISSING_VALUE" in categories([
            "-m", "owner", "--gid-owner", "-j", "DROP"
        ]),
        "missing_value_short_match": "MISSING_VALUE" in categories([
            "-p", "-m", "owner", "-j", "DROP"
        ]),
        "missing_value_long_option": "MISSING_VALUE" in categories([
            "-m", "owner", "--uid-owner", "--gid-owner",
            "1000", "-j", "DROP"
        ]),
        "valid_owner_rule_still_mapped": status([
            "-m", "owner", "--uid-owner", "1000", "-j", "DROP"
        ]) == "KNOWN_MAPPED",
        "invalid_negation": "INVALID_NEGATION" in categories([
            "-m", "owner", "!", "!", "--uid-owner", "1000",
            "-j", "DROP",
        ]),
        "unsupported_negation": "UNSUPPORTED_NEGATION" in categories([
            "!", "-m", "owner", "-j", "DROP"
        ]),
        "log_mapping": status([
            "-j", "LOG", "--log-prefix", "FW:"
        ]) == "KNOWN_MAPPED",
        "target_count": "TARGET_COUNT_INVALID" in categories([
            "-m", "owner", "--uid-owner", "1000"
        ]),
        "fail_closed": classify([
            "-m", "owner", "--uid-owner", "1000", "-j", "ACCEPT"
        ])["effective_packet_decision"] == "NOT_VERIFIED",
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

    families = {}

    for family, command in (
        ("IPv4", "iptables-save"),
        ("IPv6", "ip6tables-save"),
    ):
        status, raw = run(command)

        if status != "OK":
            families[family] = {
                "status": status,
                "effective_packet_decision": "NOT_VERIFIED",
            }
            continue

        families[family] = {
            "status": "OK",
            "analysis": inspect(raw, family),
        }

    print(json.dumps({
        "schema": "R8B-12",
        "mode": "LIVE_READ_ONLY_SAFE_MATCH_MODULE_MAPPING",
        "families": families,
        "mapping_is_diagnostic_only": True,
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
