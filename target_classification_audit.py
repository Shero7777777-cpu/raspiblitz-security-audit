#!/usr/bin/env python3
"""R8B-09: Read-only firewall target classification and fail-closed audit."""

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

VERDICTS = {"ACCEPT", "DROP", "REJECT", "RETURN"}
EXTENSIONS = {
    "LOG", "NFLOG", "MARK", "CONNMARK",
    "CONNSECMARK", "SECMARK", "TRACE",
    "TCPMSS", "CLASSIFY", "DSCP", "TOS",
    "TTL", "HL", "AUDIT",
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
    committed = False
    chains = {}
    policies = {}
    errors = 0

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith("*"):
            if table is not None and not committed:
                errors += 1
            table = line[1:]
            committed = False
            continue
        if line == "COMMIT":
            if table is None or committed:
                errors += 1
                continue
            table = None
            committed = True
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

    if table is not None and not committed:
        errors += 1

    return chains, policies, errors

def target_info(tokens, chain_names):
    target_options = {"-j", "--jump", "-g", "--goto"}
    value_options = {
        "-p", "--protocol", "-s", "--source", "-d", "--destination",
        "-i", "--in-interface", "-o", "--out-interface", "-m",
        "--match", "-c", "--comment", "--log-prefix", "--dport", "--sport",
        "--dports", "--sports", "--tcp-flags", "--ctstate", "--state",
    }
    targets = []
    malformed = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in target_options:
            if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                malformed = True
                index += 1
                continue
            targets.append((token, tokens[index + 1]))
            index += 2
            continue
        if token in value_options:
            needed = 2 if token != "--tcp-flags" else 3
            if index + needed - 1 >= len(tokens):
                malformed = True
                index += 1
                continue
            index += needed
            continue
        index += 1

    if malformed:
        return {
            "classification": "PARSE_ERROR",
            "target_type": "MALFORMED_TARGET",
            "flow": "NOT_VERIFIED",
        }

    if len(targets) > 1:
        return {
            "classification": "PARSE_ERROR",
            "target_type": "MULTIPLE_TARGETS",
            "flow": "NOT_VERIFIED",
        }

    if not targets:
        if "-c" in tokens:
            return {
                "classification": "COUNTER_ONLY",
                "target_type": "NONE",
                "flow": "NOT_VERIFIED",
            }
        return {
            "classification": "UNSUPPORTED",
            "target_type": "NO_TARGET",
            "flow": "NOT_VERIFIED",
        }

    option, target = targets[0]
    kind = "GOTO" if option in {"-g", "--goto"} else "JUMP"

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
        "COUNTER_ONLY": 0,
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
        "multiple_targets": rows[10]["classification"] == "PARSE_ERROR",
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
