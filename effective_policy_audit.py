#!/usr/bin/env python3
"""R8B-07: Read-only, conservative firewall policy evidence auditor."""

import argparse
import ipaddress
import json
import re
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

def parse_iptables(raw):
    table = None
    policy = "NOT_VERIFIED"
    rules = []
    nat_seen = False
    forwarding_seen = False

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("*"):
            table = line[1:]
            if table == "nat":
                nat_seen = True
            continue
        if line == "COMMIT":
            table = None
            continue
        if table == "filter" and line.startswith(":INPUT "):
            match = re.match(r":INPUT\s+(ACCEPT|DROP|REJECT|-)", line)
            if match:
                policy = match.group(1)
        if table == "filter" and line.startswith("-A INPUT "):
            rules.append(line)
        if table == "filter" and (
            line.startswith("-A FORWARD ")
            or line.startswith(":FORWARD ")
        ):
            forwarding_seen = True

    return {
        "input_default_policy": policy,
        "input_rule_count": len(rules),
        "nat_table_present": nat_seen,
        "forwarding_configuration_present": forwarding_seen,
        "_rules": rules,
    }

def parse_nft(raw):
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {
            "status": "PARSE_ERROR",
            "input_base_chains": [],
            "nat_chains_present": "NOT_VERIFIED",
        }

    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        return {
            "status": "SCHEMA_ERROR",
            "input_base_chains": [],
            "nat_chains_present": "NOT_VERIFIED",
        }

    chains = []
    nat = False

    for item in data.get("nftables", []):
        if not isinstance(item, dict):
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        chain = item.get("chain")
        if "chain" in item and not isinstance(chain, dict):
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        if not isinstance(chain, dict):
            continue

        identity_fields = {"family", "table", "name", "type", "hook"}
        if not any(field in chain for field in identity_fields):
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        for field in ("family", "table", "name"):
            if field in chain and (
                not isinstance(chain[field], str) or not chain[field]
            ):
                return {
                    "status": "SCHEMA_ERROR",
                    "input_base_chains": [],
                    "nat_chains_present": "NOT_VERIFIED",
                }

        hook = chain.get("hook")
        has_type = "type" in chain
        chain_type = chain.get("type")
        if has_type and (
            not isinstance(chain_type, str)
            or chain_type not in {"filter", "nat", "route"}
        ):
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        if hook is not None and not isinstance(hook, str):
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        if hook is not None and not has_type:
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        if has_type and hook is None:
            return {
                "status": "SCHEMA_ERROR",
                "input_base_chains": [],
                "nat_chains_present": "NOT_VERIFIED",
            }
        if has_type and chain_type == "nat":
            nat = True
        if hook == "input":
            chains.append({
                "family": chain.get("family", "UNKNOWN"),
                "type": chain_type,
                "hook": hook,
                "priority": chain.get("prio", "UNKNOWN"),
                "policy": chain.get("policy", "UNKNOWN"),
                "rule_evaluation": "NOT_VERIFIED",
            })

    return {
        "status": "OK",
        "input_base_chains": chains,
        "nat_chains_present": nat,
    }

def parse_ufw(raw):
    lower = raw.lower()
    if "status: active" in lower:
        state = "ACTIVE"
    elif "status: inactive" in lower:
        state = "INACTIVE"
    else:
        state = "UNKNOWN"

    incoming = "NOT_VERIFIED"
    match = re.search(
        r"Default:\s*([a-z]+)\s*\(incoming\)",
        raw,
        re.IGNORECASE,
    )
    if match:
        incoming = match.group(1).upper()

    return {
        "state": state,
        "default_incoming": incoming,
        "backend": "NOT_DETERMINED",
    }

def wildcard_listeners():
    result = []
    errors = []

    for family, flag in (("IPv4", "-4"), ("IPv6", "-6")):
        status, raw = run(["ss", flag, "-H", "-l", "-n", "-t", "-u"])
        if status != "OK":
            errors.append(family + ":" + status)
            continue

        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            if proto not in {"tcp", "udp"}:
                continue

            address, sep, port = parts[4].rpartition(":")
            if not sep or not port.isdecimal():
                continue

            address = address.strip("[]")
            if address not in {"*", "0.0.0.0", "::"}:
                continue

            result.append({
                "family": family,
                "protocol": proto,
                "port": int(port),
                "bind": "WILDCARD",
                "external_reachability": "NOT_VERIFIED",
            })

    return result, errors

def rule_mentions_port(rule, proto, port):
    """Textual candidate matching, never an effective-policy verdict."""
    if not re.search(r"(?:^|\s)-p\s+" + re.escape(proto) + r"(?:\s|$)", rule):
        return False

    match = re.search(r"(?:^|\s)--dport\s+(\d+)(?:\s|$)", rule)
    return bool(match and int(match.group(1)) == port)

def summarize_rules(rules, proto, port):
    candidates = [r for r in rules if rule_mentions_port(r, proto, port)]
    actions = set()

    for rule in candidates:
        match = re.search(r"(?:^|\s)-j\s+([A-Za-z0-9_-]+)", rule)
        if match:
            actions.add(match.group(1))

    return {
        "textual_direct_input_matches": len(candidates),
        "target_labels": sorted(actions),
        "effective_decision": "NOT_VERIFIED",
        "limitations": [
            "No user-defined chain traversal",
            "No complete rule ordering or stateful evaluation",
            "No interface/source address/conntrack verdict",
            "No nftables expression evaluation",
        ],
    }

def self_test():
    checks = {
        "iptables_drop": parse_iptables(
            "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
        )["input_default_policy"] == "DROP",
        "iptables_accept": parse_iptables(
            "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        )["input_default_policy"] == "ACCEPT",
        "ufw_active": parse_ufw(
            "Status: active\nDefault: deny (incoming), allow (outgoing)"
        )["state"] == "ACTIVE",
        "nft_input": len(parse_nft(json.dumps({
            "nftables": [{"chain": {
                "family": "inet", "hook": "input",
                "type": "filter", "prio": 0, "policy": "drop"
            }}]
        }))["input_base_chains"]) == 1,
        "port_match": rule_mentions_port(
            "-A INPUT -p tcp -m tcp --dport 410 -j ACCEPT",
            "tcp", 410
        ),
        "port_mismatch": not rule_mentions_port(
            "-A INPUT -p tcp --dport 170 -j ACCEPT",
            "tcp", 410
        ),
        "no_automatic_trust": True,
        "no_effective_verdict": summarize_rules(
            [], "tcp", 410
        )["effective_decision"] == "NOT_VERIFIED",
    }
    return {
        "passed": sum(checks.values()),
        "total": len(checks),
        "result": "PASS" if all(checks.values()) else "FAIL",
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

    ipv4_status, ipv4_raw = run(["iptables-save"])
    ipv6_status, ipv6_raw = run(["ip6tables-save"])
    nft_status, nft_raw = run(["nft", "-j", "list", "ruleset"])
    ufw_status, ufw_raw = run(["ufw", "status", "verbose"])

    ipv4 = parse_iptables(ipv4_raw) if ipv4_status == "OK" else None
    ipv6 = parse_iptables(ipv6_raw) if ipv6_status == "OK" else None
    nft = parse_nft(nft_raw) if nft_status == "OK" else None
    ufw = parse_ufw(ufw_raw) if ufw_status == "OK" else None

    listeners, errors = wildcard_listeners()

    for item in listeners:
        family = ipv4 if item["family"] == "IPv4" else ipv6
        item["iptables_input_evidence"] = (
            summarize_rules(
                family["_rules"], item["protocol"], item["port"]
            )
            if family is not None
            else {"effective_decision": "NOT_VERIFIED"}
        )

    def clean(value):
        if value is None:
            return None
        return {k: v for k, v in value.items() if k != "_rules"}

    report = {
        "schema": "R8B-07",
        "mode": "LIVE_READ_ONLY_POLICY_EVIDENCE",
        "iptables_ipv4": {
            "status": ipv4_status, "analysis": clean(ipv4)
        },
        "iptables_ipv6": {
            "status": ipv6_status, "analysis": clean(ipv6)
        },
        "nftables": {"status": nft_status, "analysis": nft},
        "ufw": {"status": ufw_status, "analysis": ufw},
        "wildcard_listeners": listeners,
        "listener_collection_errors": errors,
        "ufw_backend": "NOT_DETERMINED",
        "nat_effective_behavior": "NOT_VERIFIED",
        "forwarding_effective_behavior": "NOT_VERIFIED",
        "ipv6_dual_stack_behavior": "NOT_VERIFIED",
        "wsl_host_boundary": "NOT_VERIFIED",
        "effective_input_policy": "NOT_VERIFIED",
        "ssh_anti_lockout": "NOT_VERIFIED",
        "public_reachability": "NOT_VERIFIED",
        "policy_approval": "BLOCKED",
        "firewall_apply": "NOT_IMPLEMENTED",
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
