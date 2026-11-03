#!/usr/bin/env python3
"""R8B-06: Local, read-only firewall evidence and regression audit."""

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

ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

MAX_OUTPUT = 4 * 1024 * 1024


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
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
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
    status, raw, returncode = _bounded_collect([exe, *argv[1:]], MAX_OUTPUT, ENV)
    if status != "OK":
        return status, ""
    if returncode != 0:
        return "ERROR", ""
    return "OK", raw.decode("utf-8", "replace")

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
