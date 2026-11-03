#!/usr/bin/env python3
"""R8B-04: Read-only firewall policy proposal, never applies rules."""

import argparse
import ipaddress
import json
import os
import re
import stat
import shutil
import selectors
import signal
import subprocess
import time
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LIMIT = 4 * 1024 * 1024

KNOWN = {
    ("tcp", 2222): ("SSH", "ADMIN"),
    ("tcp", 8300): ("BITCOIN_P2P", "P2P"),
    ("tcp", 18333): ("BITCOIN_TESTNET_P2P", "P2P"),
    ("tcp", 38333): ("BITCOIN_SIGNET_P2P", "P2P"),
    ("tcp", 8332): ("BITCOIN_RPC", "SENSITIVE"),
    ("tcp", 18332): ("BITCOIN_TESTNET_RPC", "SENSITIVE"),
    ("tcp", 38332): ("BITCOIN_SIGNET_RPC", "SENSITIVE"),
    ("tcp", 9735): ("LIGHTNING_P2P", "P2P"),
    ("tcp", 10000): ("LND_GRPC", "SENSITIVE"),
    ("tcp", 50000): ("ELECTRUM_TCP", "SENSITIVE"),
    ("tcp", 50505): ("ELECTRUM_TLS", "SENSITIVE"),
    ("tcp", 9010): ("TOR_SOCKS", "SENSITIVE"),
    ("tcp", 9011): ("TOR_CONTROL", "SENSITIVE"),
    ("tcp", 8200): ("HTTP_PROXY", "SENSITIVE"),
    ("tcp", 5400): ("DNS", "SENSITIVE"),
    ("udp", 5400): ("DNS", "SENSITIVE"),
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

def collect_listeners():
    status, raw = run(["ss", "-H", "-l", "-n", "-t", "-u", "-p"])
    if status != "OK":
        return status, []

    found = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        if proto not in {"tcp", "udp"}:
            continue

        match = re.search(r":(\d+)$", parts[4])
        if not match:
            continue

        port = int(match.group(1))
        name, role = KNOWN.get(
            (proto, port), ("UNKNOWN", "UNKNOWN")
        )

        found.append({
            "protocol": proto,
            "port": port,
            "candidate": name,
            "role": role,
            "identity_verified": False,
            "reachability_verified": False,
        })

    return "OK", found

def ssh_diagnostic(listeners):
    ports = sorted({
        x["port"] for x in listeners
        if x["protocol"] == "tcp" and x["port"] == 22
    })

    paths = ("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd")
    sshd = next(
        (p for p in paths if _resolve_trusted_executable(p) is not None),
        None,
    )

    result = {
        "default_port_listener_present": bool(ports),
        "sshd_binary_available": sshd is not None,
        "custom_ssh_ports": "NOT_DETERMINED",
        "active_admin_path_verified": False,
        "anti_lockout": "BLOCKED",
    }

    if sshd:
        status, raw = run([sshd, "-T"])
        result["configuration_status"] = status
        if status == "OK":
            result["configured_port_count"] = sum(
                1 for line in raw.splitlines()
                if re.fullmatch(r"port\s+\d+", line.strip())
            )

    return result

def normalize_trust(cidrs, interfaces):
    networks = []
    for value in cidrs:
        network = ipaddress.ip_network(value, strict=True)
        if str(network) not in networks:
            networks.append(str(network))

    clean_interfaces = []
    for value in interfaces:
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,32}", value):
            raise ValueError("Invalid interface name")
        if value not in clean_interfaces:
            clean_interfaces.append(value)

    return networks, clean_interfaces

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--audit", action="store_true")
    modes.add_argument("--dry-run", action="store_true")
    parser.add_argument("--trusted-cidr", action="append", default=[])
    parser.add_argument("--trusted-interface", action="append", default=[])
    parser.add_argument("--allow-public-p2p", action="store_true")
    args = parser.parse_args()

    if args.audit and (
        args.trusted_cidr or args.trusted_interface
        or args.allow_public_p2p
    ):
        parser.error("Policy options require --dry-run")

    try:
        networks, interfaces = normalize_trust(
            args.trusted_cidr, args.trusted_interface
        )
    except ValueError as exc:
        parser.error(str(exc))

    status, listeners = collect_listeners()
    ssh = ssh_diagnostic(listeners)

    report = {
        "schema": "R8B-04",
        "mode": "DRY_RUN" if args.dry_run else "AUDIT",
        "listener_collection": status,
        "listener_count": len(listeners),
        "candidate_services": listeners,
        "ssh": ssh,
        "trust": {
            "cidrs": networks,
            "interfaces": interfaces,
            "automatic_private_network_trust": False,
        },
        "proposed_ufw_commands": [],
        "review_required": [],
        "policy_approval": "BLOCKED",
        "apply_implemented": False,
    }

    if args.dry_run:
        if not networks and not interfaces:
            report["review_required"].append(
                "No explicit trusted administration boundary"
            )

        if not ssh["active_admin_path_verified"]:
            report["review_required"].append(
                "SSH anti-lockout is not verified"
            )

        if status != "OK":
            report["review_required"].append(
                "Listener inventory unavailable"
            )

        for item in listeners:
            proto = item["protocol"]
            port = item["port"]
            role = item["role"]

            if role == "UNKNOWN":
                report["review_required"].append(
                    f"Unknown listener {proto}/{port}"
                )
                continue

            if role == "SENSITIVE":
                report["review_required"].append(
                    f"Sensitive service {proto}/{port}: "
                    "verify bind address and access policy"
                )
                continue

            if role == "ADMIN":
                report["review_required"].append(
                    f"Administrative listener {proto}/{port}: "
                    "explicit anti-lockout review required"
                )
                continue

            if role == "P2P" and args.allow_public_p2p:
                report["proposed_ufw_commands"].append(
                    f"ufw allow {port}/{proto} "
                    "comment 'R8B04_P2P_CANDIDATE'"
                )
            elif role == "P2P":
                report["review_required"].append(
                    f"P2P listener {proto}/{port}: "
                    "public access not authorized"
                )

        report["review_required"].append(
            "Firewall backend, IPv6, rule ordering, "
            "existing policy and effective reachability "
            "not verified"
        )

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
