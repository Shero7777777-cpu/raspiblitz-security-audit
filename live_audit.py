#!/usr/bin/env python3
"""R8B-03: Read-only local network/service classification preview."""

import argparse
import json
import os
import re
import stat
import shutil
import selectors
import signal
import time
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

PORTS = {
    ("tcp", 22): ("SSH", "PRIVATE_CANDIDATE"),
    ("tcp", 8333): ("BITCOIN_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 18333): ("BITCOIN_TESTNET_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 38333): ("BITCOIN_SIGNET_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 8332): ("BITCOIN_RPC", "PRIVATE_CANDIDATE"),
    ("tcp", 18332): ("BITCOIN_TESTNET_RPC", "PRIVATE_CANDIDATE"),
    ("tcp", 38332): ("BITCOIN_SIGNET_RPC", "PRIVATE_CANDIDATE"),
    ("tcp", 9735): ("LIGHTNING_P2P", "PUBLIC_CANDIDATE"),
    ("tcp", 10009): ("LND_GRPC", "PRIVATE_CANDIDATE"),
    ("tcp", 8080): ("LND_REST_OR_OTHER", "UNCLASSIFIED"),
    ("tcp", 50001): ("ELECTRUM_TCP", "PRIVATE_CANDIDATE"),
    ("tcp", 50002): ("ELECTRUM_TLS", "PRIVATE_CANDIDATE"),
    ("tcp", 9050): ("TOR_SOCKS", "PRIVATE_CANDIDATE"),
    ("tcp", 9051): ("TOR_CONTROL", "PRIVATE_CANDIDATE"),
    ("tcp", 8118): ("HTTP_PROXY", "PRIVATE_CANDIDATE"),
    ("tcp", 1194): ("OPENVPN_TCP", "UNCLASSIFIED"),
    ("udp", 1194): ("OPENVPN_UDP", "UNCLASSIFIED"),
    ("tcp", 443): ("HTTPS_OR_VPN", "UNCLASSIFIED"),
    ("udp", 53): ("DNS", "PRIVATE_CANDIDATE"),
    ("tcp", 53): ("DNS", "PRIVATE_CANDIDATE"),
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
    deadline=time.monotonic()+10.0; proc=None; selector=None; completed=False
    try:
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,close_fds=True,start_new_session=True)
        selector=selectors.DefaultSelector(); selector.register(proc.stdout,selectors.EVENT_READ); output=bytearray()
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:return "TIMEOUT",b"",None
            if not selector.select(remaining):return "TIMEOUT",b"",None
            count=min(65536,limit+1-len(output))
            if count<=0:return "OUTPUT_LIMIT",b"",None
            chunk=os.read(proc.stdout.fileno(),count)
            if not chunk:break
            output.extend(chunk)
            if len(output)>limit:return "OUTPUT_LIMIT",b"",None
        remaining=deadline-time.monotonic()
        if remaining<=0:return "TIMEOUT",b"",None
        try: rc=proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:return "TIMEOUT",b"",None
        completed=True; return "OK",bytes(output),rc
    except (OSError,ValueError):return "ERROR",b"",None
    finally:
        if proc is not None:
            if not completed:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except OSError:
                    try:proc.kill()
                    except (OSError,ValueError,RuntimeError):pass
                try:proc.wait(timeout=0.5)
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):pass
            if proc.stdout is not None:
                try:proc.stdout.close()
                except (OSError,ValueError,RuntimeError):pass
        if selector is not None:
            try:selector.close()
            except (OSError,ValueError,RuntimeError):pass

def run(argv, accept_nonzero=False):
    executable=_resolve_trusted_executable(argv[0])
    if not executable:return "UNAVAILABLE", ""
    status,raw,returncode=_bounded_collect([executable,*argv[1:]],4*1024*1024,ENV)
    if status=="TIMEOUT":return "ERROR", ""
    if status!="OK":return status, ""
    if returncode!=0 and not accept_nonzero:return "ERROR", ""
    return "OK",raw.decode("utf-8",errors="replace")

def classify(proto, port):
    return PORTS.get(
        (proto, port),
        ("UNKNOWN", "UNCLASSIFIED"),
    )

def listeners():
    status, raw = run(["ss", "-H", "-l", "-n", "-t", "-u"])
    if status != "OK":
        return {"status": status}

    result = {
        "status": "OK",
        "total": 0,
        "public_candidates": 0,
        "private_candidates": 0,
        "unclassified": 0,
        "candidate_services": [],
        "endpoints_redacted": True,
    }

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in {"tcp", "udp"}:
            continue
        local = parts[4]
        match = re.search(r":(\d+)$", local)
        if not match:
            continue

        port = int(match.group(1))
        name, category = classify(proto, port)
        result["total"] += 1

        if category == "PUBLIC_CANDIDATE":
            result["public_candidates"] += 1
        elif category == "PRIVATE_CANDIDATE":
            result["private_candidates"] += 1
        else:
            result["unclassified"] += 1

        if name != "UNKNOWN":
            result["candidate_services"].append({
                "service": name,
                "category": category,
                "port": port,
                "protocol": proto,
                "identity_verified": False,
                "reachability_verified": False,
            })

    return result

def ssh():
    paths = [
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/sbin/sshd",
    ]
    executable = next(
        (p for p in paths if _resolve_trusted_executable(p) is not None),
        None,
    )
    if executable is None:
        return {
            "status": "UNAVAILABLE",
            "listener_may_still_exist": True,
        }

    status, raw = run([executable, "-T"])
    if status != "OK":
        return {"status": status}

    ports = []
    for line in raw.splitlines():
        match = re.fullmatch(r"port\s+(\d+)", line.strip())
        if match:
            ports.append(int(match.group(1)))

    return {
        "status": "OK",
        "configured_port_count": len(ports),
        "configured_ports_redacted": True,
        "active_ssh_path_verified": False,
    }

def systemd():
    status, raw = run(
        ["systemctl", "is-system-running"],
        accept_nonzero=True,
    )
    if status != "OK":
        return {"status": status}

    state = raw.strip()
    allowed = {
        "running", "degraded", "maintenance",
        "starting", "stopping", "offline",
        "initializing",
    }
    return {
        "status": "OK",
        "state": state if state in allowed else "UNKNOWN",
        "nonzero_exit_is_not_automatically_error": True,
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit", action="store_true", required=True)
    args = p.parse_args()

    report = {
        "schema": "R8B-03",
        "mode": "LIVE_READ_ONLY_CLASSIFICATION",
        "raspiblitz_compatibility": "UNVERIFIED",
        "trust_policy": "EXPLICIT_ONLY",
        "classification_method": "PORT_HEURISTIC_ONLY",
        "firewall_apply_available": False,
        "policy_rules_generated": False,
        "ssh_anti_lockout_verified": False,
        "checks": {},
    }

    report["checks"]["listeners"] = listeners()
    report["checks"]["ssh"] = ssh()
    report["checks"]["systemd"] = systemd()

    for name, argv in {
        "interfaces": ["ip", "-j", "address", "show"],
        "routes": ["ip", "-j", "route", "show", "table", "all"],
        "ufw": ["ufw", "status"],
        "nftables": ["nft", "-j", "list", "ruleset"],
        "iptables": ["iptables-save"],
        "ip6tables": ["ip6tables-save"],
    }.items():
        status, raw = run(argv)
        report["checks"][name] = {
            "status": status,
            "raw_details_redacted": True,
            "data_read": status == "OK",
        }

    report["checks"]["tailscale"] = {
        "client_available": _resolve_trusted_executable("tailscale") is not None,
        "trusted": False,
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
