#!/usr/bin/env python3
"""R8B-05: Read-only listener, bind, process and SSH audit."""

import argparse
import ipaddress
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

ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

MAX_BYTES = 4 * 1024 * 1024

SENSITIVE_PORTS = {
    2222, 5400, 8300, 10000, 50000, 50505,
    9010, 9011, 9012, 9013, 8200,
    5330, 5333, 5334, 5335, 11500,
}

SSH_PATHS = (
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
)


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
            if len(output)>limit:
                rc=proc.poll()
                if rc is not None: completed=True; return "OUTPUT_LIMIT",b"",rc
                return "OUTPUT_LIMIT",b"",None
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

def run(argv, allow_nonzero=False):
    executable=_resolve_trusted_executable(argv[0])
    if not executable:return "UNAVAILABLE","",None
    status,raw,returncode=_bounded_collect([executable,*argv[1:]],MAX_BYTES,ENV)
    if status!="OK":return status,"",returncode
    if returncode!=0 and not allow_nonzero:return "ERROR","",returncode
    return "OK",raw.decode("utf-8",errors="replace"),returncode

def split_endpoint(value):
    """Extract numeric port without exposing address."""
    if value.startswith("["):
        match = re.fullmatch(r"\[(.+)\]:(\d+)", value)
        if not match:
            return None, None
        return match.group(1), int(match.group(2))

    if ":" not in value:
        return None, None

    address, port = value.rsplit(":", 1)
    if not port.isdecimal():
        return None, None

    return address, int(port)

def bind_class(address):
    if address in {"*", "0.0.0.0", "::"}:
        return "WILDCARD"

    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "UNKNOWN"

    if ip.is_loopback:
        return "LOOPBACK"

    if ip.is_link_local:
        return "LINK_LOCAL"

    if ip.is_unspecified:
        return "WILDCARD"

    return "SPECIFIC_ADDRESS"

def family_of(address):
    if address == "*":
        return "UNKNOWN"

    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        return "UNKNOWN"

def process_metadata(line):
    """Extract only process labels and whether a PID was visible."""
    matches = re.findall(
        r'\("([^"]{1,80})",pid=(\d+)',
        line,
    )
    if not matches:
        return {
            "process_visible": False,
            "process_labels": [],
            "pid_redacted": True,
        }

    labels = sorted({name for name, _ in matches})
    return {
        "process_visible": True,
        "process_labels": labels,
        "pid_redacted": True,
    }

def collect():
    status, raw, _ = run(
        ["ss", "-H", "-l", "-n", "-t", "-u", "-p"]
    )
    if status != "OK":
        return status, []

    entries = []

    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue

        proto = fields[0].lower()
        if proto not in {"tcp", "udp"}:
            continue

        address, port = split_endpoint(fields[4])
        if address is None:
            continue

        metadata = process_metadata(line)

        entries.append({
            "protocol": proto,
            "port": port,
            "address_family": family_of(address),
            "bind_class": bind_class(address),
            "sensitive_port": port in SENSITIVE_PORTS,
            "process": metadata,
            "identity_verified": False,
            "external_reachability_verified": False,
        })

    return "OK", entries

def ssh_status(entries):
    sshd = next(
        (
            path for path in SSH_PATHS
            if _resolve_trusted_executable(path) is not None
        ),
        None,
    )

    ssh_process_listeners = [
        item for item in entries
        if "sshd" in item["process"]["process_labels"]
    ]

    result = {
        "sshd_binary_available": sshd is not None,
        "sshd_process_listener_count": len(ssh_process_listeners),
        "active_ssh_environment": bool(os.environ.get("SSH_CONNECTION")),
        "configured_port_count": None,
        "configuration_status": "UNAVAILABLE",
        "anti_lockout": "NOT_VERIFIED",
    }

    if sshd:
        status, output, _ = run([sshd, "-T"])
        result["configuration_status"] = status
        if status == "OK":
            result["configured_port_count"] = sum(
                1 for line in output.splitlines()
                if re.fullmatch(r"port\s+\d+", line.strip())
            )

    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true", required=True)
    args = parser.parse_args()

    status, entries = collect()

    counts = {
        "loopback": 0,
        "wildcard": 0,
        "specific_address": 0,
        "link_local": 0,
        "unknown": 0,
        "ipv4": 0,
        "ipv6": 0,
        "family_unknown": 0,
        "sensitive": 0,
        "process_visible": 0,
    }

    for item in entries:
        counts[item["bind_class"].lower()] += 1
        counts[
            item["address_family"].lower()
            if item["address_family"] != "UNKNOWN"
            else "family_unknown"
        ] += 1
        counts["sensitive"] += int(item["sensitive_port"])
        counts["process_visible"] += int(
            item["process"]["process_visible"]
        )

    report = {
        "schema": "R8B-05",
        "mode": "LIVE_READ_ONLY_BIND_AUDIT",
        "listener_status": status,
        "listener_count": len(entries),
        "counts": counts,
        "listeners": entries,
        "ssh": ssh_status(entries),
        "trust": {
            "automatic_lan_trust": False,
            "automatic_vpn_trust": False,
            "automatic_rfc1918_trust": False,
        },
        "firewall_apply": "NOT_IMPLEMENTED",
        "policy_approval": "BLOCKED",
        "raspiblitz_validation": "NOT_PERFORMED",
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
