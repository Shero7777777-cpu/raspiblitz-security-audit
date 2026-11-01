#!/usr/bin/env python3
"""Read-only, fixture-based RaspiBlitz firewall policy preview. No host inspection."""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


def load_fixture(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("interfaces"), list)
        or not isinstance(data.get("services"), list)
    ):
        raise ValueError("Fixture requires interfaces and services arrays")
    return data


def audit(data):
    print("MODE: AUDIT (fixture only; no host inspection)")
    print("INTERFACES:")
    for iface in data["interfaces"]:
        print(f"  {iface['name']}: {iface.get('address', 'unknown')}")
    print("SERVICES:")
    for svc in data["services"]:
        print(
            f"  {svc['name']}: {svc['protocol']}/{svc['port']} "
            f"bind={svc['bind']} classification=UNVERIFIED"
        )
    print("FIREWALL: UNKNOWN (fixture preview does not inspect UFW/nftables)")
    print("HOST CHANGES: NONE")


def dry_run(data, trusted_interfaces, trusted_cidrs):
    names = {iface["name"] for iface in data["interfaces"]}
    unknown = set(trusted_interfaces) - names

    if unknown:
        raise ValueError(
            "Unknown trusted interface(s): " + ", ".join(sorted(unknown))
        )

    normalized = [
        str(ipaddress.ip_network(c, strict=True))
        for c in trusted_cidrs
    ]

    print("MODE: DRY-RUN (fixture only; no executable firewall rules)")
    print(
        "TRUSTED INTERFACES: "
        + (", ".join(trusted_interfaces) if trusted_interfaces else "NONE")
    )
    print(
        "TRUSTED SOURCE CIDRS: "
        + (", ".join(normalized) if normalized else "NONE")
    )

    print("SERVICE REVIEW:")
    for svc in data["services"]:
        print(
            f"  {svc['name']} {svc['protocol']}/{svc['port']}: "
            "UNCLASSIFIED - manual review required"
        )

    print(
        "PROPOSED POLICY: NOT GENERATED "
        "(classification and firewall backend not validated)"
    )
    print("SSH ANTI-LOCKOUT: NOT VERIFIED")
    print("HOST CHANGES: NONE")


def main():
    p = argparse.ArgumentParser(description=__doc__)

    p.add_argument(
        "--fixture",
        required=True,
        help="JSON fixture file (never probes host)",
    )

    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--audit", action="store_true")
    modes.add_argument("--dry-run", action="store_true")

    p.add_argument("--trusted-interface", action="append", default=[])
    p.add_argument("--trusted-cidr", action="append", default=[])

    args = p.parse_args()

    try:
        data = load_fixture(args.fixture)

        if args.audit:
            if args.trusted_interface or args.trusted_cidr:
                p.error("Trust options only apply to --dry-run")
            audit(data)
        else:
            dry_run(
                data,
                args.trusted_interface,
                args.trusted_cidr,
            )

    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
