# Security and Safety Boundaries

## Release classification

SOURCE REVIEW ONLY — NOT APPROVED FOR PRODUCTION EXECUTION.

This project is an experimental diagnostic prototype, not a
production firewall hardening system.

## Mandatory blocking conditions

RASPIBLITZ_VALIDATION=NOT_PERFORMED
EFFECTIVE_FIREWALL_POLICY=NOT_VERIFIED
SSH_ANTI_LOCKOUT=NOT_VERIFIED
PUBLIC_REACHABILITY=NOT_VERIFIED
POLICY_APPROVAL=BLOCKED
FIREWALL_APPLY=NOT_IMPLEMENTED
RUNTIME_READ_ONLY=NOT_VERIFIED
RUNTIME_PRIVACY_REDACTION=NOT_VERIFIED

## Port and network placeholders

Deployment-specific mappings may contain deliberately illustrative
values. They must not be accepted as accurate target-node settings.

Before any proposed live execution, the reviewer must locally verify
the actual service ports, interface bindings, network segmentation,
and access policies.

The reviewer must distinguish:
- Standard protocol defaults
- Deployment-specific placeholders
- Synthetic regression-test fixtures
- Values collected from the target host

Do not blindly replace every number or address in the source.

## Access and trust

LAN, VPN, Tailscale, loopback, and private-address membership do not
automatically establish trust. Verify explicit authorization and
network policy independently.

Bitcoin and Lightning P2P exposure must not imply that SSH, RPC,
administration, or Electrum interfaces should be publicly reachable.

## Runtime diagnostics

Live audit output may disclose the target host's own interfaces,
addresses, CIDRs, listeners, ports, process details, or policy
structure. Do not publicly share raw reports without local review.

Source-code inspection alone does not prove runtime redaction or
absence of side effects.

## Firewall changes

Firewall apply is NOT_IMPLEMENTED. No production firewall changes
are authorized by this alpha-review release.

SSH anti-lockout, rollback, and effective packet filtering have
not been verified on a real RaspiBlitz.

## Reviewer responsibility

First review the source and run isolated fixture-based tests.
Independently validate command paths and output handling before
authorizing any live diagnostic execution.

The author does not need access to the reviewer's private
configuration or credentials.
