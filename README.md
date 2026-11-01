# RaspiBlitz Firewall Policy Auditor

**Version:** v0.1.0-alpha-review

**Status:** SOURCE REVIEW ONLY — NOT PRODUCTION READY

An experimental, opt-in Debian/RaspiBlitz security auditing
prototype. It provides listener and bind inspection, SSH diagnostics,
firewall rule parsing, chain traversal, target classification,
unsupported-condition diagnostics, and firewall policy previews.

This is not a firewall deployment or hardening implementation.
It does not implement firewall apply, rollback, or verified
SSH anti-lockout protection.

## Intended audience

RaspiBlitz maintainers, security reviewers, and experienced
Debian/Linux operators reviewing source code and isolated fixtures.

## Source modules

- auditor.py — fixture-based audit and policy preview
- live_audit.py — host listener, SSH, and systemd inventory
- policy_preview.py — audit and dry-run proposal
- bind_audit.py — listener, bind, process, and SSH inspection
- firewall_audit.py — firewall backend and trust classification
- effective_policy_audit.py — firewall policy diagnostics
- chain_traversal_audit.py — chain traversal analysis
- target_classification_audit.py — firewall target classification
- strict_condition_audit.py — condition validation
- unsupported_condition_diagnostics.py — unsupported rule diagnostics
- safe_module_mapping_audit_r8b12a.py — alpha-review mapping candidate
- fixture.json — synthetic fixture

The mapping candidate is supplied for source review only. Historical
development findings remain limitations, not evidence of current
production safety.

## Mandatory configuration review

IMPORTANT: Some service-port mappings and network values are
intentionally illustrative placeholders. They are NOT verified
RaspiBlitz defaults or a representation of the reviewer's node.

The reviewer must identify deployment-specific values locally,
distinguish placeholders from standard protocol defaults, and
validate classifications and regressions before considering
any live use.

The author does not request the reviewer's LAN/VPN addresses,
credentials, private SSH configuration, or other secrets.

Synthetic test addresses and ports should not be mechanically
replaced with production values. Preserve their test purpose.

## Security boundaries

- No automatic trust for LAN, VPN, Tailscale, or private networks.
- Bitcoin/Lightning public P2P must be distinguished from private
  RPC, SSH, administration, and Electrum services.
- No automatic firewall changes.
- No production deployment approval.
- No live execution until outstanding safety blockers are resolved.

Read SAFETY.md, TESTING.md, and LIMITATIONS.md before use.

## Development validation

- Static source review is fixture-only in this alpha package.
- Runtime read-only behavior: NOT_VERIFIED.
- Privacy redaction of runtime output: NOT_VERIFIED.
- Real RaspiBlitz validation: NOT_PERFORMED.

These results are historical local-development observations,
not evidence of successful testing after subsequent source edits.

## License

Distributed under the [MIT License](LICENSE). This license does not
constitute approval for live execution or production deployment.
