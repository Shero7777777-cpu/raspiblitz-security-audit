# Reviewer Testing Guide

## Current permitted review scope

Initial review is restricted to:
1. Source-code inspection
2. Static syntax checks
3. Isolated fixture-based regression tests
4. Review of command construction and output redaction

Do not run live host audits on a production RaspiBlitz merely
because this package is described as read-only.

## Preflight review

Confirm:
- The complete source tree is understood.
- All deployment-specific placeholders are identified.
- Standard protocol defaults are distinguished from placeholders.
- Synthetic regression fixtures retain their original meaning.
- No network interface or private CIDR is automatically trusted.
- No unexpected filesystem, service, or firewall mutation exists.
- All subprocess command arguments are independently reviewed.
- Runtime report privacy is addressed before sharing output.

## Local isolated checks

Suggested non-live commands after source review:

    python3 -B -m py_compile auditor.py

Note: py_compile can write bytecode cache files. For a strictly
no-write syntax review, use Python's ast.parse() on source text
instead.

Use only explicitly verified fixture/self-test entry points.
Do not assume that a --self-test option is side-effect free
without inspecting its implementation.

The included mapping candidate must be independently reviewed after
any modification.

## November 2026 review validation record

Local isolated validation covered bounded subprocess migration in 10/10
audit modules, source and candidate contract regressions, post-write
parser regressions, harmless native WSL fixtures, SHA256 verification,
and a complete Git-diff review. R8B-16A38 through R8B-16A41 exercised
the four parser fixes and their cross-module consistency, including LOG
prefix/comment literal text, multiple targets, malformed input, missing
`COMMIT`, counter-only rules, nft JSON null validation, and NAT chain
type classification.

These historical local results are not a substitute for reproducible
testing of the published revision. This repository does not include a
complete CI harness or a standalone reproducible test suite. For a
strict no-write syntax check, parse each Python source with `ast.parse()`
rather than a command that creates `__pycache__`.

Do not run `--audit` on a physical RaspiBlitz before independent source
review and explicit authorization for an isolated validation plan.

## Configuration review

The reviewer or an explicitly authorized local agent must:
1. Inventory the actual RaspiBlitz service configuration locally.
2. Verify SSH, Bitcoin, Lightning, RPC, Electrum, Tor, and other
   relevant endpoints.
3. Resolve deployment-specific port placeholders.
4. Verify LAN, VPN, Tailscale, and Tor boundaries.
5. Preserve synthetic test fixtures.
6. Re-run relevant regressions after modifications.
7. Confirm that diagnostic output is safe to disclose.
8. Independently establish read-only behavior before live execution.

Do not send private network addresses, secrets, credentials,
or raw diagnostic output to the author.

## Live testing

BLOCKED pending independent review of runtime read-only behavior,
privacy redaction, and command safety.

A production RaspiBlitz is not the first test target.
Use an isolated and recoverable environment if a reviewer later
authorizes runtime testing.

## Reporting findings

Report:
- Module and line number
- Expected behavior
- Observed behavior
- Reproduction steps using synthetic inputs
- Whether a finding is security relevant

Redact real addresses, credentials, and host-specific configuration.
