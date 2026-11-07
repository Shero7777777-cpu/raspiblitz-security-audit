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

Offline smoke tests must use synthetic or independently obtained files:

    python3 -B auditor.py --review-snapshots --iptables-v4 synthetic-v4.save
    python3 -B auditor.py --review-snapshots --iptables-v6 synthetic-v6.save
    python3 -B auditor.py --review-snapshots --nft-json synthetic-nft.json
    python3 -B auditor.py --review-snapshots --ufw-text synthetic-ufw.txt

Verify that every output is one JSON document no larger than 65,536 bytes and that it
contains the four `NOT_VERIFIED`/`NOT_IMPLEMENTED` limitations. Re-run the two
fixture commands in README after changes. Do not obtain snapshots from a live node as
part of these tests.

Offline review results and offline argument errors are emitted as one JSON document.
The standard `--help` response is the sole documented text-output exception.

## Offline Snapshot Reviewer Quick Test

Run the following command from the repository root as an ordinary user. It creates
only synthetic snapshots in an operating-system temporary directory, invokes only
`auditor.py --review-snapshots`, and removes the directory automatically even when
an assertion fails.

    python3 -I -B - <<'PY'
    import json
    import pathlib
    import subprocess
    import sys
    import tempfile

    auditor = pathlib.Path("auditor.py").resolve()
    assert auditor.is_file(), "run this test from the repository root"
    canaries = (
        "203.0.113.91",
        "2001:db8::91",
        "192.0.2.0/24",
        "CHAIN_QUICK_TEST",
        "reviewer_quick_user",
        "host-quick-test.invalid",
        "TOKEN_QUICK_TEST",
    )
    passed = []

    def run_case(name, arguments, expected_code, expected_status):
        completed = subprocess.run(
            [sys.executable, "-B", str(auditor), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        assert completed.returncode == expected_code, (
            name, "exit", expected_code, completed.returncode
        )
        assert len(lines) == 1, (name, "JSON document count", len(lines))
        report = json.loads(lines[0])
        assert report["results"][0]["status"] == expected_status, (
            name, "status", expected_status, report["results"][0]["status"]
        )
        assert report["limitations"] == {
            "effective_policy": "NOT_VERIFIED",
            "firewall_apply": "NOT_IMPLEMENTED",
            "public_reachability": "NOT_VERIFIED",
            "ssh_anti_lockout": "NOT_VERIFIED",
        }, (name, "limitations")
        combined = completed.stdout + completed.stderr
        assert "Traceback" not in combined, (name, "traceback")
        assert all(value not in combined for value in canaries), (
            name, "privacy canary leak"
        )
        passed.append(name)
        print(f"{name}=PASS")

    with tempfile.TemporaryDirectory(prefix="raspiblitz-offline-quick-") as tmp:
        temporary_directory = pathlib.Path(tmp)
        snapshots = {
            "v4": (
                "*filter\n"
                ":INPUT DROP [0:0]\n"
                "-A INPUT -p tcp --dport 8333 -j ACCEPT\n"
                "COMMIT\n"
            ),
            "v6": (
                "*filter\n"
                ":INPUT DROP [0:0]\n"
                "-A INPUT -p tcp --dport 9735 -j ACCEPT\n"
                "COMMIT\n"
            ),
            "missing_commit": "*filter\n:INPUT DROP [0:0]\n",
            "multiple_targets": (
                "*filter\n"
                ":INPUT DROP [0:0]\n"
                "-A INPUT -j ACCEPT -j DROP\n"
                "COMMIT\n"
            ),
            "nft": '{"nftables": []}\n',
            "nft_null": "null\n",
            "ufw": "Status: active\nDefault: deny (incoming)\n",
            "ufw_unknown": "Status: mystery\n",
            "privacy": " ".join(canaries) + "\n",
        }
        paths = {}
        for name, content in snapshots.items():
            path = temporary_directory / name
            path.write_text(content, encoding="utf-8")
            paths[name] = str(path)

        run_case("synthetic_ipv4", ["--review-snapshots", "--iptables-v4", paths["v4"]], 0, "SYNTAX_PARSED")
        run_case("synthetic_ipv6", ["--review-snapshots", "--iptables-v6", paths["v6"]], 0, "SYNTAX_PARSED")
        run_case("synthetic_nft", ["--review-snapshots", "--nft-json", paths["nft"]], 0, "SYNTAX_PARSED")
        run_case("synthetic_ufw", ["--review-snapshots", "--ufw-text", paths["ufw"]], 0, "SYNTAX_PARSED")
        run_case("missing_commit", ["--review-snapshots", "--iptables-v4", paths["missing_commit"]], 2, "PARSE_ERROR")
        run_case("multiple_targets", ["--review-snapshots", "--iptables-v4", paths["multiple_targets"]], 2, "PARSE_ERROR")
        run_case("nft_null", ["--review-snapshots", "--nft-json", paths["nft_null"]], 2, "SCHEMA_ERROR")
        run_case("ufw_unknown", ["--review-snapshots", "--ufw-text", paths["ufw_unknown"]], 2, "UNRECOGNIZED")
        run_case("invalid_cli", ["--review-snapshots", "--audit", "--iptables-v4", paths["v4"]], 2, "INVALID_OFFLINE_ARGUMENTS")
        run_case("fixture_rejected", ["--review-snapshots", "--fixture", "TOKEN_QUICK_TEST", "--iptables-v4", paths["v4"]], 2, "INVALID_OFFLINE_ARGUMENTS")
        run_case("trust_rejected", ["--review-snapshots", "--trusted-interface", "CHAIN_QUICK_TEST", "--iptables-v4", paths["v4"]], 2, "INVALID_OFFLINE_ARGUMENTS")
        run_case("privacy_canaries", ["--review-snapshots", "--ufw-text", paths["privacy"]], 2, "UNRECOGNIZED")

        source = auditor.read_text(encoding="utf-8")
        forbidden_live_calls = (
            "iptables-save",
            "ip6tables-save",
            "systemctl",
            "subprocess.",
            "socket.",
        )
        assert all(value not in source for value in forbidden_live_calls)
        print("no_live_collection=PASS")

    assert not temporary_directory.exists(), "temporary directory was not removed"
    print("temporary_cleanup=PASS")
    assert len(passed) == 12, ("scenario count", len(passed))
    print("OFFLINE_SNAPSHOT_REVIEWER_QUICK_TEST=PASS")
    PY

The accepted files are existing IPv4 or IPv6 `iptables-save` text, nftables JSON,
and UFW status text acquired independently of this program. The tool never obtains
these files itself. The reviewer needs only Python 3, permission to run the script,
and read access to the selected snapshots.

Each input is limited to 4 MiB, all inputs together to 8 MiB, and the JSON output to
64 KiB. Real snapshots can contain private addressing, custom chain names, host data,
and other sensitive configuration; do not publish or share raw snapshots. A successful
offline result confirms only completion of supported syntax parsing. Effective firewall
policy, SSH anti-lockout, and public reachability remain unverified.

`O_NOFOLLOW` rejects a symlink in the final path component, but parent-directory
symlinks are not fully blocked. Use a reviewed directory tree without symlinked parents.
Testing on a physical production RaspiBlitz remains unauthorized.

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
