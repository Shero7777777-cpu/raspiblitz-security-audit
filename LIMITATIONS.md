# Known Limitations

This alpha-review prototype has the following known limitations:

1. No validation on a real RaspiBlitz has been performed.
2. Historical static review findings remain BLOCKED until independently
   resolved for a target deployment.
3. Dynamic subprocess command construction requires review.
4. Runtime read-only behavior has not been verified.
5. Runtime privacy redaction has not been verified.
6. Effective firewall packet behavior has not been verified.
7. SSH anti-lockout has not been verified.
8. Public reachability has not been verified.
9. Firewall apply is not implemented.
10. Rollback and production hardening are not implemented.
11. Some source mappings contain illustrative port placeholders.
12. Modules may classify services inconsistently until mappings
    are reviewed and normalized for the target environment.
13. Historical WSL regression results do not validate later edits.
14. Host-specific diagnostic output can contain sensitive metadata.
15. Source review findings are not evidence of current production safety.

This project must not be represented as production-ready or as
having passed a real RaspiBlitz security validation.

## Review architecture limits

There is no central coordinator, no shared whole-audit deadline, and no
coordinator-level bound on the total JSON report size. Hard process
isolation through systemd or cgroups has not been verified on a target
RaspiBlitz. An optional coordinator design was validated only in memory;
no production coordinator has been implemented. This code is not
approved for production deployment.
## Offline review limitations

Successful syntax parsing does not establish effective packet policy, SSH anti-lockout
protection, or public reachability. These remain `NOT_VERIFIED`; firewall application
is `NOT_IMPLEMENTED`. UFW text parsing recognizes only its documented status/default
patterns. There is no OS-level parser watchdog.

This build has not been validated on a physical RaspiBlitz. Live-node testing remains
blocked until an independent source review confirms read-only behavior, output privacy,
snapshot provenance, recovery planning, and explicit authorization for an isolated
test. No command in this repository should be used to collect live snapshots for that
purpose without a separate decision.
