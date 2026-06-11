# MITRE ATT&CK Cybersecurity Tabletop Exercise — libdogecoin (Round 4 Reassessment)

## Purpose

This Round 4 reassessment was performed after syncing to the latest `0.1.5-dev` base branch and re-evaluating previously deferred mitigations.

## Executive Summary

- Base branch updates were merged and conflict-resolved with existing Round 1–3 controls preserved.
- New mitigation implemented in this round:
  - **M30 (IPv6 subnet peer diversity):** the SPV peer diversity limit now applies to IPv6 peers using a `/48` prefix in addition to the existing IPv4 `/16` limit.
- Risk changes:
  - **S3 (Eclipse Attack on SPV): Medium → Low**
  - Other scenario ratings unchanged from Round 3.

## Round 4 Mitigation Status

| ID | Mitigation | Status | Implementation |
|----|-----------|--------|----------------|
| M30 | IPv6 subnet limiting for peer diversity | ✅ Implemented | `src/net.c`: `count_peers_in_subnet()` now enforces `/16` for IPv4 and `/48` for IPv6 with per-family connection limits |
| M18 | Wallet encryption at rest | ⏳ Deferred | Requires wallet format/version upgrade and migration path |
| M26 | ASN diversity for peer connections | ⏳ Deferred | Still requires ASN mapping source without adding fragile dependency risk |
| M27 | Third-party crypto audit | ⏳ Deferred | External engagement/tracking in security process |
| M31 | Branch protection enforcement | ⏳ Deferred | Repository administration/policy control (outside library runtime) |
| M32 | RNG/nonce statistical bias testing in CI | ⏳ Deferred | Needs deterministic CI harness and acceptance thresholds |
| M33 | Wallet format v2 embedded HMAC model | ⏳ Deferred | Requires backward-compatible format migration |

## Scenario Reassessment Delta (Round 3 → Round 4)

| Scenario | Round 3 | Round 4 | Rationale |
|---------|---------|---------|-----------|
| S3 — Network-Level Eclipse Attack on SPV Nodes | Medium | **Low** | IPv6 peers are no longer exempt from subnet diversity controls; attacker concentration via IPv6 prefix reuse is reduced |
| S1, S2, S4, S5, S6, S7, S8 | Unchanged | Unchanged | No new runtime control changes in this round affecting those scenarios |

## Residual Risk Summary

- **Low risk:** S1, S2, S3, S4, S5, S7
- **Medium risk:** S6 (wallet tampering with key-material exposure), S8 (insider/backdoor risk pending external audit and governance controls)

## Validation Notes

- Existing wallet integrity controls (M15/M16/M17) remained in place after base-branch merge conflict resolution.
- Existing key-handling hardening remained in place and was merged with upstream DIT protections in ECC signing paths.

## References

- [Round 1 Tabletop Exercise](mitre_att&ck_tabletop.md)
- [Round 2 Reassessment](mitre_att&ck_tabletop_round2.md)
- [Round 3 Reassessment](mitre_att&ck_tabletop_round3.md)
