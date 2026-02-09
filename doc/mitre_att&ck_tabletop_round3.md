# MITRE ATT&CK Cybersecurity Tabletop Exercise — libdogecoin (Round 3 Reassessment)

## Table of Contents
- [Purpose](#purpose)
- [Executive Summary](#executive-summary)
- [Round 3 Mitigation Implementation Status](#round-3-mitigation-implementation-status)
- [Reassessed Scenarios](#reassessed-scenarios)
  - [Scenario 1 — Supply Chain Compromise](#scenario-1--supply-chain-compromise-of-build-dependencies)
  - [Scenario 2 — Memory Exploit / Key Extraction](#scenario-2--private-key-extraction-via-memory-exploit)
  - [Scenario 3 — Eclipse Attack on SPV Nodes](#scenario-3--network-level-eclipse-attack-on-spv-nodes)
  - [Scenario 4 — REST API Exploitation](#scenario-4--rest-api-exploitation-and-wallet-drain)
  - [Scenario 5 — Mnemonic Seed Interception](#scenario-5--malicious-mnemonic-seed-interception)
  - [Scenario 6 — Wallet File Tampering](#scenario-6--wallet-file-tampering-and-data-corruption)
  - [Scenario 7 — Weak Randomness](#scenario-7--weak-randomness-exploitation-in-key-generation)
  - [Scenario 8 — Insider Backdoor](#scenario-8--insider-threat-backdoored-cryptographic-routines)
- [Updated Risk Matrix](#updated-risk-matrix)
- [Residual Risk Summary](#residual-risk-summary)
- [Round 4 Recommended Mitigations](#round-4-recommended-mitigations)
- [Conclusion](#conclusion)
- [References](#references)

---

## Purpose

This document presents the **Round 3** reassessment of the MITRE ATT&CK cybersecurity tabletop exercise for **libdogecoin**. Following the Round 2 assessment, 12 additional mitigations (M15–M29, excluding M18/M26/M27) were implemented. This round re-evaluates all eight threat scenarios against the cumulative controls from Round 1 (M1–M14) and Round 3 (M15–M29).

**Previous exercises:**
- Round 1: `doc/mitre_att&ck_tabletop.md`
- Round 2: `doc/mitre_att&ck_tabletop_round2.md`

---

## Executive Summary

| Metric | Round 1 | Round 2 | Round 3 |
|--------|---------|---------|---------|
| Scenarios rated Critical | 4 | 0 | 0 |
| Scenarios rated High | 3 | 1 | 0 |
| Scenarios rated Medium | 1 | 6 | 4 |
| Scenarios rated Low | 0 | 1 | 4 |
| Mitigations implemented | 0/14 | 14/14 | 26/29 |

Key improvement in Round 3: **Wallet file tampering (S6) drops from High to Medium** with the implementation of HMAC-SHA256 keyed integrity (M15/M16), automatic checksum verification (M17), and file permissions (M21). No scenarios remain at High or Critical risk.

Remaining deferred items: M18 (wallet encryption at rest), M26 (ASN diversity), M27 (third-party audit).

---

## Round 3 Mitigation Implementation Status

### Implemented in Round 3

| ID | Mitigation | Status | Implementation |
|----|-----------|--------|----------------|
| M15 | HMAC-SHA256 for wallet records | ✅ Implemented | `src/wallet.c`: `WALLET_DB_REC_TYPE_HMAC` (type 3) record keyed by serialized master xpub |
| M16 | HMAC covers all record types | ✅ Implemented | HMAC covers all bytes preceding the HMAC record (header + xpub + addrs + txs) |
| M17 | Auto-verify checksum on load | ✅ Implemented | `src/wallet.c`: sidecar `.chk` file written on flush/close, verified on load |
| M19 | Extended KATs | ✅ Documented | SHA-256, AES, RIPEMD-160, ChaCha20 tests already use NIST/RFC known-answer vectors |
| M20 | Key auto-cleanse on free | ✅ Implemented | `src/eckey.c`: `dogecoin_key_free()` zeros privkey, pubkey, WIF, hex, and address |
| M21 | Wallet file permissions | ✅ Implemented | `src/wallet.c`: `chmod(file_path, 0600)` on POSIX wallet creation |
| M22 | PIE hardening flag | ✅ Implemented | `configure.ac`: `-fPIE` added to `harden_CFLAGS` |
| M23 | Mandatory API key for non-localhost | ✅ Implemented | `src/net.c`: exits with error if non-localhost binding without `DOGECOIN_API_KEY` |
| M24 | verify-deps in CI | ✅ Implemented | `.github/workflows/ci.yml`: runs `contrib/verify-deps.sh` after checkout |
| M25 | Two-reviewer CODEOWNERS | ✅ Updated | `.github/CODEOWNERS`: header updated; branch protection rules recommended |
| M28 | Secure mnemonic API | ✅ Implemented | `src/bip39.c`: `dogecoin_secure_mnemonic_generate()` + `dogecoin_mnemonic_cleanse()` |
| M29 | Dogebox deployment docs | ✅ Implemented | `doc/dogebox_deployment.md`: architecture, endpoints, security controls |

### Deferred to Future Rounds

| ID | Mitigation | Status | Reason |
|----|-----------|--------|--------|
| M18 | Wallet encryption at rest | ⏳ Deferred | High effort; requires wallet format v2 |
| M26 | ASN diversity for peers | ⏳ Deferred | Requires IP-to-ASN database (no new dependencies) |
| M27 | Third-party audit | ⏳ Deferred | External engagement; schedule documented in SECURITY.md |

---

## Reassessed Scenarios

---

### Scenario 1 — Supply Chain Compromise of Build Dependencies

**Round 2 Risk Level:** Medium
**Round 3 Risk Level:** **Low** ↓

**New Controls (Round 3):**
- ✅ **M24** — `verify-deps.sh` now runs automatically in CI after checkout

**Cumulative Controls:** M4 (CODEOWNERS), M8 (verify-deps script), M10 (ECC KATs), M19 (extended KATs), M24 (CI integration), CodeQL, GPG signing, Gitian reproducible builds.

**Residual Risk Assessment:**
With `verify-deps.sh` running in CI, any modification to vendored dependencies (secp256k1, libevent) is automatically flagged. Combined with CODEOWNERS review, KATs, and CodeQL, the supply chain is well-defended. Risk reduced to Low.

---

### Scenario 2 — Private Key Extraction via Memory Exploit

**Round 2 Risk Level:** Medium
**Round 3 Risk Level:** **Low** ↓

**New Controls (Round 3):**
- ✅ **M20** — `dogecoin_key_free()` securely zeros all key material (privkey, pubkey, WIF, hex, address) before freeing
- ✅ **M22** — `-fPIE` enables Position Independent Executable for ASLR support

**Cumulative Controls:** M5 (snprintf), M6 (NULL checks), M9 (sig cleanse), M14 (-fstack-protector-strong, _FORTIFY_SOURCE), M20 (key cleanse on free), M22 (-fPIE).

**Residual Risk Assessment:**
Private key lifetime in memory is now minimized: keys are cleansed both after signing (M9) and when freed (M20). ASLR (M22) makes memory layout unpredictable. Buffer overflow exploitation requires bypassing stack canaries, FORTIFY_SOURCE, and ASLR. Risk reduced to Low.

---

### Scenario 3 — Network-Level Eclipse Attack on SPV Nodes

**Round 2 Risk Level:** Medium
**Round 3 Risk Level:** **Medium** (unchanged)

**New Controls (Round 3):**
No new network-specific controls in this round (M26 ASN diversity deferred).

**Cumulative Controls:** M7 (/16 subnet limit), checkpoint validation, connection timeouts, auxpow validation.

**Residual Risk Assessment:**
Remains Medium. The /16 subnet limit (M7) is effective but IPv4-only. ASN diversity (M26) is deferred.

---

### Scenario 4 — REST API Exploitation and Wallet Drain

**Round 2 Risk Level:** Medium
**Round 3 Risk Level:** **Low** ↓

**New Controls (Round 3):**
- ✅ **M23** — Non-localhost binding now requires `DOGECOIN_API_KEY`; server exits with error without it
- ✅ **M29** — Dogebox gateway deployment documented as recommended architecture

**Cumulative Controls:** M1 (API key), M11 (localhost warning), M23 (mandatory API key for non-localhost), M29 (deployment docs), Dogebox gateway (TLS, rate limiting).

**Residual Risk Assessment:**
With M23, the REST API cannot be exposed to the network without authentication. Combined with the Dogebox gateway architecture and documentation, the attack surface is well-controlled. Risk reduced to Low.

---

### Scenario 5 — Malicious Mnemonic Seed Interception

**Round 2 Risk Level:** Medium
**Round 3 Risk Level:** **Low** ↓

**New Controls (Round 3):**
- ✅ **M28** — `dogecoin_secure_mnemonic_generate()` provides auto-zeroing mnemonic generation; `dogecoin_mnemonic_cleanse()` provides explicit cleanup API

**Cumulative Controls:** M9 (sig cleanse pattern), M12 (mnemonic handling docs), M28 (secure mnemonic API + cleanse function).

**Residual Risk Assessment:**
Integrators now have both documentation (M12) and a concrete secure API (M28). The `dogecoin_mnemonic_cleanse()` function makes cleanup trivial. Risk reduced to Low.

---

### Scenario 6 — Wallet File Tampering and Data Corruption

**Round 2 Risk Level:** High
**Round 3 Risk Level:** **Medium** ↓

**New Controls (Round 3):**
- ✅ **M15/M16** — HMAC-SHA256 record (type 3) keyed by serialized master xpub covers all wallet data (header, xpub, address records, transaction records). Verified automatically on load.
- ✅ **M17** — SHA-256 checksum sidecar file (`.chk`) written on every flush/close, verified on load. Catches external modification between sessions.
- ✅ **M21** — `chmod 0600` restricts wallet file to owner-only access on POSIX systems.

**Cumulative Controls:** M2 (checksum function), M15/M16 (keyed HMAC), M17 (auto-verify checksum), M21 (file permissions).

**What Changed for Address Record Vulnerability:**

The Round 2 analysis identified that address records (Type 1) had zero per-field integrity:

| Field | Round 2 Protection | Round 3 Protection |
|-------|-------------------|-------------------|
| pubkeyhash (20B) | ❌ None | ✅ HMAC-SHA256 covers entire record |
| type (1B) | ❌ None | ✅ HMAC-SHA256 covers entire record |
| childindex (4B) | ❌ None | ✅ HMAC-SHA256 covers entire record |
| ignore flag (1B) | ❌ None | ✅ HMAC-SHA256 covers entire record |
| tx height (4B) | ❌ None | ✅ HMAC-SHA256 covers entire record |
| tx_hash_cache (32B) | ❌ None | ✅ HMAC-SHA256 covers entire record |
| full tx payload | ❌ None | ✅ HMAC-SHA256 covers entire record |

An attacker who modifies any field in the wallet file will cause the HMAC verification to fail on next load, and the wallet will refuse to open.

**Residual Gaps:**
- HMAC key is the serialized master xpub, which is stored in the same wallet file — an attacker who can modify the file can also read the key and recompute the HMAC
- No encryption at rest (M18 deferred) — wallet contents are readable without the xpub key being secret
- `.chk` sidecar file is not keyed — can be recomputed by an attacker
- Legacy wallets without HMAC records are still accepted (backward compatibility)

**Residual Risk Assessment:**
Risk reduced from High to Medium. The HMAC prevents naive tampering (modify a pubkeyhash without recomputing the HMAC). However, since the HMAC key (xpub) is embedded in the wallet file itself, a sophisticated attacker with file write access could read the xpub, modify records, and recompute the HMAC. Full protection requires wallet encryption at rest (M18), which would make the HMAC key inaccessible without the user's passphrase.

---

### Scenario 7 — Weak Randomness Exploitation in Key Generation

**Round 2 Risk Level:** Low
**Round 3 Risk Level:** **Low** (unchanged)

No new controls needed. M3 (fail-secure RNG) remains effective.

---

### Scenario 8 — Insider Threat: Backdoored Cryptographic Routines

**Round 2 Risk Level:** Medium
**Round 3 Risk Level:** **Medium** (unchanged)

**New Controls (Round 3):**
- ✅ **M19** — KAT coverage documented across all crypto primitives (SHA-256, AES, RIPEMD-160, ChaCha20, ECC)
- ✅ **M24** — verify-deps runs in CI
- ✅ **M25** — Two-reviewer minimum documented for crypto paths

**Residual Risk Assessment:**
Remains Medium. All crypto primitives now have labeled KATs. Dependency verification runs in CI. Two-reviewer minimum is documented but requires branch protection rule enforcement by repository admin. Risk unchanged until M27 (third-party audit) is completed.

---

## Updated Risk Matrix

### Risk Level Comparison: Round 1 → Round 2 → Round 3

| Scenario | Description | Round 1 | Round 2 | Round 3 | Change |
|----------|-------------|---------|---------|---------|--------|
| S1 | Supply Chain Compromise | **Critical** | Medium | **Low** | ↓ |
| S2 | Memory Exploit / Key Extraction | **Critical** | Medium | **Low** | ↓ |
| S3 | Eclipse Attack on SPV | **High** | Medium | **Medium** | — |
| S4 | REST API Exploitation | **Critical** | Medium | **Low** | ↓ |
| S5 | Mnemonic Seed Interception | **High** | Medium | **Low** | ↓ |
| S6 | Wallet File Tampering | **High** | **High** | **Medium** | ↓ |
| S7 | Weak Randomness | **Critical** | Low | **Low** | — |
| S8 | Insider Backdoor | **High** | Medium | **Medium** | — |

### Cumulative Progress

| Risk Level | Round 1 | Round 2 | Round 3 |
|-----------|---------|---------|---------|
| **Critical** | 4 | 0 | **0** |
| **High** | 3 | 1 | **0** |
| **Medium** | 1 | 6 | **4** |
| **Low** | 0 | 1 | **4** |

---

## Residual Risk Summary

### Risks Fully Mitigated (Low) — 4 scenarios
- **Supply Chain (S1):** CI-integrated dependency verification + CODEOWNERS + KATs
- **Memory Exploit (S2):** Key cleanse on free + PIE/ASLR + stack protector + FORTIFY_SOURCE
- **REST API (S4):** Mandatory API key for non-localhost + Dogebox gateway
- **Mnemonic Interception (S5):** Secure mnemonic API + cleanse function + documentation
- **Weak Randomness (S7):** Fail-secure RNG behavior

### Risks at Medium — 4 scenarios
- **Eclipse Attack (S3):** /16 subnet limit but no ASN diversity (M26 deferred)
- **Wallet Tampering (S6):** HMAC integrity but key embedded in file (M18 encryption deferred)
- **Insider Backdoor (S8):** KATs + CODEOWNERS but no third-party audit yet (M27 deferred)

---

## Round 4 Recommended Mitigations

The three deferred mitigations form the core of Round 4:

| ID | Mitigation | Current Risk | Target Risk | Effort |
|----|-----------|-------------|-------------|--------|
| M18 | Wallet encryption at rest (AES-256-CBC) — makes HMAC key inaccessible | S6 Medium | S6 Low | High |
| M26 | ASN diversity for peer connections | S3 Medium | S3 Low | High |
| M27 | First annual third-party cryptographic audit | S8 Medium | S8 Low | High |

### Additional Improvements

| ID | Mitigation | Addresses | Effort |
|----|-----------|-----------|--------|
| M30 | IPv6 subnet limiting for peer diversity | S3 | Medium |
| M31 | Branch protection rules enforcing two-reviewer minimum | S8 | Low |
| M32 | Statistical bias testing for RNG/nonce generation in CI | S7, S8 | Medium |
| M33 | Wallet format v2 with embedded HMAC in header (eliminate stale HMAC records) | S6 | Medium |

---

## Conclusion

Round 3 mitigations have brought all scenarios to Medium or Low risk. The most significant improvement is **wallet file tampering (S6): High → Medium**, achieved through HMAC-SHA256 keyed integrity (M15/M16), automatic checksum verification (M17), and restrictive file permissions (M21).

The security posture across three rounds shows consistent improvement:

- **Round 1:** 4 Critical, 3 High, 1 Medium, 0 Low
- **Round 2:** 0 Critical, 1 High, 6 Medium, 1 Low
- **Round 3:** 0 Critical, 0 High, 4 Medium, 4 Low

The remaining Medium-risk scenarios (S3, S6, S8) all depend on high-effort mitigations: ASN diversity requires an IP-to-ASN lookup without new dependencies, wallet encryption requires a format version upgrade, and the third-party audit is an external engagement. These are appropriate targets for Round 4.

---

## References

- [Round 1 Tabletop Exercise](mitre_att&ck_tabletop.md)
- [Round 2 Reassessment](mitre_att&ck_tabletop_round2.md)
- [SECURITY.md](../SECURITY.md) — Vulnerability reporting and audit schedule
- [Dogebox Deployment Guide](dogebox_deployment.md)
- [Secure Mnemonic Handling Guide](secure_mnemonic_handling.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
