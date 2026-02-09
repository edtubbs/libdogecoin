# MITRE ATT&CK Cybersecurity Tabletop Exercise — libdogecoin (Round 2 Reassessment)

## Table of Contents
- [Purpose](#purpose)
- [Executive Summary](#executive-summary)
- [Mitigation Implementation Status](#mitigation-implementation-status)
- [Reassessed Scenarios](#reassessed-scenarios)
  - [Scenario 1 — Supply Chain Compromise of Build Dependencies](#scenario-1--supply-chain-compromise-of-build-dependencies)
  - [Scenario 2 — Private Key Extraction via Memory Exploit](#scenario-2--private-key-extraction-via-memory-exploit)
  - [Scenario 3 — Network-Level Eclipse Attack on SPV Nodes](#scenario-3--network-level-eclipse-attack-on-spv-nodes)
  - [Scenario 4 — REST API Exploitation and Wallet Drain](#scenario-4--rest-api-exploitation-and-wallet-drain)
  - [Scenario 5 — Malicious Mnemonic Seed Interception](#scenario-5--malicious-mnemonic-seed-interception)
  - [Scenario 6 — Wallet File Tampering and Data Corruption](#scenario-6--wallet-file-tampering-and-data-corruption)
  - [Scenario 7 — Weak Randomness Exploitation in Key Generation](#scenario-7--weak-randomness-exploitation-in-key-generation)
  - [Scenario 8 — Insider Threat: Backdoored Cryptographic Routines](#scenario-8--insider-threat-backdoored-cryptographic-routines)
- [Updated Risk Matrix](#updated-risk-matrix)
- [Residual Risk Summary](#residual-risk-summary)
- [Round 3 Recommended Mitigations](#round-3-recommended-mitigations)
- [Exercise Procedures](#exercise-procedures)
- [Conclusion](#conclusion)
- [References](#references)

---

## Purpose

This document presents the **Round 2** reassessment of the MITRE ATT&CK cybersecurity tabletop exercise for the **libdogecoin** C library. Following the initial assessment (see `doc/mitre_att&ck_tabletop.md`), 14 mitigations (M1–M14) were implemented. This round re-evaluates each of the eight original threat scenarios against the updated codebase, measures residual risk, identifies remaining gaps, and recommends next-round mitigations.

**Previous exercise:** `doc/mitre_att&ck_tabletop.md` (Round 1)

---

## Executive Summary

The Round 1 tabletop exercise identified 8 threat scenarios and recommended 14 mitigations. All 14 have been implemented:

- **4 Critical** mitigations (M1–M4): REST API authentication, wallet checksums, RNG fail-secure, CODEOWNERS — all deployed
- **5 High** mitigations (M5–M9): Safe string ops, allocation checks, peer diversity, dependency verification, signature cleansing — all deployed
- **5 Medium** mitigations (M10–M14): KATs, localhost binding, mnemonic docs, SECURITY.md, hardening flags — all deployed

**Overall risk posture improvement:**

| Metric | Round 1 | Round 2 |
|--------|---------|---------|
| Scenarios rated Critical | 4 | 0 |
| Scenarios rated High | 3 | 3 |
| Scenarios rated Medium | 1 | 4 |
| Scenarios rated Low | 0 | 1 |
| Mitigations implemented | 0/14 | 14/14 |

Key residual risks center on **TLS encryption for the REST API** (M1 partial — auth implemented but no encryption in transit), **wallet encryption at rest** (M2 partial — integrity check implemented but not full AES encryption of the wallet file), and **runtime entropy validation** (M3 partial — fail-secure implemented but no entropy quality testing).

---

## Mitigation Implementation Status

| ID | Mitigation | Status | Implementation |
|----|-----------|--------|----------------|
| M1 | REST API authentication | ✅ Implemented | `src/rest.c`: `check_api_key()` validates `X-API-Key` header against `DOGECOIN_API_KEY` env var |
| M2 | Wallet integrity checksum | ✅ Implemented | `src/wallet.c`: `dogecoin_wallet_checksum()` computes SHA-256 over wallet file contents |
| M3 | RNG fail-secure | ✅ Implemented | `src/random.c`: `fread()` short-read returns `false` instead of `assert()` |
| M4 | Multi-party code review | ✅ Implemented | `.github/CODEOWNERS`: Security-critical paths require maintainer review |
| M5 | Safe string operations | ✅ Implemented | `src/eckey.c`, `src/net.c`, `src/bip39.c`, `src/smpv.c`: `strcpy()` → `snprintf()` |
| M6 | Allocation NULL checks | ✅ Implemented | `src/eckey.c`, `src/random.c`: NULL checks on `calloc` return values |
| M7 | Peer diversity enforcement | ✅ Implemented | `src/net.c`: `count_peers_in_subnet()` limits to `DOGECOIN_MAX_PEERS_PER_SUBNET=2` per /16 |
| M8 | Dependency hash verification | ✅ Implemented | `contrib/verify-deps.sh`: SHA-256 integrity check for vendored subtrees |
| M9 | Signature struct cleansing | ✅ Implemented | `src/ecc.c`: `dogecoin_mem_zero()` on all `secp256k1_ecdsa_signature` structs post-sign |
| M10 | Cryptographic KATs | ✅ Implemented | `test/ecc_tests.c`: Known-answer test with privkey `0x01` → generator point pubkey |
| M11 | Localhost binding warning | ✅ Implemented | `src/net.c`: `fprintf(stderr, "WARNING: ...")` on non-localhost HTTP bind |
| M12 | Mnemonic handling docs | ✅ Implemented | `doc/secure_mnemonic_handling.md`: Lifecycle guidance, anti-patterns, platform notes |
| M13 | Security policy & audit schedule | ✅ Implemented | `SECURITY.md`: Vulnerability reporting, audit schedule, controls inventory |
| M14 | Compiler hardening flags | ✅ Implemented | `configure.ac`: `-fstack-protector-strong -D_FORTIFY_SOURCE=2` with feature-test fallback |

---

## Reassessed Scenarios

---

### Scenario 1 — Supply Chain Compromise of Build Dependencies

**Round 1 Risk Level:** Critical
**Round 2 Risk Level:** **Medium** ↓

**ATT&CK Techniques:** T1584, T1195.001, T1129, T1553.002, T1528

**Mitigations Applied:**
- ✅ **M4** — `.github/CODEOWNERS` requires maintainer review for changes to `src/secp256k1/` and `src/libevent/`
- ✅ **M8** — `contrib/verify-deps.sh` provides SHA-256 integrity verification for vendored dependencies
- ✅ **M10** — Known-answer tests (KATs) would detect behavioral changes in cryptographic routines after a dependency update

**Controls Now in Place:**
1. Dependency subtree updates trigger CODEOWNERS review
2. `contrib/verify-deps.sh` can verify vendored file integrity
3. ECC KAT tests validate correct signing behavior
4. CodeQL static analysis in CI detects known vulnerability patterns
5. GPG signing keys and Gitian reproducible builds

**Residual Gaps:**
- `verify-deps.sh` requires manually pinning hashes after reviewed updates (hashes are self-computed on first run)
- No automated SBOM (Software Bill of Materials) generation with releases
- No differential testing against a reference implementation (e.g., comparing against Bitcoin Core's secp256k1 test vectors)
- KATs test basic sign/verify but do not test for subtle nonce bias

**Residual Risk Assessment:**
An attacker would need to (1) compromise a vendored subtree, (2) pass CODEOWNERS review, (3) pass CodeQL analysis, (4) pass KAT tests, and (5) avoid detection by `verify-deps.sh`. This multi-layer defense significantly raises the attacker cost.

**Discussion Questions:**
1. Should `verify-deps.sh` be integrated into CI to run automatically on every build?
2. When will the first SBOM be published?
3. Should KATs include nonce-bias statistical tests (e.g., sign 10,000 messages and test r-value distribution)?

---

### Scenario 2 — Private Key Extraction via Memory Exploit

**Round 1 Risk Level:** Critical
**Round 2 Risk Level:** **Medium** ↓

**ATT&CK Techniques:** T1592.002, T1190, T1203, T1003.007, T1005, T1041

**Mitigations Applied:**
- ✅ **M5** — `strcpy()` replaced with `snprintf()` in `eckey.c`, `net.c`, `bip39.c`, `smpv.c`
- ✅ **M6** — NULL checks on `calloc` returns in `eckey.c`, `random.c`
- ✅ **M9** — Signature structs zeroed with `dogecoin_mem_zero()` after all ECC signing operations
- ✅ **M14** — `-fstack-protector-strong -D_FORTIFY_SOURCE=2` in `configure.ac`

**Controls Now in Place:**
1. Safe string handling eliminates `strcpy` buffer overflow vectors
2. Allocation failure handling prevents NULL-pointer dereference
3. Signature material zeroed immediately after use
4. Stack canaries detect stack buffer overflows at runtime
5. `_FORTIFY_SOURCE=2` provides compile-time and runtime buffer overflow checks
6. Existing `memcpy_safe()`, `dogecoin_mem_zero()`, `dogecoin_privkey_cleanse()` for key wiping

**Residual Gaps:**
- Private keys in the `uthash` hash table still persist for the lifetime of the table — no automatic expiry
- `-fPIE` (Position Independent Executable) not yet added to hardening flags
- No ASLR enforcement at the library level (depends on application/OS)
- Heap allocations for keys are not guarded by `mlock()` to prevent swap
- Some `strcpy` calls remain in `src/seal.c` (used only with `test_password` compile flag)

**Residual Risk Assessment:**
Buffer overflow exploitation is now significantly harder: `snprintf` prevents string overflows, `_FORTIFY_SOURCE=2` catches many buffer issues at runtime, and stack canaries detect stack smashing. The primary remaining vector is information leakage through key material persisting in heap memory.

**Discussion Questions:**
1. Should the key hash table implement automatic expiry/cleansing after a configurable timeout?
2. Is `mlock()` appropriate for key storage buffers to prevent swap?
3. Should `-fPIE` be added to the hardening flags?

---

### Scenario 3 — Network-Level Eclipse Attack on SPV Nodes

**Round 1 Risk Level:** High
**Round 2 Risk Level:** **Medium** ↓

**ATT&CK Techniques:** T1595.002, T1583.005, T1190, T1059, T1656, T1565.002, T1657

**Mitigations Applied:**
- ✅ **M7** — `src/net.c`: `count_peers_in_subnet()` enforces `DOGECOIN_MAX_PEERS_PER_SUBNET=2` per /16 subnet

**Controls Now in Place:**
1. Per-/16 subnet connection limit prevents single-operator domination
2. Existing checkpoint validation at known block heights
3. Connection timeout (10s) and ping interval (120s) limit stale connections
4. Auxpow validation for merge-mined blocks
5. Block header chain-work validation

**Residual Gaps:**
- Subnet limit is IPv4-only; IPv6 peers are not limited
- No ASN (Autonomous System Number) diversity enforcement — attacker can use IPs from different /16s in the same ASN
- No peer reputation scoring or banning of misbehaving peers beyond basic `NODE_MISSBEHAVED` flag
- No outbound peer rotation — once connected, peers remain until disconnect
- `DOGECOIN_MAX_PEERS_PER_SUBNET=2` is hardcoded — not configurable at runtime
- No DNS seed verification or DNSSEC enforcement

**Residual Risk Assessment:**
The /16 subnet limit raises the bar for eclipse attacks: an attacker now needs IPs across at least 4 distinct /16 subnets to monopolize the default 8 connections. However, a well-resourced attacker (botnet, cloud hosting) can still acquire diverse IPs. ASN-level diversity would further increase the cost.

**Discussion Questions:**
1. Should the subnet limit be configurable via a CLI flag or environment variable?
2. Is ASN-level diversity enforcement feasible without adding a dependency (e.g., MaxMind GeoIP)?
3. Should the SPV client implement periodic outbound peer rotation (disconnect one peer every N minutes and connect a fresh one)?

---

### Scenario 4 — REST API Exploitation and Wallet Drain

**Round 1 Risk Level:** Critical
**Round 2 Risk Level:** **High** ↓

**ATT&CK Techniques:** T1596, T1190, T1087.002, T1654, T1005, T1657

**Mitigations Applied:**
- ✅ **M1** — `src/rest.c`: `check_api_key()` validates `X-API-Key` header against `DOGECOIN_API_KEY` environment variable; returns 403 Forbidden on mismatch
- ✅ **M11** — `src/net.c`: Warning printed to stderr when HTTP server binds to non-localhost address

**Controls Now in Place:**
1. API key authentication blocks unauthenticated access when `DOGECOIN_API_KEY` is set
2. Non-localhost binding produces a visible security warning
3. REST API remains optional — must be explicitly started with `-u` flag
4. Error handling via `evhttp_send_error()`

**Residual Gaps:**
- **No TLS/HTTPS** — API key transmitted in plaintext over the network, vulnerable to interception
- **No rate limiting** — API can be brute-forced or DoS'd
- Authentication is opt-in (env var) — if `DOGECOIN_API_KEY` is not set, API is completely open
- No CORS policy enforcement
- No input validation/sanitization on query parameters beyond path matching
- API key is a single shared secret — no per-user/per-role access control
- No audit logging of API requests

**Residual Risk Assessment:**
The API key authentication is a significant improvement but incomplete: without TLS, the key can be intercepted by network observers. Without rate limiting, the key can be brute-forced. The risk level remains High because the REST API exposes financial data (balances, UTXOs) and a successful compromise enables wallet enumeration.

**Discussion Questions:**
1. Should TLS be a requirement before the API key feature is considered production-ready?
2. Can libevent's built-in SSL support be enabled without adding a new dependency?
3. Should API key authentication be mandatory (not opt-in) when binding to non-localhost?
4. Should the API implement separate read-only vs. write/sign authorization tiers?

---

### Scenario 5 — Malicious Mnemonic Seed Interception

**Round 1 Risk Level:** High
**Round 2 Risk Level:** **Medium** ↓

**ATT&CK Techniques:** T1189, T1129, T1056.001, T1552.004, T1115, T1113, T1567

**Mitigations Applied:**
- ✅ **M12** — `doc/secure_mnemonic_handling.md` provides lifecycle guidance: generation, display, verification, seed derivation, destruction
- ✅ **M9** — Signature struct cleansing demonstrates the pattern for secure memory handling

**Controls Now in Place:**
1. Comprehensive integrator documentation with anti-patterns table
2. `dogecoin_mem_zero()` available and recommended for mnemonic buffers
3. Platform-specific guidance (Linux `mlock()`, Windows `VirtualLock()`)
4. TEE (OP-TEE/Open Enclave) integration available for high-value use cases
5. BIP39 checksum validation for mnemonic integrity

**Residual Gaps:**
- Library does not enforce mnemonic cleanup — integrators must follow documentation
- No `dogecoin_mnemonic_cleanse()` convenience API
- No auto-zeroing buffer type for mnemonics
- Mnemonic string allocated on heap with standard allocator — no `mlock()` by default
- Library cannot prevent integrator anti-patterns (logging, clipboard, CLI args)

**Residual Risk Assessment:**
Risk is reduced from High to Medium because integrators now have clear guidance. However, the library cannot enforce proper handling by consuming applications. The mnemonic exposure window is determined by the integrator's implementation, not by libdogecoin.

**Discussion Questions:**
1. Should the library provide a `dogecoin_secure_mnemonic_generate()` API that returns an auto-zeroing buffer?
2. Can `dogecoin_generate_mnemonic()` be modified to accept a caller-provided buffer (avoiding heap allocation)?
3. Should the library print a deprecation warning if the mnemonic is not explicitly cleansed within N seconds?

---

### Scenario 6 — Wallet File Tampering and Data Corruption

**Round 1 Risk Level:** High
**Round 2 Risk Level:** **High** (unchanged)

**ATT&CK Techniques:** T1078.003, T1556, T1070.004, T1565.001, T1657

**Mitigations Applied:**
- ✅ **M2** — `src/wallet.c`: `dogecoin_wallet_checksum()` computes SHA-256 hash over wallet file contents

**Controls Now in Place:**
1. SHA-256 checksum function available for integrity verification
2. Magic byte validation (`0xA8F011C5`) on wallet file load
3. Record-level magic bytes (`0xC8F2691E`) for structural integrity
4. Version number validation
5. Master public key double-write verification on load

**Residual Gaps:**
- **Checksum is not automatically computed or verified** — `dogecoin_wallet_checksum()` must be called explicitly by the consuming application
- **No HMAC** — checksum is a plain hash, not keyed; an attacker who modifies the file can recompute the hash
- **No encryption at rest** — private keys/master key in wallet file are not encrypted (except when using TPM/seal features)
- **No file permission enforcement** — library does not set `chmod 0600` on wallet creation
- **No backup/recovery mechanism** in the library
- The checksum is external — not embedded in the wallet file format itself

**Residual Risk Assessment:**
Risk remains High because the checksum is not keyed (HMAC) and is not automatically verified. An attacker with file write access can modify the wallet and recompute the hash. The fundamental gap — no encryption at rest — means private key material in the wallet file is accessible to any process with read access.

**Discussion Questions:**
1. Should `dogecoin_wallet_load()` automatically verify the checksum and fail on mismatch?
2. Should the wallet format be extended to embed an HMAC in the file header?
3. Can the existing AES-256-CBC implementation be used to encrypt the wallet file at rest?
4. Should wallet creation enforce `chmod 0600` on POSIX systems?

---

### Scenario 7 — Weak Randomness Exploitation in Key Generation

**Round 1 Risk Level:** Critical
**Round 2 Risk Level:** **Low** ↓

**ATT&CK Techniques:** T1592.001, T1587.004, T1110, T1552.004, T1657

**Mitigations Applied:**
- ✅ **M3** — `src/random.c`: `fread()` short-read returns `false`; `fopen()` failure returns `false` — key generation propagates failure to caller
- ✅ **M6** — `src/random.c`: NULL check on `fast_random_context` allocation

**Controls Now in Place:**
1. RNG failure is fail-secure — key generation refuses to proceed without full entropy read
2. Platform-specific RNG: BCryptGenRandom (Windows), `/dev/urandom` (Linux)
3. ChaCha20-based `fast_random_context` for additional randomization
4. secp256k1 context randomized via `secp256k1_context_randomize()`
5. NULL allocation check prevents use of uninitialized random context

**Residual Gaps:**
- No runtime entropy quality validation (e.g., compression test on entropy bytes)
- No mixing of multiple entropy sources (OS + hardware RNG + timing jitter)
- `fast_random_context` seeding quality not independently verified
- Embedded/IoT platforms may have `/dev/urandom` available but with low entropy at boot
- No compile-time assertion that `WITH_TESTING` mode (which uses `rand()`) is disabled in production builds

**Residual Risk Assessment:**
Risk is reduced to Low because the fail-secure behavior ensures that key generation cannot proceed without a full entropy read from the OS RNG. On standard Linux/Windows/macOS systems, this provides cryptographically strong randomness. The remaining risks apply primarily to unusual embedded environments.

**Discussion Questions:**
1. Should libdogecoin add a `dogecoin_entropy_check()` API for integrators to validate entropy quality?
2. Should production builds fail to compile if `WITH_TESTING` is defined?
3. Is hardware RNG mixing (RDRAND on x86, RNDR on ARM) worth the platform complexity?

---

### Scenario 8 — Insider Threat: Backdoored Cryptographic Routines

**Round 1 Risk Level:** High
**Round 2 Risk Level:** **Medium** ↓

**ATT&CK Techniques:** T1585, T1199, T1129, T1553.002, T1606, T1657

**Mitigations Applied:**
- ✅ **M4** — `.github/CODEOWNERS` requires maintainer review for `src/ecc.c`, `src/aes.c`, `src/random.c`, `src/bip32.c`, `src/bip39.c`, `src/key.c`, `src/eckey.c`, `src/seal.c`
- ✅ **M10** — `test/ecc_tests.c`: Known-answer test validates privkey→pubkey derivation (secp256k1 generator point) and sign/verify round-trip
- ✅ **M13** — `SECURITY.md` establishes annual third-party audit schedule

**Controls Now in Place:**
1. CODEOWNERS enforces maintainer review on all cryptographic code paths
2. KAT test verifies ECC signing produces correct results for known inputs
3. KAT negative test confirms wrong hash fails verification
4. CodeQL static analysis in CI
5. GPG-signed commits
6. Annual audit schedule documented in SECURITY.md
7. Gitian reproducible builds

**Residual Gaps:**
- KAT tests cover ECC but not AES, SHA-256, RIPEMD-160, or ChaCha20
- No statistical bias testing for nonce generation (r-value distribution)
- No differential testing against a reference implementation
- CODEOWNERS requires only one reviewer (not a minimum of two)
- No branch protection rules requiring status checks to pass before merge
- Annual audit has not yet been conducted (schedule documented but no audit performed)

**Residual Risk Assessment:**
The multi-layer defense (CODEOWNERS + KATs + CodeQL + GPG signing + reproducible builds) significantly raises the bar. A subtle backdoor would need to pass code review, avoid triggering KAT failures, evade CodeQL detection, and remain undetected until the next audit. The primary gap is limited KAT coverage — only ECC is tested with known-answer vectors.

**Discussion Questions:**
1. Should KATs be extended to cover AES-256-CBC, SHA-256, RIPEMD-160, and ChaCha20?
2. Should CODEOWNERS require a minimum of two reviewers for cryptographic paths?
3. When will the first annual third-party audit be conducted?
4. Should statistical bias tests be added to CI (e.g., sign 10,000 messages, test nonce distribution)?

---

## Updated Risk Matrix

### Risk Level Comparison: Round 1 vs Round 2

| Scenario | Description | Round 1 | Round 2 | Change | Key Mitigation |
|----------|-------------|---------|---------|--------|----------------|
| S1 | Supply Chain Compromise | **Critical** | **Medium** | ↓↓ | M4, M8, M10 |
| S2 | Memory Exploit / Key Extraction | **Critical** | **Medium** | ↓↓ | M5, M6, M9, M14 |
| S3 | Eclipse Attack on SPV | **High** | **Medium** | ↓ | M7 |
| S4 | REST API Exploitation | **Critical** | **High** | ↓ | M1, M11 |
| S5 | Mnemonic Seed Interception | **High** | **Medium** | ↓ | M12, M9 |
| S6 | Wallet File Tampering | **High** | **High** | — | M2 (partial) |
| S7 | Weak Randomness | **Critical** | **Low** | ↓↓↓ | M3, M6 |
| S8 | Insider Backdoor | **High** | **Medium** | ↓ | M4, M10, M13 |

### ATT&CK Technique Coverage

| ATT&CK ID | Technique | Round 1 Risk | Round 2 Risk | Mitigation Coverage |
|------------|-----------|-------------|-------------|---------------------|
| T1190 | Exploit Public-Facing Application | Critical | High | M1, M5, M6, M14 |
| T1195.001 | Supply Chain — Software Dependencies | Critical | Medium | M4, M8, M10 |
| T1657 | Financial Theft | Critical | High | M1, M2, M3, M7 |
| T1552.004 | Unsecured Credentials — Private Keys | Critical | Medium | M3, M9, M12 |
| T1565.001 | Data Manipulation — Stored Data | High | High | M2 (partial) |
| T1565.002 | Data Manipulation — Transmitted Data | High | Medium | M7, M11 |
| T1003.007 | OS Credential Dumping | High | Medium | M9, M14 |
| T1005 | Data from Local System | High | Medium | M1, M9, M14 |
| T1199 | Trusted Relationship | High | Medium | M4, M10, M13 |
| T1553.002 | Subvert Trust Controls | High | Medium | M4, M8, M10 |
| T1110 | Brute Force | High | Low | M3 |

---

## Residual Risk Summary

### Risks Fully Mitigated (Low)
- **Weak Randomness (S7):** RNG fail-secure behavior ensures key generation cannot proceed without verified entropy

### Risks Significantly Reduced (Medium)
- **Supply Chain (S1):** Multi-layer defense with CODEOWNERS, dependency verification, and KATs
- **Memory Exploit (S2):** Safe string ops, allocation checks, signature cleansing, and compiler hardening
- **Eclipse Attack (S3):** Per-/16 subnet diversity limits
- **Mnemonic Interception (S5):** Comprehensive integrator documentation
- **Insider Backdoor (S8):** Code review enforcement, KATs, and audit schedule

### Risks Partially Mitigated (High)
- **REST API Exploitation (S4):** Authentication implemented but no TLS encryption; brute-force possible
- **Wallet File Tampering (S6):** Checksum available but not keyed (HMAC) and not auto-verified; no encryption at rest

---

## Round 3 Recommended Mitigations

Based on residual risk analysis, the following mitigations are recommended for the next cycle:

### Priority 1 — Critical (Address REST API and Wallet gaps)

| ID | Mitigation | Addresses | Effort |
|----|-----------|-----------|--------|
| M15 | Add TLS support for REST API (via libevent SSL or mbedTLS) | S4 | High |
| M16 | Implement HMAC-SHA256 keyed integrity for wallet file (embedded in header) | S6 | Medium |
| M17 | Implement wallet file encryption at rest using AES-256-CBC | S6 | Medium |
| M18 | Make API key mandatory when binding to non-localhost | S4 | Low |

### Priority 2 — High (Expand defense depth)

| ID | Mitigation | Addresses | Effort |
|----|-----------|-----------|--------|
| M19 | Add rate limiting for REST API (token bucket per source IP) | S4 | Medium |
| M20 | Extend KATs to AES-256-CBC, SHA-256, RIPEMD-160, ChaCha20 | S8 | Low |
| M21 | Add private key expiry/auto-cleanse in uthash key table | S2 | Medium |
| M22 | Enforce `chmod 0600` on wallet file creation (POSIX) | S6 | Low |
| M23 | Add `-fPIE` to hardening flags for ASLR support | S2 | Low |

### Priority 3 — Medium (Process and documentation)

| ID | Mitigation | Addresses | Effort |
|----|-----------|-----------|--------|
| M24 | Integrate `verify-deps.sh` into CI pipeline | S1 | Low |
| M25 | Require two-reviewer minimum for cryptographic CODEOWNERS paths | S8 | Low |
| M26 | Implement peer reputation scoring and ASN diversity | S3 | High |
| M27 | Conduct first annual third-party cryptographic audit | S1, S7, S8 | High |
| M28 | Add `dogecoin_secure_mnemonic_generate()` with auto-zeroing buffer | S5 | Medium |

---

## Exercise Procedures

### Round 2 Execution

| Phase | Duration | Activity |
|-------|----------|----------|
| Review | 15 min | Review Round 1 findings and M1–M14 implementation status |
| Reassessment | 90 min | Walk through each scenario, evaluate residual risk with new controls |
| Gap Analysis | 20 min | Identify remaining gaps and map to Round 3 mitigations (M15–M28) |
| Prioritization | 15 min | Rank M15–M28 by impact/effort, assign owners |
| Action Planning | 10 min | Set timelines for Priority 1 items, schedule Round 3 |

### Recommended Round 3 Timeline

| Milestone | Target |
|-----------|--------|
| M18 (mandatory API key for non-localhost) | 2 weeks |
| M20 (extended KATs) | 2 weeks |
| M22 (wallet file permissions) | 2 weeks |
| M23 (`-fPIE` hardening) | 2 weeks |
| M24 (verify-deps in CI) | 2 weeks |
| M16 (wallet HMAC) | 4 weeks |
| M17 (wallet encryption) | 6 weeks |
| M15 (REST TLS) | 8 weeks |
| M27 (first audit) | 12 weeks |

---

## Conclusion

The Round 1 mitigations (M1–M14) have materially improved libdogecoin's security posture. Four scenarios previously rated Critical are now at Medium or Low, and no scenarios remain at Critical. The most significant improvements are in RNG fail-secure behavior (S7: Critical→Low), memory exploit resistance (S2: Critical→Medium), and supply chain protection (S1: Critical→Medium).

The two remaining High-risk scenarios — REST API exploitation (S4) and wallet file tampering (S6) — require TLS encryption and keyed integrity verification, respectively. These are recommended as Priority 1 for Round 3.

Regular tabletop exercise re-assessment (every 6–12 months) and the first annual third-party audit will ensure the security posture continues to improve.

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Round 1 Tabletop Exercise](mitre_att&ck_tabletop.md)
- [SECURITY.md](../SECURITY.md) — Vulnerability reporting and audit schedule
- [Secure Mnemonic Handling Guide](secure_mnemonic_handling.md)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic Code for Generating Deterministic Keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [NIST SP 800-90A: Random Number Generation](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [Eclipse Attacks on Bitcoin's Peer-to-Peer Network (Heilman et al.)](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman)
