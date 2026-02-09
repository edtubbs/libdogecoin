# MITRE ATT&CK Cybersecurity Tabletop Exercise — libdogecoin

## Table of Contents
- [Purpose](#purpose)
- [Scope](#scope)
- [MITRE ATT&CK Framework Overview](#mitre-attck-framework-overview)
- [Asset Inventory](#asset-inventory)
- [Threat Actor Profiles](#threat-actor-profiles)
- [Attack Surface Analysis](#attack-surface-analysis)
- [Tabletop Scenarios](#tabletop-scenarios)
  - [Scenario 1 — Supply Chain Compromise of Build Dependencies](#scenario-1--supply-chain-compromise-of-build-dependencies)
  - [Scenario 2 — Private Key Extraction via Memory Exploit](#scenario-2--private-key-extraction-via-memory-exploit)
  - [Scenario 3 — Network-Level Eclipse Attack on SPV Nodes](#scenario-3--network-level-eclipse-attack-on-spv-nodes)
  - [Scenario 4 — REST API Exploitation and Wallet Drain](#scenario-4--rest-api-exploitation-and-wallet-drain)
  - [Scenario 5 — Malicious Mnemonic Seed Interception](#scenario-5--malicious-mnemonic-seed-interception)
  - [Scenario 6 — Wallet File Tampering and Data Corruption](#scenario-6--wallet-file-tampering-and-data-corruption)
  - [Scenario 7 — Weak Randomness Exploitation in Key Generation](#scenario-7--weak-randomness-exploitation-in-key-generation)
  - [Scenario 8 — Insider Threat: Backdoored Cryptographic Routines](#scenario-8--insider-threat-backdoored-cryptographic-routines)
- [MITRE ATT&CK Technique Mapping Summary](#mitre-attck-technique-mapping-summary)
- [Consolidated Mitigations](#consolidated-mitigations)
- [Tabletop Exercise Procedures](#tabletop-exercise-procedures)
- [Conclusion](#conclusion)
- [References](#references)

---

## Purpose

This document presents a cybersecurity tabletop exercise for the **libdogecoin** C library, structured around the [MITRE ATT&CK](https://attack.mitre.org/) framework. The exercise identifies realistic threat scenarios, maps them to ATT&CK tactics and techniques, evaluates existing controls, and recommends mitigations.

The goal is to strengthen the security posture of libdogecoin by proactively analyzing how adversaries could target the library, its build pipeline, its runtime components, and applications built on top of it.

---

## Scope

This tabletop exercise covers the following components of libdogecoin:

| Component | Description |
|-----------|-------------|
| **Core Library** | Cryptographic operations (secp256k1, AES-256-CBC, SHA-256, RIPEMD-160), key management (BIP32/BIP39/BIP44), transaction construction, script evaluation |
| **Wallet Subsystem** | Binary wallet file storage, HD key derivation, UTXO tracking, address management |
| **SPV Node** | Simplified Payment Verification, P2P protocol, block header sync, checkpoint validation |
| **REST API** | HTTP endpoints for balance queries, address listing, and transaction data |
| **CLI Tools** | `such` (address/transaction tool), `sendtx` (transaction broadcaster), `spvnode` (SPV client) |
| **Build Pipeline** | Autoconf/CMake build system, secp256k1/libevent dependencies, CI/CD (GitHub Actions), reproducible builds (Gitian) |
| **Platform Support** | Linux, macOS, Windows, ARM, OP-TEE/Open Enclave trusted execution environments |

---

## MITRE ATT&CK Framework Overview

The [MITRE ATT&CK](https://attack.mitre.org/) framework categorizes adversary behavior into **Tactics** (the "why") and **Techniques** (the "how"). This exercise maps libdogecoin threats to the following ATT&CK tactics:

| Tactic | ATT&CK ID | Relevance to libdogecoin |
|--------|-----------|--------------------------|
| Reconnaissance | TA0043 | Gathering info about library APIs, network endpoints, wallet formats |
| Resource Development | TA0042 | Creating exploit tools, malicious forks, or trojanized dependencies |
| Initial Access | TA0001 | Exploiting network services, supply chain, or developer environments |
| Execution | TA0002 | Running malicious code through library API abuse or injected payloads |
| Persistence | TA0003 | Modifying wallet files or build scripts to maintain access |
| Privilege Escalation | TA0004 | Escalating from library context to system-level access |
| Defense Evasion | TA0005 | Bypassing checksums, code signing, or integrity checks |
| Credential Access | TA0006 | Extracting private keys, mnemonics, or wallet encryption keys |
| Discovery | TA0007 | Enumerating wallet addresses, balances, transaction history |
| Collection | TA0009 | Harvesting private keys, seed phrases, wallet data |
| Exfiltration | TA0010 | Transmitting stolen keys or wallet data to adversary infrastructure |
| Impact | TA0040 | Draining wallets, corrupting blockchain data, denial of service |

---

## Asset Inventory

### Critical Assets

| Asset | Sensitivity | Location in Codebase |
|-------|-------------|---------------------|
| Private keys (ECDSA secp256k1) | **CRITICAL** | `src/ecc.c`, `src/eckey.c`, `src/key.c` |
| HD master seed / mnemonic phrases | **CRITICAL** | `src/bip39.c`, `src/bip32.c` |
| Wallet file (binary format) | **HIGH** | `src/wallet.c` — magic `0xA8F011C5` |
| AES encryption keys | **HIGH** | `src/aes.c` |
| UTXO set / transaction data | **HIGH** | `src/transaction.c`, `src/tx.c` |
| Random number generator state | **HIGH** | `src/random.c` — ChaCha20 + OS entropy |
| P2P peer connections / node state | **MEDIUM** | `src/net.c`, `src/spv.c` |
| REST API endpoints | **MEDIUM** | `src/rest.c` |
| Build system / CI configuration | **MEDIUM** | `Makefile.am`, `.github/workflows/` |
| secp256k1 / libevent dependencies | **MEDIUM** | `src/secp256k1/`, `src/libevent/` |

### Data Flow Summary

```
User Input → CLI Tools (such/sendtx/spvnode)
                ↓
         Core Library API
                ↓
    ┌───────────┼───────────┐
    ↓           ↓           ↓
Key Generation  Transaction  SPV Node
(random.c →    Construction  (net.c →
 ecc.c →       (tx.c →       protocol.c →
 bip32/39.c)   script.c)     spv.c)
    ↓           ↓           ↓
    └───────────┼───────────┘
                ↓
         Wallet Storage          REST API
         (wallet.c →             (rest.c →
          file I/O)               evhttp)
```

---

## Threat Actor Profiles

| Actor | Motivation | Capability | Relevant Scenarios |
|-------|-----------|------------|-------------------|
| **Financially Motivated Criminal** | Steal cryptocurrency | Medium — exploit known vulns, phishing, malware | Scenarios 2, 4, 5 |
| **Nation-State APT** | Disrupt cryptocurrency ecosystem, surveillance | High — zero-days, supply chain attacks, advanced persistence | Scenarios 1, 7, 8 |
| **Malicious Insider** | Financial gain, sabotage | High — direct code access, social engineering of maintainers | Scenarios 1, 8 |
| **Hacktivists** | Disrupt Dogecoin network | Low-Medium — DDoS, public exploit tools | Scenarios 3, 6 |
| **Opportunistic Attacker** | Steal funds from exposed nodes | Low — automated scanning, known exploit scripts | Scenarios 4, 6 |

---

## Attack Surface Analysis

### External Attack Surface

| Surface | Entry Point | Risk |
|---------|------------|------|
| **P2P Network** | TCP connections to Dogecoin peers via `net.c` | Malformed messages, eclipse attacks |
| **REST API** | HTTP server on configurable port via `rest.c` | No authentication, no TLS, information disclosure |
| **CLI Input** | Command-line arguments to `such`, `sendtx`, `spvnode` | Argument injection, path traversal |
| **Wallet File** | Binary file read/write via `wallet.c` | Tampering, corruption, unauthorized access |

### Internal Attack Surface

| Surface | Entry Point | Risk |
|---------|------------|------|
| **Memory** | Heap allocations for keys, seeds, buffers | Buffer overflow, use-after-free, info leaks |
| **RNG State** | `fast_random_context` ChaCha20 state | Predictable keys if entropy is weak |
| **Build Dependencies** | secp256k1, libevent subtrees | Supply chain compromise |
| **Shared Library** | `libdogecoin.so` / `libdogecoin.dll` linked by applications | Library injection, symbol hijacking |

---

## Tabletop Scenarios

---

### Scenario 1 — Supply Chain Compromise of Build Dependencies

**Narrative:** A nation-state actor compromises the upstream secp256k1 repository or intercepts the libevent dependency during the build process. The attacker introduces a subtle backdoor that weakens the ECDSA signing nonce generation, making private keys recoverable from published signatures.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Resource Development | Compromise Infrastructure | T1584 | Compromise upstream dependency repo |
| Initial Access | Supply Chain Compromise — Software Dependencies | T1195.001 | Inject backdoor into secp256k1 or libevent |
| Execution | Shared Modules | T1129 | Backdoored library loaded at runtime |
| Defense Evasion | Subvert Trust Controls — Code Signing | T1553.002 | Modify code while maintaining valid-looking commit history |
| Credential Access | Steal Application Access Token | T1528 | Recover private keys from weakened ECDSA nonces |

**Existing Controls:**
- secp256k1 and libevent are vendored as subtrees (reduces real-time upstream risk)
- Gitian reproducible build system (`contrib/gitian-build.sh`) enables verification
- CodeQL static analysis in CI (`.github/workflows/ql.yml`)
- GPG signing keys in `contrib/signing-keys/`

**Gaps:**
- No automated dependency integrity verification (hash pinning) in the build
- Subtree updates are manual and could introduce unreviewed changes
- No Software Bill of Materials (SBOM) generation

**Discussion Questions:**
1. How would the team detect a subtle cryptographic weakness introduced in a dependency update?
2. What is the review process for updating vendored subtrees?
3. Could reproducible builds catch a targeted backdoor that only activates on specific platforms?

**Recommended Mitigations:**
- Implement cryptographic hash verification for all vendored dependencies
- Require multi-party code review for any dependency subtree updates
- Generate and publish SBOM with each release
- Add differential testing against reference implementations after dependency updates

---

### Scenario 2 — Private Key Extraction via Memory Exploit

**Narrative:** An attacker discovers a heap buffer overflow in the transaction deserialization code (`src/serialize.c` or `src/tx.c`). By sending a crafted transaction to an application using libdogecoin, the attacker achieves arbitrary read access to process memory and extracts private keys stored in the hash table managed by `src/eckey.c`.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Reconnaissance | Gather Victim Host Information — Software | T1592.002 | Identify libdogecoin version and memory layout |
| Initial Access | Exploit Public-Facing Application | T1190 | Send crafted transaction via P2P or REST API |
| Execution | Exploitation for Client Execution | T1203 | Trigger buffer overflow in deserialization |
| Credential Access | OS Credential Dumping — Proc Filesystem | T1003.007 | Read process memory for key material |
| Collection | Data from Local System | T1005 | Extract private keys from `uthash` key store |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Send stolen keys to attacker infrastructure |

**Existing Controls:**
- `deser_bytes()` performs buffer length validation before reads
- `memcpy_safe()` used for sensitive copy operations
- `dogecoin_privkey_cleanse()` and `dogecoin_mem_zero()` for key wiping
- Comprehensive deserialization test suite (`test/unittests.c`)

**Gaps:**
- Not all `malloc`/`calloc` return values are checked for NULL
- Private keys remain in memory for the lifetime of the key hash table
- No Address Space Layout Randomization (ASLR) enforcement at the library level
- Some use of `strcpy()` without bounds checking (e.g., in `eckey.c`)

**Discussion Questions:**
1. What is the window of exposure for private keys in memory?
2. Should libdogecoin implement automatic key cleansing after signing operations?
3. How would applications detect memory corruption in the library?

**Recommended Mitigations:**
- Replace all `strcpy()` usage with `strncpy()` or safe string functions
- Validate all memory allocation return values
- Minimize private key lifetime in memory — cleanse immediately after use
- Compile with hardening flags: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`
- Consider memory-safe wrappers or guard pages around key storage

---

### Scenario 3 — Network-Level Eclipse Attack on SPV Nodes

**Narrative:** An attacker controlling multiple IP addresses performs an eclipse attack against an SPV node running `spvnode`. By monopolizing all peer connections, the attacker feeds the node a fabricated chain of block headers that passes checkpoint validation but contains fraudulent transactions, tricking the victim into accepting a fake payment.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Reconnaissance | Active Scanning — Vulnerability Scanning | T1595.002 | Scan for exposed SPV nodes on default ports |
| Resource Development | Acquire Infrastructure — Botnet | T1583.005 | Deploy nodes across multiple IP ranges |
| Initial Access | Exploit Public-Facing Application | T1190 | Connect to SPV node P2P service |
| Execution | Command and Scripting Interpreter | T1059 | Automate fake block header generation |
| Defense Evasion | Impersonation | T1656 | Impersonate legitimate Dogecoin network peers |
| Impact | Data Manipulation — Transmitted Data Manipulation | T1565.002 | Feed fabricated block headers and transactions |
| Impact | Financial Theft | T1657 | Trick victim into accepting invalid payments |

**Existing Controls:**
- Checkpoint system in `src/spv.c` validates chain at known block heights
- `dogecoin_net_spv_post_cmd()` validates block headers against chain work
- Connection timeout (10s) and ping interval (120s) limit stale connections
- Auxpow validation for merge-mined blocks

**Gaps:**
- No peer diversity enforcement (ASN/subnet diversity)
- No maximum connections-per-IP or per-subnet limit visible in `net.c`
- No DNS seed verification or peer reputation scoring
- SPV inherently trusts majority hashpower — cannot validate full transactions

**Discussion Questions:**
1. How many malicious peers would be needed to eclipse a default-configured `spvnode`?
2. Are the hardcoded checkpoints updated frequently enough?
3. Should libdogecoin implement outbound peer rotation or diversity requirements?

**Recommended Mitigations:**
- Enforce peer connection diversity (limit per-subnet, per-ASN connections)
- Implement peer reputation scoring based on behavior
- Add configurable minimum peer count before accepting chain state
- Support connection to trusted/whitelisted nodes
- Implement fraud proof verification where possible

---

### Scenario 4 — REST API Exploitation and Wallet Drain

**Narrative:** An attacker discovers an exposed libdogecoin REST API on the internet. Since the API lacks authentication, the attacker queries `/getBalance` and `/getAddresses` to enumerate wallet contents, then uses the information to construct and broadcast unauthorized transactions, draining the wallet.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Reconnaissance | Search Open Technical Databases | T1596 | Scan for exposed HTTP services (Shodan/Censys) |
| Initial Access | Exploit Public-Facing Application | T1190 | Connect to unauthenticated REST API |
| Discovery | Account Discovery — Domain Account | T1087.002 | Query `/getAddresses` for wallet addresses |
| Discovery | System Financial Information Discovery | T1654 | Query `/getBalance` and `/getTransactions` |
| Collection | Data from Local System | T1005 | Harvest UTXO set and address information |
| Impact | Financial Theft | T1657 | Construct and broadcast drain transactions |

**Existing Controls:**
- REST API is optional and must be explicitly started
- API bound to configurable address (can limit to localhost)
- Error handling via `evhttp_send_error()`

**Gaps:**
- **No authentication or authorization** on any REST endpoint
- **No TLS/HTTPS** — all data transmitted in plaintext
- No rate limiting or request throttling
- No API key, token, or session management
- No input validation on query parameters
- No CORS policy enforcement

**Discussion Questions:**
1. Should the REST API be enabled by default, or require explicit opt-in with security warnings?
2. What is the minimum viable authentication mechanism for the REST API?
3. Should transaction-signing endpoints be exposed via REST at all?

**Recommended Mitigations:**
- Implement authentication (API key, mTLS, or token-based) for all REST endpoints
- Add TLS support via OpenSSL/mbedTLS integration
- Bind to localhost (`127.0.0.1`) by default — require explicit flag for network exposure
- Implement rate limiting (e.g., token bucket per source IP)
- Add CORS headers and input validation for all endpoints
- Separate read-only from write/sign endpoints with distinct authorization levels

---

### Scenario 5 — Malicious Mnemonic Seed Interception

**Narrative:** An attacker compromises a developer workstation or a user-facing application that integrates libdogecoin. When a user generates a new wallet using BIP39 mnemonic generation (`src/bip39.c`), the attacker intercepts the mnemonic phrase during generation or display, before it can be securely stored.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Initial Access | Drive-by Compromise | T1189 | Compromise application integrating libdogecoin |
| Execution | Shared Modules | T1129 | Load malicious shared library alongside libdogecoin |
| Credential Access | Input Capture — Keylogging | T1056.001 | Capture mnemonic as user types or views it |
| Credential Access | Unsecured Credentials — Private Keys | T1552.004 | Read mnemonic from process memory |
| Collection | Clipboard Data | T1115 | Intercept mnemonic copied to clipboard |
| Collection | Screen Capture | T1113 | Screenshot mnemonic display |
| Exfiltration | Exfiltration Over Web Service | T1567 | Send mnemonic to attacker-controlled server |

**Existing Controls:**
- BIP39 implementation uses SHA-256 checksum validation
- Entropy generated from OS random source (`/dev/urandom`, BCryptGenRandom)
- `dogecoin_mem_zero()` available for clearing sensitive buffers

**Gaps:**
- No guidance to integrators on secure mnemonic handling
- Mnemonic string allocated on heap — lifetime not explicitly bounded
- No anti-screenshot or secure display recommendations
- Library does not enforce mnemonic cleanup after use

**Discussion Questions:**
1. Should libdogecoin provide a "secure mnemonic display" API that auto-clears?
2. How should the library guide integrators on mnemonic lifecycle management?
3. What role should TEE (OP-TEE/Open Enclave) play in mnemonic generation?

**Recommended Mitigations:**
- Provide API that returns mnemonics in secure, auto-zeroing buffers
- Document secure mnemonic handling requirements for integrators
- Add warnings in API documentation about mnemonic exposure risks
- Encourage TEE-based key generation for high-value wallets
- Implement `dogecoin_mnemonic_cleanse()` for explicit memory clearing

---

### Scenario 6 — Wallet File Tampering and Data Corruption

**Narrative:** An attacker with local file system access (malware, compromised application, or physical access) modifies the libdogecoin binary wallet file. The attacker alters stored addresses or UTXO data to redirect funds or corrupt the wallet state, causing financial loss when the user next constructs a transaction.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Initial Access | Valid Accounts — Local Accounts | T1078.003 | Gain local access to system with wallet file |
| Persistence | Modify Authentication Process | T1556 | Alter wallet file to persist malicious addresses |
| Defense Evasion | Indicator Removal — File Deletion | T1070.004 | Replace wallet with modified copy matching magic bytes |
| Impact | Data Manipulation — Stored Data Manipulation | T1565.001 | Modify wallet addresses, UTXOs, or key records |
| Impact | Financial Theft | T1657 | Redirect transactions to attacker-controlled addresses |

**Existing Controls:**
- Magic byte validation (`0xA8F011C5`) on wallet file load
- Record-level magic bytes (`0xC8F2691E`) for structural integrity
- Version number validation

**Gaps:**
- **No cryptographic integrity check** (MAC/HMAC) on wallet file contents
- **No encryption at rest** for wallet file (keys may be stored in cleartext)
- No file permission enforcement from the library
- No tamper-detection mechanism beyond magic bytes
- No backup/recovery mechanism built into the library

**Discussion Questions:**
1. Should wallet files include an HMAC over their contents?
2. What encryption-at-rest scheme is appropriate for the wallet file?
3. How should the library handle detection of a tampered wallet file?

**Recommended Mitigations:**
- Add HMAC-SHA256 integrity verification to wallet file format
- Implement wallet file encryption at rest (AES-256-CBC is already available)
- Set restrictive file permissions (0600) on wallet file creation
- Implement wallet backup and recovery mechanisms
- Add checksum per-record for granular corruption detection

---

### Scenario 7 — Weak Randomness Exploitation in Key Generation

**Narrative:** An attacker identifies that a specific platform or build configuration of libdogecoin uses a weak random number generator. On a system where `/dev/urandom` is unavailable and the fallback is the insecure testing-mode `rand()`, or where the ChaCha20 fast random context is seeded with insufficient entropy, the attacker can predict generated private keys.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Reconnaissance | Gather Victim Host Information — Hardware | T1592.001 | Identify target platform and entropy sources |
| Resource Development | Develop Capabilities — Exploits | T1587.004 | Build key prediction tool based on weak RNG |
| Credential Access | Brute Force | T1110 | Enumerate predicted key space |
| Credential Access | Unsecured Credentials — Private Keys | T1552.004 | Derive private keys from predictable RNG output |
| Impact | Financial Theft | T1657 | Steal funds using predicted private keys |

**Existing Controls:**
- Platform-specific RNG: BCryptGenRandom (Windows), `/dev/urandom` (Linux)
- ChaCha20-based `fast_random_context` for additional randomization
- secp256k1 context randomized via `secp256k1_context_randomize()`
- Testing mode (`WITH_TESTING`) uses `rand()` but is compile-time gated

**Gaps:**
- `/dev/urandom` open failure path does not have a secure fallback
- No runtime entropy quality validation
- `fast_random_context` seeding not verified for sufficient entropy
- Embedded/IoT platforms may have limited entropy sources
- No compile-time or runtime assertion that `WITH_TESTING` is disabled in production

**Discussion Questions:**
1. What happens if `/dev/urandom` is unavailable on a production system?
2. How can the library verify entropy quality at runtime?
3. Should key generation refuse to proceed below an entropy threshold?

**Recommended Mitigations:**
- Add entropy quality checks before key generation (e.g., compress-test entropy bytes)
- Fail securely if no cryptographic RNG is available — refuse to generate keys
- Add runtime assertion / build flag to prevent `WITH_TESTING` RNG in release builds
- Mix multiple entropy sources (OS + hardware + timing jitter)
- Document platform-specific entropy requirements for integrators

---

### Scenario 8 — Insider Threat: Backdoored Cryptographic Routines

**Narrative:** A malicious contributor submits a pull request that introduces a subtle flaw in the ECDSA signing code (`src/ecc.c`) or the AES encryption implementation (`src/aes.c`). The change appears to be a performance optimization or refactor but actually introduces a bias in nonce generation or a known-key weakness, allowing the attacker to later recover private keys from published signatures.

**ATT&CK Mapping:**

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Resource Development | Establish Accounts | T1585 | Create credible developer identity |
| Initial Access | Trusted Relationship | T1199 | Gain commit access through contribution history |
| Execution | Shared Modules | T1129 | Backdoored code compiled into library |
| Defense Evasion | Subvert Trust Controls — Code Signing | T1553.002 | Backdoor passes code review due to subtlety |
| Credential Access | Forge Web Credentials | T1606 | Use stolen keys to sign fraudulent transactions |
| Impact | Financial Theft | T1657 | Recover private keys from published signatures |

**Existing Controls:**
- Open-source code — all changes publicly visible
- CodeQL static analysis in CI pipeline
- GPG-signed commits (signing keys in `contrib/signing-keys/`)
- Gitian reproducible builds for verifiable binaries

**Gaps:**
- No formal cryptographic audit schedule
- No automated differential testing against reference implementations
- Code review process not formalized for security-critical paths
- No branch protection rules enforcing multi-party review
- Static analysis may not catch subtle cryptographic weaknesses

**Discussion Questions:**
1. Which code paths should require multi-party review?
2. How often should external cryptographic audits be performed?
3. Can automated testing detect biased nonce generation or weakened encryption?

**Recommended Mitigations:**
- Require minimum two-reviewer approval for changes to `src/ecc.c`, `src/aes.c`, `src/random.c`, `src/bip32.c`, `src/bip39.c`
- Implement automated known-answer tests (KATs) for all cryptographic functions
- Schedule annual third-party cryptographic audit
- Add statistical bias testing for RNG and signing nonce generation
- Enforce branch protection with CODEOWNERS for security-critical paths

---

## MITRE ATT&CK Technique Mapping Summary

The following table provides a consolidated view of all ATT&CK techniques identified across the eight scenarios:

| ATT&CK ID | Technique | Scenarios | Risk Level |
|------------|-----------|-----------|------------|
| T1190 | Exploit Public-Facing Application | 2, 3, 4 | **Critical** |
| T1195.001 | Supply Chain Compromise — Software Dependencies | 1 | **Critical** |
| T1657 | Financial Theft | 3, 4, 5, 6, 7, 8 | **Critical** |
| T1552.004 | Unsecured Credentials — Private Keys | 5, 7 | **Critical** |
| T1565.001 | Data Manipulation — Stored Data | 6 | **High** |
| T1565.002 | Data Manipulation — Transmitted Data | 3 | **High** |
| T1003.007 | OS Credential Dumping — Proc Filesystem | 2 | **High** |
| T1005 | Data from Local System | 2, 4 | **High** |
| T1199 | Trusted Relationship | 8 | **High** |
| T1553.002 | Subvert Trust Controls — Code Signing | 1, 8 | **High** |
| T1110 | Brute Force | 7 | **High** |
| T1129 | Shared Modules | 1, 5, 8 | **Medium** |
| T1056.001 | Input Capture — Keylogging | 5 | **Medium** |
| T1113 | Screen Capture | 5 | **Medium** |
| T1115 | Clipboard Data | 5 | **Medium** |
| T1078.003 | Valid Accounts — Local Accounts | 6 | **Medium** |
| T1583.005 | Acquire Infrastructure — Botnet | 3 | **Medium** |
| T1584 | Compromise Infrastructure | 1 | **Medium** |
| T1585 | Establish Accounts | 8 | **Medium** |
| T1587.004 | Develop Capabilities — Exploits | 7 | **Medium** |
| T1592.001 | Gather Victim Host Information — Hardware | 7 | **Low** |
| T1592.002 | Gather Victim Host Information — Software | 2 | **Low** |
| T1595.002 | Active Scanning — Vulnerability Scanning | 3 | **Low** |
| T1596 | Search Open Technical Databases | 4 | **Low** |
| T1656 | Impersonation | 3 | **Low** |
| T1059 | Command and Scripting Interpreter | 3 | **Low** |

---

## Consolidated Mitigations

The following mitigations address the highest-impact risks identified across all scenarios, prioritized by effectiveness:

### Priority 1 — Critical

| ID | Mitigation | Addresses |
|----|-----------|-----------|
| M1 | Implement REST API authentication (API keys, mTLS) and TLS encryption | Scenario 4 |
| M2 | Add cryptographic integrity (HMAC) and encryption at rest for wallet files | Scenario 6 |
| M3 | Fail securely on RNG unavailability — refuse key generation without verified entropy | Scenario 7 |
| M4 | Enforce multi-party code review for security-critical paths (ecc, aes, random, bip32/39) | Scenarios 1, 8 |

### Priority 2 — High

| ID | Mitigation | Addresses |
|----|-----------|-----------|
| M5 | Replace unsafe string operations (`strcpy`) with bounds-checked alternatives | Scenario 2 |
| M6 | Validate all `malloc`/`calloc` return values | Scenario 2 |
| M7 | Implement peer diversity enforcement for SPV connections | Scenario 3 |
| M8 | Add dependency hash verification and SBOM generation | Scenario 1 |
| M9 | Minimize private key lifetime in memory with auto-cleanse after signing | Scenarios 2, 5 |

### Priority 3 — Medium

| ID | Mitigation | Addresses |
|----|-----------|-----------|
| M10 | Add automated known-answer tests (KATs) for cryptographic functions | Scenario 8 |
| M11 | Implement REST API rate limiting and localhost-only default binding | Scenario 4 |
| M12 | Document secure mnemonic handling for library integrators | Scenario 5 |
| M13 | Schedule annual third-party cryptographic security audit | Scenarios 1, 7, 8 |
| M14 | Compile with hardening flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`) | Scenario 2 |

---

## Tabletop Exercise Procedures

### Pre-Exercise Setup

1. **Participants:** Lead maintainer(s), core contributors, security advisor, and representative downstream integrators
2. **Duration:** 2-3 hours
3. **Materials:** This document, access to the libdogecoin codebase, and a whiteboard/shared document for notes
4. **Roles:**
   - **Facilitator** — Guides discussion, presents scenarios, manages time
   - **Red Team** — Argues the attacker's perspective, identifies weaknesses
   - **Blue Team** — Proposes defenses, evaluates existing controls
   - **Scribe** — Documents decisions, action items, and mitigation commitments

### Exercise Flow

| Phase | Duration | Activity |
|-------|----------|----------|
| Introduction | 15 min | Review MITRE ATT&CK framework and asset inventory |
| Scenario Walkthrough | 90 min | Walk through 3-4 scenarios (selected by facilitator based on priority) |
| For each scenario: | 20 min | Present narrative → Identify gaps → Discuss mitigations → Assign action items |
| Gap Analysis | 20 min | Review consolidated mitigations, prioritize by effort/impact |
| Action Planning | 15 min | Assign owners and timelines for top-priority mitigations |
| Wrap-up | 10 min | Summary of findings and next steps |

### Post-Exercise Actions

1. **Publish findings:** Create GitHub issues for each accepted mitigation
2. **Track progress:** Add mitigations to the project roadmap
3. **Re-test:** Schedule follow-up tabletop in 6-12 months
4. **Share learnings:** Update security documentation and contributor guidelines

### Scenario Selection Guide

Select scenarios based on deployment context:

| If deploying as... | Prioritize Scenarios |
|--------------------|---------------------|
| Library for wallet applications | 2, 5, 7, 8 |
| SPV node operator | 3, 4, 6 |
| REST API service | 4, 2, 6 |
| General integration | 1, 8, 2, 7 |

---

## Conclusion

This MITRE ATT&CK tabletop exercise identifies eight realistic threat scenarios spanning supply chain, memory safety, network, API, cryptographic, and insider threats to libdogecoin. The analysis reveals that while the library implements strong cryptographic primitives (secp256k1, AES-256-CBC, ChaCha20) and includes safety mechanisms (secure memory zeroing, buffer validation, checkpoints), there are areas for improvement — particularly in REST API security, wallet file integrity, and formal code review processes for security-critical paths.

The consolidated mitigations provide a prioritized roadmap for hardening the library. Regular re-assessment through follow-up tabletop exercises will ensure the security posture evolves with the threat landscape.

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Bitcoin secp256k1 Security Policy](https://github.com/bitcoin-core/secp256k1/blob/master/SECURITY.md)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic Code for Generating Deterministic Keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [NIST SP 800-90A: Random Number Generation](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [CWE-338: Use of Cryptographically Weak PRNG](https://cwe.mitre.org/data/definitions/338.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [Eclipse Attacks on Bitcoin's Peer-to-Peer Network (Heilman et al.)](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman)
