# Security Policy — libdogecoin

## Reporting Vulnerabilities

If you discover a security vulnerability in libdogecoin, please report it
responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email the maintainers at the address listed in the repository contact
   information with a detailed description of the vulnerability.
3. Include steps to reproduce, affected versions, and potential impact.
4. Allow a reasonable timeframe (90 days) for a fix before public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Audit Schedule

As recommended by the MITRE ATT&CK tabletop exercise (see
`doc/mitre_att&ck_tabletop.md`, Mitigation M13):

- **Annual third-party cryptographic audit** of the core library, focusing on
  ECC signing, AES encryption, RNG implementation, and BIP32/39 key derivation.
- **Continuous static analysis** via CodeQL in CI (`.github/workflows/ql.yml`).
- **Tabletop exercise review** every 12 months to reassess threat landscape.

## Security Controls

The following security controls are implemented in the codebase:

| Control | Location | Description |
|---------|----------|-------------|
| API key authentication | `src/rest.c` | `DOGECOIN_API_KEY` env var for REST API |
| Secure memory zeroing | `src/mem.c` | `dogecoin_mem_zero()` for sensitive data |
| Signature struct cleanse | `src/ecc.c` | Signature objects zeroed after signing |
| RNG fail-secure | `src/random.c` | Key generation fails if entropy unavailable |
| Hardening flags | `configure.ac` | `-fstack-protector-strong -D_FORTIFY_SOURCE=2` |
| Safe string ops | `src/eckey.c`, etc. | `snprintf()` replaces `strcpy()` |
| Allocation checks | `src/eckey.c`, etc. | NULL checks on `calloc` return values |
| CODEOWNERS | `.github/CODEOWNERS` | Multi-party review for security paths |
| Peer diversity | `src/net.c` | Per-/16 subnet connection limits |
| Localhost default | `src/net.c` | Warning on non-localhost HTTP binding |
