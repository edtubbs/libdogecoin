Mainnet E2E debug bundle (relay guard update)

Changes validated:
- Added strict sendtx fatal detection in all three scripts for:
  - "Seen on other nodes: 0"
  - "not relayed back"
  - "very likely invalid"

Runs:
- falcon: explicit relay failure now fails fast with [ERROR] sendtx reported explicit relay failure
- dilithium2: explicit relay failure now fails fast with [ERROR] sendtx reported explicit relay failure
- raccoong: run output captured; command output grew very large and exited via tooling boundary, see raccoong_run.txt and temp artifacts

Starting funded txid in scripts remains:
63d79b47b6d55b5143afb5f7782f9300da5d6a4837b5c9837a1769e3e0c44621
