# Seal — TPM-Backed Seed/Mnemonic/HD-Node Encryption

`src/seal.c` implements TPM-backed encryption of secrets (seeds, BIP-39
mnemonics, and `dogecoin_hdnode` masters) on three platforms:

- **Windows (TBS / NCrypt)** — `_WIN64 && USE_TPM2`
- **Linux (TSS2 / ESAPI)** — `__linux__ && USE_TSS2`
- **YubiKey PIV (PKCS#11)** — `USE_YUBIKEY` (cross-platform fallback)

This document focuses on the Linux/TSS2 path: setup, testing with the
emulator, persistent-handle layout, and the public API.

## Linux setup

Install the userspace TSS2 stack and a TPM (real hardware or an emulator):

```sh
# Build dependencies
sudo apt-get install -y libtss2-dev pkg-config

# For local testing without real hardware
sudo apt-get install -y swtpm tpm2-tools
```

Configure libdogecoin with TSS2 support:

```sh
./autogen.sh
./configure --enable-tss2
make -j$(nproc)
```

Both autotools and CMake prefer `pkg-config` (`tss2-esys >= 2.4.0`) and fall
back to a plain library lookup. They additionally verify the
`tss2/tss2_esys.h` header is present, so a misconfigured `libtss2-dev`
install fails at configure time rather than at link time.

## Testing with the swtpm emulator

The unit tests under `test/tpm_tests.c` work against either a real TPM 2.0
device or the [swtpm](https://github.com/stefanberger/swtpm) emulator. The
CI matrix uses swtpm on `127.0.0.1:2321` (command port) and `2322` (control
port) and the test driver picks up `tcti=swtpm` automatically when
configured via `TPM2TOOLS_TCTI`.

A typical local emulator setup:

```sh
# Start swtpm in TCP socket mode
mkdir -p /tmp/swtpm-state
swtpm socket \
  --tpm2 \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear \
  --tpmstate dir=/tmp/swtpm-state \
  --log level=20 &

# Point libdogecoin / tpm2-tools at the emulator
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"

# Run the project test suite (non-interactive password)
./configure --enable-tss2 --enable-test-passwd
make check
```

To exercise the seal module specifically:

```sh
./tests
```

`test_tpm` will exercise:

- `dogecoin_generate_mnemonic_encrypt_with_tpm` /
  `dogecoin_decrypt_mnemonic_with_tpm`
- `dogecoin_generate_hdnode_encrypt_with_tpm` /
  `dogecoin_decrypt_hdnode_with_tpm`
- `dogecoin_list_encryption_keys_in_tpm`

The multi-persistent slot path is gated on
`TPM2_PT_HR_TRANSIENT_AVAIL >= 4`. Older `libtpms` (e.g. Ubuntu 22.04 ships
0.9.3 with `MAX_LOADED_OBJECTS = 3`) will skip those subtests.

## Persistent-handle layout

Each slot's wrapping key lives at a deterministic persistent handle in the
**owner hierarchy** range (`0x81710000`–`0x817EFFFF`). The base address
encodes the kind of secret, and the low 16 bits encode the file slot:

| Kind                | Base address  | Examples                  |
|---------------------|---------------|---------------------------|
| Encrypted seed      | `0x81710000`  | `0x81710000`–`0x8171FFFF` |
| Encrypted mnemonic  | `0x81720000`  | `0x81720000`–`0x8172FFFF` |
| Encrypted HD node   | `0x81730000`  | `0x81730000`–`0x8173FFFF` |

The persistent-handle constants are defined in `src/seal.c`
(`LINUX_TPM_PERSISTENT_BASE_*`). They live in the **owner** range
(`0x81000000`–`0x817FFFFF`) so `Esys_EvictControl` succeeds with
`ESYS_TR_RH_OWNER` authorization. The platform range (`0x81800000`+)
requires platform auth that user-mode processes typically cannot obtain
on a real TPM.

On disk, an encrypted blob is stored as:

```
[ TPM2_HANDLE persistent_addr ][ RSA-2048 ciphertext ]
```

`dogecoin_list_encryption_keys_in_tpm` enumerates persistent handles via
`Esys_GetCapability(TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST)` and reports
the slots that match a libdogecoin base.

## Resource management

All Linux/TSS2 code paths route every early-return through a small helper
defined in `src/seal.c`:

```c
// Frees a NULL-terminated list of Esys-allocated pointers and finalizes
// the ESYS context. Both ctx and any list pointer may be NULL.
static void tpm_cleanup(ESYS_CONTEXT** ctx, ...);
```

Callers pass the address of the context plus any `Esys_Free`-able pointers
returned via `Esys_GetRandom`, `Esys_CreatePrimary`, `Esys_RSA_Encrypt`, or
`Esys_GetCapability`. Transient handles created with `Esys_CreatePrimary`
are explicitly flushed via `Esys_FlushContext` before `tpm_cleanup`, and
persistent handles obtained via `Esys_TR_FromTPMPublic` are closed with
`Esys_TR_Close`.

## API examples

Encrypt a freshly generated seed and persist it under slot 0:

```c
#include <dogecoin/seal.h>

SEED seed = {0};
if (!dogecoin_generate_seed_encrypt_with_tpm(seed, /*file_num=*/0,
                                             /*overwrite=*/true)) {
    /* TPM unavailable, slot already in use, or password mismatch. */
    abort();
}
```

Decrypt the same slot back into a usable seed buffer:

```c
SEED seed = {0};
if (!dogecoin_decrypt_seed_with_tpm(seed, /*file_num=*/0)) {
    /* Wrong password, missing file, or TPM unavailable. */
    abort();
}
```

Mnemonic and HD-node variants follow the same pattern:

```c
MNEMONIC mnemonic = {0};
dogecoin_generate_mnemonic_encrypt_with_tpm(
    mnemonic, /*file_num=*/0, /*overwrite=*/true,
    "english", " ", NULL);

dogecoin_decrypt_mnemonic_with_tpm(mnemonic, /*file_num=*/0);

dogecoin_hdnode node;
dogecoin_generate_hdnode_encrypt_with_tpm(&node, 0, true);
dogecoin_decrypt_hdnode_with_tpm(&node, 0);
```

To enumerate the slots currently provisioned in the TPM:

```c
wchar_t* names[MAX_FILES] = {0};
size_t count = 0;
if (dogecoin_list_encryption_keys_in_tpm(names, &count)) {
    for (size_t i = 0; i < count; i++) {
        wprintf(L"slot: %ls\n", names[i]);
        free(names[i]);
    }
}
```

## Troubleshooting

- **`Esys_Initialize` fails immediately** — no TCTI configured. Set
  `TPM2TOOLS_TCTI` (e.g. `swtpm:host=127.0.0.1,port=2321` for emulator,
  `device:/dev/tpmrm0` for real hardware) or install
  `libtss2-tcti-tabrmd0` and run via the resource manager.
- **`TPM_RC_OBJECT_MEMORY` on emulator** — `libtpms < 0.10` ships with
  `MAX_LOADED_OBJECTS = 3`. Each persistent reserves a transient slot, so
  multi-key tests need `TPM2_PT_HR_TRANSIENT_AVAIL >= 4`. The test suite
  gates on this property automatically.
- **`TPM_RC_VALUE` from `EvictControl`** — the persistent handle is in the
  platform range. Use only the libdogecoin owner-hierarchy bases above.
