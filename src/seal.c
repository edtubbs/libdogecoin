/**
 * Copyright (c) 2023 edtubbs
 * Copyright (c) 2023-2024 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <dogecoin/aes.h>
#include <dogecoin/base58.h>
#include <dogecoin/bip32.h>
#include <dogecoin/bip39.h>
#include <dogecoin/ecc.h>
#include <dogecoin/eckey.h>
#include <dogecoin/random.h>
#include <dogecoin/sha2.h>
#include <dogecoin/seal.h>
#include <dogecoin/utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#endif

#ifdef _MSC_VER
#include <win/winunistd.h>
#else
#include <unistd.h>
#endif

#if defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)
#include <tbs.h>
#include <ncrypt.h>
#endif

#ifndef WINVER
#define WINVER 0x0600
#endif

#if defined (__linux__) && defined (USE_TSS2)
#include <stdarg.h>
#include <unistd.h>
#include <wchar.h>
#include <tss2/tss2_esys.h>
#endif

#ifdef USE_YUBIKEY
#include <ykpiv/ykpiv.h>
#endif

/*
 * Defines
 */
#define RESP_RAND_OFFSET 12 // Offset to the random data in the TPM2_CC_GetRandom response
#define MAX_RSA_ENCRYPTED_SIZE 256
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define SALT_SIZE 16
#define NAME_MAX_LEN 100
#define PASS_MAX_LEN 100
#define FILE_PATH_MAX_LEN 1000
#define PBKDF2_ITERATIONS 10000
#define ENCRYPTED_SEED_SIZE 64 // AES-256 CBC encrypted seed, no padding
#define ENCRYPTED_MNEMONIC_SIZE 768 // AES-256 CBC encrypted mnemonic, no padding

// Common format string for file numbering
#define FILE_NUM_FORMAT "%03d" // Used for Unix-like systems
#define FILE_NUM_FORMAT_W L"%03d" // Wide string version for Windows

// Base names for the items
#define BASE_NAME_MNEMONIC "dogecoin_mnemonic_"
#define BASE_NAME_MNEMONIC_W L"dogecoin_mnemonic_"
#define BASE_NAME_SEED "dogecoin_seed_"
#define BASE_NAME_SEED_W L"dogecoin_seed_"
#define BASE_NAME_MASTER "dogecoin_master_"
#define BASE_NAME_MASTER_W L"dogecoin_master_"

// Suffices for the items
#define SUFFIX_TPM "_tpm"
#define SUFFIX_TPM_W L"_tpm"
#define SUFFIX_SW "_sw"
#define SUFFIX_SW_W L"_sw"

// Directory path for storage
#define CRYPTO_DIR_PATH "./.store/"
#define CRYPTO_DIR_PATH_W L"store\\"

// TPM object names without encryption method suffix for Windows
#define MNEMONIC_TPM_OBJ_NAME_WIN BASE_NAME_MNEMONIC_W FILE_NUM_FORMAT_W
#define SEED_TPM_OBJ_NAME_WIN BASE_NAME_SEED_W FILE_NUM_FORMAT_W
#define MASTER_TPM_OBJ_NAME_WIN BASE_NAME_MASTER_W FILE_NUM_FORMAT_W

// Full file path and names for Windows (with TPM encryption method suffix)
#define MNEMONIC_TPM_FILE_NAME_WIN CRYPTO_DIR_PATH_W BASE_NAME_MNEMONIC_W FILE_NUM_FORMAT_W SUFFIX_TPM_W
#define SEED_TPM_FILE_NAME_WIN CRYPTO_DIR_PATH_W BASE_NAME_SEED_W FILE_NUM_FORMAT_W SUFFIX_TPM_W
#define MASTER_TPM_FILE_NAME_WIN CRYPTO_DIR_PATH_W BASE_NAME_MASTER_W FILE_NUM_FORMAT_W SUFFIX_TPM_W

// Full file path and names for Windows (with software encryption method suffix)
#define MNEMONIC_SW_FILE_NAME_WIN CRYPTO_DIR_PATH_W BASE_NAME_MNEMONIC_W FILE_NUM_FORMAT_W SUFFIX_SW_W
#define SEED_SW_FILE_NAME_WIN CRYPTO_DIR_PATH_W BASE_NAME_SEED_W FILE_NUM_FORMAT_W SUFFIX_SW_W
#define MASTER_SW_FILE_NAME_WIN CRYPTO_DIR_PATH_W BASE_NAME_MASTER_W FILE_NUM_FORMAT_W SUFFIX_SW_W

// Full file path and names for Unix-like systems (with software encryption method suffix)
#define MNEMONIC_SW_FILE_NAME CRYPTO_DIR_PATH BASE_NAME_MNEMONIC FILE_NUM_FORMAT SUFFIX_SW
#define SEED_SW_FILE_NAME CRYPTO_DIR_PATH BASE_NAME_SEED FILE_NUM_FORMAT SUFFIX_SW
#define MASTER_SW_FILE_NAME CRYPTO_DIR_PATH BASE_NAME_MASTER FILE_NUM_FORMAT SUFFIX_SW

// Custom tags for encrypted seeds, mnemonics, and HD nodes
#define SEED_DATA_TAG(file_num) (0x005F1000 + file_num)
#define MNEMONIC_DATA_TAG(file_num) (0x005F2000 + file_num)
#define HDNODE_DATA_TAG(file_num) (0x005F3000 + file_num)

// Persistent TPM2 handle ranges for the RSA wrapping keys created by libdogecoin.
// Each slot's persistent handle is derived from its file number, mirroring the
// per-name persistence the Windows NCrypt path provides via NCryptCreatePersistedKey.
// These bases live in the owner-hierarchy persistent range (0x81000000-0x817FFFFF)
// so EvictControl can install them with ESYS_TR_RH_OWNER authorization. The
// platform range (0x81800000+) would require platform auth which user-mode
// processes typically cannot obtain on a real TPM.
#define LINUX_TPM_PERSISTENT_BASE_SEED      0x81710000u
#define LINUX_TPM_PERSISTENT_BASE_MNEMONIC  0x81720000u
#define LINUX_TPM_PERSISTENT_BASE_HDNODE    0x81730000u
#define LINUX_TPM_PERSISTENT_RANGE_MASK     0xFFFF0000u
#define LINUX_TPM_PERSISTENT_SLOT_MASK      0x0000FFFFu

/**
 * @brief Validates a file number
 *
 * Validates a file number to ensure it is within the valid range.
 *
 * @param[in] file_num The file number to validate
 * @return true if the file number is valid, false otherwise.
 */
dogecoin_bool fileValid (const int file_num)
{

    // Check if the file number is valid
    if (file_num < NO_FILE || file_num > TEST_FILE)
    {
        return false;
    }
    return true;

}

#if defined(__linux__) && defined(USE_TSS2)
/**
 * @brief Reads a password from the user for TPM operations.
 *
 * Reads a password interactively using getpass, optionally prompting for
 * confirmation. In test mode, uses the compiled-in PASSWD_STR constant.
 *
 * @param out Output buffer for the password.
 * @param out_size Size of the output buffer.
 * @param prompt Prompt string displayed to the user.
 * @param confirm Whether to prompt for password confirmation.
 * @return Returns true if the password was read successfully, false otherwise.
 */
static dogecoin_bool linux_tpm_get_password(char* out, size_t out_size, const char* prompt, dogecoin_bool confirm)
{
#ifdef TEST_PASSWD
    (void)prompt;
    (void)confirm;
    if (out_size < sizeof(PASSWD_STR)) {
        return false;
    }
    strncpy(out, PASSWD_STR, out_size);
    return true;
#else
    char password_copy[128] = {0};
    char* password = getpass(prompt);
    size_t password_len = password ? strnlen(password, sizeof(password_copy)) : 0;
    if (!password || password_len == 0 || password_len >= sizeof(password_copy)) {
        return false;
    }
    strncpy(password_copy, password, sizeof(password_copy) - 1);

    if (confirm) {
        char* confirm_password = getpass("Confirm password: ");
        if (!confirm_password || strcmp(password_copy, confirm_password) != 0) {
            return false;
        }
    }

    if (strlen(password_copy) >= out_size) {
        return false;
    }
    strncpy(out, password_copy, out_size - 1);
    return true;
#endif
}

/**
 * @brief Computes the persistent TPM2 handle for a given filename prefix and slot.
 *
 * Computes the owner-hierarchy persistent TPM2 handle for the given secret type
 * prefix and slot number. Returns 0 if the prefix is not a known libdogecoin prefix.
 *
 * @param filename_prefix Prefix used to identify the encrypted object type.
 * @param file_num Slot number used to derive the persistent handle.
 * @return The persistent handle value, or 0 if inputs do not map to a valid handle.
 */
static TPM2_HANDLE linux_tpm_persistent_handle(const char* filename_prefix, int file_num)
{
    uint32_t base = 0;
    if (strcmp(filename_prefix, "encrypted_seed") == 0) {
        base = LINUX_TPM_PERSISTENT_BASE_SEED;
    } else if (strcmp(filename_prefix, "encrypted_mnemonic") == 0) {
        base = LINUX_TPM_PERSISTENT_BASE_MNEMONIC;
    } else if (strcmp(filename_prefix, "encrypted_hdnode") == 0) {
        base = LINUX_TPM_PERSISTENT_BASE_HDNODE;
    } else {
        return 0;
    }
    if (file_num < 0 || (uint32_t)file_num > LINUX_TPM_PERSISTENT_SLOT_MASK) {
        return 0;
    }
    return (TPM2_HANDLE)(base | (uint32_t)file_num);
}

/**
 * @brief Frees ESYS allocations and finalizes an ESYS context.
 *
 * Frees a NULL-terminated list of Esys-allocated pointers with Esys_Free and
 * finalizes the ESYS context when provided. Both ctx and any list pointer may
 * be NULL.
 *
 * @param ctx Optional ESYS context pointer to finalize.
 * @param ... NULL-terminated list of Esys-allocated pointers to free.
 */
static void tpm_cleanup(ESYS_CONTEXT** ctx, ...)
{
    va_list ap;
    va_start(ap, ctx);
    for (;;) {
        void* p = va_arg(ap, void*);
        if (p == NULL) {
            break;
        }
        Esys_Free(p);
    }
    va_end(ap);
    if (ctx && *ctx) {
        Esys_Finalize(ctx);
    }
}

/**
 * @brief Runs TPM startup for Linux TSS2 paths.
 *
 * Runs the TPM startup command using ESAPI. Returns true if startup succeeds
 * or if the TPM is already initialized by another consumer.
 *
 * @param context Initialized ESYS context.
 * @return Returns true when startup succeeds or TPM is already initialized.
 */
static dogecoin_bool linux_tpm_startup(ESYS_CONTEXT* context)
{
    TSS2_RC rc = Esys_Startup(context, TPM2_SU_CLEAR);
    if (rc == TSS2_RC_SUCCESS) {
        return true;
    }
    // TPM2_RC_INITIALIZE means startup was already completed elsewhere.
    if (rc == TPM2_RC_INITIALIZE) {
        return true;
    }
    return false;
}

/**
 * @brief Encrypts a blob using a TPM-persisted per-slot RSA wrapping key.
 *
 * Encrypts input bytes using a per-slot RSA wrapping key persisted in the TPM.
 * The on-disk file stores the persistent handle followed by the RSA ciphertext.
 *
 * @param in Input plaintext bytes.
 * @param in_size Number of plaintext bytes.
 * @param file_num Slot index used for persistent object addressing.
 * @param overwrite Whether to evict and replace an existing persistent key.
 * @param filename_prefix Prefix used for encrypted file naming.
 * @param password_prompt Prompt string for user password entry.
 * @return Returns true on successful encryption and file write, false otherwise.
 */
static dogecoin_bool linux_tpm_encrypt_blob(const uint8_t* in, size_t in_size, const int file_num, const dogecoin_bool overwrite, const char* filename_prefix, const char* password_prompt)
{
    dogecoin_bool ok = false;
    TPM2_HANDLE persistent_addr = linux_tpm_persistent_handle(filename_prefix, file_num);
    if (persistent_addr == 0) {
        return false;
    }

    char filename[100];
    snprintf(filename, sizeof(filename), "%s_%d", filename_prefix, file_num);

    ESYS_CONTEXT* context = NULL;
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }

    if (!linux_tpm_startup(context)) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    // If a persistent object already occupies the slot, refuse unless
    // overwrite is set. When overwrite is set, evict first so EvictControl can
    // install the new key on the same persistent address.
    ESYS_TR existing = ESYS_TR_NONE;
    TSS2_RC tr_rc = Esys_TR_FromTPMPublic(context, persistent_addr,
                                          ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                          &existing);
    if (tr_rc == TSS2_RC_SUCCESS) {
        if (!overwrite) {
            Esys_TR_Close(context, &existing);
            tpm_cleanup(&context, NULL);
            return false;
        }
        ESYS_TR removed = ESYS_TR_NONE;
        tr_rc = Esys_EvictControl(context, ESYS_TR_RH_OWNER, existing,
                                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                  persistent_addr, &removed);
        if (removed != ESYS_TR_NONE) {
            Esys_TR_Close(context, &removed);
        }
        Esys_TR_Close(context, &existing);
        if (tr_rc != TSS2_RC_SUCCESS) {
            tpm_cleanup(&context, NULL);
            return false;
        }
    }

    char password[128] = {0};
    if (!linux_tpm_get_password(password, sizeof(password), password_prompt, true)) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    ESYS_TR keyHandle = ESYS_TR_NONE;
    ESYS_TR persistentHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC* outPublic = NULL;
    TPM2B_CREATION_DATA* creationData = NULL;
    TPM2B_DIGEST* creationHash = NULL;
    TPMT_TK_CREATION* creationTicket = NULL;
    TPM2B_PUBLIC_KEY_RSA* cipher = NULL;

    TPM2B_AUTH authValuePrimary = {0};
    authValuePrimary.size = strlen(password);
    if (authValuePrimary.size > sizeof(authValuePrimary.buffer)) {
        tpm_cleanup(&context, NULL);
        return false;
    }
    memcpy(authValuePrimary.buffer, password, authValuePrimary.size);

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0, .buffer = {0}},
            .data = {.size = 0, .buffer = {0}},
        },
    };

    memcpy(inSensitivePrimary.sensitive.userAuth.buffer, password, authValuePrimary.size);
    inSensitivePrimary.sensitive.userAuth.size = authValuePrimary.size;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = {.algorithm = TPM2_ALG_NULL},
                .scheme = {.scheme = TPM2_ALG_RSAES},
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0, .buffer = {0}},
        },
    };

    TPM2B_DATA outsideInfo = {.size = 0, .buffer = {0}};
    TPML_PCR_SELECTION creationPCR = {.count = 0};
    TPM2B_AUTH authValue = {.size = 0, .buffer = {0}};

    result = Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &authValue);
    if (result != TSS2_RC_SUCCESS) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    result = Esys_CreatePrimary(context,
                                ESYS_TR_RH_OWNER,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &inSensitivePrimary,
                                &inPublic,
                                &outsideInfo,
                                &creationPCR,
                                &keyHandle,
                                &outPublic,
                                &creationData,
                                &creationHash,
                                &creationTicket);

    if (result != TSS2_RC_SUCCESS) {
        tpm_cleanup(&context, outPublic, creationData, creationHash, creationTicket, NULL);
        return false;
    }
    tpm_cleanup(NULL, outPublic, creationData, creationHash, creationTicket, NULL);

    // Encrypt plaintext against the transient RSA key before persisting it.
    // This avoids immediate persistent-slot round-tripping and reduces
    // TPM_RC_OBJECT_MEMORY risk on constrained TPM implementations.
    TPM2B_PUBLIC_KEY_RSA plain = {0};
    if (in_size > sizeof(plain.buffer)) {
        Esys_FlushContext(context, keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }
    plain.size = in_size;
    memcpy(plain.buffer, in, in_size);

    TPMT_RSA_DECRYPT scheme = {.scheme = TPM2_ALG_RSAES};
    result = Esys_RSA_Encrypt(context,
                              keyHandle,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &plain,
                              &scheme,
                              NULL,
                              &cipher);
    if (result != TSS2_RC_SUCCESS) {
        Esys_FlushContext(context, keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    // Persist the wrapping key under the deterministic 0x81xx_xxxx handle.
    // After this call, keyHandle is consumed and persistentHandle becomes the
    // live ESYS_TR for the persistent object.
    result = Esys_EvictControl(context, ESYS_TR_RH_OWNER, keyHandle,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               persistent_addr, &persistentHandle);
    if (result != TSS2_RC_SUCCESS || persistentHandle == ESYS_TR_NONE) {
        tpm_cleanup(NULL, cipher, NULL);
        Esys_FlushContext(context, keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    result = Esys_TR_SetAuth(context, persistentHandle, &authValuePrimary);
    if (result != TSS2_RC_SUCCESS) {
        tpm_cleanup(NULL, cipher, NULL);
        Esys_TR_Close(context, &persistentHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    if (!overwrite && access(filename, F_OK) == 0) {
        tpm_cleanup(NULL, cipher, NULL);
        Esys_TR_Close(context, &persistentHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        tpm_cleanup(NULL, cipher, NULL);
        Esys_TR_Close(context, &persistentHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    ok = fwrite(&persistent_addr, 1, sizeof(persistent_addr), fp) == sizeof(persistent_addr);
    ok &= fwrite(cipher->buffer, 1, cipher->size, fp) == cipher->size;

    fclose(fp);
    tpm_cleanup(NULL, cipher, NULL);
    Esys_TR_Close(context, &persistentHandle);
    tpm_cleanup(&context, NULL);
    return ok;
}

/**
 * @brief Decrypts a blob using a TPM-persisted per-slot RSA wrapping key.
 *
 * Decrypts a blob previously encrypted with a per-slot RSA wrapping key
 * persisted in the TPM. Reads the persistent handle and ciphertext from disk.
 *
 * @param out Output plaintext buffer.
 * @param out_size Output buffer size in bytes.
 * @param file_num Slot index used for persistent object addressing.
 * @param filename_prefix Prefix used for encrypted file naming.
 * @param password_prompt Prompt string for user password entry.
 * @param actual_size Optional decrypted byte count output.
 * @return Returns true on successful decryption, false otherwise.
 */
static dogecoin_bool linux_tpm_decrypt_blob(uint8_t* out, size_t out_size, const int file_num, const char* filename_prefix, const char* password_prompt, size_t* actual_size)
{
    dogecoin_bool ok = false;
    ESYS_CONTEXT* context = NULL;
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }

    if (!linux_tpm_startup(context)) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    char filename[100];
    snprintf(filename, sizeof(filename), "%s_%d", filename_prefix, file_num);
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    TPM2_HANDLE persistent_addr = 0;
    if (fread(&persistent_addr, 1, sizeof(persistent_addr), fp) != sizeof(persistent_addr)) {
        fclose(fp);
        tpm_cleanup(&context, NULL);
        return false;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        tpm_cleanup(&context, NULL);
        return false;
    }
    long file_size = ftell(fp);
    long header_size = (long)sizeof(persistent_addr);
    if (file_size <= header_size || fseek(fp, header_size, SEEK_SET) != 0) {
        fclose(fp);
        tpm_cleanup(&context, NULL);
        return false;
    }

    size_t encrypted_size = (size_t)(file_size - header_size);
    if (encrypted_size > MAX_RSA_ENCRYPTED_SIZE) {
        fclose(fp);
        tpm_cleanup(&context, NULL);
        return false;
    }
    uint8_t encrypted_blob[MAX_RSA_ENCRYPTED_SIZE] = {0};
    if (fread(encrypted_blob, 1, encrypted_size, fp) != encrypted_size) {
        fclose(fp);
        tpm_cleanup(&context, NULL);
        return false;
    }
    fclose(fp);

    // Resolve the persistent TPM2 handle into an ESYS_TR for the live object.
    ESYS_TR keyHandle = ESYS_TR_NONE;
    result = Esys_TR_FromTPMPublic(context, persistent_addr,
                                   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &keyHandle);
    if (result != TSS2_RC_SUCCESS) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    char password[128] = {0};
    if (!linux_tpm_get_password(password, sizeof(password), password_prompt, false)) {
        Esys_TR_Close(context, &keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    TPM2B_AUTH authValue = {0};
    authValue.size = strlen(password);
    if (authValue.size > sizeof(authValue.buffer)) {
        Esys_TR_Close(context, &keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }
    memcpy(authValue.buffer, password, authValue.size);
    TPM2B_AUTH authValuePrimary = {.size = 0};

    result = Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &authValuePrimary);
    if (result != TSS2_RC_SUCCESS) {
        Esys_TR_Close(context, &keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }
    result = Esys_TR_SetAuth(context, keyHandle, &authValue);
    if (result != TSS2_RC_SUCCESS) {
        Esys_TR_Close(context, &keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    TPMT_RSA_DECRYPT scheme = {.scheme = TPM2_ALG_RSAES};
    TPM2B_PUBLIC_KEY_RSA cipher = {.size = encrypted_size, .buffer = {0}};
    memcpy(cipher.buffer, encrypted_blob, encrypted_size);
    TPM2B_DATA label = {.size = 0};
    TPM2B_PUBLIC_KEY_RSA* plain = NULL;

    result = Esys_RSA_Decrypt(context, keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &cipher, &scheme, &label, &plain);
    if (result != TSS2_RC_SUCCESS || plain == NULL || plain->size > out_size) {
        tpm_cleanup(NULL, plain, NULL);
        Esys_TR_Close(context, &keyHandle);
        tpm_cleanup(&context, NULL);
        return false;
    }

    memcpy(out, plain->buffer, plain->size);
    if (actual_size) {
        *actual_size = plain->size;
    }
    tpm_cleanup(NULL, plain, NULL);
    Esys_TR_Close(context, &keyHandle);
    tpm_cleanup(&context, NULL);
    ok = true;
    return ok;
}
#endif

/**
 * @brief Encrypts a seed using the TPM
 *
 * Encrypts a seed using the TPM and stores the encrypted seed in a file.
 *
 * @param[in] seed The seed to encrypt
 * @param[in] size The size of the seed
 * @param[in] file_num The file number to encrypt the seed for
 * @param[in] overwrite Whether or not to overwrite an existing seed
 * @return true if the seed was encrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_encrypt_seed_with_tpm(const SEED seed, const size_t size, const int file_num, const dogecoin_bool overwrite) {
#if defined(__linux__) && defined(USE_TSS2)
    if (seed == NULL || !fileValid(file_num)) {
        return false;
    }
    return linux_tpm_encrypt_blob((const uint8_t*)seed, size, file_num, overwrite, "encrypted_seed", "Enter password for seed encryption: ");
#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Validate the input parameters
    if (seed == NULL)
    {
        fprintf(stderr, "ERROR: Invalid seed\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Format the name of the encrypted seed file
    wchar_t filename[FILE_PATH_MAX_LEN] = {0};
    swprintf(filename, sizeof(filename), SEED_TPM_FILE_NAME_WIN, file_num);

    // Check if the file already exists and if not, prompt for overwriting
    if (!overwrite && _waccess(filename, F_OK) != -1)
    {
        fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
        return false;
    }

    // Declare variables
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hEncryptionKey;
    DWORD cbResult;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;
    DWORD dwFlags = 0; // Use NCRYPT_MACHINE_KEY_FLAG for machine-level keys or 0 for user-level keys

    // Format the name of the encrypted seed object
    wchar_t name[NAME_MAX_LEN] = {0};
    swprintf(name, sizeof(name), SEED_TPM_OBJ_NAME_WIN, file_num);

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Create a new persistent encryption key
    status = NCryptCreatePersistedKey(hProvider, &hEncryptionKey, NCRYPT_RSA_ALGORITHM, name, 0, overwrite ? NCRYPT_OVERWRITE_KEY_FLAG : dwFlags);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to create new persistent encryption key (0x%08x)\n", status);
        NCryptFreeObject(hProvider);
        return false;
    }

#ifndef TEST_PASSWD
    // Set the UI policy to force high protection (PIN dialog)
    NCRYPT_UI_POLICY uiPolicy;
    memset(&uiPolicy, 0, sizeof(NCRYPT_UI_POLICY));
    uiPolicy.dwVersion = 1;
    uiPolicy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
    uiPolicy.pszDescription = L"BIP32 seed for dogecoin wallet";
    status = NCryptSetProperty(hEncryptionKey, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&uiPolicy, sizeof(NCRYPT_UI_POLICY), 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to set UI policy for encryption key (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }
#endif

    // Generate a new encryption key in the TPM storage provider
    status = NCryptFinalizeKey(hEncryptionKey, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to generate new encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Open the existing encryption key in the TPM storage provider
    status = NCryptOpenKey(hProvider, &hEncryptionKey, name, 0, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open existing encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Encrypt the seed using the encryption key
    status = NCryptEncrypt(hEncryptionKey, (PBYTE)seed, (DWORD)size, NULL, NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to encrypt the seed (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Allocate memory for the encrypted seed
    pbOutput = (PBYTE)malloc(cbResult);
    if (!pbOutput)
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for encrypted data\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Encrypt the seed using the encryption key
    status = NCryptEncrypt(hEncryptionKey, (PBYTE)seed, (DWORD)size, NULL, pbOutput, cbResult, &cbOutput, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to encrypt the seed (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Create the directory for storing the encrypted seed if it doesn't exist
    if (_wmkdir(CRYPTO_DIR_PATH_W) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "ERROR: Failed to create directory\n");
        return false;
    }

    // Successfully encrypted the seed
    // Create a file with the encrypted seed
    // Open the file for binary write, "wb+" to overwrite if exists
    FILE* fp = _wfopen(filename, overwrite ? L"wb+" : L"wb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for writing\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Write the encrypted seed to the file
    size_t bytesWritten = fwrite(pbOutput, 1, cbOutput, fp);
    if (bytesWritten != cbOutput)
    {
        fprintf(stderr, "ERROR: Failed to write encrypted seed to file\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Close the file
    fclose(fp);

    // Free the encryption key handle and close the TPM storage provider
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;

#else
    (void) seed;
    (void) size;
    (void) file_num;
    (void) overwrite;
    return false;
#endif
}

/**
 * @brief Decrypt a BIP32 seed with the TPM
 *
 * Decrypt a BIP32 seed previously encrypted with a TPM2 persistent encryption key.
 *
 * @param seed Decrypted seed will be stored here
 * @param file_num The file number for the encrypted seed
 * @return Returns true if the seed is decrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_seed_with_tpm(SEED seed, const int file_num) {
#if defined(__linux__) && defined(USE_TSS2)
    if (seed == NULL || !fileValid(file_num)) {
        return false;
    }
    size_t actual_size = 0;
    return linux_tpm_decrypt_blob((uint8_t*)seed, MAX_SEED_SIZE, file_num, "encrypted_seed", "Enter password for seed decryption: ", &actual_size);
#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Validate the input parameters
    if (seed == NULL)
    {
        fprintf(stderr, "ERROR: Invalid seed\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Declare variables
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hEncryptionKey;
    DWORD cbResult;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;

    // Format the name of the encrypted seed object
    wchar_t name[NAME_MAX_LEN] = {0};
    swprintf(name, sizeof(name), SEED_TPM_OBJ_NAME_WIN, file_num);

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Open the existing encryption key in the TPM storage provider
    status = NCryptOpenKey(hProvider, &hEncryptionKey, name, 0, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open existing encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Read the encrypted seed from the file
    wchar_t filename[FILE_PATH_MAX_LEN] = {0};
    swprintf(filename, sizeof(filename), SEED_TPM_FILE_NAME_WIN, file_num);
    FILE* fp = _wfopen(filename, L"rb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for reading\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Get the size of the encrypted seed
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate memory for the encrypted seed
    pbOutput = (PBYTE) malloc(fileSize);
    if (!pbOutput)
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for reading file\n");
        fclose(fp);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Read the encrypted seed from the file
    DWORD bytesRead = (DWORD)fread(pbOutput, 1, fileSize, fp);
    fclose(fp);

    // Validate the number of bytes read
    if (bytesRead != fileSize)
    {
        fprintf(stderr, "ERROR: Failed to read file\n");
        dogecoin_free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Decrypt the encrypted data
    status = NCryptDecrypt(hEncryptionKey, pbOutput, bytesRead, NULL, (PBYTE)seed, (DWORD)MAX_SEED_SIZE, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        // Failed to decrypt the encrypted data
        fprintf(stderr, "ERROR: Failed to decrypt the encrypted data (0x%08x)\n", status);
        dogecoin_free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);

        return false;
    }

    // Free the output buffer, encryption key handle, and close the TPM storage provider
    dogecoin_free(pbOutput);
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;
#else
    (void) seed;
    (void) file_num;
    return false;
#endif
}

/**
 * @brief Encrypt a BIP32 seed with software
 *
 * Encrypt a BIP32 seed with software and store the encrypted seed in a file.
 *
 * @param seed The seed to encrypt
 * @param size The size of the seed
 * @param file_num The file number to encrypt the seed for
 * @param overwrite Whether or not to overwrite an existing seed
 * @param encrypted_blob_out The encrypted blob will be stored here
 * @param encrypted_blob_size The size of the encrypted blob
 * @return Returns true if the seed is encrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_encrypt_seed_with_sw(const SEED seed, const size_t size, const int file_num, const dogecoin_bool overwrite, const char* test_password, ENCRYPTED_BLOB* encrypted_blob_out, size_t* encrypted_blob_size)
{
#ifndef USE_OPTEE // OPTEE has no filesystem or console
    // Validate the input parameters
    if (seed == NULL)
    {
        fprintf(stderr, "ERROR: Invalid seed\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // File operations
    FILE *fp = NULL;
    if (file_num != NO_FILE)
    {
    #ifdef _WIN32
        if (_wmkdir(CRYPTO_DIR_PATH_W) == -1 && errno != EEXIST)
        {
            fprintf(stderr, "ERROR: Failed to create directory\n");
            return false;
        }
        wchar_t fullpath[FILE_PATH_MAX_LEN] = {0};
        swprintf(fullpath, sizeof(fullpath), SEED_SW_FILE_NAME_WIN, file_num);
        if (!overwrite && _waccess(fullpath, F_OK) != -1)
        {
            fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
            return false;
        }
        fp = _wfopen(fullpath, overwrite ? L"wb+" : L"wb");
    #else
        if (mkdir(CRYPTO_DIR_PATH, 0777) == -1 && errno != EEXIST)
        {
            fprintf(stderr, "ERROR: Failed to create directory\n");
            return false;
        }
        char fullpath[FILE_PATH_MAX_LEN] = {0};
        snprintf(fullpath, sizeof(fullpath), SEED_SW_FILE_NAME, file_num);
        if (!overwrite && access(fullpath, F_OK) != -1)
        {
            fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
            return false;
        }
        fp = fopen(fullpath, overwrite ? "wb+" : "wb");
    #endif
        if (!fp)
        {
            fprintf(stderr, "ERROR: Failed to open file for writing.\n");
            return false;
        }
    }

    // Prompt for the password
    char* password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       password = malloc(PASS_MAX_LEN);
       strcpy(password, test_password);
    }
    else
#else
    (void) test_password;
#endif
    password = getpass("Enter password for seed encryption: \n");
    if (password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        fp ? fclose(fp) : 0;
        return false;
    }
    if (strlen(password) == 0)
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Confirm the password
    char* confirm_password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       confirm_password = malloc(PASS_MAX_LEN);
       strcpy(confirm_password, test_password);
    }
    else
#endif
    confirm_password = getpass("Confirm password: \n");
    if (confirm_password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }
    if (strcmp(password, confirm_password) != 0)
    {
        fprintf(stderr, "ERROR: Passwords do not match.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_mem_zero(confirm_password, strlen(confirm_password));
        dogecoin_free(password);
        dogecoin_free(confirm_password);
        fp ? fclose(fp) : 0;
        return false;
    }
    // Clear the confirm password
    dogecoin_mem_zero(confirm_password, strlen(confirm_password));
    dogecoin_free(confirm_password);

    // Generate two random salts
    uint8_t salt_encryption[SALT_SIZE], salt_verification[SALT_SIZE];
    if (!dogecoin_random_bytes(salt_encryption, SALT_SIZE, 1) ||
        !dogecoin_random_bytes(salt_verification, SALT_SIZE, 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Derive the encryption key from the password and salt using PBKDF2
    uint8_t encryption_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_encryption, SALT_SIZE, PBKDF2_ITERATIONS, encryption_key, AES_KEY_SIZE);

    // Derive a separate key for verification
    uint8_t verification_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_verification, SALT_SIZE, PBKDF2_ITERATIONS, verification_key, AES_KEY_SIZE);

    // Hash the verification key
    uint8_t verification_key_hash[SHA512_DIGEST_LENGTH];
    sha512_raw(verification_key, AES_KEY_SIZE, verification_key_hash);

    // Clear the password
    dogecoin_mem_zero(password, strlen(password));
    dogecoin_free(password);

    // Generate a random IV for AES encryption
    uint8_t iv[AES_IV_SIZE];
    if (!dogecoin_random_bytes(iv, sizeof(iv), 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        fp ? fclose(fp) : 0;
        return false;
    }

    // Encrypt the seed using AES
    size_t encrypted_size = size;
    dogecoin_bool padding_used = false;
    uint8_t* encrypted_seed = malloc(encrypted_size);
    if (!encrypted_seed)
    {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        fp ? fclose(fp) : 0;
        return false;
    }

    size_t encrypted_actual_size = aes256_cbc_encrypt(encryption_key, iv, seed, size, padding_used, encrypted_seed);
    if (encrypted_actual_size == 0)
    {
        fprintf(stderr, "ERROR: AES encryption failed.\n");
        dogecoin_free(encrypted_seed);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Write the IV, salt, verification key hash, and encrypted seed to the file
    if (fp != NULL)
    {
        fwrite(iv, 1, sizeof(iv), fp);
        fwrite(salt_encryption, 1, SALT_SIZE, fp);
        fwrite(salt_verification, 1, SALT_SIZE, fp);
        fwrite(verification_key_hash, 1, sizeof(verification_key_hash), fp);
        fwrite(encrypted_seed, 1, encrypted_size, fp);
        fp ? fclose(fp) : 0;
    }
    else if (encrypted_blob_out != NULL && encrypted_blob_size != NULL)
    {
        memcpy(*encrypted_blob_out, iv, sizeof(iv));
        memcpy(*encrypted_blob_out + sizeof(iv), salt_encryption, SALT_SIZE);
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE, salt_verification, SALT_SIZE);
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE + SALT_SIZE, verification_key_hash, sizeof(verification_key_hash));
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash), encrypted_seed, encrypted_size);
        *encrypted_blob_size = sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash) + encrypted_size;
    }
    else if (encrypted_blob_size != NULL)
    {
        *encrypted_blob_size = sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash) + encrypted_size;
    }

    // Free the encrypted seed
    dogecoin_free(encrypted_seed);

    return true;
#else
    (void) seed;
    (void) size;
    (void) file_num;
    (void) overwrite;
    (void) test_password;
    (void) encrypted_blob_out;
    (void) encrypted_blob_size;
    return false;
#endif
}

/**
 * @brief Decrypt a BIP32 seed with software
 *
 * Decrypt a BIP32 seed previously encrypted with software.
 *
 * @param seed Decrypted seed will be stored here
 * @param file_num The file number for the encrypted seed
 * @param test_password The password to use for testing
 * @param encrypted_blob The encrypted blob to decrypt
 * @param encrypted_blob_size The size of the encrypted blob
 * @return Returns true if the seed is decrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_seed_with_sw(SEED seed, const int file_num, const char* test_password, ENCRYPTED_BLOB encrypted_blob)
{
#ifndef USE_OPTEE // Software decryption is not supported in the OP-TEE environment
    // Validate the input parameters
    if (seed == NULL)
    {
        fprintf(stderr, "ERROR: Invalid seed\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Prompt for the password
    char* password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       password = malloc(PASS_MAX_LEN);
       strcpy(password, test_password);
    }
    else
#else
    (void) test_password;
#endif
    password = getpass("Enter password for seed decryption: \n");
    if (password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        return false;
    }
    if (strlen(password) == 0)
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        dogecoin_free(password);
        return false;
    }

    // Open the file for reading
#ifdef _WIN32
    wchar_t fullpath[FILE_PATH_MAX_LEN] = {0};
    swprintf(fullpath, sizeof(fullpath), SEED_SW_FILE_NAME_WIN, file_num);
    FILE* fp = _wfopen(fullpath, L"rb");
#else
    char fullpath[FILE_PATH_MAX_LEN] = {0};
    snprintf(fullpath, sizeof(fullpath), SEED_SW_FILE_NAME, file_num);
    FILE* fp = fopen(fullpath, "rb");
#endif
    if (!fp && encrypted_blob == NULL)
    {
        fprintf(stderr, "ERROR: Failed to open file for reading.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        return false;
    }

    // Read the IV from the file or blob
    uint8_t iv[AES_IV_SIZE];
    if (fp != NULL)
    {
        if (fread(iv, 1, sizeof(iv), fp) != sizeof(iv))
        {
            fprintf(stderr, "ERROR: Failed to read IV from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(iv, encrypted_blob, sizeof(iv));
    }

    // Read the encryption and verification salts from the file or blob
    uint8_t salt_encryption[SALT_SIZE], salt_verification[SALT_SIZE];
    if (fp != NULL)
    {
        if (fread(salt_encryption, 1, SALT_SIZE, fp) != SALT_SIZE ||
            fread(salt_verification, 1, SALT_SIZE, fp) != SALT_SIZE)
        {
            fprintf(stderr, "ERROR: Failed to read salts from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(salt_encryption, encrypted_blob + sizeof(iv), SALT_SIZE);
        memcpy(salt_verification, encrypted_blob + sizeof(iv) + SALT_SIZE, SALT_SIZE);
    }

    // Read the verification key hash from the file or blob
    uint8_t stored_verification_key_hash[SHA512_DIGEST_LENGTH];
    if (fp != NULL)
    {
        if (fread(stored_verification_key_hash, 1, sizeof(stored_verification_key_hash), fp) != sizeof(stored_verification_key_hash))
        {
            fprintf(stderr, "ERROR: Failed to read verification key hash from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(stored_verification_key_hash, encrypted_blob + sizeof(iv) + SALT_SIZE + SALT_SIZE, sizeof(stored_verification_key_hash));
    }

    // Derive the verification key from the password and verification salt using PBKDF2
    uint8_t derived_verification_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_verification, SALT_SIZE, PBKDF2_ITERATIONS, derived_verification_key, AES_KEY_SIZE);

    // Hash the derived verification key
    uint8_t derived_verification_key_hash[SHA512_DIGEST_LENGTH];
    sha512_raw(derived_verification_key, AES_KEY_SIZE, derived_verification_key_hash);

    // Compare the derived verification key hash with the stored one
    if (memcmp(stored_verification_key_hash, derived_verification_key_hash, SHA512_DIGEST_LENGTH) != 0)
    {
        fprintf(stderr, "ERROR: Incorrect password.\n");
        fclose(fp);
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        return false;
    }

    // Derive the encryption key from the password and encryption salt using PBKDF2
    uint8_t encryption_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_encryption, SALT_SIZE, PBKDF2_ITERATIONS, encryption_key, AES_KEY_SIZE);

    // Clear the password
    dogecoin_mem_zero(password, strlen(password));
    dogecoin_free(password);

    // Read the encrypted seed from the file or blob
    size_t encrypted_size = ENCRYPTED_SEED_SIZE;
    uint8_t* encrypted_seed = malloc(encrypted_size);
    if (!encrypted_seed)
    {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        fclose(fp);
        return false;
    }

    if (fp != NULL)
    {
        if (fread(encrypted_seed, 1, encrypted_size, fp) != encrypted_size)
        {
            fprintf(stderr, "ERROR: Failed to read encrypted seed from file.\n");
            fclose(fp);
            dogecoin_free(encrypted_seed);
            return false;
        }

        fclose(fp);
    }
    else
    {
        memcpy(encrypted_seed, encrypted_blob + sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(stored_verification_key_hash), encrypted_size);
    }

    // Decrypt the seed using AES
    dogecoin_bool padding_used = false;
    size_t decrypted_actual_size = aes256_cbc_decrypt(encryption_key, iv, encrypted_seed, encrypted_size, padding_used, seed);
    dogecoin_free(encrypted_seed);

    if (decrypted_actual_size == 0)
    {
        fprintf(stderr, "ERROR: AES decryption failed.\n");
        dogecoin_free(encrypted_seed);
        return false;
    }

    return true;
#else
    (void) seed;
    (void) file_num;
    (void) test_password;
    (void) encrypted_blob;
    return false;
#endif
}


/**
 * @brief Generate a HD node object with the TPM
 *
 * Generate a HD node object with the TPM
 *
 * @param out The HD node object to generate
 * @param file_num The file number of the encrypted mnemonic
 * @param overwrite Whether or not to overwrite the existing HD node object
 * @return Returns true if the keypair and chain_code are generated successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_generate_hdnode_encrypt_with_tpm(dogecoin_hdnode* out, const int file_num, dogecoin_bool overwrite)
{
#if defined(__linux__) && defined(USE_TSS2)
    if (out == NULL || !fileValid(file_num)) {
        return false;
    }

    ESYS_CONTEXT* context = NULL;
    TPM2B_DIGEST* random_bytes = NULL;
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }

    if (!linux_tpm_startup(context)) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    result = Esys_GetRandom(context,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            32,
                            &random_bytes);
    if (result != TSS2_RC_SUCCESS || random_bytes == NULL || random_bytes->size != 32) {
        tpm_cleanup(&context, random_bytes, NULL);
        return false;
    }

    dogecoin_hdnode_from_seed((uint8_t*)random_bytes->buffer, 32, out);
    tpm_cleanup(&context, random_bytes, NULL);
    return linux_tpm_encrypt_blob((const uint8_t*)out, sizeof(dogecoin_hdnode), file_num, overwrite, "encrypted_hdnode", "Enter password for HD node encryption: ");

#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Validate the input parameters
    if (out == NULL)
    {
        fprintf(stderr, "ERROR: Invalid HD node\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Format the name of the encrypted HD node file
    wchar_t filename[FILE_PATH_MAX_LEN] = {0};
    swprintf(filename, sizeof(filename), MASTER_TPM_FILE_NAME_WIN, file_num);

    // Check if the file already exists and if not, prompt for overwriting
        if (!overwrite && _waccess(filename, F_OK) != -1)
    {
        fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
        return false;
    }

    // Initialize variables
    dogecoin_mem_zero(out, sizeof(dogecoin_hdnode));
    out->depth = 0;
    out->fingerprint = 0x00000000;
    out->child_num = 0;

    // Generate a new master key
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hEncryptionKey;
    DWORD cbResult;
    PBYTE pbResult = NULL;
    DWORD dwFlags = 0; // Use NCRYPT_MACHINE_KEY_FLAG for machine-level keys or 0 for user-level keys

    // Format the name of the HD node
    wchar_t name[NAME_MAX_LEN] = {0};
    swprintf(name, sizeof(name), MASTER_TPM_OBJ_NAME_WIN, file_num);

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Create a new persistent encryption key
    status = NCryptCreatePersistedKey(hProvider, &hEncryptionKey, NCRYPT_RSA_ALGORITHM, name, 0, overwrite ? NCRYPT_OVERWRITE_KEY_FLAG : dwFlags);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to create new persistent encryption key (0x%08x)\n", status);
        NCryptFreeObject(hProvider);
        return false;
    }

#ifndef TEST_PASSWD
    // Set the UI policy to force high protection (PIN dialog)
    NCRYPT_UI_POLICY uiPolicy;
    memset(&uiPolicy, 0, sizeof(NCRYPT_UI_POLICY));
    uiPolicy.dwVersion = 1;
    uiPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
    uiPolicy.pszDescription = L"BIP32 master key for dogecoin wallet";
    status = NCryptSetProperty(hEncryptionKey, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&uiPolicy, sizeof(NCRYPT_UI_POLICY), 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to set UI policy for encryption key (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }
#endif

    // Generate a new encryption key in the TPM storage provider
    status = NCryptFinalizeKey(hEncryptionKey, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to generate new encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Open the existing encryption key in the TPM storage provider
    status = NCryptOpenKey(hProvider, &hEncryptionKey, name, 0, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open existing encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Create TBS context (TPM2)
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    TBS_RESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hContext);
    if (hr != TBS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to create TBS context (0x%08x)\n", hr);
        return false;
    }

    // Send TPM2_CC_GetRandom command
    const BYTE cmd_random[] = {
        0x80, 0x01,             // tag: TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // commandSize: size of the entire command byte array
        0x00, 0x00, 0x01, 0x7B, // commandCode: TPM2_CC_GetRandom
        0x00, 0x20              // parameter: 32 bytes
    };
    BYTE resp_random[TBS_IN_OUT_BUF_SIZE_MAX] = { 0 };
    UINT32 resp_randomSize = TBS_IN_OUT_BUF_SIZE_MAX;
    hr = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd_random, sizeof(cmd_random), resp_random, &resp_randomSize);
    if (hr != TBS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to send TPM2_CC_GetRandom command (0x%08x)\n", hr);

        // Close TBS context
        hr = Tbsip_Context_Close(hContext);
        if (hr != TBS_SUCCESS)
        {
            fprintf(stderr, "ERROR: Failed to close TBS context (0x%08x)\n", hr);
        }
        return false;
    }

    // Close TBS context
    hr = Tbsip_Context_Close(hContext);
    if (hr != TBS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to close TBS context (0x%08x)\n", hr);
        return false;
    }

    // Derive the HD node from the seed
    dogecoin_hdnode_from_seed((uint8_t*)&resp_random[RESP_RAND_OFFSET], 32, out);

    // Encrypt the HD node with the encryption key
    status = NCryptEncrypt(hEncryptionKey, (PBYTE)out, (DWORD)sizeof(dogecoin_hdnode), NULL, NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to encrypt the HD node with the encryption key (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Allocate memory for the encrypted HD node
    pbResult = (PBYTE)malloc(cbResult);
    if (pbResult == NULL)
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for the encrypted HD node\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Encrypt the HD node with the encryption key
    status = NCryptEncrypt(hEncryptionKey, (PBYTE)out, (DWORD)sizeof(dogecoin_hdnode), NULL, pbResult, cbResult, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to encrypt the HD node with the encryption key (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        dogecoin_free(pbResult);
        return false;
    }

    // Create the directory for storing the encrypted key if it doesn't exist
    if (_wmkdir(CRYPTO_DIR_PATH_W) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "ERROR: Failed to create directory\n");
        return false;
    }

    // Successfully encrypted the HD node with the encryption key
    // Create a file with the encrypted HD node
    // Open the file for binary write, "wb+" to overwrite if exists
    FILE* fp = _wfopen(filename, overwrite ? L"wb+" : L"wb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for writing\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        dogecoin_free(pbResult);
        return false;
    }

    // Write the encrypted HD node to the file
    size_t bytesWritten = fwrite(pbResult, 1, cbResult, fp);
    if (bytesWritten != cbResult)
    {
        fprintf(stderr, "ERROR: Failed to write encrypted hdnode to file\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        dogecoin_free(pbResult);
        fclose(fp);
        return false;
    }

    // Close the file
    fclose(fp);

    // Free the memory for the encrypted HD node
    dogecoin_free(pbResult);

    // Free the encryption key and provider
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;

#else
    (void) out;
    (void) file_num;
    (void) overwrite;
    return false;
#endif
}

/**
 * @brief Decrypt a HD node with the TPM
 *
 * Decrypt a HD node previously encrypted with a TPM2 persistent encryption key.
 *
 * @param out The decrypted HD node will be stored here
 * @param file_num The file number for the encrypted HD node
 * @return Returns true if the HD node is decrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_hdnode_with_tpm(dogecoin_hdnode* out, const int file_num)
{
#if defined(__linux__) && defined(USE_TSS2)
    size_t actual_size = 0;
    if (out == NULL || !fileValid(file_num)) {
        return false;
    }
    if (!linux_tpm_decrypt_blob((uint8_t*)out, sizeof(dogecoin_hdnode), file_num, "encrypted_hdnode", "Enter password for HD node decryption: ", &actual_size)) {
        return false;
    }
    return actual_size == sizeof(dogecoin_hdnode);

#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Validate the input parameters
    if (out == NULL)
    {
        fprintf(stderr, "ERROR: Invalid HD node\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Declare variables
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hEncryptionKey;
    DWORD cbResult;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;

    // Format the name of the encrypted HD node object
    wchar_t name[NAME_MAX_LEN] = {0};
    swprintf(name, sizeof(name), MASTER_TPM_OBJ_NAME_WIN, file_num);

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Open the existing encryption key in the TPM storage provider
    status = NCryptOpenKey(hProvider, &hEncryptionKey, name, 0, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open existing encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Read the encrypted HD node from the file
    wchar_t filename[FILE_PATH_MAX_LEN] = {0};
    swprintf(filename, sizeof(filename), MASTER_TPM_FILE_NAME_WIN, file_num);
    FILE* fp = _wfopen(filename, L"rb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for reading\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Get the size of the encrypted HD node
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate memory for the encrypted HD node
    pbOutput = (PBYTE) malloc(fileSize);
    if (!pbOutput)
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for reading file\n");
        fclose(fp);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Read the encrypted HD node from the file
    DWORD bytesRead = (DWORD)fread(pbOutput, 1, fileSize, fp);
    fclose(fp);

    // Validate the number of bytes read
    if (bytesRead != fileSize)
    {
        fprintf(stderr, "ERROR: Failed to read file\n");
        dogecoin_free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Decrypt the encrypted data
    status = NCryptDecrypt(hEncryptionKey, pbOutput, bytesRead, NULL, (PBYTE)out, sizeof(dogecoin_hdnode), &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        // Failed to decrypt the encrypted data
        fprintf(stderr, "ERROR: Failed to decrypt the encrypted data (0x%08x)\n", status);
        dogecoin_free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Free memory and close handles
    dogecoin_free(pbOutput);
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;

#else
    (void) out;
    (void) file_num;
    return false;
#endif
}

/**
 * @brief Generate a HD node object with software encryption
 *
 * Generate a HD node object with software encryption and store it in a file.
 *
 * @param out The HD node object to generate
 * @param file_num The file number of the encrypted mnemonic
 * @param overwrite Whether or not to overwrite the existing HD node object
 * @param test_password The password to use for testing
 * @param encrypted_blob_out The encrypted HD node will be stored here
 * @param encrypted_blob_size The size of the encrypted HD node will be stored here
 * @return Returns true if the HD node is generated and encrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_generate_hdnode_encrypt_with_sw(dogecoin_hdnode* out, const int file_num, dogecoin_bool overwrite, const char* test_password, ENCRYPTED_BLOB* encrypted_blob_out, size_t* encrypted_blob_size)
{
#ifndef USE_OPTEE // OPTEE has no filesystem or console
    // Validate the input parameters
    if (out == NULL)
    {
        fprintf(stderr, "ERROR: Invalid HD node\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // File operations
    FILE *fp = NULL;
    if (file_num != NO_FILE)
    {
#ifdef _WIN32
        if (_wmkdir(CRYPTO_DIR_PATH_W) == -1 && errno != EEXIST)
        {
            fprintf(stderr, "ERROR: Failed to create directory\n");
            return false;
        }
        wchar_t fullpath[FILE_PATH_MAX_LEN] = {0};
        swprintf(fullpath, sizeof(fullpath), MASTER_SW_FILE_NAME_WIN, file_num);
        if (!overwrite && _waccess(fullpath, F_OK) != -1)
        {
            fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
            return false;
        }
        fp = _wfopen(fullpath, overwrite ? L"wb+" : L"wb");
#else
        if (mkdir(CRYPTO_DIR_PATH, 0777) == -1 && errno != EEXIST)
        {
            fprintf(stderr, "ERROR: Failed to create directory\n");
            return false;
        }
        char fullpath[FILE_PATH_MAX_LEN] = {0};
        snprintf(fullpath, sizeof(fullpath), MASTER_SW_FILE_NAME, file_num);
        if (!overwrite && access(fullpath, F_OK) != -1)
        {
            fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
            return false;
        }
        fp = fopen(fullpath, overwrite ? "wb+" : "wb");
#endif
        if (!fp)
        {
            fprintf(stderr, "ERROR: Failed to open file for writing.\n");
            return false;
        }
    }

    // Prompt for the password
    char* password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       password = malloc(PASS_MAX_LEN);
       strcpy(password, test_password);
    }
    else
#else
    (void) test_password;
#endif
    password = getpass("Enter password for HD node encryption: \n");
    if (password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        fp ? fclose(fp) : 0;
        return false;
    }
    if (strlen(password) == 0)
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Confirm the password
    char* confirm_password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       confirm_password = malloc(PASS_MAX_LEN);
       strcpy(confirm_password, test_password);
    }
    else
#endif
    confirm_password = getpass("Confirm password: \n");
    if (confirm_password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }
    if (strcmp(password, confirm_password) != 0)
    {
        fprintf(stderr, "ERROR: Passwords do not match.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_mem_zero(confirm_password, strlen(confirm_password));
        dogecoin_free(password);
        dogecoin_free(confirm_password);
        fp ? fclose(fp) : 0;
        return false;
    }
    dogecoin_mem_zero(confirm_password, strlen(confirm_password));
    dogecoin_free(confirm_password);

    // Generate two random salts
    uint8_t salt_encryption[SALT_SIZE], salt_verification[SALT_SIZE];
    if (!dogecoin_random_bytes(salt_encryption, SALT_SIZE, 1) ||
        !dogecoin_random_bytes(salt_verification, SALT_SIZE, 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Derive encryption key
    uint8_t encryption_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_encryption, SALT_SIZE, PBKDF2_ITERATIONS, encryption_key, AES_KEY_SIZE);

    // Derive a separate key for verification
    uint8_t verification_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_verification, SALT_SIZE, PBKDF2_ITERATIONS, verification_key, AES_KEY_SIZE);

    // Hash the verification key
    uint8_t verification_key_hash[SHA512_DIGEST_LENGTH];
    sha512_raw(verification_key, AES_KEY_SIZE, verification_key_hash);

    // Clear the password
    dogecoin_mem_zero(password, strlen(password));
    dogecoin_free(password);

    // Generate a random IV for AES encryption
    uint8_t iv[AES_IV_SIZE];
    if (!dogecoin_random_bytes(iv, sizeof(iv), 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        fp ? fclose(fp) : 0;
        return false;
    }

    // Derive the HD node from the seed
    SEED seed = {0};
    if (!dogecoin_random_bytes(seed, sizeof(seed), 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        fp ? fclose(fp) : 0;
        return false;
    }
    dogecoin_hdnode_from_seed(seed, sizeof(seed), out);

    // Encrypt the HD node with AES
    size_t encrypted_size = sizeof(dogecoin_hdnode);
    dogecoin_bool padding_used = false;
    uint8_t* encrypted_data = malloc(encrypted_size);
    if (!encrypted_data)
    {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        fp ? fclose(fp) : 0;
        return false;
    }

    size_t encrypted_actual_size = aes256_cbc_encrypt(encryption_key, iv, (uint8_t*)out, encrypted_size, padding_used, encrypted_data);
    if (encrypted_actual_size == 0)
    {
        fprintf(stderr, "ERROR: AES encryption failed.\n");
        dogecoin_free(encrypted_data);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Write the IV, salts, verification key hash, and encrypted HD node to the file
    if (fp != NULL)
    {
        fwrite(iv, 1, sizeof(iv), fp);
        fwrite(salt_encryption, 1, SALT_SIZE, fp);
        fwrite(salt_verification, 1, SALT_SIZE, fp);
        fwrite(verification_key_hash, 1, sizeof(verification_key_hash), fp);
        fwrite(encrypted_data, 1, encrypted_actual_size, fp);
        fclose(fp);
    }
    else if (encrypted_blob_out != NULL && encrypted_blob_size != NULL)
    {
        memcpy(*encrypted_blob_out, iv, sizeof(iv));
        memcpy(*encrypted_blob_out + sizeof(iv), salt_encryption, SALT_SIZE);
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE, salt_verification, SALT_SIZE);
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE + SALT_SIZE, verification_key_hash, sizeof(verification_key_hash));
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash), encrypted_data, encrypted_actual_size);
        *encrypted_blob_size = sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash) + encrypted_actual_size;
    }

    // Free the encrypted data
    dogecoin_free(encrypted_data);

    return true;
#else
    (void) out;
    (void) file_num;
    (void) overwrite;
    (void) test_password;
    (void) encrypted_blob_out;
    (void) encrypted_blob_size;
    return false;
#endif
}

/**
 * @brief Decrypt a HD node with software decryption
 *
 * Decrypt a HD node previously encrypted with software encryption.
 *
 * @param out The decrypted HD node will be stored here
 * @param file_num The file number for the encrypted HD node
 * @param test_password The password to use for testing
 * @param encrypted_blob The encrypted blob containing the HD node
 * @param encrypted_blob_size The size of the encrypted blob
 * @return Returns true if the HD node is decrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_hdnode_with_sw(dogecoin_hdnode* out, const int file_num, const char* test_password, ENCRYPTED_BLOB encrypted_blob)
{
#ifndef USE_OPTEE // OPTEE has no filesystem or console
    // Validate the input parameters
    if (out == NULL)
    {
        fprintf(stderr, "ERROR: Invalid HD node\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Prompt for the password
    char* password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       password = malloc(PASS_MAX_LEN);
       strcpy(password, test_password);
    }
    else
#else
    (void) test_password;
#endif
    password = getpass("Enter password for HD node decryption: \n");
    if (password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        return false;
    }
    if (strlen(password) == 0)
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        dogecoin_free(password);
        return false;
    }

    // Open the file for reading
    FILE *fp = NULL;
    if (file_num != NO_FILE)
    {
#ifdef _WIN32
        wchar_t fullpath[FILE_PATH_MAX_LEN] = {0};
        swprintf(fullpath, sizeof(fullpath), MASTER_SW_FILE_NAME_WIN, file_num);
        fp = _wfopen(fullpath, L"rb");
#else
        char fullpath[FILE_PATH_MAX_LEN] = {0};
        snprintf(fullpath, sizeof(fullpath), MASTER_SW_FILE_NAME, file_num);
        fp = fopen(fullpath, "rb");
#endif
        if (!fp && encrypted_blob == NULL)
        {
            fprintf(stderr, "ERROR: Failed to open file for reading.\n");
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }

    // Read the IV from the file or blob
    uint8_t iv[AES_IV_SIZE];
    if (fp != NULL)
    {
        if (fread(iv, 1, sizeof(iv), fp) != sizeof(iv))
        {
            fprintf(stderr, "ERROR: Failed to read IV from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(iv, encrypted_blob, sizeof(iv));
    }

    // Read the encryption and verification salts from the file or blob
    uint8_t salt_encryption[SALT_SIZE], salt_verification[SALT_SIZE];
    if (fp != NULL)
    {
        if (fread(salt_encryption, 1, SALT_SIZE, fp) != SALT_SIZE ||
            fread(salt_verification, 1, SALT_SIZE, fp) != SALT_SIZE)
        {
            fprintf(stderr, "ERROR: Failed to read salts from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(salt_encryption, encrypted_blob + sizeof(iv), SALT_SIZE);
        memcpy(salt_verification, encrypted_blob + sizeof(iv) + SALT_SIZE, SALT_SIZE);
    }

    // Read the verification key hash from the file or blob
    uint8_t stored_verification_key_hash[SHA512_DIGEST_LENGTH];
    if (fp != NULL)
    {
        if (fread(stored_verification_key_hash, 1, sizeof(stored_verification_key_hash), fp) != sizeof(stored_verification_key_hash))
        {
            fprintf(stderr, "ERROR: Failed to read verification key hash from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(stored_verification_key_hash, encrypted_blob + sizeof(iv) + SALT_SIZE + SALT_SIZE, sizeof(stored_verification_key_hash));
    }

    // Derive the verification key from the password and verification salt using PBKDF2
    uint8_t derived_verification_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_verification, SALT_SIZE, PBKDF2_ITERATIONS, derived_verification_key, AES_KEY_SIZE);

    // Hash the derived verification key
    uint8_t derived_verification_key_hash[SHA512_DIGEST_LENGTH];
    sha512_raw(derived_verification_key, AES_KEY_SIZE, derived_verification_key_hash);

    // Compare the derived verification key hash with the stored one
    if (memcmp(stored_verification_key_hash, derived_verification_key_hash, SHA512_DIGEST_LENGTH) != 0)
    {
        fprintf(stderr, "ERROR: Incorrect password.\n");
        fclose(fp);
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        return false;
    }

    // Derive the encryption key from the password and encryption salt using PBKDF2
    uint8_t encryption_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_encryption, SALT_SIZE, PBKDF2_ITERATIONS, encryption_key, AES_KEY_SIZE);

    // Clear the password
    dogecoin_mem_zero(password, strlen(password));
    dogecoin_free(password);

    // Read the encrypted HD node from the file or blob
    size_t encrypted_size = sizeof(dogecoin_hdnode);
    uint8_t* encrypted_data = malloc(encrypted_size);
    if (!encrypted_data)
    {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        fclose(fp);
        return false;
    }

    if (fp != NULL)
    {
        if (fread(encrypted_data, 1, encrypted_size, fp) != encrypted_size)
        {
            fprintf(stderr, "ERROR: Failed to read encrypted HD node from file.\n");
            fclose(fp);
            dogecoin_free(encrypted_data);
            return false;
        }

        fclose(fp);
    }
    else
    {
        memcpy(encrypted_data, encrypted_blob + sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(stored_verification_key_hash), encrypted_size);
    }

    // Decrypt the HD node with software decryption (AES)
    dogecoin_bool padding_used = false;
    size_t decrypted_actual_size = aes256_cbc_decrypt(encryption_key, iv, encrypted_data, encrypted_size, padding_used, (uint8_t*)out);
    dogecoin_free(encrypted_data);

    if (decrypted_actual_size == 0)
    {
        fprintf(stderr, "ERROR: AES decryption failed.\n");
        return false;
    }

    return true;
#else
    (void) out;
    (void) file_num;
    (void) test_password;
    (void) encrypted_blob;
    return false;
#endif
}

/**
 * @brief Generate a mnemonic and encrypt it with the TPM
 *
 * Generate a mnemonic and encrypt it with a TPM2 persistent encryption key.
 *
 * @param mnemonic The generated mnemonic will be stored here
 * @param file_num The file number for the encrypted mnemonic
 * @param overwrite If true, overwrite the existing encrypted mnemonic
 * @param lang The language to use for the mnemonic
 * @param space The mnemonic space to use
 * @param words The mnemonic words to use
 * @return Returns true if the mnemonic is generated and encrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_generate_mnemonic_encrypt_with_tpm(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, const char* lang, const char* space, const char* words)
{
#if defined(__linux__) && defined(USE_TSS2)
    if (mnemonic == NULL || !fileValid(file_num)) {
        return false;
    }

    ESYS_CONTEXT* context = NULL;
    TPM2B_DIGEST* random_bytes = NULL;
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }

    if (!linux_tpm_startup(context)) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    result = Esys_GetRandom(context,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            32,
                            &random_bytes);
    if (result != TSS2_RC_SUCCESS || random_bytes == NULL || random_bytes->size != 32) {
        tpm_cleanup(&context, random_bytes, NULL);
        return false;
    }

    char* rand_hex = utils_uint8_to_hex((uint8_t*)random_bytes->buffer, random_bytes->size);
    size_t mnemonicSize = 0;
    int mnemonicResult = dogecoin_generate_mnemonic("256", lang, space, (const char*)rand_hex, words, NULL, &mnemonicSize, mnemonic);
    utils_clear_buffers();
    tpm_cleanup(&context, random_bytes, NULL);
    if (mnemonicResult == -1) {
        return false;
    }
    return linux_tpm_encrypt_blob((const uint8_t*)mnemonic, strlen(mnemonic) + 1, file_num, overwrite, "encrypted_mnemonic", "Enter password for mnemonic encryption: ");

#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Validate the input parameters
    if (mnemonic == NULL)
    {
        fprintf(stderr, "ERROR: Invalid mnemonic\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Format the name of the encrypted HD node file
    wchar_t filename[FILE_PATH_MAX_LEN] = {0};
    swprintf(filename, sizeof(filename), MNEMONIC_TPM_FILE_NAME_WIN, file_num);

    // Check if the file already exists and if not, prompt for overwriting
        if (!overwrite && _waccess(filename, F_OK) != -1)
    {
        fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
        return false;
    }

    // Declare variables
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hEncryptionKey;
    DWORD cbResult;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;
    DWORD dwFlags = 0; // Use NCRYPT_MACHINE_KEY_FLAG for machine-level keys or 0 for user-level keys

    // Format the name of the mnemonic
    wchar_t name[NAME_MAX_LEN] = {0};
    swprintf(name, sizeof(name), MNEMONIC_TPM_OBJ_NAME_WIN, file_num);

    // Create TBS context (TPM2)
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    TBS_RESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hContext);
    if (hr != TBS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to create TBS context (0x%08x)\n", hr);
        return false;
    }

    // Send TPM2_CC_GetRandom command
    const BYTE cmd_random[] = {
        0x80, 0x01,             // tag: TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // commandSize: size of the entire command byte array
        0x00, 0x00, 0x01, 0x7B, // commandCode: TPM2_CC_GetRandom
        0x00, 0x20              // parameter: 32 bytes
    };
    BYTE resp_random[TBS_IN_OUT_BUF_SIZE_MAX] = { 0 };
    UINT32 resp_randomSize =  TBS_IN_OUT_BUF_SIZE_MAX;
    hr = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd_random, sizeof(cmd_random), resp_random, &resp_randomSize);
    if (hr != TBS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to send TPM2_CC_GetRandom command (0x%08x)\n", hr);

        // Close TBS context
        hr = Tbsip_Context_Close(hContext);
        if (hr != TBS_SUCCESS)
        {
            fprintf(stderr, "ERROR: Failed to close TBS context (0x%08x)\n", hr);
        }
        return false;
    }

    // Close TBS context
    hr = Tbsip_Context_Close(hContext);
    if (hr != TBS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to close TBS context (0x%08x)\n", hr);
        return false;
    }

    // Convert the random data to hex
    // TODO: This is a hack, we should be able to use the random data directly
    char* rand_hex = utils_uint8_to_hex(&resp_random[RESP_RAND_OFFSET], 32);

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Create a new persistent encryption key
    status = NCryptCreatePersistedKey(hProvider, &hEncryptionKey, NCRYPT_RSA_ALGORITHM, name, 0, overwrite ? NCRYPT_OVERWRITE_KEY_FLAG : dwFlags);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to create new persistent encryption key (0x%08x)\n", status);
        NCryptFreeObject(hProvider);
        return false;
    }

#ifndef TEST_PASSWD
    // Set the UI policy to force high protection (PIN dialog)
    NCRYPT_UI_POLICY uiPolicy;
    memset(&uiPolicy, 0, sizeof(NCRYPT_UI_POLICY));
    uiPolicy.dwVersion = 1;
    uiPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
    uiPolicy.pszDescription = L"BIP39 seed phrase for dogecoin wallet";
    status = NCryptSetProperty(hEncryptionKey, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&uiPolicy, sizeof(NCRYPT_UI_POLICY), 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to set UI policy for encryption key (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }
#endif

    // Generate a new encryption key in the TPM storage provider
    status = NCryptFinalizeKey(hEncryptionKey, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to generate new encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Open the existing encryption key in the TPM storage provider
    status = NCryptOpenKey(hProvider, &hEncryptionKey, name, 0, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open existing encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Generate the BIP-39 mnemonic from the random data
    size_t mnemonicSize = 0;
    int mnemonicResult = dogecoin_generate_mnemonic("256", lang, space, (const char*)rand_hex, words, NULL, &mnemonicSize, mnemonic);
    if (mnemonicResult == -1)
    {
        fprintf(stderr, "ERROR: Failed to generate mnemonic\n");
        NCryptFreeObject(hProvider);
        utils_clear_buffers();
        return false;
    }

    // Clear the random data
    utils_clear_buffers();

    // Encrypt the mnemonic using the encryption key
    status = NCryptEncrypt(hEncryptionKey, (PBYTE)mnemonic, (DWORD) mnemonicSize, NULL, NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to encrypt the mnemonic (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Allocate memory for the encrypted data
    pbOutput = (PBYTE) malloc(cbResult);
    if (!pbOutput)
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for encrypted data\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Encrypt the mnemonic using the encryption key
    status = NCryptEncrypt(hEncryptionKey, (PBYTE)mnemonic, (DWORD) mnemonicSize, NULL, pbOutput, cbResult, &cbOutput, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to encrypt the mnemonic (0x%08x)\n", status);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Create the directory for storing the encrypted mnemonic if it doesn't exist
    if (_wmkdir(CRYPTO_DIR_PATH_W) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "ERROR: Failed to create directory\n");
        return false;
    }

    // Successfully encrypted the mnemonic
    // Create a file with the encrypted mnemonic
    // Open the file for binary write, "wb+" to overwrite if exists
    FILE* fp = _wfopen(filename, overwrite ? L"wb+" : L"wb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for writing\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Write the encrypted mnemonic to the file
    size_t bytesWritten = fwrite(pbOutput, 1, cbOutput, fp);
    if (bytesWritten != cbOutput)
    {
        fprintf(stderr, "ERROR: Failed to write encrypted mnemonic to file\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Close the file
    fclose(fp);

    // Free the memory for the encrypted data
    dogecoin_free(pbOutput);

    // Free the encryption key and provider
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;
#else
    (void) mnemonic;
    (void) file_num;
    (void) overwrite;
    (void) lang;
    (void) space;
    (void) words;
    return false;
#endif
}

/**
 * @brief Decrypts a BIP-39 mnemonic
 *
 * Decrypts a BIP-39 mnemonic using the TPM storage provider
 *
 * @param mnemonic The decrypted mnemonic will be stored here
 * @param file_num The file number of the encrypted mnemonic
 *
 * @return True if the mnemonic was successfully decrypted, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_mnemonic_with_tpm(MNEMONIC mnemonic, const int file_num)
{
#if defined(__linux__) && defined(USE_TSS2)
    size_t actual_size = 0;
    if (mnemonic == NULL || !fileValid(file_num)) {
        return false;
    }
    dogecoin_mem_zero(mnemonic, sizeof(MNEMONIC));
    if (!linux_tpm_decrypt_blob((uint8_t*)mnemonic, sizeof(MNEMONIC), file_num, "encrypted_mnemonic", "Enter password for mnemonic decryption: ", &actual_size)) {
        return false;
    }
    mnemonic[sizeof(MNEMONIC) - 1] = '\0';
    return actual_size > 0;

#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Validate the input parameters
    if (mnemonic == NULL)
    {
        fprintf(stderr, "ERROR: Invalid mnemonic\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Declare variables
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hEncryptionKey;
    DWORD cbResult;
    PBYTE pbOutput = NULL;

    // Format the name of the mnemonic
    wchar_t name[NAME_MAX_LEN] = {0};
    swprintf(name, sizeof(name), MNEMONIC_TPM_OBJ_NAME_WIN, file_num);

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Open the existing encryption key in the TPM storage provider
    status = NCryptOpenKey(hProvider, &hEncryptionKey, name, 0, 0);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open existing encryption key in TPM storage provider (0x%08x)\n", status);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Read the encrypted mnemonic from the file
    wchar_t filename[FILE_PATH_MAX_LEN] = {0};
    swprintf(filename, sizeof(filename), MNEMONIC_TPM_FILE_NAME_WIN, file_num);
    FILE* fp = _wfopen(filename, L"rb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for reading\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Get the size of the file
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate memory for the encrypted data
    pbOutput = (PBYTE) malloc(fileSize);
    if (!pbOutput)
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for reading file\n");
        fclose(fp);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Read the encrypted data from the file
    DWORD bytesRead = (DWORD)fread(pbOutput, 1, fileSize, fp);
    fclose(fp);

    // Check that the file was read successfully
    if (bytesRead != fileSize)
    {
        fprintf(stderr, "ERROR: Failed to read file\n");
        dogecoin_free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Decrypt the encrypted data
    status = NCryptDecrypt(hEncryptionKey, pbOutput, bytesRead, NULL, (PBYTE)mnemonic, sizeof(MNEMONIC), &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to decrypt the encrypted data (0x%08x)\n", status);
        dogecoin_free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Free the output buffer, encryption key handle, and close the TPM storage provider
    dogecoin_free(pbOutput);
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;
#else
    (void) mnemonic;
    (void) file_num;
    return false;
#endif
}

/**
 * @brief Generate a mnemonic and encrypt it with software encryption
 *
 * Generate a mnemonic, prompt for a password, and encrypt it with software-based encryption.
 *
 * @param mnemonic The generated mnemonic will be stored here
 * @param file_num The file number for the encrypted mnemonic
 * @param overwrite If true, overwrite the existing encrypted mnemonic
 * @param lang The language to use for the mnemonic
 * @param space The mnemonic space to use
 * @param words The mnemonic words to use
 * @param test_password The password to use for testing
 * @param encrypted_blob_out The encrypted mnemonic will be stored here
 * @param encrypted_blob_size The size of the encrypted mnemonic will be stored here
 * @return Returns true if the mnemonic is generated and encrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_generate_mnemonic_encrypt_with_sw(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, const char* lang, const char* space, const char* words, const char* test_password, ENCRYPTED_BLOB* encrypted_blob_out, size_t* encrypted_blob_size)
{
#ifndef USE_OPTEE // OPTEE has no filesystem or console
    // Validate the input parameters
    if (mnemonic == NULL)
    {
        fprintf(stderr, "ERROR: Invalid mnemonic\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // File operations
    FILE *fp = NULL;
    if (file_num != NO_FILE)
    {
#ifdef _WIN32
        if (_wmkdir(CRYPTO_DIR_PATH_W) == -1 && errno != EEXIST)
        {
            fprintf(stderr, "ERROR: Failed to create directory\n");
            return false;
        }
        wchar_t fullpath[FILE_PATH_MAX_LEN] = {0};
        swprintf(fullpath, sizeof(fullpath), MNEMONIC_SW_FILE_NAME_WIN, file_num);
        if (!overwrite && _waccess(fullpath, F_OK) != -1)
        {
            fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
            return false;
        }
        fp = _wfopen(fullpath, overwrite ? L"wb+" : L"wb");
#else
        if (mkdir(CRYPTO_DIR_PATH, 0777) == -1 && errno != EEXIST)
        {
            fprintf(stderr, "ERROR: Failed to create directory\n");
            return false;
        }
        char fullpath[FILE_PATH_MAX_LEN] = {0};
        snprintf(fullpath, sizeof(fullpath), MNEMONIC_SW_FILE_NAME, file_num);
        if (!overwrite && access(fullpath, F_OK) != -1)
        {
            fprintf(stderr, "ERROR: File already exists. Use overwrite flag to replace it.\n");
            return false;
        }
        fp = fopen(fullpath, overwrite ? "wb+" : "wb");
#endif
        if (!fp)
        {
            fprintf(stderr, "ERROR: Failed to open file for writing.\n");
            return false;
        }
    }

    // Prompt for the password
    char* password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       password = malloc(PASS_MAX_LEN);
       strcpy(password, test_password);
    }
    else
#else
    (void) test_password;
#endif
    password = getpass("Enter password for mnemonic encryption: \n");
    if (password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        fp ? fclose(fp) : 0;
        return false;
    }
    if (strlen(password) == 0)
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Confirm the password
    char* confirm_password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       confirm_password = malloc(PASS_MAX_LEN);
       strcpy(confirm_password, test_password);
    }
    else
#endif
    confirm_password = getpass("Confirm password: \n");
    if (confirm_password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }
    if (strcmp(password, confirm_password) != 0)
    {
        fprintf(stderr, "ERROR: Passwords do not match.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_mem_zero(confirm_password, strlen(confirm_password));
        dogecoin_free(password);
        dogecoin_free(confirm_password);
        fp ? fclose(fp) : 0;
        return false;
    }
    dogecoin_mem_zero(confirm_password, strlen(confirm_password));
    dogecoin_free(confirm_password);

    // Generate two random salts
    uint8_t salt_encryption[SALT_SIZE], salt_verification[SALT_SIZE];
    if (!dogecoin_random_bytes(salt_encryption, SALT_SIZE, 1) ||
        !dogecoin_random_bytes(salt_verification, SALT_SIZE, 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Derive encryption key
    uint8_t encryption_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_encryption, SALT_SIZE, PBKDF2_ITERATIONS, encryption_key, AES_KEY_SIZE);

    // Derive a separate key for verification
    uint8_t verification_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_verification, SALT_SIZE, PBKDF2_ITERATIONS, verification_key, AES_KEY_SIZE);

    // Hash the verification key
    uint8_t verification_key_hash[SHA512_DIGEST_LENGTH];
    sha512_raw(verification_key, AES_KEY_SIZE, verification_key_hash);

    // Clear the password
    dogecoin_mem_zero(password, strlen(password));
    dogecoin_free(password);

    // Generate the BIP-39 mnemonic
    size_t mnemonicSize = 0;
    int mnemonicResult = dogecoin_generate_mnemonic("256", lang, space, NULL, words, NULL, &mnemonicSize, mnemonic);
    if (mnemonicResult == -1)
    {
        fprintf(stderr, "ERROR: Failed to generate mnemonic\n");
        fp ? fclose(fp) : 0;
        return false;
    }

    // Encrypt the mnemonic with AES
    uint8_t iv[AES_IV_SIZE];
    if (!dogecoin_random_bytes(iv, sizeof(iv), 1))
    {
        fprintf(stderr, "ERROR: Failed to generate random bytes.\n");
        fp ? fclose(fp) : 0;
        return false;
    }

    size_t encrypted_size = ENCRYPTED_MNEMONIC_SIZE;
    dogecoin_bool padding_used = false;
    uint8_t* encrypted_data = malloc(encrypted_size);
    if (!encrypted_data)
    {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        fp ? fclose(fp) : 0;
        return false;
    }
    memset(encrypted_data, 0, encrypted_size);

    size_t encrypted_actual_size = aes256_cbc_encrypt(encryption_key, iv, (uint8_t*)mnemonic, encrypted_size, padding_used, encrypted_data);
    if (encrypted_actual_size == 0)
    {
        fprintf(stderr, "ERROR: AES encryption failed.\n");
        dogecoin_free(encrypted_data);
        fp ? fclose(fp) : 0;
        return false;
    }

    // Write the IV, salts, verification key hash, and encrypted mnemonic to the file
    if (fp != NULL)
    {
        fwrite(iv, 1, sizeof(iv), fp);
        fwrite(salt_encryption, 1, SALT_SIZE, fp);
        fwrite(salt_verification, 1, SALT_SIZE, fp);
        fwrite(verification_key_hash, 1, sizeof(verification_key_hash), fp);
        fwrite(encrypted_data, 1, encrypted_actual_size, fp);
        fclose(fp);
    }
    else if (encrypted_blob_out != NULL && encrypted_blob_size != NULL)
    {
        memcpy(*encrypted_blob_out, iv, sizeof(iv));
        memcpy(*encrypted_blob_out + sizeof(iv), salt_encryption, SALT_SIZE);
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE, salt_verification, SALT_SIZE);
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE + SALT_SIZE, verification_key_hash, sizeof(verification_key_hash));
        memcpy(*encrypted_blob_out + sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash), encrypted_data, encrypted_actual_size);
        *encrypted_blob_size = sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(verification_key_hash) + encrypted_actual_size;
    }

    // Free the encrypted data
    dogecoin_free(encrypted_data);

    return true;
#else
    (void) mnemonic;
    (void) file_num;
    (void) overwrite;
    (void) lang;
    (void) space;
    (void) words;
    (void) test_password;
    (void) encrypted_blob_out;
    (void) encrypted_blob_size;
    return false;
#endif
}

/**
 * @brief Decrypt a BIP-39 mnemonic with software decryption
 *
 * Decrypt a BIP-39 mnemonic previously encrypted with software-based encryption.
 *
 * @param mnemonic The decrypted mnemonic will be stored here
 * @param file_num The file number for the encrypted mnemonic
 * @param test_password The password to use for testing
 * @param encrypted_blob The encrypted blob containing the mnemonic
 * @param encrypted_blob_size The size of the encrypted blob
 * @return Returns true if the mnemonic is decrypted successfully, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_mnemonic_with_sw(MNEMONIC mnemonic, const int file_num, const char* test_password, ENCRYPTED_BLOB encrypted_blob)
{
#ifndef USE_OPTEE // OPTEE has no filesystem or console
    // Validate the input parameters
    if (mnemonic == NULL)
    {
        fprintf(stderr, "ERROR: Invalid mnemonic\n");
        return false;
    }

    // Validate the file number
    if (!fileValid(file_num))
    {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Prompt for the password
    char* password = NULL;
#ifdef TEST_PASSWD
    if (test_password)
    {
       password = malloc(PASS_MAX_LEN);
       strcpy(password, test_password);
    }
    else
#else
    (void) test_password;
#endif
    password = getpass("Enter password for mnemonic decryption: \n");
    if (password == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read password.\n");
        return false;
    }
    if (strlen(password) == 0)
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        dogecoin_free(password);
        return false;
    }

    // Open the file for reading
    FILE *fp = NULL;
    if (file_num != NO_FILE)
    {
#ifdef _WIN32
        wchar_t fullpath[FILE_PATH_MAX_LEN] = {0};
        swprintf(fullpath, sizeof(fullpath), MNEMONIC_SW_FILE_NAME_WIN, file_num);
        fp = _wfopen(fullpath, L"rb");
#else
        char fullpath[FILE_PATH_MAX_LEN] = {0};
        snprintf(fullpath, sizeof(fullpath), MNEMONIC_SW_FILE_NAME, file_num);
        fp = fopen(fullpath, "rb");
#endif
        if (!fp && encrypted_blob == NULL)
        {
            fprintf(stderr, "ERROR: Failed to open file for reading.\n");
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }

    // Read the IV, encryption salt, and verification salt from the file or blob
    uint8_t iv[AES_IV_SIZE], salt_encryption[SALT_SIZE], salt_verification[SALT_SIZE];
    if (fp != NULL)
    {
        if (fread(iv, 1, sizeof(iv), fp) != sizeof(iv) ||
            fread(salt_encryption, 1, SALT_SIZE, fp) != SALT_SIZE ||
            fread(salt_verification, 1, SALT_SIZE, fp) != SALT_SIZE)
        {
            fprintf(stderr, "ERROR: Failed to read data from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(iv, encrypted_blob, sizeof(iv));
        memcpy(salt_encryption, encrypted_blob + sizeof(iv), SALT_SIZE);
        memcpy(salt_verification, encrypted_blob + sizeof(iv) + SALT_SIZE, SALT_SIZE);
    }

    // Read the verification key hash from the file or blob
    uint8_t stored_verification_key_hash[SHA512_DIGEST_LENGTH];
    if (fp != NULL)
    {
        if (fread(stored_verification_key_hash, 1, sizeof(stored_verification_key_hash), fp) != sizeof(stored_verification_key_hash))
        {
            fprintf(stderr, "ERROR: Failed to read verification key hash from file.\n");
            fclose(fp);
            dogecoin_mem_zero(password, strlen(password));
            dogecoin_free(password);
            return false;
        }
    }
    else
    {
        memcpy(stored_verification_key_hash, encrypted_blob + sizeof(iv) + SALT_SIZE + SALT_SIZE, sizeof(stored_verification_key_hash));
    }

    // Derive the verification key from the password and verification salt using PBKDF2
    uint8_t derived_verification_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_verification, SALT_SIZE, PBKDF2_ITERATIONS, derived_verification_key, AES_KEY_SIZE);

    // Hash the derived verification key
    uint8_t derived_verification_key_hash[SHA512_DIGEST_LENGTH];
    sha512_raw(derived_verification_key, AES_KEY_SIZE, derived_verification_key_hash);

    // Compare the derived verification key hash with the stored one
    if (memcmp(stored_verification_key_hash, derived_verification_key_hash, SHA512_DIGEST_LENGTH) != 0)
    {
        fprintf(stderr, "ERROR: Incorrect password.\n");
        fclose(fp);
        dogecoin_mem_zero(password, strlen(password));
        dogecoin_free(password);
        return false;
    }

    // Derive the encryption key from the password and encryption salt using PBKDF2
    uint8_t encryption_key[AES_KEY_SIZE];
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password), salt_encryption, SALT_SIZE, PBKDF2_ITERATIONS, encryption_key, AES_KEY_SIZE);

    // Clear the password
    dogecoin_mem_zero(password, strlen(password));
    dogecoin_free(password);

    // Read the encrypted mnemonic from the file or blob
    size_t encrypted_size = ENCRYPTED_MNEMONIC_SIZE;
    uint8_t* encrypted_data = malloc(encrypted_size);
    if (!encrypted_data)
    {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        fclose(fp);
        return false;
    }

    if (fp != NULL)
    {
        if (fread(encrypted_data, 1, encrypted_size, fp) != encrypted_size)
        {
            fprintf(stderr, "ERROR: Failed to read encrypted mnemonic from file.\n");
            fclose(fp);
            dogecoin_free(encrypted_data);
            return false;
        }

        fclose(fp);
    }
    else
    {
        memcpy(encrypted_data, encrypted_blob + sizeof(iv) + SALT_SIZE + SALT_SIZE + sizeof(stored_verification_key_hash), encrypted_size);
    }

    // Decrypt the mnemonic with AES
    dogecoin_bool padding_used = false;
    size_t decrypted_actual_size = aes256_cbc_decrypt(encryption_key, iv, encrypted_data, encrypted_size, padding_used, (uint8_t*)mnemonic);
    dogecoin_free(encrypted_data);

    if (decrypted_actual_size == 0)
    {
        fprintf(stderr, "ERROR: AES decryption failed.\n");
        return false;
    }

    return true;
#else
    (void) mnemonic;
    (void) file_num;
    (void) test_password;
    (void) encrypted_blob;
    return false;
#endif
}

/**
 * @brief List the encryption keys in the TPM storage provider
 *
 * Lists the encryption keys in the TPM storage provider
 *
 * @param names The names of the encryption keys will be stored here
 * @param count The number of encryption keys will be stored here
 *
 * @return True if the encryption keys were successfully listed, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_list_encryption_keys_in_tpm(wchar_t* names[], size_t* count)
{
#if defined(__linux__) && defined(USE_TSS2)
    if (names == NULL || count == NULL) {
        return false;
    }
    *count = 0;

    ESYS_CONTEXT* context = NULL;
    if (Esys_Initialize(&context, NULL, NULL) != TSS2_RC_SUCCESS) {
        return false;
    }
    if (!linux_tpm_startup(context)) {
        tpm_cleanup(&context, NULL);
        return false;
    }

    // Walk the persistent-handle range of the TPM with TPM2_CAP_HANDLES and
    // emit a libdogecoin-style name for each entry that matches one of the
    // libdogecoin persistent-handle bases.
    TPM2_HANDLE start = TPM2_PERSISTENT_FIRST;
    TPMI_YES_NO more = TPM2_NO;
    do {
        TPMS_CAPABILITY_DATA* cap = NULL;
        TSS2_RC rc = Esys_GetCapability(context,
                                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                        TPM2_CAP_HANDLES, start,
                                        TPM2_MAX_CAP_HANDLES, &more, &cap);
        if (rc != TSS2_RC_SUCCESS || cap == NULL) {
            for (size_t i = 0; i < *count; i++) {
                free(names[i]);
                names[i] = NULL;
            }
            *count = 0;
            tpm_cleanup(&context, cap, NULL);
            return false;
        }

        const TPML_HANDLE* handles = &cap->data.handles;
        for (UINT32 i = 0; i < handles->count; i++) {
            if (*count >= MAX_FILES) break;
            TPM2_HANDLE ph = handles->handle[i];
            uint32_t base = ph & LINUX_TPM_PERSISTENT_RANGE_MASK;
            unsigned slot = ph & LINUX_TPM_PERSISTENT_SLOT_MASK;
            const wchar_t* fmt = NULL;
            size_t buflen = 0;
            if (base == LINUX_TPM_PERSISTENT_BASE_SEED) {
                fmt = L"dogecoin_seed_%03u";
                buflen = wcslen(L"dogecoin_seed_000") + 1;
            } else if (base == LINUX_TPM_PERSISTENT_BASE_MNEMONIC) {
                fmt = L"dogecoin_mnemonic_%03u";
                buflen = wcslen(L"dogecoin_mnemonic_000") + 1;
            } else if (base == LINUX_TPM_PERSISTENT_BASE_HDNODE) {
                fmt = L"dogecoin_master_%03u";
                buflen = wcslen(L"dogecoin_master_000") + 1;
            }
            if (fmt == NULL) {
                continue;
            }
            names[*count] = malloc(buflen * sizeof(wchar_t));
            if (names[*count] == NULL) {
                for (size_t j = 0; j < *count; j++) {
                    free(names[j]);
                    names[j] = NULL;
                }
                *count = 0;
                tpm_cleanup(&context, cap, NULL);
                return false;
            }
            swprintf(names[*count], buflen, fmt, slot);
            (*count)++;
        }

        if (handles->count > 0) {
            start = handles->handle[handles->count - 1] + 1;
        } else {
            more = TPM2_NO;
        }
        tpm_cleanup(NULL, cap, NULL);
    } while (more == TPM2_YES && start <= TPM2_PERSISTENT_LAST && *count < MAX_FILES);

    tpm_cleanup(&context, NULL);
    return true;

#elif defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2)

    // Declare ncrypt variables
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;
    DWORD dwFlags = 0; // Use NCRYPT_MACHINE_KEY_FLAG for machine-level keys or 0 for user-level keys
    PVOID ppEnumState = NULL;

    // Open the TPM storage provider
    status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, dwFlags);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to open TPM storage provider (0x%08x)\n", status);
        return false;
    }

    // Enumerate the keys in the TPM storage provider
    NCryptKeyName* keyList = NULL;

    while (true)
    {
        // Get the next key in the list
        status = NCryptEnumKeys(hProvider, NULL, &keyList, &ppEnumState, dwFlags);
        if (status == NTE_NO_MORE_ITEMS)
        {
            break;
        }
        else if (status != ERROR_SUCCESS)
        {
            fprintf(stderr, "ERROR: Failed to enumerate keys in TPM storage provider (0x%08x)\n", status);
            NCryptFreeObject(hProvider);
            return false;
        }

        // Allocate memory for the name
        names[*count] = malloc((wcslen(keyList->pszName) + 1) * sizeof(wchar_t));

        if (names[*count] == NULL)
        {
            fprintf(stderr, "ERROR: Failed to allocate memory for object name\n");
            NCryptFreeObject(hProvider);
            return false;
        }

        // Copy the name
        swprintf(names[*count], (wcslen(keyList->pszName) + 1) * sizeof(wchar_t), L"%ls", keyList->pszName);

        // Increment the count of keys
        (*count)++;
    }

    // Free the key list
    NCryptFreeBuffer(keyList);

    // Close the TPM storage provider
    NCryptFreeObject(hProvider);

    // Free the enumeration state
    NCryptFreeBuffer(ppEnumState);

    return true;
#else
    (void) names;
    (void) count;
    return false;
#endif

}

/**
 * @brief Generate a BIP39 english mnemonic with the TPM
 *
 * Generates a BIP39 english mnemonic with the TPM storage provider
 *
 * @param mnemonic The generated mnemonic will be stored here
 * @param file_num The file number of the encrypted mnemonic
 * @param overwrite If true, overwrite the existing mnemonic
 *
 * @return True if the mnemonic was successfully generated, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool generateRandomEnglishMnemonicTPM(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite)
{

    // Generate an English mnemonic with the TPM
    return dogecoin_generate_mnemonic_encrypt_with_tpm(mnemonic, file_num, overwrite, "eng", " ", NULL);
}

/**
 * @brief Generate a BIP39 english mnemonic with software encryption
 *
 * Generates a BIP39 english mnemonic with software-based encryption
 *
 * @param mnemonic The generated mnemonic will be stored here
 * @param file_num The file number of the encrypted mnemonic
 * @param overwrite If true, overwrite the existing mnemonic
 * @param encrypted_blob The encrypted blob will be stored here
 * @param encrypted_blob_size The size of the encrypted blob will be stored here
 *
 * @return True if the mnemonic was successfully generated, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool generateRandomEnglishMnemonicSW(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, ENCRYPTED_BLOB* encrypted_blob, size_t* encrypted_blob_size)
{

    // Generate an English mnemonic with software encryption
    return dogecoin_generate_mnemonic_encrypt_with_sw(mnemonic, file_num, overwrite, "eng", " ", NULL, NULL, encrypted_blob, encrypted_blob_size);
}

#ifdef USE_YUBIKEY

/**
 * @brief Encrypt a seed with software encryption and write it to a YubiKey
 *
 * Encrypts a seed with software encryption and writes it to a YubiKey
 *
 * @param seed The seed to encrypt
 * @param size The size of the seed
 * @param file_num The file number of the encrypted seed
 * @param overwrite If true, overwrite the existing encrypted seed
 * @param test_password The password to use for testing
 *
 * @return True if the seed was successfully encrypted and written to the YubiKey, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_encrypt_seed_with_sw_to_yubikey(const SEED seed, const size_t size, const int file_num, const dogecoin_bool overwrite, const char* test_password)
{
    ENCRYPTED_BLOB encrypted_blob;
    size_t encrypted_blob_size = 0;
    dogecoin_bool result = dogecoin_encrypt_seed_with_sw(seed, size, NO_FILE, overwrite, test_password, &encrypted_blob, &encrypted_blob_size);
    if (!result)
    {
        return false;
    }

    ykpiv_state *state = NULL;

    // Initialize and connect the YubiKey
    if (ykpiv_init(&state, true) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to initialize YubiKey.\n");
        return false;
    }
    if (ykpiv_connect(state, NULL) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to connect to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    // Prompt for the management key
    char* mgm_key = getpass("Enter YubiKey management key: \n");
    if (mgm_key == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read management key.\n");
        ykpiv_done(state);
        return false;
    }

    // Decode the management key from hex into binary
    unsigned char binary_mgm_key[24];
    size_t binary_mgm_key_len = sizeof(binary_mgm_key);
    if (ykpiv_hex_decode(mgm_key, strlen(mgm_key), binary_mgm_key, &binary_mgm_key_len) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to decode management key.\n");
        dogecoin_mem_zero(mgm_key, strlen(mgm_key));
        dogecoin_free(mgm_key);
        ykpiv_done(state);
        return false;
    }

    // Authenticate with the YubiKey using the management key
    if (ykpiv_authenticate(state, binary_mgm_key) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to authenticate with YubiKey.\n");
        dogecoin_mem_zero(mgm_key, strlen(mgm_key));
        dogecoin_mem_zero(binary_mgm_key, sizeof(binary_mgm_key));
        dogecoin_free(mgm_key);
        ykpiv_done(state);
        return false;
    }

    dogecoin_mem_zero(mgm_key, strlen(mgm_key));
    dogecoin_free(mgm_key);

    // Write the encrypted blob directly to the YubiKey using the defined tag
    if (ykpiv_save_object(state, SEED_DATA_TAG(file_num), encrypted_blob, encrypted_blob_size) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to save encrypted seed to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    ykpiv_done(state); // Clean up YubiKey state after use
    return true;
}

/**
 * @brief Decrypt a seed with software decryption from a YubiKey
 *
 * Decrypts a seed with software decryption from a YubiKey
 *
 * @param seed The decrypted seed will be stored here
 * @param file_num The file number of the encrypted seed
 * @param test_password The password to use for testing
 *
 * @return True if the seed was successfully decrypted, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_seed_with_sw_from_yubikey(SEED seed, const int file_num, const char* test_password)
{
    ykpiv_state *state = NULL;
    ENCRYPTED_BLOB encrypted_blob;
    unsigned long encrypted_blob_size = sizeof(encrypted_blob);

    // Initialize and connect the YubiKey
    if (ykpiv_init(&state, true) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to initialize YubiKey.\n");
        return false;
    }
    if (ykpiv_connect(state, NULL) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to connect to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    // Verify the PIN to enable reading from the PIN-protected slot
    char* pin = getpass("Enter YubiKey PIN: \n");
    int tries;
    if (ykpiv_verify(state, pin, &tries) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Incorrect PIN. Tries left: %d\n", tries);
        ykpiv_done(state);
        dogecoin_free(pin);
        return false;
    }

    dogecoin_free(pin);

    // Retrieve the encrypted blob from the YubiKey
    if (ykpiv_fetch_object(state, SEED_DATA_TAG(file_num), encrypted_blob, &encrypted_blob_size) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to retrieve encrypted seed from YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    ykpiv_done(state); // Clean up YubiKey state after use

    // Decrypt the seed using the software decryption function
    return dogecoin_decrypt_seed_with_sw(seed, NO_FILE, test_password, encrypted_blob);
}

/**
 * @brief Encrypt a BIP-39 mnemonic with software encryption and write it to a YubiKey
 *
 * Encrypts a BIP-39 mnemonic with software encryption and writes it to a YubiKey
 *
 * @param mnemonic The mnemonic to encrypt
 * @param file_num The file number of the encrypted mnemonic
 * @param overwrite If true, overwrite the existing encrypted mnemonic
 * @param test_password The password to use for testing
 *
 * @return True if the mnemonic was successfully encrypted and written to the YubiKey, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey(dogecoin_hdnode* hdnode, const int file_num, const dogecoin_bool overwrite, const char* test_password)
{
    ENCRYPTED_BLOB encrypted_blob;
    size_t encrypted_blob_size = 0;
    dogecoin_bool result = dogecoin_generate_hdnode_encrypt_with_sw(hdnode, NO_FILE, overwrite, test_password, &encrypted_blob, &encrypted_blob_size);
    if (!result)
    {
        return false;
    }

    ykpiv_state *state = NULL;

    // Initialize and connect the YubiKey
    if (ykpiv_init(&state, true) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to initialize YubiKey.\n");
        return false;
    }
    if (ykpiv_connect(state, NULL) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to connect to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    // Prompt for the management key
    char* mgm_key = getpass("Enter YubiKey management key: \n");
    if (mgm_key == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read management key.\n");
        ykpiv_done(state);
        return false;
    }

    // Decode the management key from hex into binary
    unsigned char binary_mgm_key[24];
    size_t binary_mgm_key_len = sizeof(binary_mgm_key);
    if (ykpiv_hex_decode(mgm_key, strlen(mgm_key), binary_mgm_key, &binary_mgm_key_len) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to decode management key.\n");
        dogecoin_mem_zero(mgm_key, strlen(mgm_key));
        dogecoin_free(mgm_key);
        ykpiv_done(state);
        return false;
    }

    // Authenticate with the YubiKey using the management key
    if (ykpiv_authenticate(state, binary_mgm_key) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to authenticate with YubiKey.\n");
        dogecoin_mem_zero(mgm_key, strlen(mgm_key));
        dogecoin_mem_zero(binary_mgm_key, sizeof(binary_mgm_key));
        dogecoin_free(mgm_key);
        ykpiv_done(state);
        return false;
    }

    dogecoin_mem_zero(mgm_key, strlen(mgm_key));
    dogecoin_free(mgm_key);

    // Write the encrypted blob directly to the YubiKey using the defined tag
    if (ykpiv_save_object(state, HDNODE_DATA_TAG(file_num), encrypted_blob, encrypted_blob_size) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to save encrypted HD node to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    ykpiv_done(state); // Clean up YubiKey state after use
    return true;
}

/**
 * @brief Decrypt a BIP-39 mnemonic with software decryption from a YubiKey
 *
 * Decrypts a BIP-39 mnemonic with software decryption from a YubiKey
 *
 * @param mnemonic The decrypted mnemonic will be stored here
 * @param file_num The file number of the encrypted mnemonic
 * @param test_password The password to use for testing
 *
 * @return True if the mnemonic is decrypted successfully, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_hdnode_with_sw_from_yubikey(dogecoin_hdnode* hdnode, const int file_num, const char* test_password)
{
    ykpiv_state *state = NULL;
    ENCRYPTED_BLOB encrypted_blob;
    unsigned long encrypted_blob_size = sizeof(encrypted_blob);

    // Initialize and connect the YubiKey
    if (ykpiv_init(&state, true) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to initialize YubiKey.\n");
        return false;
    }
    if (ykpiv_connect(state, NULL) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to connect to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    // Verify the PIN to enable reading from the PIN-protected slot
    char* pin = getpass("Enter YubiKey PIN: \n");
    int tries;
    if (ykpiv_verify(state, pin, &tries) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Incorrect PIN. Tries left: %d\n", tries);
        ykpiv_done(state);
        dogecoin_free(pin);
        return false;
    }

    dogecoin_free(pin);

    // Retrieve the encrypted blob from the YubiKey
    if (ykpiv_fetch_object(state, HDNODE_DATA_TAG(file_num), encrypted_blob, &encrypted_blob_size) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to retrieve encrypted HD node from YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    ykpiv_done(state); // Clean up YubiKey state after use

    // Decrypt the HD node using the software decryption function
    return dogecoin_decrypt_hdnode_with_sw(hdnode, NO_FILE, test_password, encrypted_blob);
}

/**
 * @brief Encrypt a BIP-39 mnemonic with software encryption and write it to a YubiKey
 *
 * Encrypts a BIP-39 mnemonic with software encryption and writes it to a YubiKey
 *
 * @param mnemonic The mnemonic to encrypt
 * @param file_num The file number of the encrypted mnemonic
 * @param overwrite If true, overwrite the existing encrypted mnemonic
 * @param lang The language of the mnemonic
 * @param space The space between words in the mnemonic
 * @param words The word list for the mnemonic
 * @param test_password The password to use for testing
 *
 * @return True if the mnemonic was successfully encrypted and written to the YubiKey, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, const char* lang, const char* space, const char* words, const char* test_password)
{
    ENCRYPTED_BLOB encrypted_blob;
    size_t encrypted_blob_size = 0;
    dogecoin_bool result = dogecoin_generate_mnemonic_encrypt_with_sw(mnemonic, NO_FILE, overwrite, lang, space, words, test_password, &encrypted_blob, &encrypted_blob_size);
    if (!result)
    {
        return false;
    }

    ykpiv_state *state = NULL;

    // Initialize and connect the YubiKey
    if (ykpiv_init(&state, true) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to initialize YubiKey.\n");
        return false;
    }
    if (ykpiv_connect(state, NULL) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to connect to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    // Prompt for the management key
    char* mgm_key = getpass("Enter YubiKey management key: \n");
    if (mgm_key == NULL)
    {
        fprintf(stderr, "ERROR: Failed to read management key.\n");
        ykpiv_done(state);
        return false;
    }

    // Decode the management key from hex into binary
    unsigned char binary_mgm_key[24];
    size_t binary_mgm_key_len = sizeof(binary_mgm_key);
    if (ykpiv_hex_decode(mgm_key, strlen(mgm_key), binary_mgm_key, &binary_mgm_key_len) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to decode management key.\n");
        dogecoin_mem_zero(mgm_key, strlen(mgm_key));
        dogecoin_free(mgm_key);
        ykpiv_done(state);
        return false;
    }

    // Authenticate with the YubiKey using the management key
    if (ykpiv_authenticate(state, binary_mgm_key) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to authenticate with YubiKey.\n");
        dogecoin_mem_zero(mgm_key, strlen(mgm_key));
        dogecoin_mem_zero(binary_mgm_key, sizeof(binary_mgm_key));
        dogecoin_free(mgm_key);
        ykpiv_done(state);
        return false;
    }

    dogecoin_mem_zero(mgm_key, strlen(mgm_key));
    dogecoin_free(mgm_key);

    // Write the encrypted blob directly to the YubiKey using the defined tag
    if (ykpiv_save_object(state, MNEMONIC_DATA_TAG(file_num), encrypted_blob, encrypted_blob_size) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to save encrypted mnemonic to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    ykpiv_done(state); // Clean up YubiKey state after use
    return true;
}

/**
 * @brief Decrypt a BIP-39 mnemonic with software decryption from a YubiKey
 *
 * Decrypts a BIP-39 mnemonic with software decryption from a YubiKey
 *
 * @param mnemonic The decrypted mnemonic will be stored here
 * @param file_num The file number of the encrypted mnemonic
 * @param test_password The password to use for testing
 *
 * @return True if the mnemonic is decrypted successfully, false otherwise
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_decrypt_mnemonic_with_sw_from_yubikey(MNEMONIC mnemonic, const int file_num, const char* test_password)
{
    ykpiv_state *state = NULL;
    ENCRYPTED_BLOB encrypted_blob;
    unsigned long encrypted_blob_size = sizeof(encrypted_blob);

    // Initialize and connect the YubiKey
    if (ykpiv_init(&state, true) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to initialize YubiKey.\n");
        return false;
    }
    if (ykpiv_connect(state, NULL) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to connect to YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    // Verify the PIN to enable reading from the PIN-protected slot
    char* pin = getpass("Enter YubiKey PIN: \n");
    int tries;
    if (ykpiv_verify(state, pin, &tries) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Incorrect PIN. Tries left: %d\n", tries);
        ykpiv_done(state);
        dogecoin_free(pin);
        return false;
    }

    dogecoin_free(pin);

    // Retrieve the encrypted blob from the YubiKey
    if (ykpiv_fetch_object(state, MNEMONIC_DATA_TAG(file_num), encrypted_blob, &encrypted_blob_size) != YKPIV_OK)
    {
        fprintf(stderr, "ERROR: Failed to retrieve encrypted mnemonic from YubiKey.\n");
        ykpiv_done(state);
        return false;
    }

    ykpiv_done(state); // Clean up YubiKey state after use

    // Decrypt the mnemonic using the software decryption function
    return dogecoin_decrypt_mnemonic_with_sw(mnemonic, NO_FILE, test_password, encrypted_blob);
}

#endif
