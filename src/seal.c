/**
 * Copyright (c) 2023 edtubbs
 * Copyright (c) 2023 The Dogecoin Foundation
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

#include <dogecoin/base58.h>
#include <dogecoin/bip32.h>
#include <dogecoin/bip39.h>
#include <dogecoin/ecc.h>
#include <dogecoin/eckey.h>
#include <dogecoin/sha2.h>
#include <dogecoin/seal.h>
#include <dogecoin/utils.h>

#if defined (_WIN64) && !defined(__MINGW64__)
#include <windows.h>
#include <tbs.h>
#include <ncrypt.h>
#endif

#ifndef WINVER
#define WINVER 0x0600
#endif

#if defined (__linux__) && defined (USE_TSS2)
#include <unistd.h>
#include <wchar.h>
#include <tss2/tss2_esys.h>
#endif

/*
 * Defines
 */
#define RESP_RAND_OFFSET 12 // Offset to the random data in the TPM2_CC_GetRandom response

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
    if (file_num < DEFAULT_FILE || file_num > TEST_FILE)
    {
        return false;
    }
    return true;

}

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
    ESYS_CONTEXT* context = NULL;

    // Initialize TPM context
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }

    result = Esys_Startup(context, TPM2_SU_STATE);
    if (result != TPM2_RC_SUCCESS) {
        return false;
    }

    // Get the password
    char* password = getpass("Enter password for seed encryption: ");
    if (strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty.\n");
        Esys_Finalize(&context);
        return false;
    }

    // Confirm the password
    char* confirm_password = getpass("Confirm password: ");
    if (strcmp(password, confirm_password) != 0) {
        fprintf(stderr, "Error: Passwords do not match.\n");
        Esys_Finalize(&context);
        return false;
    }

    // Now, create the primary key
    ESYS_TR keyHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC* outPublic = NULL;
    TPM2B_CREATION_DATA* creationData = NULL;
    TPM2B_DIGEST* creationHash = NULL;
    TPMT_TK_CREATION* creationTicket = NULL;
    TPM2B_PUBLIC_KEY_RSA* cipher = NULL;
    TPM2B_DATA* null_data = NULL;

    TPM2B_AUTH authValuePrimary;
    authValuePrimary.size = strlen(password);
    if (authValuePrimary.size > sizeof(authValuePrimary.buffer)) {
        fprintf(stderr, "Error: Password is too long.\n");
        Esys_Finalize(&context);
        return false;
    }
    memcpy(authValuePrimary.buffer, password, authValuePrimary.size);

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0},
            },
            .data = {
                .size = 0,
                .buffer = {0},
            },
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
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL},
                .scheme = { .scheme = TPM2_ALG_RSAES },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            },
        },
    };

    // Create the RSA key
    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    result = Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &authValue);
    if (result != TSS2_RC_SUCCESS) {
        // Handle any errors during finishing here
        Esys_Finalize(&context);
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
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);

        Esys_Finalize(&context);
        return false;
    }

    // Combine keyHandle with file_num to create the filename
    char filename[100];
    sprintf(filename, "encrypted_seed_%d", file_num);

    // Set the session for the decryption operation using the owner
    result = Esys_TR_SetAuth(context, keyHandle, &authValuePrimary);
    if (result != TSS2_RC_SUCCESS) {
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);

        Esys_Finalize(&context);
        return false;
    }

    ESYS_TR persistentHandle = ESYS_TR_NONE;  // Persistent handle for the key

    // Attempt to make the key persistent
    result = Esys_EvictControl(context,
        ESYS_TR_RH_OWNER,
        keyHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_PERSISTENT_FIRST,
        &persistentHandle);

    if (result != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_EvictControl failed with error code 0x%X\n", result);
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);

        Esys_Finalize(&context);
        return false;
    }

    size_t plain_size = size;
    TPM2B_PUBLIC_KEY_RSA plain;
    if (plain_size > sizeof(plain.buffer)) {
        fprintf(stderr, "Error: Seed size too large.\n");
        Esys_Finalize(&context);
        return false;
    }
    plain.size = plain_size;
    memcpy(plain.buffer, seed, plain_size);

    TPMT_RSA_DECRYPT scheme = {
        .scheme = TPM2_ALG_RSAES
    };

    // Declare variables for encrypted data
    uint8_t encrypted_seed[256];  // Adjust the size according to your needs
    size_t encrypted_size = sizeof(encrypted_seed);

    // Perform RSA encryption using TPM
    result = Esys_RSA_Encrypt(context,
                              persistentHandle,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &plain,
                              &scheme,
                              NULL, // No label in this case
                              &cipher);

    if (result != TSS2_RC_SUCCESS) {
        Esys_FlushContext(context, keyHandle);
        Esys_Finalize(&context);
        return false;
    }

    // Store encrypted data and context blob in a file
    FILE* fp = fopen(filename, overwrite ? "wb+" : "wb");
    if (!fp) {
        Esys_FlushContext(context, keyHandle);
        Esys_Finalize(&context);
        return false;
    }

    // Write the keyHandle as a header to the file
    size_t bytes_written = fwrite(&persistentHandle, 1, sizeof(persistentHandle), fp);

    // Serialize the context data for writing
    TPMS_CONTEXT* contextData = NULL;
    result = Esys_ContextSave(context, persistentHandle, &contextData);
    if (result != TSS2_RC_SUCCESS) {
        fclose(fp);
        Esys_FlushContext(context, keyHandle);
        Esys_Finalize(&context);
        return false;
    }

    // Write the context data fields to the file individually
    bytes_written = fwrite(&(contextData->sequence), 1, sizeof(contextData->sequence), fp);
    bytes_written = fwrite(&(contextData->savedHandle), 1, sizeof(contextData->savedHandle), fp);
    bytes_written = fwrite(&(contextData->hierarchy), 1, sizeof(contextData->hierarchy), fp);
    bytes_written = fwrite(&(contextData->contextBlob.size), 1, sizeof(contextData->contextBlob.size), fp);
    bytes_written = fwrite(contextData->contextBlob.buffer, 1, contextData->contextBlob.size, fp);

    // Write the encrypted seed to the file
    bytes_written = fwrite(cipher->buffer, 1, cipher->size, fp);

    // Close the file
    fclose(fp);

    // Clean up
    Esys_FlushContext(context, keyHandle);
    Esys_Finalize(&context);

    return true;

#elif defined (_WIN64) && !defined(__MINGW64__)

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
    DWORD dwFlags = 0; // Use NCRYPT_MACHINE_KEY_FLAG for machine-level keys or 0 for user-level keys

    // Format the name of the encrypted seed object
    wchar_t* name = SEED_OBJECT_NAME_FORMAT;
    swprintf(name, (wcslen(name) + 1) * sizeof(wchar_t), SEED_OBJECT_NAME_FORMAT, file_num);

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

    // Successfully encrypted the seed
    // Create a file with the encrypted seed
    // Open the file for binary write, "wb+" to overwrite if exists
    FILE* fp = _wfopen(name, overwrite ? L"wb+" : L"wb");
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
    ESYS_CONTEXT* context = NULL;

    // Initialize TPM context
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        return false;
    }

    result = Esys_Startup(context, TPM2_SU_STATE);
    if (result != TPM2_RC_SUCCESS) {
        return false;
    }

    // Format the filename to include the file_num
    char filename[100];
    snprintf(filename, sizeof(filename), "encrypted_seed_%d", file_num);

    // Open the existing encryption key
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        Esys_Finalize(&context);
        return false;
    }

    // Read the keyHandle from the file
    ESYS_TR keyHandle;
    size_t keyHandleSize = sizeof(keyHandle);
    size_t bytesRead = fread(&keyHandle, 1, keyHandleSize, fp);
    if (bytesRead != keyHandleSize) {
        fclose(fp);
        Esys_Finalize(&context);
        return false;
    }

    // Read the context data fields from the file individually
    TPMS_CONTEXT* contextData = (TPMS_CONTEXT*)malloc(sizeof(TPMS_CONTEXT));
    if (!contextData) {
        fclose(fp);
        Esys_Finalize(&context);
        return false;
    }
    memset(contextData, 0, sizeof(TPMS_CONTEXT));
    bytesRead = fread(&(contextData->sequence), 1, sizeof(contextData->sequence), fp);
    bytesRead = fread(&(contextData->savedHandle), 1, sizeof(contextData->savedHandle), fp);
    bytesRead = fread(&(contextData->hierarchy), 1, sizeof(contextData->hierarchy), fp);
    bytesRead = fread(&(contextData->contextBlob.size), 1, sizeof(contextData->contextBlob.size), fp);

    if (bytesRead != sizeof(contextData->contextBlob.size)) {
        fclose(fp);
        free(contextData); // Free allocated memory
        Esys_Finalize(&context);
        return false;
    }

    // Read the contextBlob.buffer
    bytesRead = fread(contextData->contextBlob.buffer, 1, contextData->contextBlob.size, fp);
    if (bytesRead != contextData->contextBlob.size) {
        fclose(fp);
        free(contextData); // Free allocated memory
        Esys_Finalize(&context);
        return false;
    }

    // Load the context data
    result = Esys_ContextLoad(context, contextData, &keyHandle);
    if (result != TSS2_RC_SUCCESS) {
        fclose(fp);
        free(contextData); // Free allocated memory
        Esys_Finalize(&context);
        return false;
    }

    // Declare variables for encrypted data
    uint8_t encrypted_seed[256];  // Adjust the size according to your needs
    size_t encrypted_size = sizeof(encrypted_seed);

    // Read the encrypted data from the file
    bytesRead = fread(encrypted_seed, 1, encrypted_size, fp);
    if (bytesRead != encrypted_size) {
        fclose(fp);
        Esys_Finalize(&context);
        return false;
    }

    // Close the file as we have obtained the keyHandle and context data
    fclose(fp);

    // Prompt for the password
    char* password = getpass("Enter password for seed decryption: ");

    // Use the obtained password and keyHandle for TPM decryption
    TPM2B_AUTH authValue;
    authValue.size = strlen(password);
    if (authValue.size > sizeof(authValue.buffer)) {
        fprintf(stderr, "Error: Password is too long.\n");
        Esys_Finalize(&context);
        return false;
    }
    memcpy(authValue.buffer, password, authValue.size);

    // Define authValuePrimary for ESYS_TR_RH_OWNER
    TPM2B_AUTH authValuePrimary;
    authValuePrimary.size = 0;

    // Set the session for the decryption operation using the owner
    result = Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &authValuePrimary);
    if (result != TSS2_RC_SUCCESS) {
        Esys_Finalize(&context);
        return false;
    }

    // Set the session for the decryption operation using the keyHandle
    result = Esys_TR_SetAuth(context, keyHandle, &authValue);
    if (result != TSS2_RC_SUCCESS) {
        Esys_Finalize(&context);
        return false;
    }

    // Declare variables for decrypted data
    TPMT_RSA_DECRYPT scheme = {
        .scheme = TPM2_ALG_RSAES
    };
    TPM2B_PUBLIC_KEY_RSA cipher = {
        .size = encrypted_size,
        .buffer = {0},
    };

    // Write the encrypted data to the cipher buffer
    memcpy(cipher.buffer, encrypted_seed, encrypted_size);

    TPM2B_DATA label = { .size = 0 };  // No label in this case
    TPM2B_PUBLIC_KEY_RSA* plain = (TPM2B_PUBLIC_KEY_RSA*)malloc(sizeof(TPM2B_PUBLIC_KEY_RSA));
    if (!plain) {
        Esys_Finalize(&context);
        return false;
    }

    // Decrypt the encrypted data using TPM
    result = Esys_RSA_Decrypt(context, keyHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &cipher, &scheme, &label, &plain);
    if (result != TSS2_RC_SUCCESS) {
        free(plain);
        Esys_Finalize(&context);
        return false;
    }

    // Copy the decrypted data to the output seed
    if (plain->size <= MAX_SEED_SIZE) {
        memcpy(seed, plain->buffer, plain->size);
    } else {
        free(plain);
        Esys_Finalize(&context);
        return false;
    }

    // Clean up
    free(plain);
    Esys_Finalize(&context);

    return true;

#elif defined (_WIN64) && !defined(__MINGW64__)

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
    wchar_t* name = SEED_OBJECT_NAME_FORMAT;
    swprintf(name, (wcslen(name) + 1) * sizeof(wchar_t), SEED_OBJECT_NAME_FORMAT, file_num);

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
    FILE* fp = _wfopen(name, L"rb");
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
        free(pbOutput);
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
        free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);

        return false;
    }

    // Free the output buffer, encryption key handle, and close the TPM storage provider
    free(pbOutput);
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;
#else
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
#if defined (_WIN64) && !defined(__MINGW64__)

    // Validate the input parameters
    if (!fileValid(file_num)) {
        fprintf(stderr, "ERROR: Invalid file number\n");
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
    wchar_t* name = HDNODE_OBJECT_NAME_FORMAT;
    swprintf(name, (wcslen(name) + 1) * sizeof(wchar_t), HDNODE_OBJECT_NAME_FORMAT, file_num);

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
        free(pbResult);
        return false;
    }

    // Successfully encrypted the HD node with the encryption key
    // Create a file with the encrypted HD node
    // Open the file for binary write, "wb+" to overwrite if exists
    FILE* fp = _wfopen(name, overwrite ? L"wb+" : L"wb");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open file for writing\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        free(pbResult);
        return false;
    }

    // Write the encrypted HD node to the file
    size_t bytesWritten = fwrite(pbResult, 1, cbResult, fp);
    if (bytesWritten != cbResult)
    {
        fprintf(stderr, "ERROR: Failed to write encrypted hdnode to file\n");
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        free(pbResult);
        fclose(fp);
        return false;
    }

    // Close the file
    fclose(fp);

    // Free the memory for the encrypted HD node
    free(pbResult);

    // Free the encryption key and provider
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;

#else
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
#if defined (_WIN64) && !defined(__MINGW64__)

    // Validate the input parameters
    if (out == NULL) {
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
    wchar_t* name = HDNODE_OBJECT_NAME_FORMAT;
    swprintf(name, (wcslen(name) + 1) * sizeof(wchar_t), HDNODE_OBJECT_NAME_FORMAT, file_num);

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
    FILE* fp = _wfopen(name, L"rb");
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
        free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Decrypt the encrypted data
    status = NCryptDecrypt(hEncryptionKey, pbOutput, bytesRead, NULL, (PBYTE)out, (DWORD)cbResult, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        // Failed to decrypt the encrypted data
        fprintf(stderr, "ERROR: Failed to decrypt the encrypted data (0x%08x)\n", status);
        free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Free memory and close handles
    free(pbOutput);
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;

#else
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
#if defined (_WIN64) && !defined(__MINGW64__)

    // Validate the input parameters
    if (mnemonic == NULL) {
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
    DWORD cbOutput = 0;
    DWORD dwFlags = 0; // Use NCRYPT_MACHINE_KEY_FLAG for machine-level keys or 0 for user-level keys

    // Format the name of the mnemonic
    wchar_t* name = MNEMONIC_OBJECT_NAME_FORMAT;
    swprintf(name, (wcslen(name) + 1) * sizeof(wchar_t), MNEMONIC_OBJECT_NAME_FORMAT, file_num);

    // Create TBS context (TPM2)
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
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

    // Successfully encrypted the mnemonic
    // Create a file with the encrypted mnemonic
    // Open the file for binary write, "wb+" to overwrite if exists
    FILE* fp = _wfopen(name, overwrite ? L"wb+" : L"wb");
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
    free(pbOutput);

    // Free the encryption key and provider
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;
#else
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
#if defined (_WIN64) && !defined(__MINGW64__)

    // Validate the input parameters
    if (mnemonic == NULL) {
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
    wchar_t* name = MNEMONIC_OBJECT_NAME_FORMAT;
    swprintf(name, (wcslen(name) + 1) * sizeof(wchar_t), MNEMONIC_OBJECT_NAME_FORMAT, file_num);

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
    FILE* fp = _wfopen(name, L"rb");
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
        free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Decrypt the encrypted data
    status = NCryptDecrypt(hEncryptionKey, pbOutput, bytesRead, NULL, (PBYTE)mnemonic, sizeof(MNEMONIC), &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    if (status != ERROR_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to decrypt the encrypted data (0x%08x)\n", status);
        free(pbOutput);
        NCryptFreeObject(hEncryptionKey);
        NCryptFreeObject(hProvider);
        return false;
    }

    // Free the output buffer, encryption key handle, and close the TPM storage provider
    free(pbOutput);
    NCryptFreeObject(hEncryptionKey);
    NCryptFreeObject(hProvider);

    return true;
#else
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
#if defined (_WIN64) && !defined(__MINGW64__)

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
    // Validate the input parameters
    if (!fileValid(file_num)) {
        fprintf(stderr, "ERROR: Invalid file number\n");
        return false;
    }

    // Generate an English mnemonic with the TPM
    return dogecoin_generate_mnemonic_encrypt_with_tpm(mnemonic, file_num, overwrite, "eng", " ", NULL);
}
