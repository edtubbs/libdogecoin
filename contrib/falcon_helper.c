/*
 * Falcon-512 Helper Tool
 * Utility for generating keypairs, signing, verifying, and creating commitments
 * with Falcon-512 post-quantum signatures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>

static void print_usage(const char* progname) {
    printf("Falcon-512 Helper Tool\n");
    printf("Usage:\n");
    printf("  %s keygen                          - Generate keypair\n", progname);
    printf("  %s sign <sk_hex> <msg_hex>          - Sign message\n", progname);
    printf("  %s verify <pk_hex> <msg_hex> <sig_hex> - Verify signature\n", progname);
    printf("  %s commit <pk_hex> <sig_hex>        - Generate commitment\n", progname);
    printf("\nExamples:\n");
    printf("  %s keygen\n", progname);
    printf("  %s sign <sk> $(echo -n 'Hello World' | xxd -p)\n", progname);
    printf("  %s commit <pk> <sig>\n", progname);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        
        printf("Generating Falcon-512 keypair...\n");
        
        if (!dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len)) {
            fprintf(stderr, "Error: Failed to generate keypair\n");
            fprintf(stderr, "Make sure libdogecoin was built with liboqs support\n");
            return 1;
        }
        
        char* pk_hex = utils_uint8_to_hex(pk, pk_len);
        char* sk_hex = utils_uint8_to_hex(sk, sk_len);
        
        printf("\n=== Keypair Generated ===\n");
        printf("PUBLIC_KEY=%s\n", pk_hex);
        printf("SECRET_KEY=%s\n", sk_hex);
        printf("PK_LEN=%zu\n", pk_len);
        printf("SK_LEN=%zu\n", sk_len);
        printf("\n⚠️  Keep your secret key safe! Anyone with it can sign messages.\n");
        
        free(pk_hex);
        free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
        return 0;
        
    } else if (strcmp(argv[1], "sign") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for sign command\n");
            print_usage(argv[0]);
            return 1;
        }
        
        printf("Signing message with Falcon-512...\n");
        
        size_t sk_len;
        uint8_t* sk = utils_hex_to_uint8(argv[2], &sk_len);
        if (!sk) {
            fprintf(stderr, "Error: Invalid secret key hex\n");
            return 1;
        }
        
        size_t msg_len;
        uint8_t* msg = utils_hex_to_uint8(argv[3], &msg_len);
        if (!msg) {
            fprintf(stderr, "Error: Invalid message hex\n");
            free(sk);
            return 1;
        }
        
        uint8_t* sig = NULL;
        size_t sig_len = 0;
        
        if (!dogecoin_falcon512_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            fprintf(stderr, "Error: Failed to sign message\n");
            fprintf(stderr, "Check that secret key is valid and libdogecoin has liboqs support\n");
            free(sk);
            free(msg);
            return 1;
        }
        
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        
        printf("\n=== Signature Generated ===\n");
        printf("SIGNATURE=%s\n", sig_hex);
        printf("SIG_LEN=%zu\n", sig_len);
        printf("MSG_LEN=%zu\n", msg_len);
        
        free(sig_hex);
        dogecoin_free(sig);
        free(sk);
        free(msg);
        return 0;
        
    } else if (strcmp(argv[1], "verify") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: Missing arguments for verify command\n");
            print_usage(argv[0]);
            return 1;
        }
        
        printf("Verifying Falcon-512 signature...\n");
        
        size_t pk_len;
        uint8_t* pk = utils_hex_to_uint8(argv[2], &pk_len);
        if (!pk) {
            fprintf(stderr, "Error: Invalid public key hex\n");
            return 1;
        }
        
        size_t msg_len;
        uint8_t* msg = utils_hex_to_uint8(argv[3], &msg_len);
        if (!msg) {
            fprintf(stderr, "Error: Invalid message hex\n");
            free(pk);
            return 1;
        }
        
        size_t sig_len;
        uint8_t* sig = utils_hex_to_uint8(argv[4], &sig_len);
        if (!sig) {
            fprintf(stderr, "Error: Invalid signature hex\n");
            free(pk);
            free(msg);
            return 1;
        }
        
        dogecoin_bool verified = dogecoin_falcon512_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        
        printf("\n=== Verification Result ===\n");
        if (verified) {
            printf("✓ VERIFIED=true\n");
            printf("The signature is valid for this message and public key.\n");
        } else {
            printf("✗ VERIFIED=false\n");
            printf("The signature is INVALID or does not match the message/public key.\n");
        }
        
        free(pk);
        free(msg);
        free(sig);
        return verified ? 0 : 1;
        
    } else if (strcmp(argv[1], "commit") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for commit command\n");
            print_usage(argv[0]);
            return 1;
        }
        
        printf("Generating Falcon-512 commitment...\n");
        
        size_t pk_len;
        uint8_t* pk = utils_hex_to_uint8(argv[2], &pk_len);
        if (!pk) {
            fprintf(stderr, "Error: Invalid public key hex\n");
            return 1;
        }
        
        size_t sig_len;
        uint8_t* sig = utils_hex_to_uint8(argv[3], &sig_len);
        if (!sig) {
            fprintf(stderr, "Error: Invalid signature hex\n");
            free(pk);
            return 1;
        }
        
        uint8_t commit[32];
        if (!dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            fprintf(stderr, "Error: Failed to generate commitment\n");
            free(pk);
            free(sig);
            return 1;
        }
        
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        
        printf("\n=== Commitment Generated ===\n");
        printf("COMMIT=%s\n", commit_hex);
        printf("COMMIT_LEN=32\n");
        printf("\nThis 32-byte commitment can be included in an OP_RETURN output.\n");
        printf("OP_RETURN script: 6a20%s\n", commit_hex);
        
        free(pk);
        free(sig);
        return 0;
        
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
}
