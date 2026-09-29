/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include "testutil.h"

static int is_fips;
static int bad_fips;

static int test_is_fips_enabled(void)
{
    int is_fips_enabled, is_fips_loaded;
    EVP_MD *sha256 = NULL;

    /*
     * Check we're in FIPS mode when we're supposed to be. We do this early to
     * confirm that EVP_default_properties_is_fips_enabled() works even before
     * other function calls have auto-loaded the config file.
     */
    is_fips_enabled = EVP_default_properties_is_fips_enabled(NULL);
    is_fips_loaded = OSSL_PROVIDER_available(NULL, "fips");

    /*
     * Check we're in an expected state. EVP_default_properties_is_fips_enabled
     * can return true even if the FIPS provider isn't loaded - it is only based
     * on the default properties. However we only set those properties if also
     * loading the FIPS provider.
     */
    if (!TEST_int_eq(is_fips || bad_fips, is_fips_enabled)
        || !TEST_int_eq(is_fips && !bad_fips, is_fips_loaded))
        return 0;

    /*
     * Fetching an algorithm shouldn't change the state and should come from
     * expected provider.
     */
    sha256 = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    if (bad_fips) {
        if (!TEST_ptr_null(sha256)) {
            EVP_MD_free(sha256);
            return 0;
        }
    } else {
        if (!TEST_ptr(sha256))
            return 0;
        if (is_fips
            && !TEST_str_eq(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(sha256)),
                "fips")) {
            EVP_MD_free(sha256);
            return 0;
        }
        EVP_MD_free(sha256);
    }

    /* State should still be consistent */
    is_fips_enabled = EVP_default_properties_is_fips_enabled(NULL);
    if (!TEST_int_eq(is_fips || bad_fips, is_fips_enabled))
        return 0;

    return 1;
}

#ifndef OPENSSL_NO_ML_KEM
/* Fetch |name| as a KEM, requiring the fips provider and the given approval. */
static int kem_fips_approval(const char *name, int approved)
{
    EVP_KEM *yes = EVP_KEM_fetch(NULL, name, "fips=yes");
    EVP_KEM *no = EVP_KEM_fetch(NULL, name, "fips=no");
    int ret = 1;

    if (approved) {
        /* Must be available as an approved (fips=yes) algorithm. */
        if (!TEST_ptr(yes))
            ret = 0;
    } else {
        /*
         * Must be marked non-approved: not selectable under fips=yes, but
         * still available under fips=no (marked, not removed).
         */
        if (!TEST_ptr_null(yes) || !TEST_ptr(no))
            ret = 0;
    }
    EVP_KEM_free(yes);
    EVP_KEM_free(no);
    return ret;
}

/*
 * The hybrid ML-KEM KEMs only concatenate the component shared secrets and do
 * not apply an approved KDF.  Per FIPS 140-3 IG D.S additional comment 8.a the
 * NIST-curve (SecP*) hybrids and X25519MLKEM768 are approved, but X448MLKEM1024
 * is not and must be non-approved.
 */
static int test_mlx_kem_fips_approval(void)
{
    if (!is_fips || bad_fips)
        return 1; /* Only meaningful with the FIPS module loaded. */

# ifndef OPENSSL_NO_ECX
    if (!kem_fips_approval("X25519MLKEM768", 1)
        || !kem_fips_approval("X448MLKEM1024", 0))
        return 0;
# endif
# ifndef OPENSSL_NO_EC
    if (!kem_fips_approval("SecP256r1MLKEM768", 1)
        || !kem_fips_approval("SecP384r1MLKEM1024", 1))
        return 0;
# endif
    return 1;
}
#endif /* OPENSSL_NO_ML_KEM */

int setup_tests(void)
{
    size_t argc;
    char *arg1;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    argc = test_get_argument_count();
    switch (argc) {
    case 0:
        is_fips = 0;
        bad_fips = 0;
        break;
    case 1:
        arg1 = test_get_argument(0);
        if (strcmp(arg1, "fips") == 0) {
            is_fips = 1;
            bad_fips = 0;
            break;
        } else if (strcmp(arg1, "badfips") == 0) {
            /* Configured for FIPS, but the module fails to load */
            is_fips = 0;
            bad_fips = 1;
            break;
        }
        /* fall through */
    default:
        TEST_error("Invalid argument\n");
        return 0;
    }

    /* Must be the first test before any other libcrypto calls are made */
    ADD_TEST(test_is_fips_enabled);
#ifndef OPENSSL_NO_ML_KEM
    ADD_TEST(test_mlx_kem_fips_approval);
#endif
    return 1;
}
