#include <openssl/evp.h>
#include <openssl/fips_sli.h>
#include <openssl/kdf.h>
#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_EC is defined */
#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/rand.h>

#include "testutil.h"
#include "fips_slitest_helper.h"

static int test_sli_noop(void) {
    int res = 0; /* 0 means test failure    */
    EVP_MD_CTX* ctx = NULL;
    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto end;
    if (!TEST_true(fips_sli_is_approved_EVP_MD_CTX(ctx)))
        goto end;
    if (!TEST_false(fips_sli_is_approved_EVP_MD_CTX(NULL)))
        goto end;
    res = 1; /* test case successful */
end:
    EVP_MD_CTX_free(ctx);
    return res;
}

static int cmac_aes_cbc(void) {
    int success = 0;
    CMAC_CTX *ctx = NULL;
    size_t maclen = 0;

    if (!TEST_ptr(ctx = CMAC_CTX_new()))
        return 0;
    if (!TEST_true(CMAC_Init(ctx, get_key_16(), 16, EVP_aes_128_cbc(), NULL))
            || !TEST_true(CMAC_Final(ctx, NULL, &maclen))
       ) {
        CMAC_CTX_free(ctx);
        return 0;
    }

    uint8_t mac[maclen];

    if (!TEST_true(maclen > 0)
            || !TEST_true(CMAC_Update(ctx, get_msg_16(), 16))
            || !TEST_true(CMAC_Final(ctx, mac, &maclen))
            || !TEST_true(fips_sli_is_approved_CMAC_CTX(ctx))
       )
        goto end;
    success = 1;
end:
    CMAC_CTX_free(ctx);
    return success;
}

static int cmac_no_des(void) {
    int success = 0;
    CMAC_CTX *ctx = NULL;
    size_t maclen = 0;

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        TEST_note("Skipping test because DES is disabled in FIPS mode");
        return 1;
    }
#endif

    if (!TEST_ptr(ctx = CMAC_CTX_new()))
        return 0;
    if (!TEST_true(CMAC_Init(ctx, get_key_16(), 16, EVP_des_ede_cbc(), NULL))
            || !TEST_true(CMAC_Final(ctx, NULL, &maclen))
       ) {
        CMAC_CTX_free(ctx);
        return 0;
    }

    uint8_t mac[maclen];

    if (!TEST_true(maclen > 0)
            || !TEST_int_eq(16, EVP_CIPHER_key_length(EVP_des_ede_cbc()))
            || !TEST_true(CMAC_Update(ctx, get_msg_16(), 16))
            || !TEST_true(CMAC_Final(ctx, mac, &maclen))
            || !TEST_false(fips_sli_is_approved_CMAC_CTX(ctx))
       )
        goto end;
    success = 1;
end:
    CMAC_CTX_free(ctx);
    return success;
}

typedef struct {
    int fips_approved;
    int cipher_nid;
} SLI_CMAC_TEST;

static const SLI_CMAC_TEST cmac_tests[] = {
    // Cipher must fit to key length of 32 B
    {1, NID_aes_256_cbc},
    {0, NID_camellia_256_cbc},
};
static const size_t cmac_tests_len = sizeof(cmac_tests) / sizeof(cmac_tests[0]);

static int cmac_via_md_ctx(int cmac_test_index) {
    int success = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD* md = NULL;
    unsigned char* mac = NULL;
    size_t maclen = 0;

    EVP_PKEY *key = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode()
            && cmac_tests[cmac_test_index].cipher_nid == NID_camellia_256_cbc) {
        TEST_note("Skipping test because Camellia is disabled in FIPS mode");
        success = 1;
        goto end;
    }
#endif

    if (!TEST_true(get_cmac_key(cmac_tests[cmac_test_index].cipher_nid,
                                &key) == 1))
        goto end;
    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto end;
    // hash doesn't matter here but must be present...
    if (!TEST_true(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)))
        goto end;
    if (!TEST_true(EVP_DigestSignInit(ctx, NULL, md, NULL, key)))
        goto end;
    if (!TEST_true(EVP_DigestSignUpdate(ctx, get_msg_16(), 16)))
        goto end;
    size_t req = 0;
    if (!TEST_true(EVP_DigestSignFinal(ctx, NULL, &req)))
        goto end;
    if (!TEST_true(req > 0))
        goto end;
    if (!TEST_ptr(mac = OPENSSL_malloc(req)))
        goto end;
    maclen = req;
    if (!TEST_true(EVP_DigestSignFinal(ctx, mac, &maclen)))
        goto end;
    if (cmac_tests[cmac_test_index].fips_approved) {
        if (!TEST_true(fips_sli_is_approved_EVP_MD_CTX(ctx)))
            goto end;
    } else {
        if (!TEST_false(fips_sli_is_approved_EVP_MD_CTX(ctx)))
            goto end;
    }

    success = 1;
end:
    if (mac)
        OPENSSL_free(mac);
    EVP_MD_CTX_free(ctx);
    return success;
}

#ifndef OPENSSL_NO_EC
typedef struct {
    int fips_approved;
    int curve_nid;
} SLI_ECDSA_TEST;

static const SLI_ECDSA_TEST ecdsa_tests[] = {
    {0, NID_secp112r2},
    {1, NID_secp521r1},
#ifndef OPENSSL_NO_EC2M
    {0, NID_sect163r1},
#endif
    {0, NID_brainpoolP512r1},
};
static const size_t ecdsa_tests_len = sizeof(ecdsa_tests) / sizeof(ecdsa_tests[0]);

/* Adapted from openssl/test/ecdsatest.c */
static int ecdsa_via_EVP_DigestSign(int ecdsa_test_index) {
    unsigned char *sig = NULL;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    size_t sig_len;
    const int nid = ecdsa_tests[ecdsa_test_index].curve_nid;
    int success = 0;
    const uint8_t* tbs = get_msg_128();

    TEST_note("testing ECDSA for curve %s", OBJ_nid2sn(nid));

    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
            || !TEST_ptr(eckey = EC_KEY_new_by_curve_name(nid))
            || !TEST_true(EC_KEY_generate_key(eckey))
            || !TEST_ptr(pkey = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_assign_EC_KEY(pkey, eckey)))
        goto err;

    sig_len = ECDSA_size(eckey);

    if (!TEST_ptr(sig = OPENSSL_malloc(sig_len))
            /* create a signature */
            || !TEST_true(EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey))
            || !TEST_true(EVP_DigestSign(mctx, sig, &sig_len, tbs, sizeof(tbs)))
            || !TEST_int_le(sig_len, ECDSA_size(eckey)))
        goto err;

    // SLI shows proper status for sign()
    if (ecdsa_tests[ecdsa_test_index].fips_approved) {
        if (!TEST_true(fips_sli_is_approved_EVP_MD_CTX(mctx)))
            goto err;
    } else {
        if (!TEST_false(fips_sli_is_approved_EVP_MD_CTX(mctx)))
            goto err;
    }

    /* positive test, verify with correct key, 1 return */
    if (!TEST_true(EVP_MD_CTX_reset(mctx))
            || !TEST_true(EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey)))
        goto err;

    /* a resetted and initialised ctx should be okay again */
    if (!TEST_true(fips_sli_is_approved_EVP_MD_CTX(mctx)))
        goto err;

    if (!TEST_int_eq(EVP_DigestVerify(mctx, sig, sig_len, tbs, sizeof(tbs)), 1))
        goto err;

    // SLI shows proper status for verify()
    if (ecdsa_tests[ecdsa_test_index].fips_approved) {
        if (!TEST_true(fips_sli_is_approved_EVP_MD_CTX(mctx)))
            goto err;
    } else {
        if (!TEST_false(fips_sli_is_approved_EVP_MD_CTX(mctx)))
            goto err;
    }

    success = 1;
err:
    EVP_PKEY_free(pkey);
    if (mctx != NULL)
        EVP_MD_CTX_free(mctx);
    if (sig != NULL)
        OPENSSL_free(sig);
    return success;
}
#endif

typedef struct {
    int fips_approved;
    int cipher_nid;
} SLI_CIPHER_TEST;

static const SLI_CIPHER_TEST cipher_tests[] = {
    {1, NID_aes_128_cfb128},
    {1, NID_aes_256_gcm},
    {0, NID_des_ede3_cbc},
    {0, NID_des_ede3_cfb8},
    {0, NID_des_ofb64},
    {0, NID_des_ede_ecb},
    {0, NID_des_ede_ofb64},
    {0, NID_idea_cbc},
    {1, NID_aes_128_xts},
    {1, NID_aes_256_xts},
};
static const size_t cipher_tests_len = sizeof(cipher_tests) / sizeof(cipher_tests[0]);

static size_t get_ciphertext_len(size_t plaintextlen, const EVP_CIPHER *cipher) {
    /* maximum value according to manpage */
    return plaintextlen + EVP_CIPHER_block_size(cipher);
}

static int cipher(int cipher_test_index) {
    int success = 0;
    unsigned char *key = NULL, *iv = NULL, *ctext = NULL;
    int ctext_written_len = 0;
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t* const ptext = get_msg_16();
    const size_t ptext_len = 16;
    const int cipher_nid = cipher_tests[cipher_test_index].cipher_nid;

    TEST_note("testing SLI for cipher %s", OBJ_nid2sn(cipher_nid));

#ifdef OPENSSL_NO_IDEA
    switch (cipher_nid) {
    case NID_idea_cbc:
        TEST_note("Skipping test since IDEA is not supported in this build");
        success = 1;
        goto end;
    }
#endif

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        switch (cipher_nid) {
        case NID_des_ofb64:
        case NID_des_ede_ecb:
        case NID_des_ede_ofb64:
        case NID_idea_cbc:
            TEST_note("Skipping test since DES/IDEA are disabled in FIPS mode");
            success = 1;
            goto end;
        }
    }
#endif

    if (!TEST_ptr(cipher = EVP_get_cipherbynid(cipher_nid))) {
        goto end;
    }

    const size_t key_len = EVP_CIPHER_key_length(cipher);
    const size_t iv_len = EVP_CIPHER_iv_length(cipher);
    TEST_note("have keylen = %zd, ivlen = %zd", key_len, iv_len);

    if (!TEST_ptr(key = OPENSSL_malloc(key_len))
            || !TEST_ptr(ctext = OPENSSL_malloc(get_ciphertext_len(ptext_len, cipher)))
            || !TEST_true(RAND_bytes(key, key_len) == 1))
        goto end;

    if (iv_len != 0) {
        if (!TEST_ptr(iv = OPENSSL_malloc(iv_len))
                || !TEST_true(RAND_bytes(iv, iv_len) == 1))
            goto end;
    }

    int tmp_len = 0;
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) == 1)
            || !TEST_true(EVP_EncryptUpdate(ctx, ctext, &ctext_written_len, ptext, ptext_len) == 1)
            || !TEST_true(ctext_written_len <= get_ciphertext_len(ptext_len, cipher))
            || !TEST_true(EVP_EncryptFinal_ex(ctx, ctext + ctext_written_len, &tmp_len) == 1))
        goto end;

    if (!TEST_true(ctext_written_len + tmp_len <= get_ciphertext_len(ptext_len, cipher)))
        goto end;

    if (cipher_tests[cipher_test_index].fips_approved) {
        if (!TEST_true(fips_sli_is_approved_EVP_CIPHER_CTX(ctx)))
            goto end;
    } else {
        if (!TEST_false(fips_sli_is_approved_EVP_CIPHER_CTX(ctx)))
            goto end;
    }

    success = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    if (key != NULL)
        OPENSSL_free(key);
    if (iv != NULL)
        OPENSSL_free(iv);
    if (ctext != NULL)
        OPENSSL_free(ctext);
    return success;
}

#ifndef OPENSSL_NO_RSA
typedef struct {
    int fips_approved;
    int cipher_nid;
    uint8_t rsa_key_id;
} SLI_SEALENV_TEST;

static const SLI_SEALENV_TEST sealenv_tests[] = {
    // consider RSA enc/dec as always disapproved
    {0, NID_aes_128_cfb128, 0},
    {0, NID_aes_256_gcm, 1},
    {0, NID_idea_cbc, 0},
    {0, NID_des_ede3_cbc, 2},
    {0, NID_aes_128_ecb, 0},
    {0, NID_aes_128_ecb, 3},
    {0, NID_aes_128_ccm, 3},
};
static const size_t sealenv_tests_len = sizeof(sealenv_tests) / sizeof(sealenv_tests[0]);

/* Asymmetric enc/dec */
static int sealenv(int sealenv_test_index) {
    int success = 0;
    RSA *rsa_pkey = RSA_new();
    EVP_PKEY *pkey = NULL;
    const EVP_CIPHER *cipher = NULL;
    const int cipher_nid = sealenv_tests[sealenv_test_index].cipher_nid;
    EVP_CIPHER_CTX *ctx = NULL;

    uint8_t* enc_sym_key = NULL;
    int enc_sym_key_len = 0;

    const uint8_t* const ptext = get_msg_128();
    const size_t ptext_len = 128;
    unsigned char *iv = NULL, *ctext = NULL;
    size_t ctext_len = 0;
    int ctext_written_len = 0;

    switch (sealenv_tests[sealenv_test_index].rsa_key_id) {
    case 0:
        get_rsa_key1(rsa_pkey);
        break;
    case 1:
        get_rsa_key2(rsa_pkey);
        break;
    case 2:
        get_rsa_key3(rsa_pkey);
        break;
    case 3:
        if (!TEST_int_eq(256, get_rsa_key2048p3(rsa_pkey)))
            goto end;
        break;
    default:
        goto end;
    }

    TEST_note("RSA enc with key #%d, cipher %s",
              sealenv_tests[sealenv_test_index].rsa_key_id,
              OBJ_nid2sn(cipher_nid));

#ifdef OPENSSL_NO_IDEA
    switch (cipher_nid) {
    case NID_idea_cbc:
        TEST_note("Skipping test since IDEA is not supported in this build");
        success = 1;
        goto end;
    }
#endif

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        switch (cipher_nid) {
        case NID_idea_cbc:
            TEST_note("Skipping test since IDEA is disabled in FIPS mode");
            success = 1;
            goto end;
        }
    }
#endif

    if (!TEST_ptr(pkey = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_assign_RSA(pkey, rsa_pkey))
            || !TEST_ptr(cipher = EVP_get_cipherbynid(cipher_nid))
            || !TEST_ptr(enc_sym_key = OPENSSL_malloc(EVP_PKEY_size(pkey)))
            || !TEST_ptr(ctext = OPENSSL_malloc(get_ciphertext_len(ptext_len, cipher)))
       )
        goto end;

    const size_t iv_len = EVP_CIPHER_iv_length(cipher);
    if (iv_len != 0) {
        if (!TEST_ptr(iv = OPENSSL_malloc(iv_len)))
            goto end;
    }

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_true(1 == EVP_SealInit(ctx, cipher, &enc_sym_key, &enc_sym_key_len, iv, &pkey, 1))
            || !TEST_true(enc_sym_key_len > 0 && enc_sym_key_len <= EVP_PKEY_size(pkey))
            || !TEST_true(1 == EVP_SealUpdate(ctx, ctext, &ctext_written_len, ptext, ptext_len))
       )
        goto end;
    ctext_len += ctext_written_len;
    if (!TEST_true(1 == EVP_SealFinal(ctx, ctext + ctext_len, &ctext_written_len)))
        goto end;
    ctext_len += ctext_written_len;
    if (!TEST_true(ctext_len <= get_ciphertext_len(ptext_len, cipher)))
        goto end;

    if (sealenv_tests[sealenv_test_index].fips_approved) {
        if (!TEST_true(fips_sli_is_approved_EVP_CIPHER_CTX(ctx)))
            goto end;
    } else {
        if (!TEST_false(fips_sli_is_approved_EVP_CIPHER_CTX(ctx)))
            goto end;
    }

    success = 1;
end:
    EVP_PKEY_free(pkey); /* also frees rsa_pkey */
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (enc_sym_key != NULL)
        OPENSSL_free(enc_sym_key);
    if (iv != NULL)
        OPENSSL_free(iv);
    if (ctext != NULL)
        OPENSSL_free(ctext);
    return success;
}
#endif

typedef struct {
    int fips_approved;
    int iterations;
    int nid_digest;
    const uint8_t key_expected[32]; // length has to be 32
} SLI_PBKDF2_TEST;

static const SLI_PBKDF2_TEST pbkdf2_tests[] = {
    {
        1, 4200, NID_sha256, {
            0xE7, 0xBE, 0x37, 0x75, 0x9D, 0x53, 0x3E, 0x5A, 0x06, 0x20, 0xC9, 0xA5, 0x3A, 0x8D, 0xA2, 0x9E,
            0x9C, 0x27, 0xDF, 0x26, 0x24, 0xAB, 0xD8, 0x8E, 0x56, 0xE5, 0xB9, 0xF5, 0xA0, 0xD6, 0xD5, 0xEE
        }
    },
    {
        1, 1347, NID_sha256, {
            0xFB, 0xBB, 0xEC, 0x28, 0x5B, 0x48, 0xE7, 0xC2, 0x54, 0x4E, 0x65, 0x0F, 0x1E, 0xC8, 0xB5, 0x1C,
            0xF5, 0xAD, 0xAE, 0x2A, 0x21, 0x56, 0x94, 0xD2, 0xE1, 0xB7, 0xC8, 0x7D, 0x7A, 0x0D, 0x63, 0x86
        }
    },
    {
        1, 4200, NID_sha1, {
            0x45, 0x96, 0x78, 0xF3, 0x92, 0x74, 0xAC, 0x5B, 0x1F, 0x2B, 0xD3, 0x75, 0x1A, 0xBA, 0x5D, 0xBE,
            0xF2, 0xDE, 0xE9, 0x88, 0x16, 0x4B, 0x0B, 0x84, 0x94, 0xD9, 0xC2, 0x2D, 0xC1, 0xB9, 0xB0, 0x8A
        }
    },
    {
        1, 4200, NID_sha3_512, {
            0x1E, 0x77, 0xC8, 0x28, 0x9A, 0x79, 0x2E, 0x25, 0x85, 0x8D, 0x73, 0xB3, 0x0D, 0xA1, 0x26, 0x65,
            0xC0, 0x04, 0x7D, 0x91, 0xB6, 0x5F, 0x89, 0x5E, 0x01, 0x82, 0x23, 0x35, 0x19, 0x2E, 0x5C, 0x09
        }
    },
    {
        0, 1347, NID_md5, {
            0xC2, 0x78, 0x16, 0xDC, 0xD1, 0xC5, 0x71, 0xBD, 0x4A, 0x06, 0x2B, 0x38, 0x50, 0xE7, 0x4E, 0xC2,
            0x0E, 0x74, 0x9D, 0xB1, 0x59, 0xA8, 0xFF, 0x11, 0x24, 0x68, 0xD0, 0xCF, 0x69, 0xE5, 0x30, 0x36
        }
    }
};
static const size_t pbkdf2_tests_len = sizeof(pbkdf2_tests) / sizeof(pbkdf2_tests[0]);

static int test_PKCS5_PBKDF2_HMAC(int pbkdf2_tests_idx) {
    int success = 0;
    const char password[] = "password";
    const unsigned char salt[] = {'s', 'a', 'l', 't'};
    const size_t password_len = sizeof(password) / sizeof(password[0]);
    const size_t salt_len = sizeof(salt) / sizeof(salt[0]);

    int iter = pbkdf2_tests[pbkdf2_tests_idx].iterations;
    const EVP_MD *digest = EVP_get_digestbynid(pbkdf2_tests[pbkdf2_tests_idx].nid_digest);
    const size_t key_len = 32;
    const size_t key_expected_len = key_len;
    uint8_t* key = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        switch (pbkdf2_tests[pbkdf2_tests_idx].nid_digest) {
        case NID_md5:
            TEST_note("Skipping test since MD5 is disabled in FIPS mode");
            success = 1;
            goto end;
        }
    }
#endif

    if (!TEST_ptr(key = OPENSSL_malloc(key_len))
            || !TEST_true(1 == PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len,
                          iter, digest,
                          key_len, key))
            || !TEST_true(fips_sli_PKCS5_PBKDF2_HMAC_is_approved(password, password_len,
                          salt, salt_len,
                          iter, digest,
                          key_len, key) == pbkdf2_tests[pbkdf2_tests_idx].fips_approved)
            || !TEST_mem_eq(key, key_len, pbkdf2_tests[pbkdf2_tests_idx].key_expected, key_expected_len))
        goto end;
    success = 1;
end:
    return success;
}

typedef struct {
    int fips_approved;
    int digest_nid;
} SLI_SSHKDF_TEST;

static const SLI_SSHKDF_TEST sshkdf_tests[] = {
    {1, NID_sha256},
    {0, NID_md5},
};
static const size_t sshkdf_tests_len = sizeof(sshkdf_tests) / sizeof(sshkdf_tests[0]);

static int sshkdf(int sshkdf_test_idx) {
    int success = 0;
    const uint8_t *key = get_key_32();
    const uint8_t *xcghash = get_msg_128();
    const uint8_t *session_id = get_key_32();
    uint8_t kdfout[16];
    size_t kdfoutlen = sizeof(kdfout) / sizeof(kdfout[0]);
    const int digest_nid = sshkdf_tests[sshkdf_test_idx].digest_nid;
    EVP_KDF_CTX *ctx = NULL;

    TEST_note("SSHKDF with %s", OBJ_nid2sn(digest_nid));

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        switch (digest_nid) {
        case NID_md5:
            TEST_note("Skipping test since MD5 is disabled in FIPS mode");
            success = 1;
            goto end;
        }
    }
#endif

    if (!TEST_ptr(ctx = EVP_KDF_CTX_new_id(NID_sshkdf))
            || !TEST_true(EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_MD, EVP_get_digestbynid(digest_nid)) == 1)
            || !TEST_true(EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_KEY, key, 32) == 1)
            || !TEST_true(EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, session_id, 32) == 1)
            || !TEST_true(EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SSHKDF_TYPE, EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV) == 1)
            || !TEST_true(EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, xcghash, 128) == 1)
            || !TEST_true(fips_sli_is_approved_EVP_KDF_CTX(ctx))
            || !TEST_true(EVP_KDF_derive(ctx, kdfout, kdfoutlen) == 1)
            || !TEST_true(fips_sli_is_approved_EVP_KDF_CTX(ctx) == sshkdf_tests[sshkdf_test_idx].fips_approved)
       )
        goto end;

    EVP_KDF_reset(ctx);

    if (!TEST_true(fips_sli_is_approved_EVP_KDF_CTX(ctx)))
        goto end;

    success = 1;
end:
    EVP_KDF_CTX_free(ctx);
    return success;
}

static int rand_bytes() {
    int success = 0;
    unsigned char r[1];
    size_t rlen = sizeof(r) / sizeof(r[0]);
    if (!TEST_true(fips_sli_RAND_bytes_is_approved(r, rlen) == 1)
            || !TEST_true(RAND_bytes(r, rlen) == 1)
            || !TEST_true(fips_sli_RAND_priv_bytes_is_approved(r, rlen) == 1)
            || !TEST_true(RAND_priv_bytes(r, rlen) == 1)
            || !TEST_true(fips_sli_RAND_priv_bytes_is_approved(r, rlen) == 1)
       )
        goto end;
    success = 1;
end:
    return success;
}

int setup_tests(void) {
    ADD_TEST(test_sli_noop);
    ADD_TEST(cmac_aes_cbc);
    ADD_TEST(cmac_no_des);
    ADD_ALL_TESTS(cmac_via_md_ctx, cmac_tests_len);
#ifdef OPENSSL_NO_EC
    TEST_note("Elliptic curves are disabled.");
#else
    ADD_ALL_TESTS(ecdsa_via_EVP_DigestSign, ecdsa_tests_len);
#endif
    ADD_ALL_TESTS(cipher, cipher_tests_len);
#ifdef OPENSSL_NO_RSA
    TEST_note("RSA is disabled.");
#else
    ADD_ALL_TESTS(sealenv, sealenv_tests_len);
#endif
    ADD_ALL_TESTS(test_PKCS5_PBKDF2_HMAC, pbkdf2_tests_len);
    ADD_ALL_TESTS(sshkdf, sshkdf_tests_len);
    ADD_TEST(rand_bytes);

    return 1; /* success */
}
