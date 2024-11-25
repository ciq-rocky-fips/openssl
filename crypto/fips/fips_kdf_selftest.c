/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include "crypto/fips.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#ifdef OPENSSL_FIPS

static int FIPS_selftest_tls13(void)
{    
    int ret = 0;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    const EVP_MD *md = EVP_sha256();
    size_t hashlen = EVP_MD_size(md);
    unsigned char out[128];
    size_t outlen = hashlen;
    const unsigned char tls13_kdf_psk[] = {
        0xF8, 0xAF, 0x6A, 0xEA, 0x2D, 0x39, 0x7B, 0xAF,
        0x29, 0x48, 0xA2, 0x5B, 0x28, 0x34, 0x20, 0x06,
        0x92, 0xCF, 0xF1, 0x7E, 0xEE, 0x91, 0x65, 0xE4,
        0xE2, 0x7B, 0xAB, 0xEE, 0x9E, 0xDE, 0xFD, 0x05
    };
         
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, tls13_kdf_psk, hashlen) <= 0)
        goto err;
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
        goto err;
        
    {              
        static const unsigned char expected[] = { //tls13_kdf_early_secret[] = {
            0x15, 0x3B, 0x63, 0x94, 0xA9, 0xC0, 0x3C, 0xF3,
            0xF5, 0xAC, 0xCC, 0x6E, 0x45, 0x5A, 0x76, 0x93,
            0x28, 0x11, 0x38, 0xA1, 0xBC, 0xFA, 0x38, 0x03,
            0xC2, 0x67, 0x35, 0xDD, 0x11, 0x94, 0xD2, 0x16
        };
                     
        if(memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_TLS13, FIPS_R_SELFTEST_FAILED);
    return ret;
}

static int FIPS_selftest_tls1_prf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_TLS1_PRF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_TLS_SECRET,
                     "secretSECRETsecret", (size_t)18) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_TLS_SEED, "seed", (size_t)4) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xe8, 0x91, 0x68, 0x49, 0x6d, 0xe5, 0x0e, 0x3b,
            0x34, 0x49, 0x10, 0xbd, 0x89, 0x42, 0x3d, 0x64
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_TLS1_PRF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_hkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[10];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_HKDF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, "secretSECRETsecretSECRET", (size_t)24) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO,
                     "label", (size_t)5) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x04, 0xb6, 0x43, 0x68, 0x62, 0x5c, 0x10, 0x17, 0x01, 0x76
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_HKDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_sshkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[32];
    const unsigned char input_key[] = {
        0x00, 0x00, 0x00, 0x80, 0x0f, 0xaa, 0x17, 0x2b,
        0x8c, 0x28, 0x7e, 0x37, 0x2b, 0xb2, 0x36, 0xad,
        0x34, 0xc7, 0x33, 0x69, 0x5c, 0x13, 0xd7, 0x7f,
        0x88, 0x2a, 0xdc, 0x0f, 0x47, 0xe5, 0xa7, 0xf6,
        0xa3, 0xde, 0x07, 0xef, 0xb1, 0x01, 0x20, 0x7a,
        0xa5, 0xd6, 0x65, 0xb6, 0x19, 0x82, 0x6f, 0x75,
        0x65, 0x91, 0xf6, 0x53, 0x10, 0xbb, 0xd2, 0xc9,
        0x2c, 0x93, 0x84, 0xe6, 0xc6, 0xa6, 0x7b, 0x42,
        0xde, 0xc3, 0x82, 0xfd, 0xb2, 0x4c, 0x59, 0x1d,
        0x79, 0xff, 0x5e, 0x47, 0x73, 0x7b, 0x0f, 0x5b,
        0x84, 0x79, 0x69, 0x4c, 0x3a, 0xdc, 0x19, 0x40,
        0x17, 0x04, 0x91, 0x2b, 0xbf, 0xec, 0x27, 0x04,
        0xd4, 0xd5, 0xbe, 0xbb, 0xfc, 0x1a, 0x7f, 0xc7,
        0x96, 0xe2, 0x77, 0x63, 0x4e, 0x40, 0x85, 0x18,
        0x51, 0xa1, 0x87, 0xec, 0x2d, 0x37, 0xed, 0x3f,
        0x35, 0x1c, 0x45, 0x96, 0xa5, 0xa0, 0x89, 0x29,
        0x16, 0xb4, 0xc5, 0x5f
    };
    const unsigned char xcghash[] = {
        0xa3, 0x47, 0xf5, 0xf1, 0xe1, 0x91, 0xc3, 0x5f,
        0x21, 0x2c, 0x93, 0x24, 0xd5, 0x86, 0x7e, 0xfd,
        0xf8, 0x30, 0x26, 0xbe, 0x62, 0xc2, 0xb1, 0x6a,
        0xe0, 0x06, 0xed, 0xb3, 0x37, 0x8d, 0x40, 0x06
    };
    const unsigned char session_id[] = {
        0x90, 0xbe, 0xfc, 0xef, 0x3f, 0xf8, 0xf9, 0x20,
        0x67, 0x4a, 0x9f, 0xab, 0x94, 0x19, 0x8c, 0xf3,
        0xfd, 0x9d, 0xca, 0x24, 0xa2, 0x1d, 0x3c, 0x9d,
        0xba, 0x39, 0x4d, 0xaa, 0xfb, 0xc6, 0x21, 0xed
    };


    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_SSHKDF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key,
                     sizeof(input_key)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, xcghash,
                     sizeof(xcghash)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, session_id,
                     sizeof(session_id)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSHKDF_TYPE, (int)'F') <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x14, 0x7a, 0x77, 0x14, 0x45, 0x12, 0x3f, 0x84,
            0x6d, 0x8a, 0xe5, 0x14, 0xd7, 0xff, 0x9b, 0x3c,
            0x93, 0xb2, 0xbc, 0xeb, 0x7c, 0x7c, 0x95, 0x00,
            0x94, 0x21, 0x61, 0xb8, 0xe2, 0xd0, 0x11, 0x0f
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_SSHKDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_pbkdf2(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[40];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_PBKDF2)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS,
		     "passwordPASSWORDpassword", (size_t)24) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT,
		     "saltSALTsaltSALTsaltSALTsaltSALTsalt", (size_t)36) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, 4096) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
            0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
            0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
            0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
            0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_PBKDF2, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

int FIPS_selftest_kdf(void)
{
    return FIPS_selftest_tls1_prf()
        && FIPS_selftest_tls13()        
        && FIPS_selftest_hkdf()
        && FIPS_selftest_sshkdf()
        && FIPS_selftest_pbkdf2();
}

#endif
