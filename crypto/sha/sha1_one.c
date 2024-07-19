/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include "openssl/opensslconf.h"

#ifdef OPENSSL_FIPS
# include "openssl/fips.h"
# include "openssl/err.h"
#endif

#include <openssl/crypto.h>
#include <openssl/sha.h>

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA_CTX c;
    static unsigned char m[SHA_DIGEST_LENGTH];

    if (FIPS_mode()) {
        FIPSerr(ERR_LIB_FIPS, FIPS_R_NON_FIPS_METHOD);
        OpenSSLDie(__FILE__, __LINE__, "FATAL FIPS Unapproved algorithm called");
        return NULL;
    }

    if (md == NULL)
        md = m;
    if (!SHA1_Init(&c))
        return NULL;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return md;
}
