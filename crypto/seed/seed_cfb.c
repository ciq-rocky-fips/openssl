/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# include "openssl/opensslconf.h"

#ifdef OPENSSL_FIPS
# include "openssl/fips.h"
# include "openssl/err.h"
#endif

#include <openssl/seed.h>
#include <openssl/modes.h>

void SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t len, const SEED_KEY_SCHEDULE *ks,
                         unsigned char ivec[SEED_BLOCK_SIZE], int *num,
                         int enc)
{
    if (FIPS_mode()) {
        FIPSerr(ERR_LIB_FIPS, FIPS_R_NON_FIPS_METHOD);
        OpenSSLDie(__FILE__, __LINE__, "FATAL FIPS Unapproved algorithm called");
        return;
    }

    CRYPTO_cfb128_encrypt(in, out, len, ks, ivec, num, enc,
                          (block128_f) SEED_encrypt);
}
