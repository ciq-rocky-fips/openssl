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

void SEED_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const SEED_KEY_SCHEDULE *ks, int enc)
{
    if (FIPS_mode()) {
        FIPSerr(ERR_LIB_FIPS, FIPS_R_NON_FIPS_METHOD);
        return;
    }

    if (enc)
        SEED_encrypt(in, out, ks);
    else
        SEED_decrypt(in, out, ks);
}
