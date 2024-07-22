/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
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

#include <openssl/rc5.h>
#include "rc5_local.h"
#include <openssl/opensslv.h>

void RC5_32_ecb_encrypt(const unsigned char *in, unsigned char *out,
                        RC5_32_KEY *ks, int encrypt)
{
    unsigned long l, d[2];

    if (FIPS_mode()) {
        FIPSerr(ERR_LIB_FIPS, FIPS_R_NON_FIPS_METHOD);
        return;
    }

    c2l(in, l);
    d[0] = l;
    c2l(in, l);
    d[1] = l;
    if (encrypt)
        RC5_32_encrypt(d, ks);
    else
        RC5_32_decrypt(d, ks);
    l = d[0];
    l2c(l, out);
    l = d[1];
    l2c(l, out);
    l = d[0] = d[1] = 0;
}
