/*
 * Copyright 1998-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl/opensslconf.h"

#ifdef OPENSSL_FIPS
# include "openssl/fips.h"
# include "openssl/err.h"
#endif

#include <openssl/des.h>
#include <openssl/rand.h>

int DES_random_key(DES_cblock *ret)
{
    if (FIPS_mode()) {
        FIPSerr(ERR_LIB_FIPS, FIPS_R_NON_FIPS_METHOD);
        return 0;
    }

    do {
        if (RAND_priv_bytes((unsigned char *)ret, sizeof(DES_cblock)) != 1)
            return 0;
    } while (DES_is_weak_key(ret));
    DES_set_odd_parity(ret);
    return 1;
}
