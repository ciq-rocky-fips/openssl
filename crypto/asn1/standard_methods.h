/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This table MUST be kept in ascending order of the NID each method
 * represents (corresponding to the pkey_id field) as OBJ_bsearch
 * is used to search it.
 */
static const EVP_PKEY_ASN1_METHOD *standard_methods[] = {
#ifndef OPENSSL_NO_RSA
    &rsa_asn1_meths[0],
    &rsa_asn1_meths[1],
#endif
#ifndef OPENSSL_NO_DH
    &dh_asn1_meth,
#endif
#ifndef OPENSSL_NO_DSA
    &dsa_asn1_meths[0],
    &dsa_asn1_meths[1],
    &dsa_asn1_meths[2],
    &dsa_asn1_meths[3],
    &dsa_asn1_meths[4],
#endif
#ifndef OPENSSL_NO_EC
    &eckey_asn1_meth,
#endif
    &hmac_asn1_meth,
#ifndef OPENSSL_NO_CMAC
    &cmac_asn1_meth,
#endif
#ifndef OPENSSL_NO_RSA
    &rsa_pss_asn1_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dhx_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ecx25519_asn1_meth,
    &ecx448_asn1_meth,
#endif
#ifndef OPENSSL_NO_POLY1305
    &poly1305_asn1_meth,
#endif
#ifndef OPENSSL_NO_SIPHASH
    &siphash_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ed25519_asn1_meth,
    &ed448_asn1_meth,
#endif
#ifndef OPENSSL_NO_SM2
    &sm2_asn1_meth,
#endif
};

static const EVP_PKEY_ASN1_METHOD *standard_methods_fips[] = {
#ifndef OPENSSL_NO_RSA
    &rsa_asn1_meths[0],
    &rsa_asn1_meths[1],
#endif
#ifndef OPENSSL_NO_DH
    &dh_asn1_meth,
#endif
#ifndef OPENSSL_NO_DSA
#ifndef OPENSSL_FIPS
    &dsa_asn1_meths[0],
    &dsa_asn1_meths[1],
    &dsa_asn1_meths[2],
    &dsa_asn1_meths[3],
    &dsa_asn1_meths[4],
#endif
#endif
#ifndef OPENSSL_NO_EC
    &eckey_asn1_meth,
#endif
    &hmac_asn1_meth,
#ifndef OPENSSL_NO_CMAC
    &cmac_asn1_meth,
#endif
#ifndef OPENSSL_NO_RSA
    &rsa_pss_asn1_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dhx_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_FIPS
    &ecx25519_asn1_meth,
    &ecx448_asn1_meth,
#endif
#endif
#ifndef OPENSSL_NO_POLY1305
#ifndef OPENSSL_FIPS
    &poly1305_asn1_meth,
#endif
#endif
#ifndef OPENSSL_NO_SIPHASH
#ifndef OPENSSL_FIPS
    &siphash_asn1_meth,
#endif
#endif
#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_FIPS
    &ed25519_asn1_meth,
    &ed448_asn1_meth,
#endif
#endif
#ifndef OPENSSL_NO_SM2
#ifndef OPENSSL_FIPS
    &sm2_asn1_meth,
#endif
#endif
};
