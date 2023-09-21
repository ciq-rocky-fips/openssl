/* fips/ecdsa/fips_ecdsa_selftest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2011.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/fips.h>
#include "crypto/fips.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#ifdef OPENSSL_FIPS
#include <openssl/rand.h>
#include "internal/nelem.h"
#include "fips_locl.h"

/* functions to change the RAND_METHOD */
static int fbytes(unsigned char *buf, int num);

static RAND_METHOD fake_rand;
static const RAND_METHOD *old_rand;
static int use_fake = 0;
static const unsigned char *numbers[2];
static int numbers_len[2];
static int fbytes_counter = 0;

static int change_rand(void)
{
  /* save old rand method */
  old_rand = RAND_get_rand_method();
  if (!old_rand)
    return 0;
  
  fake_rand = *old_rand;
  /* use own random function */
  fake_rand.bytes = fbytes;
  /* set new RAND_METHOD */
  if (!RAND_set_rand_method(&fake_rand))
    return 0;
  
  return 1;
}

static int restore_rand(void)
{
  fbytes_counter = 0;
  if (!RAND_set_rand_method(old_rand))
    return 0;
  
  return 1;
}

static int fbytes(unsigned char *buf, int num)
{
  int ret = 0;
  
  if (use_fake == 0)
    return old_rand->bytes(buf, num);
  
  use_fake = 0;
  
  if (fbytes_counter >= OSSL_NELEM(numbers))
    goto err;
  
  if (numbers_len[fbytes_counter] > num)
    goto err;
  
  /* first zero out the buffer */
  memset(buf, 0, num);
  
  /* Now set the "random" values */
  memcpy(buf + (num - numbers_len[fbytes_counter]), numbers[fbytes_counter], numbers_len[fbytes_counter]);
  
  fbytes_counter = (fbytes_counter + 1) % OSSL_NELEM(numbers);
  ret = 1;
err:
  return ret;
}



/*-
 * NIST CAVP ECDSA KATs
 * 2 X9.62 KATs; one for prime fields and one for binary fields.
 *
 * Taken from:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip
 */

typedef struct {
  const int nid;                       /* curve NID */
  const int md_nid;                    /* hash function NID */
  const unsigned char *msg;            /* message to sign */
  size_t msglen;
  const unsigned char *d;              /* ECDSA private key */
  size_t dlen;
  const unsigned char *Q;              /* ECDSA public key: (Qx,Qy) */
  size_t Qlen;
  const unsigned char *k;              /* ECDSA nonce */
  size_t klen;
  const unsigned char *r;            /* ECDSA signature (r,s) */
  size_t rlen;
  const unsigned char *s;
  size_t slen;
} ECDSA_KAT_SELFTEST_DATA;


static const unsigned char data1_msg[] = {
  0x59, 0x05, 0x23, 0x88, 0x77, 0xc7, 0x74, 0x21,
  0xf7, 0x3e, 0x43, 0xee, 0x3d, 0xa6, 0xf2, 0xd9,
  0xe2, 0xcc, 0xad, 0x5f, 0xc9, 0x42, 0xdc, 0xec,
  0x0c, 0xbd, 0x25, 0x48, 0x29, 0x35, 0xfa, 0xaf,
  0x41, 0x69, 0x83, 0xfe, 0x16, 0x5b, 0x1a, 0x04,
  0x5e, 0xe2, 0xbc, 0xd2, 0xe6, 0xdc, 0xa3, 0xbd,
  0xf4, 0x6c, 0x43, 0x10, 0xa7, 0x46, 0x1f, 0x9a,
  0x37, 0x96, 0x0c, 0xa6, 0x72, 0xd3, 0xfe, 0xb5,
  0x47, 0x3e, 0x25, 0x36, 0x05, 0xfb, 0x1d, 0xdf,
  0xd2, 0x80, 0x65, 0xb5, 0x3c, 0xb5, 0x85, 0x8a,
  0x8a, 0xd2, 0x81, 0x75, 0xbf, 0x9b, 0xd3, 0x86,
  0xa5, 0xe4, 0x71, 0xea, 0x7a, 0x65, 0xc1, 0x7c,
  0xc9, 0x34, 0xa9, 0xd7, 0x91, 0xe9, 0x14, 0x91,
  0xeb, 0x37, 0x54, 0xd0, 0x37, 0x99, 0x79, 0x0f,
  0xe2, 0xd3, 0x08, 0xd1, 0x61, 0x46, 0xd5, 0xc9,
  0xb0, 0xd0, 0xde, 0xbd, 0x97, 0xd7, 0x9c, 0xe8
};

static const unsigned char data1_d[] = {
  0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58,
  0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77, 0x1a,
  0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac,
  0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72, 0xb4, 0x64
};

static const unsigned char data1_Q[] = {
  0x04, 0x0c, 0xec, 0x02, 0x8e, 0xe0, 0x8d, 0x09,
  0xe0, 0x26, 0x72, 0xa6, 0x83, 0x10, 0x81, 0x43,
  0x54, 0xf9, 0xea, 0xbf, 0xff, 0x0d, 0xe6, 0xda,
  0xcc, 0x1c, 0xd3, 0xa7, 0x74, 0x49, 0x60, 0x76,
  0xae, 0xef, 0xf4, 0x71, 0xfb, 0xa0, 0x40, 0x98,
  0x97, 0xb6, 0xa4, 0x8e, 0x88, 0x01, 0xad, 0x12,
  0xf9, 0x5d, 0x00, 0x09, 0xb7, 0x53, 0xcf, 0x8f,
  0x51, 0xc1, 0x28, 0xbf, 0x6b, 0x0b, 0xd2, 0x7f,
  0xbd
};

static const unsigned char data1_k[] = {
  0x94, 0xa1, 0xbb, 0xb1, 0x4b, 0x90, 0x6a, 0x61,
  0xa2, 0x80, 0xf2, 0x45, 0xf9, 0xe9, 0x3c, 0x7f,
  0x3b, 0x4a, 0x62, 0x47, 0x82, 0x4f, 0x5d, 0x33,
  0xb9, 0x67, 0x07, 0x87, 0x64, 0x2a, 0x68, 0xde
};

static const unsigned char data1_r[] = {
  0xe3, 0x95, 0xf6, 0xdb, 0x12, 0x71, 0x90, 0xfa,
  0x70, 0xa6, 0x80, 0xeb, 0xf6, 0x8a, 0x18, 0x35,
  0x6f, 0xef, 0xf2, 0x36, 0x65, 0xb9, 0x31, 0xc3,
  0xa2, 0x14, 0x80, 0xdf, 0x86, 0xc4, 0xec, 0xbc
};

static const unsigned char data1_s[] = {
  0xa5, 0x01, 0x04, 0x78, 0x93, 0xd9, 0x60, 0xcc,
  0x20, 0xce, 0xbd, 0xbb, 0x6f, 0x79, 0xb9, 0x7e,
  0x45, 0x23, 0x80, 0x73, 0x87, 0x83, 0x53, 0x63,
  0xe3, 0x80, 0x2b, 0x68, 0xcf, 0x32, 0xa1, 0xa2
};


# define make_ecdsa_kat_test(nid, md_nid, pr) {	\
nid, md_nid,				\
pr##_msg, sizeof(pr##_msg),		\
pr##_d,   sizeof(pr##_d),			\
pr##_Q,   sizeof(pr##_Q),		    \
pr##_k,   sizeof(pr##_k),			\
pr##_r,   sizeof(pr##_r),			\
pr##_s,   sizeof(pr##_s)			\
}

static ECDSA_KAT_SELFTEST_DATA test_ecdsa_data[] = {
  make_ecdsa_kat_test(NID_secp256k1, NID_sha256, data1)
};

int FIPS_selftest_ecdsa()
{
  int rv;
  size_t i, siglen, p_len;
  
  for (i = 0; i < sizeof(test_ecdsa_data) / sizeof(ECDSA_KAT_SELFTEST_DATA); i++) {
    EC_KEY *ec = NULL;
    BIGNUM *r = NULL, *s = NULL;
    const BIGNUM *sig_r = NULL, *sig_s = NULL;
    EVP_PKEY *pk = NULL;
    unsigned char *sig = NULL;
    const unsigned char *tsig = NULL;
    unsigned char *p_buf = NULL;
    ECDSA_SIG *dsa_sig = NULL;
    int rand_set = 0;
    rv = 0;
    
    ECDSA_KAT_SELFTEST_DATA *ecd = test_ecdsa_data + i;
    
    /* Create the Message Digest Context */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto err;
    
    r = BN_bin2bn(ecd->r, ecd->rlen, r);
    s = BN_bin2bn(ecd->s, ecd->slen, s);
    
    if (!r || !s)
      goto err;

    /* d[] will be used to generate a key. */
    /* k[] will be used for signature generation. */
    numbers[0] = ecd->d;
    numbers_len[0] = ecd->dlen;
    numbers[1] = ecd->k;
    numbers_len[1] = ecd->klen;
    /* swap the RNG source */
    if (!change_rand()) {
      goto err;
    } else {
      rand_set = 1;
    }
    
    ec = EC_KEY_new_by_curve_name(ecd->nid);
    if (!ec)
      goto err;
    
    /* Use d[] to generate key. */
    use_fake = 1;
    if (EC_KEY_generate_key(ec) != 1)
      goto err;
    
    if ((pk = EVP_PKEY_new()) == NULL)
      goto err;
    
    EVP_PKEY_assign_EC_KEY(pk, ec);

    if (!fips_post_started(FIPS_TEST_SIGNATURE, ecd->nid, pk))
		  return 1;
    
    p_len = EC_KEY_key2buf(ec, POINT_CONVERSION_UNCOMPRESSED, &p_buf, NULL);
    if (!p_len)
      goto err;
    
    /* Make sure generated public key matches */
    if (p_len != ecd->Qlen)
      goto err;
    if (memcmp(p_buf, ecd->Q, p_len))
      goto err;
    
    /* Initialise the DigestSign operation */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_get_digestbynid(ecd->md_nid), NULL, pk))
      goto err;
    
    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, ecd->msg, ecd->msglen))
      goto err;
    
    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to */
    /* obtain the length of the signature. Length is returned in slen */
    if(1 != EVP_DigestSignFinal(mdctx, NULL, &siglen))
      goto err;
    
    /* Allocate memory for the signature based on size in slen */
    if(!(sig = OPENSSL_malloc(siglen)))
      goto err;
    
    if (!fips_post_corrupt(FIPS_TEST_SIGNATURE, ecd->nid, pk)) {
      if (!EVP_DigestSignUpdate(mdctx, ecd->msg, 1))
        goto err;
	  }

    /* Use k[] for signature. */
    use_fake = 1;
    
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, sig, &siglen))
      goto err;

    /* extract r and s */
    tsig = sig;
    dsa_sig = d2i_ECDSA_SIG(NULL, &tsig, siglen);
    if (dsa_sig == NULL)
      goto err;
    
    sig_r = ECDSA_SIG_get0_r(dsa_sig);
    sig_s = ECDSA_SIG_get0_s(dsa_sig);
    if ((sig_r == NULL) || (sig_s == NULL))
      goto err;

    /* Compare r and s against known. */
    if ((BN_cmp(sig_r, r) != 0) || (BN_cmp(sig_s, s) != 0))
      goto err;
    
    /* Verify signature */
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_get_digestbynid(ecd->md_nid), NULL, pk))
      goto err;
    
    if (EVP_DigestVerify(mdctx, sig, siglen, ecd->msg, ecd->msglen) != 1)
      goto err;
    
    /* Success */
    rv = 1;
    fips_post_success(FIPS_TEST_SIGNATURE, ecd->nid, pk);
    
  err:
    if (rand_set){
      restore_rand();
    }

    if (rv != 1) {
      fips_post_failed(FIPS_TEST_SIGNATURE, ecd->nid, pk);
    }
    
    if (mdctx)
      EVP_MD_CTX_free(mdctx);
    if (r)
      BN_clear_free(r);
    if (s)
      BN_clear_free(s);
    if (sig)
      OPENSSL_free(sig);
    if (dsa_sig)
      ECDSA_SIG_free(dsa_sig);
    if (p_buf)
      OPENSSL_free(p_buf);
    if (pk)
      EVP_PKEY_free(pk);
    else if (ec)
      EC_KEY_free(ec);
    
    if (rv != 1) {
      FIPSerr(FIPS_F_FIPS_SELFTEST_ECDSA, FIPS_R_SELFTEST_FAILED);
      break;
    }
    
  }

  return rv;
  
}


#endif
