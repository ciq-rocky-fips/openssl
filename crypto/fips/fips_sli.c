#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include "crypto/evp.h"
#include "../evp/evp_local.h"
#include "../hmac/hmac_local.h"
#include "internal/fips_sli_local.h"

/* Main part of the FIPS Service Level Indicator
 If you want to quickly change its behaviour, you most likely want to start here
  - beware of some exceptions, though... */

FIPS_STATUS fips_sli_fsm_transition(FIPS_STATUS state, FIPS_STATUS input) {
    switch (state) {
    case FIPS_UNSET:
        switch (input) {
        case FIPS_UNSET: /* ignore */
            return state;
        case FIPS_APPROVED:
        case FIPS_NONAPPROVED:
        case FIPS_ERROR:
            return input;
        }
        break;
    case FIPS_APPROVED:
        switch (input) {
        case FIPS_UNSET: /* ignore */
        case FIPS_APPROVED:
            return state;
        case FIPS_NONAPPROVED:
        case FIPS_ERROR:
            return input;
        }
        break;
    case FIPS_NONAPPROVED:
        return state;
    case FIPS_ERROR:
        switch (input) {
        case FIPS_UNSET: /* ignore */
        case FIPS_APPROVED:
        case FIPS_ERROR:
            return state;
        case FIPS_NONAPPROVED:
            return input;
        }
    }
    abort();
}

fips_sli_define_for(EVP_CIPHER_CTX)
fips_sli_define_for(EVP_KDF_CTX)
fips_sli_define_for(EVP_MD_CTX)
fips_sli_define_for(EVP_PKEY_CTX)
fips_sli_define_for(HMAC_CTX)

typedef enum curve_usage_e {
    CURVE_KEYGEN,
    CURVE_SIGGEN,
    CURVE_SIGVER,
    CURVE_DH
} CURVE_USAGE;

/* Check whether a curve is okay for some type of usage */
static FIPS_STATUS get_fips_curve_status(const EC_GROUP *group, CURVE_USAGE u) {
    if (group == NULL) {
        return FIPS_ERROR;
    }

    switch (u) {
    case CURVE_KEYGEN:
        switch (EC_GROUP_get_curve_name(group)) {
        /* ACVP-tested curves for keygen: */
        case NID_secp224r1:
        /* SECG secp256r1 is the same as X9.62 prime256v1 (P-256) and hence omitted */
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    case CURVE_SIGVER:
        switch (EC_GROUP_get_curve_name(group)) {
        case NID_X9_62_prime192v1: /* NIST P-192 */
        case NID_secp224r1:
        /* SECG secp256r1 is the same as X9.62 prime256v1 (P-256) and hence omitted */
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
        /* nist k curves */
        case NID_sect233k1:
        case NID_sect283k1:
        case NID_sect409k1:
        case NID_sect571k1:
        /* nist b curves */
        case NID_sect233r1:
        case NID_sect283r1:
        case NID_sect409r1:
        case NID_sect571r1:
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    case CURVE_SIGGEN:
    case CURVE_DH:
        switch (EC_GROUP_get_curve_name(group)) {
        /* see crypto/ec/ec_curve.c:2800 */
        /* nist P curves*/
        case NID_secp224r1:
        /* SECG secp256r1 is the same as X9.62 prime256v1 and hence omitted */
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    }
    return FIPS_NONAPPROVED;
}

#define make_fips_sli_check_curve(CTXTYPE, fn, usage) \
void fips_sli_check_curve_##fn##_##CTXTYPE(CTXTYPE *ctx, const EC_GROUP *group)\
{ \
     fips_sli_fsm_##CTXTYPE(ctx, get_fips_curve_status(group, usage)); \
}

make_fips_sli_check_curve(EVP_MD_CTX, siggen, CURVE_SIGGEN)
make_fips_sli_check_curve(EVP_MD_CTX, sigver, CURVE_SIGVER)
/* keygen missing because in this case we need more info than available here*/
make_fips_sli_check_curve(EVP_PKEY_CTX, siggen, CURVE_SIGGEN)
make_fips_sli_check_curve(EVP_PKEY_CTX, sigver, CURVE_SIGVER)

typedef enum hash_usage_e {
    HASH_SIGGEN,
    HASH_SIGVER,
    HASH_KDF_SSHKDF,
    HASH_KDF_PBKDF2,
    HASH_KDF_TLS,
    HASH_KDF_KBKDF,
    HASH_RNG,
    HASH_MAC
} HASH_USAGE;

static FIPS_STATUS get_fips_hash_status(const EVP_MD *md, HASH_USAGE u) {
    if (md == NULL) {
        return FIPS_ERROR;
    }

    switch (u) {
    case HASH_KDF_TLS:
        switch (EVP_MD_type(md)) {
        case NID_sha256: /* TLSv1.2 */
        case NID_sha384:
        case NID_sha512:
        case NID_md5_sha1: /* used in TLS v1.0 / v1.1 */
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    case HASH_KDF_PBKDF2:
    case HASH_KDF_SSHKDF:
    case HASH_MAC:
        switch (EVP_MD_type(md)) {
        case NID_sha1:
        case NID_sha224:
        case NID_sha256:
        case NID_sha384:
        case NID_sha512:
        case NID_sha512_224:
        case NID_sha512_256:
        case NID_sha3_224:
        case NID_sha3_256:
        case NID_sha3_384:
        case NID_sha3_512:
        case NID_shake128:
        case NID_shake256:
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    case HASH_KDF_KBKDF:
        switch (EVP_MD_type(md)) {
        case NID_sha256:
        case NID_sha384:
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    case HASH_RNG:
    case HASH_SIGGEN:
    case HASH_SIGVER:
        switch (EVP_MD_type(md)) {
        case NID_sha224:
        case NID_sha256:
        case NID_sha384:
        case NID_sha512:
        case NID_sha512_224:
        case NID_sha512_256:
        case NID_sha3_224:
        case NID_sha3_256:
        case NID_sha3_384:
        case NID_sha3_512:
        case NID_shake128:
        case NID_shake256:
            return FIPS_APPROVED;
        default:
            return FIPS_NONAPPROVED;
        }
    }
    return FIPS_ERROR;
}

#define make_fips_sli_check_hash(CTXTYPE, fn, usage) \
void fips_sli_check_hash_##fn##_##CTXTYPE(CTXTYPE *ctx, const EVP_MD *md) \
{ \
     fips_sli_fsm_##CTXTYPE(ctx, get_fips_hash_status(md, usage)); \
}

make_fips_sli_check_hash(EVP_MD_CTX, siggen, HASH_SIGGEN)
make_fips_sli_check_hash(EVP_MD_CTX, sigver, HASH_SIGVER)
make_fips_sli_check_hash(EVP_PKEY_CTX, siggen, HASH_SIGGEN)
make_fips_sli_check_hash(EVP_PKEY_CTX, sigver, HASH_SIGVER)
make_fips_sli_check_hash(HMAC_CTX, mac, HASH_MAC)
/* KDF impl is a bit special - avoid changing everything just because of that */
FIPS_STATUS fips_sli_get_hash_status_sshkdf(const EVP_MD * md) {
    return get_fips_hash_status(md, HASH_KDF_SSHKDF);
}
FIPS_STATUS fips_sli_get_hash_status_pbkdf2(const EVP_MD * md) {
    return get_fips_hash_status(md, HASH_KDF_PBKDF2);
}
FIPS_STATUS fips_sli_get_hash_status_kdf_tls1_prf(const EVP_MD * md) {
    return get_fips_hash_status(md, HASH_KDF_TLS);
}
FIPS_STATUS fips_sli_get_hash_status_kbkdf(const EVP_MD * md) {
    return get_fips_hash_status(md, HASH_KDF_KBKDF);
}

FIPS_STATUS fips_sli_get_kdf_keylen_status(size_t keylen_bytes) {
    if (keylen_bytes >= 112/8)
        return FIPS_APPROVED;
    else
        return FIPS_NONAPPROVED;
}

void fips_sli_check_key_rsa_keygen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa) {
    fips_sli_check_key_rsa_siggen_EVP_PKEY_CTX(ctx, rsa);
}

void fips_sli_check_key_rsa_siggen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa) {
    if (RSA_bits(rsa) >= 2048)
        fips_sli_approve_EVP_PKEY_CTX(ctx);
    else
        fips_sli_disapprove_EVP_PKEY_CTX(ctx);
}

void fips_sli_check_key_rsa_sigver_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa) {
    const int len_n = RSA_bits(rsa);

    if (1024 <= len_n && len_n < 2048)
        fips_sli_approve_EVP_PKEY_CTX(ctx); // legacy use
    else if (2048 <= len_n)
        fips_sli_approve_EVP_PKEY_CTX(ctx);
    else
        fips_sli_disapprove_EVP_PKEY_CTX(ctx);
}

void fips_sli_check_key_rsa_enc_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa) {
    fips_sli_disapprove_EVP_PKEY_CTX(ctx);
}

void fips_sli_check_key_rsa_dec_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa) {
    fips_sli_disapprove_EVP_PKEY_CTX(ctx);
}

void fips_sli_check_key_dsa_siggen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const DSA * dsa) {
    fips_sli_disapprove_EVP_PKEY_CTX(ctx);
}

void fips_sli_check_key_dsa_sigver_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const DSA * dsa) {
    fips_sli_disapprove_EVP_PKEY_CTX(ctx);
}

void fips_sli_check_key_dh_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const DH *dh) {
    switch (DH_get_nid(dh)) {
    /* RFC 3526 */
    case NID_modp_2048:
    case NID_modp_3072:
    case NID_modp_4096:
    case NID_modp_6144:
    case NID_modp_8192:
    /* RFC 7919 */
    case NID_ffdhe2048:
    case NID_ffdhe3072:
    case NID_ffdhe4096:
    case NID_ffdhe6144:
    case NID_ffdhe8192:
        fips_sli_approve_EVP_PKEY_CTX(ctx);
        break;
    default:
        fips_sli_disapprove_EVP_PKEY_CTX(ctx);
    }
}

void fips_sli_check_key_ecdh_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const EC_KEY *ecdh) {
    fips_sli_fsm_EVP_PKEY_CTX(ctx, get_fips_curve_status(EC_KEY_get0_group(ecdh), CURVE_DH));
}

void fips_sli_check_cipher_EVP_CIPHER_CTX(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher) {
    fips_sli_fsm_EVP_CIPHER_CTX(ctx, EVP_CIPHER_get_fips_status(cipher));
}

/** According to FIPS PUB 186-5.
 * Not really helpful because nist P curves are the only allowed curves for
 * KeyGen, and have h=1 anyway - but allow for future extensibility */
static FIPS_STATUS get_fips_keygen_ecdsa_order_status(const EC_KEY *ec) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *pwr14, *pwr16, *pwr24, *pwr32;
    const BIGNUM * cofactor = EC_GROUP_get0_cofactor(EC_KEY_get0_group(ec));
    const int n = EC_GROUP_order_bits(EC_KEY_get0_group(ec));
    FIPS_STATUS ret = FIPS_NONAPPROVED;

    if (ctx == NULL) {
        ret = FIPS_ERROR;
        goto end;
    }

    BN_CTX_start(ctx);
    pwr14 = BN_CTX_get(ctx);
    pwr16 = BN_CTX_get(ctx);
    pwr24 = BN_CTX_get(ctx);
    pwr32 = BN_CTX_get(ctx);
    if (pwr32 == NULL) {
        /* Sufficient to check the return value of the last BN_CTX_get() */
        ret = FIPS_ERROR;
        goto end;
    }
    BN_set_bit(pwr14, 14);
    BN_set_bit(pwr16, 16);
    BN_set_bit(pwr24, 24);
    BN_set_bit(pwr32, 32);

    if (224 < n && n <= 255) {
        if (BN_cmp(cofactor, pwr14) != 1)
            ret = FIPS_APPROVED;
    } else if (256 < n && n <= 383) {
        if (BN_cmp(cofactor, pwr16) != 1)
            ret = FIPS_APPROVED;

    } else if (384 < n && n <= 511) {
        if (BN_cmp(cofactor, pwr24) != 1)
            ret = FIPS_APPROVED;

    } else if (n >= 512) {
        if (BN_cmp(cofactor, pwr32) != 1)
            ret = FIPS_APPROVED;
    }

end:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

void fips_sli_check_key_ec_keygen_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx,
        const EC_KEY *ec) {
    fips_sli_fsm_EVP_PKEY_CTX(ctx, get_fips_curve_status(
                                  EC_KEY_get0_group(ec), CURVE_KEYGEN));
    fips_sli_fsm_EVP_PKEY_CTX(ctx, get_fips_keygen_ecdsa_order_status(ec));
}

/* MINOR: refactor for sign/verify, too. See crypto/rsa/rsa_pmeth.c */
static FIPS_STATUS get_fips_padding_rsa_encdec_status(int pad_mode/*,usg: enc/dec*/) {
    return FIPS_NONAPPROVED;
}

void fips_sli_check_padding_rsa_enc_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, int pad_mode) {
    fips_sli_fsm_EVP_PKEY_CTX(ctx, get_fips_padding_rsa_encdec_status(pad_mode));
}

void fips_sli_check_padding_rsa_dec_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, int pad_mode) {
    fips_sli_check_padding_rsa_enc_EVP_PKEY_CTX(ctx, pad_mode);
}
