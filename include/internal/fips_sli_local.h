#ifndef FIPS_SLI_LOCAL_H_INCLUDED
#define FIPS_SLI_LOCAL_H_INCLUDED

#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/fips_sli.h>

/* status for SLI */
typedef enum fips_status_e {
    FIPS_UNSET,
    FIPS_APPROVED,
    FIPS_NONAPPROVED,
    FIPS_ERROR,
} FIPS_STATUS;


void fips_sli_approve_EVP_KDF_CTX(EVP_KDF_CTX *ctx);
void fips_sli_approve_EVP_MD_CTX(EVP_MD_CTX *ctx);
void fips_sli_approve_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx);
void fips_sli_approve_HMAC_CTX(HMAC_CTX *ctx);

/* Unused:
 * void fips_sli_approve_EVP_CIPHER_CTX(EVP_CIPHER_CTX *ctx);
 */
void fips_sli_disapprove_EVP_CIPHER_CTX(EVP_CIPHER_CTX *ctx);
void fips_sli_disapprove_EVP_KDF_CTX(EVP_KDF_CTX *ctx);
void fips_sli_disapprove_EVP_MD_CTX(EVP_MD_CTX *ctx);
void fips_sli_disapprove_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx);
void fips_sli_disapprove_HMAC_CTX(HMAC_CTX *ctx);

//void fips_sli_error_EVP_KDF_CTX(EVP_KDF_CTX *ctx); /* unused */
//void fips_sli_error_HMAC_CTX(HMAC_CTX *ctx);
//void fips_sli_error_EVP_CIPHER_CTX(EVP_CIPHER_CTX *ctx);
void fips_sli_error_EVP_MD_CTX(EVP_MD_CTX *ctx);
void fips_sli_error_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx);

FIPS_STATUS fips_sli_fsm_transition(FIPS_STATUS state, FIPS_STATUS input);

#define fips_sli_define_basic_for(LNKG, FNNAME, CTXTYPE) \
static void fips_sli_fsm_##FNNAME(CTXTYPE *ctx, FIPS_STATUS input) {  \
    if (ctx == NULL)                                                  \
        return;                                                       \
    ctx->sli = fips_sli_fsm_transition(ctx->sli, input);              \
}                                                                     \
LNKG int fips_sli_is_approved_##FNNAME(const CTXTYPE *ctx) {          \
    if (ctx == NULL)                                                  \
        return 0;                                                     \
    return (ctx->sli == FIPS_UNSET) || (ctx->sli == FIPS_APPROVED);   \
}

#define fips_sli_define_for(CTXTYPE)                   \
fips_sli_define_basic_for(, CTXTYPE, CTXTYPE)          \
void fips_sli_approve_##CTXTYPE(CTXTYPE *ctx) {        \
    fips_sli_fsm_##CTXTYPE(ctx, FIPS_APPROVED);        \
}                                                      \
void fips_sli_disapprove_##CTXTYPE(CTXTYPE *ctx) {     \
    fips_sli_fsm_##CTXTYPE(ctx, FIPS_NONAPPROVED);     \
}                                                      \
void fips_sli_error_##CTXTYPE(CTXTYPE *ctx) {          \
    fips_sli_fsm_##CTXTYPE(ctx, FIPS_ERROR);           \
}

void fips_sli_check_hash_siggen_EVP_MD_CTX(EVP_MD_CTX * ctx, const EVP_MD * md);
void fips_sli_check_hash_sigver_EVP_MD_CTX(EVP_MD_CTX * ctx, const EVP_MD * md);
void fips_sli_check_hash_siggen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const EVP_MD * md);
void fips_sli_check_hash_sigver_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const EVP_MD * md);
void fips_sli_check_hash_mac_HMAC_CTX(HMAC_CTX * ctx, const EVP_MD * md);

FIPS_STATUS fips_sli_get_hash_status_sshkdf(const EVP_MD * md);
FIPS_STATUS fips_sli_get_hash_status_pbkdf2(const EVP_MD * md);
FIPS_STATUS fips_sli_get_hash_status_kbkdf(const EVP_MD * md);
FIPS_STATUS fips_sli_get_hash_status_kdf_tls1_prf(const EVP_MD * md);
FIPS_STATUS fips_sli_get_kdf_keylen_status(size_t keylen_bytes);

/* Check if used curve is okay for and in this context */
void fips_sli_check_curve_siggen_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const EC_GROUP *group);
void fips_sli_check_curve_sigver_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const EC_GROUP *group);

void fips_sli_check_key_ec_keygen_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const EC_KEY *ec);
void fips_sli_check_key_rsa_keygen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa);
void fips_sli_check_key_rsa_siggen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa);
void fips_sli_check_key_rsa_sigver_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa);
void fips_sli_check_key_rsa_enc_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa);
void fips_sli_check_key_rsa_dec_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const RSA * rsa);
void fips_sli_check_key_dsa_siggen_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const DSA * dsa);
void fips_sli_check_key_dsa_sigver_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, const DSA * dsa);

void fips_sli_check_key_dh_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const DH *dh);
void fips_sli_check_key_ecdh_EVP_PKEY_CTX(EVP_PKEY_CTX *ctx, const EC_KEY *ecdh);

void fips_sli_check_padding_rsa_enc_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, int pad_mode);
void fips_sli_check_padding_rsa_dec_EVP_PKEY_CTX(EVP_PKEY_CTX * ctx, int pad_mode);

FIPS_STATUS EVP_CIPHER_get_fips_status(const EVP_CIPHER *cipher);
void fips_sli_check_cipher_EVP_CIPHER_CTX(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher);

#endif /* FIPS_SLI_LOCAL_H_INCLUDED */
