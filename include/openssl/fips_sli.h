#ifndef FIPS_SLI_H_INCLUDED
#define FIPS_SLI_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/cmac.h>
# ifdef  __cplusplus
extern "C" {
# endif

/* Interface for consumers to check if their usage of the services offered by 
 * this ctx was approved */
int fips_sli_is_approved_EVP_CIPHER_CTX(const EVP_CIPHER_CTX *ctx);
int fips_sli_is_approved_EVP_KDF_CTX(const EVP_KDF_CTX *ctx);
int fips_sli_is_approved_EVP_MD_CTX(const EVP_MD_CTX *ctx);
int fips_sli_is_approved_EVP_PKEY_CTX(const EVP_PKEY_CTX *ctx);
int fips_sli_is_approved_CMAC_CTX(const CMAC_CTX *ctx);
int fips_sli_is_approved_HMAC_CTX(const HMAC_CTX *ctx);

int fips_sli_SHA1_is_approved(const unsigned char *d, size_t n, unsigned char *md);
int fips_sli_HMAC_is_approved(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);
int fips_sli_PKCS5_PBKDF2_HMAC_is_approved(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest, int keylen, unsigned char *out);
int fips_sli_RAND_bytes_is_approved(unsigned char *buf, int num);
int fips_sli_RAND_priv_bytes_is_approved(unsigned char *buf, int num);

#  ifdef  __cplusplus
}
#  endif
#endif // FIPS_SLI_H_INCLUDED
