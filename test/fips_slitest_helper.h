#ifndef __FIPS_SLITEST_HELPER_H__
#define __FIPS_SLITEST_HELPER_H__

#include <openssl/evp.h>

typedef unsigned char byte;

/** Create a MAC key: one copy for macgen, one for macver (verification)
 * Adapted from https://wiki.openssl.org/images/1/1b/T-hmac.c.tar.gz
 */
int make_hmac_keys(EVP_PKEY** skey, EVP_PKEY** vkey);

/* Adapted from https://wiki.openssl.org/images/1/1b/T-hmac.c.tar.gz */
void print_it(const char* label, const byte* buff, size_t len);

int get_cmac_key(int cipher_nid, EVP_PKEY** out);

const uint8_t* get_msg_16();
const uint8_t* get_msg_128();
/* Get constant keys of specified length */
const uint8_t* get_key_16();
const uint8_t* get_key_32();

void get_rsa_key1(RSA *key);
void get_rsa_key2(RSA *key);
void get_rsa_key3(RSA *key);
int get_rsa_key2048p3(RSA *key);

#endif /* __FIPS_SLITEST_HELPER_H__ */
