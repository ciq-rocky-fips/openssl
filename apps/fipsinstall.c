/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/fips_names.h>
#include <openssl/core_names.h>
#include <openssl/self_test.h>
#include <openssl/fipskey.h>
#include "apps.h"
#include "progs.h"
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <openssl/param_build.h>

#define BUFSIZE 4096

/* Configuration file values */
#define VERSION_KEY  "version"
#define VERSION_VAL  "1"
#define INSTALL_STATUS_VAL "INSTALL_SELF_TEST_KATS_RUN"

typedef struct st_args {
    int enable;
    int called;
} SELF_TEST_ARGS;

static OSSL_CALLBACK self_test_events;
static char *self_test_corrupt_desc = NULL;
static char *self_test_corrupt_type = NULL;
static int self_test_log = 1;
static int quiet = 0;

static OSSL_PROVIDER *prov_null = NULL;
static OSSL_LIB_CTX *libctx = NULL;
static SELF_TEST_ARGS self_test_args = { 0 };

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_IN, OPT_OUT, OPT_MODULE,
    OPT_PROV_NAME, OPT_SECTION_NAME, OPT_MAC_NAME, OPT_MACOPT, OPT_VERIFY,
    OPT_NO_LOG, OPT_CORRUPT_DESC, OPT_CORRUPT_TYPE, OPT_QUIET, OPT_CONFIG,
    OPT_NO_CONDITIONAL_ERRORS,
    OPT_NO_SECURITY_CHECKS,
    OPT_SELF_TEST_ONLOAD
} OPTION_CHOICE;

const OPTIONS fipsinstall_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verify", OPT_VERIFY, '-',
        "Verify a config file instead of generating one"},
    {"module", OPT_MODULE, '<', "File name of the provider module"},
    {"provider_name", OPT_PROV_NAME, 's', "FIPS provider name"},
    {"section_name", OPT_SECTION_NAME, 's',
     "FIPS Provider config section name (optional)"},
     {"no_conditional_errors", OPT_NO_CONDITIONAL_ERRORS, '-',
      "Disable the ability of the fips module to enter an error state if"
      " any conditional self tests fail"},
    {"no_security_checks", OPT_NO_SECURITY_CHECKS, '-',
     "Disable the run-time FIPS security checks in the module"},
    {"self_test_onload", OPT_SELF_TEST_ONLOAD, '-',
     "Forces self tests to always run on module load"},
    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input config file, used when verifying"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output config file, used when generating"},
    {"mac_name", OPT_MAC_NAME, 's', "MAC name"},
    {"macopt", OPT_MACOPT, 's', "MAC algorithm parameters in n:v form. "
                                "See 'PARAMETER NAMES' in the EVP_MAC_ docs"},
    {"noout", OPT_NO_LOG, '-', "Disable logging of self test events"},
    {"corrupt_desc", OPT_CORRUPT_DESC, 's', "Corrupt a self test by description"},
    {"corrupt_type", OPT_CORRUPT_TYPE, 's', "Corrupt a self test by type"},
    {"config", OPT_CONFIG, '<', "The parent config to verify"},
    {"quiet", OPT_QUIET, '-', "No messages, just exit status"},
    {NULL}
};

static int do_mac(EVP_MAC_CTX *ctx, unsigned char *tmp, BIO *in,
                  unsigned char *out, size_t *out_len)
{
    int ret = 0;
    int i;
    size_t outsz = *out_len;

    if (!EVP_MAC_init(ctx, NULL, 0, NULL))
        goto err;
    if (EVP_MAC_CTX_get_mac_size(ctx) > outsz)
        goto end;
    while ((i = BIO_read(in, (char *)tmp, BUFSIZE)) != 0) {
        if (i < 0 || !EVP_MAC_update(ctx, tmp, i))
            goto err;
    }
end:
    if (!EVP_MAC_final(ctx, out, out_len, outsz))
        goto err;
    ret = 1;
err:
    return ret;
}

static int load_fips_prov_and_run_self_test(const char *prov_name)
{
    int ret = 0;
    OSSL_PROVIDER *prov = NULL;

    prov = OSSL_PROVIDER_load(NULL, prov_name);
    if (prov == NULL) {
        BIO_printf(bio_err, "Failed to load FIPS module\n");
        goto end;
    }

    pct_check();

    ret = 1;
end:
    OSSL_PROVIDER_unload(prov);
    return ret;
}

static int print_mac(BIO *bio, const char *label, const unsigned char *mac,
                     size_t len)
{
    int ret;
    char *hexstr = NULL;

    hexstr = OPENSSL_buf2hexstr(mac, (long)len);
    if (hexstr == NULL)
        return 0;
    ret = BIO_printf(bio, "%s = %s\n", label, hexstr);
    OPENSSL_free(hexstr);
    return ret;
}

static int write_config_header(BIO *out, const char *prov_name,
                               const char *section)
{
    return BIO_printf(out, "openssl_conf = openssl_init\n\n")
           && BIO_printf(out, "[openssl_init]\n")
           && BIO_printf(out, "providers = provider_section\n\n")
           && BIO_printf(out, "[provider_section]\n")
           && BIO_printf(out, "%s = %s\n\n", prov_name, section);
}

/*
 * Outputs a fips related config file that contains entries for the fips
 * module checksum, installation indicator checksum and the options
 * conditional_errors and security_checks.
 *
 * Returns 1 if the config file is written otherwise it returns 0 on error.
 */
static int write_config_fips_section(BIO *out, const char *section,
                                     unsigned char *module_mac,
                                     size_t module_mac_len,
                                     int conditional_errors,
                                     int security_checks,
                                     unsigned char *install_mac,
                                     size_t install_mac_len)
{
    int ret = 0;

    if (BIO_printf(out, "[%s]\n", section) <= 0
        || BIO_printf(out, "activate = 1\n") <= 0
        || BIO_printf(out, "%s = %s\n", OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
                      VERSION_VAL) <= 0
        || BIO_printf(out, "%s = %s\n", OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS,
                      conditional_errors ? "1" : "0") <= 0
        || BIO_printf(out, "%s = %s\n", OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS,
                      security_checks ? "1" : "0") <= 0
        || !print_mac(out, OSSL_PROV_FIPS_PARAM_MODULE_MAC, module_mac,
                      module_mac_len))
        goto end;

    if (install_mac != NULL && install_mac_len > 0) {
        if (!print_mac(out, OSSL_PROV_FIPS_PARAM_INSTALL_MAC, install_mac,
                       install_mac_len)
            || BIO_printf(out, "%s = %s\n", OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
                          INSTALL_STATUS_VAL) <= 0)
        goto end;
    }
    ret = 1;
end:
    return ret;
}

static CONF *generate_config_and_load(const char *prov_name,
                                      const char *section,
                                      unsigned char *module_mac,
                                      size_t module_mac_len,
                                      int conditional_errors,
                                      int security_checks)
{
    BIO *mem_bio = NULL;
    CONF *conf = NULL;

    mem_bio = BIO_new(BIO_s_mem());
    if (mem_bio  == NULL)
        return 0;
    if (!write_config_header(mem_bio, prov_name, section)
         || !write_config_fips_section(mem_bio, section,
                                       module_mac, module_mac_len,
                                       conditional_errors,
                                       security_checks,
                                       NULL, 0))
        goto end;

    conf = app_load_config_bio(mem_bio, NULL);
    if (conf == NULL)
        goto end;

    if (CONF_modules_load(conf, NULL, 0) <= 0)
        goto end;
    BIO_free(mem_bio);
    return conf;
end:
    NCONF_free(conf);
    BIO_free(mem_bio);
    return NULL;
}

static void free_config_and_unload(CONF *conf)
{
    if (conf != NULL) {
        NCONF_free(conf);
        CONF_modules_unload(1);
    }
}

static int verify_module_load(const char *parent_config_file)
{
    return OSSL_LIB_CTX_load_config(NULL, parent_config_file);
}

/*
 * Returns 1 if the config file entries match the passed in module_mac and
 * install_mac values, otherwise it returns 0.
 */
static int verify_config(const char *infile, const char *section,
                         unsigned char *module_mac, size_t module_mac_len,
                         unsigned char *install_mac, size_t install_mac_len)
{
    int ret = 0;
    char *s = NULL;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    long len;
    CONF *conf = NULL;

    /* read in the existing values and check they match the saved values */
    conf = app_load_config(infile);
    if (conf == NULL)
        goto end;

    s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_INSTALL_VERSION);
    if (s == NULL || strcmp(s, VERSION_VAL) != 0) {
        BIO_printf(bio_err, "version not found\n");
        goto end;
    }
    s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_MODULE_MAC);
    if (s == NULL) {
        BIO_printf(bio_err, "Module integrity MAC not found\n");
        goto end;
    }
    buf1 = OPENSSL_hexstr2buf(s, &len);
    if (buf1 == NULL
            || (size_t)len != module_mac_len
            || memcmp(module_mac, buf1, module_mac_len) != 0) {
        BIO_printf(bio_err, "Module integrity mismatch\n");
        goto end;
    }
    if (install_mac != NULL && install_mac_len > 0) {
        s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_INSTALL_STATUS);
        if (s == NULL || strcmp(s, INSTALL_STATUS_VAL) != 0) {
            BIO_printf(bio_err, "install status not found\n");
            goto end;
        }
        s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_INSTALL_MAC);
        if (s == NULL) {
            BIO_printf(bio_err, "Install indicator MAC not found\n");
            goto end;
        }
        buf2 = OPENSSL_hexstr2buf(s, &len);
        if (buf2 == NULL
                || (size_t)len != install_mac_len
                || memcmp(install_mac, buf2, install_mac_len) != 0) {
            BIO_printf(bio_err, "Install indicator status mismatch\n");
            goto end;
        }
    }
    ret = 1;
end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    NCONF_free(conf);
    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}
#if 0
int dh_genkey()
{
    int ret = 1;
    DH *dh = NULL;

end:
}
#endif

int dh_genkey()
{
    int ret = 1;
    DH *a = NULL;
    int i;
    BN_GENCB *_cb = NULL;
    const BIGNUM *ap = NULL, *ag = NULL, *apub_key = NULL;

    /*
     * II) key generation
     */

    /* generate a DH group ... */
    _cb = BN_GENCB_new();
    if ( !_cb )
        goto end;
    BN_GENCB_set(_cb, &cb, NULL);

    a = DH_new();
    if ( !a ) 
        goto end;

    ret = DH_generate_parameters_ex(a, 2048, DH_GENERATOR_2, _cb);
    if ( !ret )
        goto end;

    /* ... and check whether it is valid */
    if (!DH_check(a, &i))
        goto end;
    if (i & DH_CHECK_P_NOT_PRIME) printf("DH_CHECK_P_NOT_PRIME\n");
    if (i & DH_CHECK_P_NOT_SAFE_PRIME)printf("DH_CHECK_P_NOT_SAFE_PRIME\n");
    if (i & DH_UNABLE_TO_CHECK_GENERATOR)printf("DH_UNABLE_TO_CHECK_GENERATOR\n");
    if (i & DH_NOT_SUITABLE_GENERATOR)printf("DH_NOT_SUITABLE_GENERATOR\n");
    if (i & DH_CHECK_Q_NOT_PRIME)printf("DH_CHECK_Q_NOT_PRIME\n");
    if (i & DH_CHECK_INVALID_Q_VALUE)printf("DH_CHECK_INVALID_Q_VALUE\n");
    if (i & DH_CHECK_INVALID_J_VALUE)printf("DH_CHECK_INVALID_J_VALUE\n");
    if (i & DH_MODULUS_TOO_SMALL)printf("DH_MODULUS_TOO_SMALL\n");
    if (i & DH_MODULUS_TOO_LARGE)printf("DH_MODULUS_TOO_LARGE\n");

    DH_get0_pqg(a, &ap, NULL, &ag);

    if (!DH_generate_key(a))
        goto end;
    DH_get0_key(a, &apub_key, NULL);
    
end:
    DH_free(a);
    BN_GENCB_free(_cb);    
    return ret;
}

struct rsa_keygen_st {
    size_t mod;
    const unsigned char *e;
    size_t e_len;
    const unsigned char *xp1;
    size_t xp1_len;
    const unsigned char *xp2;
    size_t xp2_len;
    const unsigned char *xp;
    size_t xp_len;
    const unsigned char *xq1;
    size_t xq1_len;
    const unsigned char *xq2;
    size_t xq2_len;
    const unsigned char *xq;
    size_t xq_len;

    const unsigned char *p1;
    size_t p1_len;
    const unsigned char *p2;
    size_t p2_len;
    const unsigned char *q1;
    size_t q1_len;
    const unsigned char *q2;
    size_t q2_len;
    const unsigned char *p;
    size_t p_len;
    const unsigned char *q;
    size_t q_len;
    const unsigned char *n;
    size_t n_len;
    const unsigned char *d;
    size_t d_len;
};

static const unsigned char rsa_keygen0_e[] = {
    0x01,0x00,0x01
};
static const unsigned char rsa_keygen0_xp[] = {
    0xcf,0x72,0x1b,0x9a,0xfd,0x0d,0x22,0x1a,0x74,0x50,0x97,0x22,0x76,0xd8,0xc0,
    0xc2,0xfd,0x08,0x81,0x05,0xdd,0x18,0x21,0x99,0x96,0xd6,0x5c,0x79,0xe3,0x02,
    0x81,0xd7,0x0e,0x3f,0x3b,0x34,0xda,0x61,0xc9,0x2d,0x84,0x86,0x62,0x1e,0x3d,
    0x5d,0xbf,0x92,0x2e,0xcd,0x35,0x3d,0x6e,0xb9,0x59,0x16,0xc9,0x82,0x50,0x41,
    0x30,0x45,0x67,0xaa,0xb7,0xbe,0xec,0xea,0x4b,0x9e,0xa0,0xc3,0x05,0xb3,0x88,
    0xd4,0x4c,0xac,0xeb,0xe4,0x03,0xc6,0xca,0xcb,0xd9,0xd3,0x4e,0xf6,0x7f,0x2c,
    0x27,0x1e,0x08,0x6c,0xc2,0xd6,0x45,0x1f,0x84,0xe4,0x3c,0x97,0x19,0xde,0xb8,
    0x55,0xaf,0x0e,0xcf,0x9e,0xb0,0x9c,0x20,0xd3,0x1f,0xa8,0xd7,0x52,0xc2,0x95,
    0x1c,0x80,0x15,0x42,0x4d,0x4f,0x19,0x16
};
static const unsigned char rsa_keygen0_xp1[] = {
    0xac,0x5f,0x7f,0x6e,0x33,0x3e,0x97,0x3a,0xb3,0x17,0x44,0xa9,0x0f,0x7a,0x54,
    0x70,0x27,0x06,0x93,0xd5,0x49,0xde,0x91,0x83,0xbc,0x8a,0x7b,0x95
};
static const unsigned char rsa_keygen0_xp2[] = {
    0x0b,0xf6,0xe8,0x79,0x5a,0x81,0xae,0x90,0x1d,0xa4,0x38,0x74,0x9c,0x0e,0x6f,
    0xe0,0x03,0xcf,0xc4,0x53,0x16,0x32,0x17,0xf7,0x09,0x5f,0xd9
};
static const unsigned char rsa_keygen0_xq[] = {
    0xfe,0xab,0xf2,0x7c,0x16,0x4a,0xf0,0x8d,0x31,0xc6,0x0a,0x82,0xe2,0xae,0xbb,
    0x03,0x7e,0x7b,0x20,0x4e,0x64,0xb0,0x16,0xad,0x3c,0x01,0x1a,0xd3,0x54,0xbf,
    0x2b,0xa4,0x02,0x9e,0xc3,0x0d,0x60,0x3d,0x1f,0xb9,0xc0,0x0d,0xe6,0x97,0x68,
    0xbb,0x8c,0x81,0xd5,0xc1,0x54,0x96,0x0f,0x99,0xf0,0xa8,0xa2,0xf3,0xc6,0x8e,
    0xec,0xbc,0x31,0x17,0x70,0x98,0x24,0xa3,0x36,0x51,0xa8,0x54,0xbd,0x9a,0x89,
    0x99,0x6e,0x57,0x5e,0xd0,0x39,0x86,0xc3,0xa3,0x1b,0xc7,0xcf,0xc4,0x4f,0x47,
    0x25,0x9e,0x2c,0x79,0xe1,0x2c,0xcc,0xe4,0x63,0xf4,0x02,0x84,0xf8,0xf6,0xa1,
    0x5c,0x93,0x14,0xf2,0x68,0x5f,0x3a,0x90,0x2f,0x4e,0x5e,0xf9,0x16,0x05,0xcf,
    0x21,0x63,0xca,0xfa,0xb0,0x08,0x02,0xc0
};
static const unsigned char rsa_keygen0_xq1[] = {
    0x9b,0x02,0xd4,0xba,0xf0,0xaa,0x14,0x99,0x6d,0xc0,0xb7,0xa5,0xe1,0xd3,0x70,
    0xb6,0x5a,0xa2,0x9b,0x59,0xd5,0x8c,0x1e,0x9f,0x3f,0x9a,0xde,0xeb,0x9e,0x9c,
    0x61,0xd6,0x5a,0xe1
};
static const unsigned char rsa_keygen0_xq2[] = {
    0x06,0x81,0x53,0xfd,0xa8,0x7b,0xa3,0x85,0x90,0x15,0x2c,0x97,0xb2,0xa0,0x17,
    0x48,0xb0,0x7f,0x0a,0x01,0x6d
};
/* expected values */
static const unsigned char rsa_keygen0_p1[] = {
    0xac,0x5f,0x7f,0x6e,0x33,0x3e,0x97,0x3a,0xb3,0x17,0x44,0xa9,0x0f,0x7a,0x54,
    0x70,0x27,0x06,0x93,0xd5,0x49,0xde,0x91,0x83,0xbc,0x8a,0x7b,0xc3
};
static const unsigned char rsa_keygen0_p2[] = {
    0x0b,0xf6,0xe8,0x79,0x5a,0x81,0xae,0x90,0x1d,0xa4,0x38,0x74,0x9c,0x0e,0x6f,
    0xe0,0x03,0xcf,0xc4,0x53,0x16,0x32,0x17,0xf7,0x09,0x5f,0xd9
};
static const unsigned char rsa_keygen0_q1[] = {
    0x9b,0x02,0xd4,0xba,0xf0,0xaa,0x14,0x99,0x6d,0xc0,0xb7,0xa5,0xe1,0xd3,0x70,
    0xb6,0x5a,0xa2,0x9b,0x59,0xd5,0x8c,0x1e,0x9f,0x3f,0x9a,0xde,0xeb,0x9e,0x9c,
    0x61,0xd6,0x5d,0x47
};
static const unsigned char rsa_keygen0_q2[] = {
    0x06,0x81,0x53,0xfd,0xa8,0x7b,0xa3,0x85,0x90,0x15,0x2c,0x97,0xb2,0xa0,0x17,
    0x48,0xb0,0x7f,0x0a,0x01,0x8f
};
static const unsigned char rsa_keygen0_p[] = {
    0xcf,0x72,0x1b,0x9a,0xfd,0x0d,0x22,0x1a,0x74,0x50,0x97,0x22,0x76,0xd8,0xc0,
    0xc2,0xfd,0x08,0x81,0x05,0xdd,0x18,0x21,0x99,0x96,0xd6,0x5c,0x79,0xe3,0x02,
    0x81,0xd7,0x0e,0x3f,0x3b,0x34,0xda,0x61,0xc9,0x2d,0x84,0x86,0x62,0x1e,0x3d,
    0x5d,0xbf,0x92,0x2e,0xcd,0x35,0x3d,0x6e,0xb9,0x59,0x16,0xc9,0x82,0x50,0x41,
    0x30,0x45,0x67,0xaa,0xb7,0xbe,0xec,0xea,0x4b,0x9e,0xa0,0xc3,0x05,0xbc,0x4c,
    0x01,0xa5,0x4b,0xbd,0xa4,0x20,0xb5,0x20,0xd5,0x59,0x6f,0x82,0x5c,0x8f,0x4f,
    0xe0,0x3a,0x4e,0x7e,0xfe,0x44,0xf3,0x3c,0xc0,0x0e,0x14,0x2b,0x32,0xe6,0x28,
    0x8b,0x63,0x87,0x00,0xc3,0x53,0x4a,0x5b,0x71,0x7a,0x5b,0x28,0x40,0xc4,0x18,
    0xb6,0x77,0x0b,0xab,0x59,0xa4,0x96,0x7d
};
static const unsigned char rsa_keygen0_q[] = {
    0xfe,0xab,0xf2,0x7c,0x16,0x4a,0xf0,0x8d,0x31,0xc6,0x0a,0x82,0xe2,0xae,0xbb,
    0x03,0x7e,0x7b,0x20,0x4e,0x64,0xb0,0x16,0xad,0x3c,0x01,0x1a,0xd3,0x54,0xbf,
    0x2b,0xa4,0x02,0x9e,0xc3,0x0d,0x60,0x3d,0x1f,0xb9,0xc0,0x0d,0xe6,0x97,0x68,
    0xbb,0x8c,0x81,0xd5,0xc1,0x54,0x96,0x0f,0x99,0xf0,0xa8,0xa2,0xf3,0xc6,0x8e,
    0xec,0xbc,0x31,0x17,0x70,0x98,0x24,0xa3,0x36,0x51,0xa8,0x54,0xc4,0x44,0xdd,
    0xf7,0x7e,0xda,0x47,0x4a,0x67,0x44,0x5d,0x4e,0x75,0xf0,0x4d,0x00,0x68,0xe1,
    0x4a,0xec,0x1f,0x45,0xf9,0xe6,0xca,0x38,0x95,0x48,0x6f,0xdc,0x9d,0x1b,0xa3,
    0x4b,0xfd,0x08,0x4b,0x54,0xcd,0xeb,0x3d,0xef,0x33,0x11,0x6e,0xce,0xe4,0x5d,
    0xef,0xa9,0x58,0x5c,0x87,0x4d,0xc8,0xcf
};
static const unsigned char rsa_keygen0_n[] = {
    0xce,0x5e,0x8d,0x1a,0xa3,0x08,0x7a,0x2d,0xb4,0x49,0x48,0xf0,0x06,0xb6,0xfe,
    0xba,0x2f,0x39,0x7c,0x7b,0xe0,0x5d,0x09,0x2d,0x57,0x4e,0x54,0x60,0x9c,0xe5,
    0x08,0x4b,0xe1,0x1a,0x73,0xc1,0x5e,0x2f,0xb6,0x46,0xd7,0x81,0xca,0xbc,0x98,
    0xd2,0xf9,0xef,0x1c,0x92,0x8c,0x8d,0x99,0x85,0x28,0x52,0xd6,0xd5,0xab,0x70,
    0x7e,0x9e,0xa9,0x87,0x82,0xc8,0x95,0x64,0xeb,0xf0,0x6c,0x0f,0x3f,0xe9,0x02,
    0x29,0x2e,0x6d,0xa1,0xec,0xbf,0xdc,0x23,0xdf,0x82,0x4f,0xab,0x39,0x8d,0xcc,
    0xac,0x21,0x51,0x14,0xf8,0xef,0xec,0x73,0x80,0x86,0xa3,0xcf,0x8f,0xd5,0xcf,
    0x22,0x1f,0xcc,0x23,0x2f,0xba,0xcb,0xf6,0x17,0xcd,0x3a,0x1f,0xd9,0x84,0xb9,
    0x88,0xa7,0x78,0x0f,0xaa,0xc9,0x04,0x01,0x20,0x72,0x5d,0x2a,0xfe,0x5b,0xdd,
    0x16,0x5a,0xed,0x83,0x02,0x96,0x39,0x46,0x37,0x30,0xc1,0x0d,0x87,0xc2,0xc8,
    0x33,0x38,0xed,0x35,0x72,0xe5,0x29,0xf8,0x1f,0x23,0x60,0xe1,0x2a,0x5b,0x1d,
    0x6b,0x53,0x3f,0x07,0xc4,0xd9,0xbb,0x04,0x0c,0x5c,0x3f,0x0b,0xc4,0xd4,0x61,
    0x96,0x94,0xf1,0x0f,0x4a,0x49,0xac,0xde,0xd2,0xe8,0x42,0xb3,0x4a,0x0b,0x64,
    0x7a,0x32,0x5f,0x2b,0x5b,0x0f,0x8b,0x8b,0xe0,0x33,0x23,0x34,0x64,0xf8,0xb5,
    0x7f,0x69,0x60,0xb8,0x71,0xe9,0xff,0x92,0x42,0xb1,0xf7,0x23,0xa8,0xa7,0x92,
    0x04,0x3d,0x6b,0xff,0xf7,0xab,0xbb,0x14,0x1f,0x4c,0x10,0x97,0xd5,0x6b,0x71,
    0x12,0xfd,0x93,0xa0,0x4a,0x3b,0x75,0x72,0x40,0x96,0x1c,0x5f,0x40,0x40,0x57,
    0x13
};
static const unsigned char rsa_keygen0_d[] = {
    0x47,0x47,0x49,0x1d,0x66,0x2a,0x4b,0x68,0xf5,0xd8,0x4a,0x24,0xfd,0x6c,0xbf,
    0x56,0xb7,0x70,0xf7,0x9a,0x21,0xc8,0x80,0x9e,0xf4,0x84,0xcd,0x88,0x01,0x28,
    0xea,0x50,0xab,0x13,0x63,0xdf,0xea,0x14,0x38,0xb5,0x07,0x42,0x81,0x2f,0xda,
    0xe9,0x24,0x02,0x7e,0xaf,0xef,0x74,0x09,0x0e,0x80,0xfa,0xfb,0xd1,0x19,0x41,
    0xe5,0xba,0x0f,0x7c,0x0a,0xa4,0x15,0x55,0xa2,0x58,0x8c,0x3a,0x48,0x2c,0xc6,
    0xde,0x4a,0x76,0xfb,0x72,0xb6,0x61,0xe6,0xd2,0x10,0x44,0x4c,0x33,0xb8,0xd2,
    0x74,0xb1,0x9d,0x3b,0xcd,0x2f,0xb1,0x4f,0xc3,0x98,0xbd,0x83,0xb7,0x7e,0x75,
    0xe8,0xa7,0x6a,0xee,0xcc,0x51,0x8c,0x99,0x17,0x67,0x7f,0x27,0xf9,0x0d,0x6a,
    0xb7,0xd4,0x80,0x17,0x89,0x39,0x9c,0xf3,0xd7,0x0f,0xdf,0xb0,0x55,0x80,0x1d,
    0xaf,0x57,0x2e,0xd0,0xf0,0x4f,0x42,0x69,0x55,0xbc,0x83,0xd6,0x97,0x83,0x7a,
    0xe6,0xc6,0x30,0x6d,0x3d,0xb5,0x21,0xa7,0xc4,0x62,0x0a,0x20,0xce,0x5e,0x5a,
    0x17,0x98,0xb3,0x6f,0x6b,0x9a,0xeb,0x6b,0xa3,0xc4,0x75,0xd8,0x2b,0xdc,0x5c,
    0x6f,0xec,0x5d,0x49,0xac,0xa8,0xa4,0x2f,0xb8,0x8c,0x4f,0x2e,0x46,0x21,0xee,
    0x72,0x6a,0x0e,0x22,0x80,0x71,0xc8,0x76,0x40,0x44,0x61,0x16,0xbf,0xa5,0xf8,
    0x89,0xc7,0xe9,0x87,0xdf,0xbd,0x2e,0x4b,0x4e,0xc2,0x97,0x53,0xe9,0x49,0x1c,
    0x05,0xb0,0x0b,0x9b,0x9f,0x21,0x19,0x41,0xe9,0xf5,0x61,0xd7,0x33,0x2e,0x2c,
    0x94,0xb8,0xa8,0x9a,0x3a,0xcc,0x6a,0x24,0x8d,0x19,0x13,0xee,0xb9,0xb0,0x48,
    0x61
};

#define ITM(x) x, sizeof(x)

static const struct rsa_keygen_st rsa_keygen_data[] = {
    {
        2048,
        ITM(rsa_keygen0_e),
        ITM(rsa_keygen0_xp1),
        ITM(rsa_keygen0_xp2),
        ITM(rsa_keygen0_xp),
        ITM(rsa_keygen0_xq1),
        ITM(rsa_keygen0_xq2),
        ITM(rsa_keygen0_xq),

        ITM(rsa_keygen0_p1),
        ITM(rsa_keygen0_p2),
        ITM(rsa_keygen0_q1),
        ITM(rsa_keygen0_q2),

        ITM(rsa_keygen0_p),
        ITM(rsa_keygen0_q),
        ITM(rsa_keygen0_n),
        ITM(rsa_keygen0_d),
    },
};

int RSA_genkey()
{

    int ret = 1;
    unsigned int primes = 3;
    unsigned int bits = 4096;
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);

    EVP_PKEY_keygen_init(pctx);

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, params);

    EVP_PKEY_generate(pctx, &pkey);
    EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
    EVP_PKEY_CTX_free(pctx);

#if 0    
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *e_bn = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *xp1_bn = NULL, *xp2_bn = NULL, *xp_bn = NULL;
    BIGNUM *xq1_bn = NULL, *xq2_bn = NULL, *xq_bn = NULL;
    const struct rsa_keygen_st *tst = &rsa_keygen_data[0];

    bld = OSSL_PARAM_BLD_new();

    xp1_bn = BN_bin2bn(tst->xp1, tst->xp1_len, NULL);
    xp2_bn = BN_bin2bn(tst->xp2, tst->xp2_len, NULL);
    xp_bn = BN_bin2bn(tst->xp, tst->xp_len, NULL);
    xq1_bn = BN_bin2bn(tst->xq1, tst->xq1_len, NULL);
    xq2_bn = BN_bin2bn(tst->xq2, tst->xq2_len, NULL);
    xq_bn = BN_bin2bn(tst->xq, tst->xq_len, NULL);

    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP1,xp1_bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP2,xp2_bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP,xp_bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ1,xq1_bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ2,xq2_bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ,xq_bn);
    params = OSSL_PARAM_BLD_to_param(bld);

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    e_bn = BN_bin2bn(tst->e, tst->e_len, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_params(ctx, params);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, tst->mod);
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e_bn);
    EVP_PKEY_keygen(ctx, &pkey);

    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);


    
    const int kBits = 1024;
    const int kExp = 3;

    int keylen;
    char *pem_key;

    RSA *rsa = RSA_generate_key(kBits, kExp, 0, 0);

    /* To get the C-string PEM form: */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    keylen = BIO_pending(bio);
    pem_key = calloc(keylen+1, 1); /* Null-terminate */
    BIO_read(bio, pem_key, keylen);

    printf("%s", pem_key);

    BIO_free_all(bio);
    RSA_free(rsa);
    free(pem_key);
#endif
    return ret;
}




static int pkey_get_bn_bytes(EVP_PKEY *pkey, const char *name,
                             unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    BIGNUM *bn = NULL;
    int sz;

    if (!EVP_PKEY_get_bn_param(pkey, name, &bn))
        goto err;
    sz = BN_num_bytes(bn);
    buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (BN_bn2binpad(bn, buf, sz) <= 0)
        goto err;

    *out_len = sz;
    *out = buf;
    BN_free(bn);
    return 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return 0;
}

int ECDSA_genkey()
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    const unsigned char *pub;
    size_t pub_len;
    EVP_PKEY *pkey = NULL;

    bld = OSSL_PARAM_BLD_new();
    if ( !bld ) {
        printf("OSSL_PARAM_BLD_new\n");
    }

    ret = OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-224", 0);
    if( ret == 0 ) {
        printf("OSSL_PARAM_BLD_push_utf8_string\n");
        goto err;
    }
    ret = OSSL_PARAM_BLD_push_octet_string(bld,
                                                       OSSL_PKEY_PARAM_PUB_KEY,
                                                       pub, pub_len);
    if( ret == 0 ) {
        printf("OSSL_PARAM_BLD_push_octet_string\n");
        goto err;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if ( !params ){
        printf("OSSL_PARAM_BLD_to_param\n");
        goto err;
    }


    ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if ( !ctx ){
        printf("EVP_PKEY_CTX_new_from_name\n");
        goto err;
    }
    ret = EVP_PKEY_fromdata_init(ctx);
    if ( ret < 1 ){
        printf("EVP_PKEY_fromdata_init\n");
        goto err;
    }

    ret = EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params);
    if ( ret < 1 ){
        printf("EVP_PKEY_fromdata\n");
        goto err;
    }

    EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
    
    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

#if 0
    EVP_PKEY *pkey = NULL;
    unsigned char *priv = NULL;
    unsigned char *pubx = NULL, *puby = NULL;
    size_t priv_len = 0, pubx_len = 0, puby_len = 0;
    
    self_test_args.called = 0;
    self_test_args.enable = 1;
    pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-224");
    if (!pkey) {
        printf("EVP_PKEY_Q_keygen\n");
        goto err;
    }

    printf("self_test_args.called %d\n", self_test_args.called);
            
    if(!pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv, &priv_len)) {
        printf("pkey_get_bn_bytes\n");
        goto err;
    }
    if(!pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pubx, &pubx_len)) {
        printf("pkey_get_bn_bytes\n");
        goto err;
    }
    if (!pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &puby, &puby_len)) {
        printf("pkey_get_bn_bytes\n");
        goto err;
    }
        

    printf("qy %s\n", puby, puby_len);
    printf("qx %s\n", pubx, pubx_len);
    printf("d %s\n", priv, priv_len);
    ret = 1;
err:
    self_test_args.enable = 0;
    self_test_args.called = 0;
    OPENSSL_clear_free(priv, priv_len);
    OPENSSL_free(pubx);
    OPENSSL_free(puby);
    EVP_PKEY_free(pkey);
    return ret;

    int ret = 1;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey_temp = NULL;
 
    // Create the context for the key generation
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!kctx)
    {
        printf("EVP_PKEY_CTX_new");
        return 0;
    }

    // Generate the key
    if(1 != EVP_PKEY_keygen_init(kctx))
    {
        printf("EVP_PKEY_keygen_init");
        return 0;
    }

    //  We're going to use the ANSI X9.62 Prime 256v1 curve
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1)) 
    {
        printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        return 0;
    }
    
    if (1 != EVP_PKEY_keygen(kctx, &pkey_temp))
    {
        printf("EVP_PKEY_keygen");
        return 0;
    }

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey_temp);

    return ret;
    #endif
}

int ECDH_genkey()
{
    int ret = 1;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey_temp = NULL;
 
    // Create the context for the key generation
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!kctx)
    {
        printf("EVP_PKEY_CTX_new");
        return 0;
    }

    // Generate the key
    if(1 != EVP_PKEY_keygen_init(kctx))
    {
        printf("EVP_PKEY_keygen_init");
        return 0;
    }

    //  We're going to use the ANSI X9.62 Prime 256v1 curve
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp384r1)) 
    {
        printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        return 0;
    }
    
    if (1 != EVP_PKEY_keygen(kctx, &pkey_temp))
    {
        printf("EVP_PKEY_keygen");
        return 0;
    }

    EVP_PKEY_print_private(bio_out, pkey_temp, 0, NULL);

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey_temp);

    return ret;
}

int gen_dh_key(void)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("group", "ffdhe2048", 0);
    params[1] = OSSL_PARAM_construct_end();

    gctx = EVP_PKEY_CTX_new_from_name(libctx, "DH", NULL);
    if (!gctx)
        printf("EVP_PKEY_CTX_new_from_name\n");
    EVP_PKEY_keygen_init(gctx);
    EVP_PKEY_CTX_set_params(gctx, params);
    EVP_PKEY_keygen(gctx, &pkey);
    EVP_PKEY_print_private(bio_out, pkey, 0, NULL);

err:
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(pkey);
    return 1;
}

int pct_check()
{
    int ret = 1;
    
    libctx = app_get0_libctx();

    OSSL_SELF_TEST_set_callback(libctx, self_test_events, &self_test_args);

printf("RSA_genkey\n");
    RSA_genkey();

printf("ECDSA_genkey\n");
    ECDSA_genkey();

printf("gen_dh_key\n");
    gen_dh_key();

printf("PCT complete\n");

    //ECDH_genkey();
    
    end:

    return ret;
}

int fipsinstall_main(int argc, char **argv)
{
    int ret = 1, verify = 0, gotkey = 0, gotdigest = 0, self_test_onload = 0;
    int enable_conditional_errors = 1, enable_security_checks = 1;
    const char *section_name = "fips_sect";
    const char *mac_name = "HMAC";
    const char *prov_name = "fips";
    BIO *module_bio = NULL, *mem_bio = NULL, *fout = NULL;
    char *in_fname = NULL, *out_fname = NULL, *prog;
    char *module_fname = NULL, *parent_config = NULL, *module_path = NULL;
    const char *tail;
    EVP_MAC_CTX *ctx = NULL, *ctx2 = NULL;
    STACK_OF(OPENSSL_STRING) *opts = NULL;
    OPTION_CHOICE o;
    unsigned char *read_buffer = NULL;
    unsigned char module_mac[EVP_MAX_MD_SIZE];
    size_t module_mac_len = EVP_MAX_MD_SIZE;
    unsigned char install_mac[EVP_MAX_MD_SIZE];
    size_t install_mac_len = EVP_MAX_MD_SIZE;
    EVP_MAC *mac = NULL;
    CONF *conf = NULL;

    //BIO_printf(bio_err, "This command is not enabled in the Rocky Enterprise Linux OpenSSL build, please consult Rocky documentation to learn how to enable FIPS mode\n");
    //return 1;

    if ((opts = sk_OPENSSL_STRING_new_null()) == NULL)
        goto end;

    prog = opt_init(argc, argv, fipsinstall_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto cleanup;
        case OPT_HELP:
            opt_help(fipsinstall_options);
            ret = 0;
            goto end;
        case OPT_IN:
            in_fname = opt_arg();
            break;
        case OPT_OUT:
            out_fname = opt_arg();
            break;
        case OPT_NO_CONDITIONAL_ERRORS:
            enable_conditional_errors = 0;
            break;
        case OPT_NO_SECURITY_CHECKS:
            enable_security_checks = 0;
            break;
        case OPT_QUIET:
            quiet = 1;
            /* FALLTHROUGH */
        case OPT_NO_LOG:
            self_test_log = 0;
            break;
        case OPT_CORRUPT_DESC:
            self_test_corrupt_desc = opt_arg();
            break;
        case OPT_CORRUPT_TYPE:
            self_test_corrupt_type = opt_arg();
            break;
        case OPT_PROV_NAME:
            prov_name = opt_arg();
            break;
        case OPT_MODULE:
            module_fname = opt_arg();
            break;
        case OPT_SECTION_NAME:
            section_name = opt_arg();
            break;
        case OPT_MAC_NAME:
            mac_name = opt_arg();
            break;
        case OPT_CONFIG:
            parent_config = opt_arg();
            break;
        case OPT_MACOPT:
            if (!sk_OPENSSL_STRING_push(opts, opt_arg()))
                goto opthelp;
            if (strncmp(opt_arg(), "hexkey:", 7) == 0)
                gotkey = 1;
            else if (strncmp(opt_arg(), "digest:", 7) == 0)
                gotdigest = 1;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        case OPT_SELF_TEST_ONLOAD:
            self_test_onload = 1;
            break;
        }
    }

    /* No extra arguments. */
    argc = opt_num_rest();
    if (argc != 0 || (verify && in_fname == NULL))
        goto opthelp;

    if (parent_config != NULL) {
        /* Test that a parent config can load the module */
        if (verify_module_load(parent_config)) {
            ret = OSSL_PROVIDER_available(NULL, prov_name) ? 0 : 1;
            if (!quiet)
                BIO_printf(bio_err, "FIPS provider is %s\n",
                           ret == 0 ? "available" : " not available");
        }
        goto end;
    }
    if (module_fname == NULL)
        goto opthelp;

    tail = opt_path_end(module_fname);
    if (tail != NULL) {
        module_path = OPENSSL_strdup(module_fname);
        if (module_path == NULL)
            goto end;
        module_path[tail - module_fname] = '\0';
        if (!OSSL_PROVIDER_set_default_search_path(NULL, module_path))
            goto end;
    }

    if (self_test_log
            || self_test_corrupt_desc != NULL
            || self_test_corrupt_type != NULL)
        OSSL_SELF_TEST_set_callback(NULL, self_test_events, NULL);

    /* Use the default FIPS HMAC digest and key if not specified. */
    if (!gotdigest && !sk_OPENSSL_STRING_push(opts, "digest:SHA256"))
        goto end;
    if (!gotkey && !sk_OPENSSL_STRING_push(opts, "hexkey:" FIPS_KEY_STRING))
        goto end;

    module_bio = bio_open_default(module_fname, 'r', FORMAT_BINARY);
    if (module_bio == NULL) {
        BIO_printf(bio_err, "Failed to open module file\n");
        goto end;
    }

    read_buffer = app_malloc(BUFSIZE, "I/O buffer");
    if (read_buffer == NULL)
        goto end;

    mac = EVP_MAC_fetch(app_get0_libctx(), mac_name, app_get0_propq());
    if (mac == NULL) {
        BIO_printf(bio_err, "Unable to get MAC of type %s\n", mac_name);
        goto end;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for module check\n");
        goto end;
    }

    if (opts != NULL) {
        int ok = 1;
        OSSL_PARAM *params =
            app_params_new_from_opts(opts, EVP_MAC_settable_ctx_params(mac));

        if (params == NULL)
            goto end;

        if (!EVP_MAC_CTX_set_params(ctx, params)) {
            BIO_printf(bio_err, "MAC parameter error\n");
            ERR_print_errors(bio_err);
            ok = 0;
        }
        app_params_free(params);
        if (!ok)
            goto end;
    }

    ctx2 = EVP_MAC_CTX_dup(ctx);
    if (ctx2 == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for install indicator\n");
        goto end;
    }

    if (!do_mac(ctx, read_buffer, module_bio, module_mac, &module_mac_len))
        goto end;

    if (self_test_onload == 0) {
        mem_bio = BIO_new_mem_buf((const void *)INSTALL_STATUS_VAL,
                                  strlen(INSTALL_STATUS_VAL));
        if (mem_bio == NULL) {
            BIO_printf(bio_err, "Unable to create memory BIO\n");
            goto end;
        }
        if (!do_mac(ctx2, read_buffer, mem_bio, install_mac, &install_mac_len))
            goto end;
    } else {
        install_mac_len = 0;
    }

    if (verify) {
        if (!verify_config(in_fname, section_name, module_mac, module_mac_len,
                           install_mac, install_mac_len))
            goto end;
        if (!quiet)
            BIO_printf(bio_err, "VERIFY PASSED\n");
    } else {

        conf = generate_config_and_load(prov_name, section_name, module_mac,
                                        module_mac_len,
                                        enable_conditional_errors,
                                        enable_security_checks);
        if (conf == NULL)
            goto end;
        if (!load_fips_prov_and_run_self_test(prov_name))
            goto end;

        fout =
            out_fname == NULL ? dup_bio_out(FORMAT_TEXT)
                              : bio_open_default(out_fname, 'w', FORMAT_TEXT);
        if (fout == NULL) {
            BIO_printf(bio_err, "Failed to open file\n");
            goto end;
        }
        if (!write_config_fips_section(fout, section_name,
                                       module_mac, module_mac_len,
                                       enable_conditional_errors,
                                       enable_security_checks,
                                       install_mac, install_mac_len))
            goto end;
        if (!quiet)
            BIO_printf(bio_err, "INSTALL PASSED\n");
    }

    ret = 0;
end:
    if (ret == 1) {
        if (!quiet)
            BIO_printf(bio_err, "%s FAILED\n", verify ? "VERIFY" : "INSTALL");
        ERR_print_errors(bio_err);
    }

cleanup:
    OPENSSL_free(module_path);
    BIO_free(fout);
    BIO_free(mem_bio);
    BIO_free(module_bio);
    sk_OPENSSL_STRING_free(opts);
    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx2);
    EVP_MAC_CTX_free(ctx);
    OPENSSL_free(read_buffer);
    free_config_and_unload(conf);
    return ret;
}

static int self_test_events(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p = NULL;
    const char *phase = NULL, *type = NULL, *desc = NULL;
    int ret = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    phase = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    desc = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    type = (const char *)p->data;

    if (self_test_log) {
        if (strcmp(phase, OSSL_SELF_TEST_PHASE_START) == 0)
            BIO_printf(bio_err, "%s : (%s) : ", desc, type);
        else if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0
                 || strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0)
            BIO_printf(bio_err, "%s\n", phase);
    }
    /*
     * The self test code will internally corrupt the KAT test result if an
     * error is returned during the corrupt phase.
     */
    if (strcmp(phase, OSSL_SELF_TEST_PHASE_CORRUPT) == 0
            && (self_test_corrupt_desc != NULL
                || self_test_corrupt_type != NULL)) {
        if (self_test_corrupt_desc != NULL
                && strcmp(self_test_corrupt_desc, desc) != 0)
            goto end;
        if (self_test_corrupt_type != NULL
                && strcmp(self_test_corrupt_type, type) != 0)
            goto end;
        BIO_printf(bio_err, "%s ", phase);
        goto err;
    }
end:
    ret = 1;
err:
    return ret;
}
