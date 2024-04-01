#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/self_test.h>
#include <stdio.h>

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
            fprintf(stderr, "%s : (%s) : ", desc, type);
        else if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0
                 || strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0)
            fprintf(stderr, "%s\n", phase);
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
        fprintf(stderr, "%s ", phase);
        goto err;
    }
end:
    ret = 1;
err:
    return ret;
}


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
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "");    
    
    if ( EVP_PKEY_pairwise_check(pctx) != 1) {
        printf("CHECK FAILED\n");
        goto err;
    }
    
    EVP_PKEY_print_private_fp(stdout, pkey, 0, NULL);
err:
    printf ("err:\n");
    ERR_print_errors_fp(stderr);
    printf("\n*********************************\n");
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

int do_ec_keygen(void)
{
    /*
     * The libctx and propq can be set if required, they are included here
     * to show how they are passed to EVP_PKEY_CTX_new_from_name().
     */
    int ret = 0;
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *genctx = NULL;
    const char *curvename = "P-256";
    int use_cofactordh = 1;

    genctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
    if (genctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)curvename, 0);
    /*
     * This is an optional parameter.
     * For many curves where the cofactor is 1, setting this has no effect.
     */
    params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                         &use_cofactordh);
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(genctx, params)) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params() failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating EC key\n\n");
    if (EVP_PKEY_generate(genctx, &key) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        goto cleanup;
    }

    
    EVP_PKEY_print_private_fp(stdout, key, 0, NULL);
    
    ret = 1;
cleanup:
    printf("\n*********************************\n");
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(key);
    return ret;
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
    EVP_PKEY_CTX *key_ctx = NULL;
    
    bld = OSSL_PARAM_BLD_new();
    if ( !bld ) {
        printf("OSSL_PARAM_BLD_new\n");
        goto err;
    }

    ret = OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    if( ret == 0 ) {
        printf("OSSL_PARAM_BLD_push_utf8_string\n");
        goto err;
    }
    ret = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len);
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

    ret = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    if ( ret < 0 ){
        printf("EVP_PKEY_fromdata\n");
        goto err;
    }
    //key_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey);
        
    EVP_PKEY_print_private_fp(stdout, pkey, 0, NULL);
    
    
    ret = 1;
err:
    printf("\n*********************************\n");
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
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
        printf("EVP_PKEY_CTX_new\n");
        return 0;
    }

    // Generate the key
    if(1 != EVP_PKEY_keygen_init(kctx))
    {
        printf("EVP_PKEY_keygen_init\n");
        EVP_PKEY_CTX_free(kctx);
        return 0;
    }

    //  We're going to use the ANSI X9.62 Prime 256v1 curve
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp384r1)) 
    {
        printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid\n");
        goto end;
    }
    
    if (1 != EVP_PKEY_keygen(kctx, &pkey_temp))
    {
        printf("EVP_PKEY_keygen\n");
        goto end;
    }

    
    EVP_PKEY_print_private_fp(stdout, pkey_temp, 0, NULL);
    

end:
    printf("\n*********************************\n");
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
    if (!gctx) {
        printf("EVP_PKEY_CTX_new_from_name\n");
        goto err;
    }

    if ( 1 != EVP_PKEY_keygen_init(gctx) ) {
        printf("EVP_PKEY_keygen_init\n");
        EVP_PKEY_CTX_free(gctx);
        return 0;
    }

    EVP_PKEY_CTX_set_params(gctx, params);
    if (1 != EVP_PKEY_keygen(gctx, &pkey) ){
        printf("EVP_PKEY_keygen\n");
        goto err;
    }

    EVP_PKEY_CTX_free(gctx);
    gctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "");

    if ( EVP_PKEY_pairwise_check(gctx) != 1) {
        printf("CHECK FAILED\n");
        goto err;
    }
    
    EVP_PKEY_print_private_fp(stdout, pkey, 0, NULL);
    

err:
    printf ("err:\n");
    ERR_print_errors_fp(stderr);
    printf("\n*********************************\n");
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(pkey);
    return 1;
}

int pct_check()
{
    int ret = 1;
    
    //OSSL_SELF_TEST_set_callback(libctx, self_test_events, &self_test_args);

printf("RSA_genkey\n");
    RSA_genkey();

printf("ECDSA_genkey\n");
    do_ec_keygen();
    //ECDSA_genkey();

printf("gen_dh_key\n");
    gen_dh_key();

printf("ECDH_genkey\n");
    ECDH_genkey();

printf("PCT complete\n");
    
    end:

    return ret;
}

int Query_MD(char *info)
{
    EVP_MD_CTX * mdctx;
    EVP_MD * md;
    mdctx = EVP_MD_CTX_new();
    md = EVP_MD_fetch(NULL,info,"fips=yes");
    if (md == NULL) {
        printf("%s NOT APPROVED\n", info);
        return 1;
    }

    printf("EVP_DigestInit_ex(mdctx,%s,NULL): %d\n", info, EVP_DigestInit_ex(mdctx,md,NULL));
    printf("OSSL_PROVIDER_available: %d\n",OSSL_PROVIDER_available(NULL,"fips"));
    printf(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(EVP_MD_CTX_get0_md(mdctx))));
    printf("\n");

    EVP_MD_free(md);
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int Query_CIPHER(char *info)
{
    EVP_CIPHER_CTX * cctx;
    EVP_CIPHER *cipher;
    cctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL,info,"fips=yes");
    if (cipher == NULL){
        printf("%s NOT APPROVED\n", info);
        return 1;
    }
    
    printf("%s APPROVED\n", info);
    
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(cctx);
    return 0;
}

int main(int argc, char *argv[]) 
{
    int ret = 0;

    libctx = OSSL_LIB_CTX_new();

    
    self_test_corrupt_desc = argv[1];

    OSSL_SELF_TEST_set_callback(NULL, self_test_events, NULL);

    ret = OSSL_PROVIDER_available(NULL, "default");
    printf("default provider available: %d\n", ret);
    printf("*************************************\n", ret);
    ret = OSSL_PROVIDER_available(NULL, "fips");
    printf("fips provider available: %d\n", ret);
    if ( ret == 0)
        goto end;        
    
    printf("*************************************\n", ret);

    Query_MD("SHA-256");       
    Query_MD("MD5");
    Query_MD("sha1");
    Query_MD("sha256");
Query_MD("sha384"); 
Query_MD("sha512");
Query_MD("sha512-224");
Query_MD("sha512-256");
Query_MD("sha3-224");
Query_MD("sha3-256");
Query_MD("sha3-384");
Query_MD("sha3-512");
Query_MD("shake128");
Query_MD("shake256");
Query_MD("rmd160");
Query_MD("blake2b512");
Query_MD("blake2s256");
Query_MD("sm3");
    Query_CIPHER("AES-128-CBC-CTS");              
    Query_CIPHER("genrsa");    
    Query_CIPHER("DSA");
    Query_CIPHER("des");
    Query_CIPHER("des-cbc");
    Query_CIPHER("des3");
    Query_CIPHER("des-ede3-cbc");

    printf("*************************************\n", ret);

exit(1);

    pct_check();

    ret =1;
end:
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

#if 0
int main(int argc, char *argv[]) 
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gen_ctx;
    int ret;
    int bits = 4096; /* example failing bits value */
    OSSL_PARAM params[3];
    unsigned int primes = 3;
    OSSL_LIB_CTX *app_libctx = NULL;

    app_libctx = OSSL_LIB_CTX_new();

    OSSL_PROVIDER_set_default_search_path(NULL, "/home/jrodriguez/FIPS/92/o3/src-git/INSTALL/lib64/ossl-modules/");
    if (!OSSL_LIB_CTX_load_config(NULL, "./gentest.cnf")) goto end;

    ret = OSSL_PROVIDER_available(NULL, "default");
    printf("default provider available: %d\n", ret);
    ret = OSSL_PROVIDER_available(NULL, "fips");
    printf("fips provider available: %d\n", ret);


    printf("Generating RSA key ( %d bits) \n", bits);
    gen_ctx =
        EVP_PKEY_CTX_new_from_name(app_libctx, "RSA", "fips");    
    if (gen_ctx == NULL) goto end;

    pkey = EVP_RSA_gen(4096);

    /*EVP_PKEY_keygen_init(gen_ctx);

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(gen_ctx, params);
    EVP_PKEY_keygen(gen_ctx, &pkey);*/

    //if (EVP_PKEY_pairwise_check(gen_ctx) <= 0)goto end;

    EVP_PKEY_print_private_fp(stdout, pkey, 0, NULL);

    printf("... done generating RSA key\n");

end:
    printf ("err:\n");
    ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gen_ctx);
    OSSL_LIB_CTX_free(app_libctx);
    return 1;
}





int main(int argc, char *argv[]) 
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gen_ctx;
    int ret;
    int bits = 3072; /* example failing bits value */

    OSSL_PROVIDER_set_default_search_path(NULL, "/home/jrodriguez/FIPS/92/o3/src-git/INSTALL/lib64/ossl-modules/");
    if (!OSSL_LIB_CTX_load_config(NULL, "./gentest.cnf")) goto end;

    ret = OSSL_PROVIDER_available(NULL, "default");
    printf("default provider available: %d\n", ret);
    ret = OSSL_PROVIDER_available(NULL, "fips");
    printf("fips provider available: %d\n", ret);

    printf("Generating RSA key ( %d bits) \n", bits);
    gen_ctx = EVP_PKEY_CTX_new_id(NID_rsaEncryption, NULL);   
    if (gen_ctx == NULL) goto end;

    if (EVP_PKEY_keygen_init(gen_ctx) <= 0) goto end;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(gen_ctx, bits) <= 0) goto end;

    if (EVP_PKEY_keygen(gen_ctx, &pkey) <= 0) goto end;
    if (EVP_PKEY_pairwise_check(gen_ctx) <= 0)goto end;

    EVP_PKEY_print_private_fp(stdout, pkey, 0, NULL);

    printf("... done generating RSA key\n");

end:
    printf ("err:\n");
    ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gen_ctx);    
    return 1;
}


int main(int argc, char *argv[]) 
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gen_ctx;
    int ret;
    int bits = 3072; /* example failing bits value */

    OSSL_PROVIDER_set_default_search_path(NULL, "/home/jrodriguez/FIPS/92/o3/src-git/INSTALL/lib64/ossl-modules/");
    if (!OSSL_LIB_CTX_load_config(NULL, "./gentest.cnf")) goto end;

    ret = OSSL_PROVIDER_available(NULL, "default");
    printf("default provider available: %d\n", ret);
    ret = OSSL_PROVIDER_available(NULL, "fips");
    printf("fips provider available: %d\n", ret);

    printf("Generating RSA key ( %d bits) \n", bits);
    gen_ctx = EVP_PKEY_CTX_new_id(NID_rsaEncryption, NULL);   
    if (gen_ctx == NULL) goto end;

    if (EVP_PKEY_keygen_init(gen_ctx) <= 0) goto end;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(gen_ctx, bits) <= 0) goto end;

    if (EVP_PKEY_keygen(gen_ctx, &pkey) <= 0) goto end;

    EVP_PKEY_print_private_fp(stdout, pkey, 0, NULL);

    printf("... done generating RSA key\n");

end:
    printf ("err:\n");
    ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gen_ctx);
    BIO_free_all(bio_out);
    return 1;
}
#endif