/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <internal/cryptlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/err.h>
/* Needed to get the other O_xxx flags. */
#ifdef OPENSSL_SYS_VMS
# include <unixio.h>
#endif
#include "apps.h"
#define INCLUDE_FUNCTION_TABLE
#include "progs.h"
#include "openssl/fips.h"
#include "openssl/fips_rand.h"

/* Structure to hold the number of columns to be displayed and the
 * field width used to display them.
 */
typedef struct {
    int columns;
    int width;
} DISPLAY_COLUMNS;

/* Special sentinel to exit the program. */
#define EXIT_THE_PROGRAM (-1)

/*
 * The LHASH callbacks ("hash" & "cmp") have been replaced by functions with
 * the base prototypes (we cast each variable inside the function to the
 * required type of "FUNCTION*"). This removes the necessity for
 * macro-generated wrapper functions.
 */
static LHASH_OF(FUNCTION) *prog_init(void);
static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[]);
static void list_pkey(void);
static void list_pkey_meth(void);
static void list_type(FUNC_TYPE ft, int one);
static void list_disabled(void);
char *default_config_file = NULL;

BIO *bio_in = NULL;
BIO *bio_out = NULL;
BIO *bio_err = NULL;

static void calculate_columns(DISPLAY_COLUMNS *dc)
{
    FUNCTION *f;
    int len, maxlen = 0;

    for (f = functions; f->name != NULL; ++f)
        if (f->type == FT_general || f->type == FT_md || f->type == FT_cipher)
            if ((len = strlen(f->name)) > maxlen)
                maxlen = len;

    dc->width = maxlen + 2;
    dc->columns = (80 - 1) / dc->width;
}

static int apps_startup(void)
{
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Set non-default library initialisation settings */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN
                          | OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;

    setup_ui_method();

    return 1;
}

static void apps_shutdown(void)
{
    destroy_ui_method();
    destroy_prefix_method();
}

static char *make_config_name(void)
{
    const char *t;
    size_t len;
    char *p;

    if ((t = getenv("OPENSSL_CONF")) != NULL)
        return OPENSSL_strdup(t);

    t = X509_get_default_cert_area();
    len = strlen(t) + 1 + strlen(OPENSSL_CONF) + 1;
    p = app_malloc(len, "config filename buffer");
    strcpy(p, t);
#ifndef OPENSSL_SYS_VMS
    strcat(p, "/");
#endif
    strcat(p, OPENSSL_CONF);

    return p;
}

typedef struct 
	{
	int id;
	const char *name;
	} POST_ID;

POST_ID id_list[] = {
	{NID_sha1, "SHA1"},
	{NID_sha224, "SHA224"},
	{NID_sha256, "SHA256"},
	{NID_sha384, "SHA384"},
	{NID_sha512, "SHA512"},
	{NID_hmacWithSHA1, "HMAC-SHA1"},
	{NID_hmacWithSHA224, "HMAC-SHA224"},
	{NID_hmacWithSHA256, "HMAC-SHA256"},
	{NID_hmacWithSHA384, "HMAC-SHA384"},
	{NID_hmacWithSHA512, "HMAC-SHA512"},
    {NID_sha3_256, "SHA3-256"},
    {NID_sha3_512, "SHA3-512"},
    {NID_shake128, "shake128"},
    {NID_shake256, "shake256"},
	{EVP_PKEY_RSA, "RSA"},
	{EVP_PKEY_DSA, "DSA"},
	{EVP_PKEY_EC, "ECDSA"},
	{EVP_PKEY_DH, "DH"},	
	{NID_aes_128_cbc, "AES-128-CBC"},
	{NID_aes_192_cbc, "AES-192-CBC"},
	{NID_aes_256_cbc, "AES-256-CBC"},
	{NID_aes_128_ctr, "AES-128-CTR"},
	{NID_aes_192_ctr, "AES-192-CTR"},
	{NID_aes_256_ctr, "AES-256-CTR"},
    {NID_aes_256_gcm, "AES-256-GCM"},
    {NID_aes_192_ccm, "AES-192-CCM"},
	{NID_aes_128_ecb, "AES-128-ECB"},
	{NID_aes_128_xts, "AES-128-XTS"},
	{NID_aes_256_xts, "AES-256-XTS"},
	{NID_des_ede3_cbc, "DES-EDE3-CBC"},
	{NID_des_ede3_ecb, "DES-EDE3-ECB"},
	{NID_secp224r1, "P-224"},
	{NID_sect233r1, "B-233"},
	{NID_sect233k1, "K-233"},
	{NID_X9_62_prime256v1, "P-256"},
	{NID_secp384r1, "P-384"},
	{NID_secp521r1, "P-521"},
    {NID_secp256k1, "secp256k1"},
    {RSA_NO_PADDING, "RSA_NO_PADDING"},
    {0, NULL}
};

static const char *lookup_id(int id)
	{
	POST_ID *n;
	static char out[40];
	for (n = id_list; n->name; n++)
		{
		if (n->id == id)
			return n->name;
		}
	sprintf(out, "ID=%d", id);
	return out;
	}

static int fail_id = -1;
static int fail_sub = -1;
static int fail_key = -1;

static int st_err, post_quiet = 0;

static int post_cb(int op, int id, int subid, void *ex)
	{
	const char *idstr, *exstr = "";
	char asctmp[20];
	int keytype = -1;
	int exp_fail = 0;
#ifdef FIPS_POST_TIME
	static struct timespec start, end, tstart, tend;
#endif
	switch(id)
		{
        case FIPS_TEST_RSA_ENCRYPT:
		idstr = "RSA ENCRYPT";
        exstr = lookup_id(subid);
		break;
		case FIPS_TEST_RSA_DECRYPT:
		idstr = "RSA DECRYPT";
        exstr = lookup_id(subid);
		break;
		case FIPS_TEST_INTEGRITY:
		idstr = "Integrity";
		if (subid == 1)
			exstr = "libcrypto";
		else if (subid == 2)
			exstr = "libssl";
		else
		   return 1;
		break;

		case FIPS_TEST_DIGEST:
		idstr = "Digest";
		exstr = lookup_id(subid);
		break;

		case FIPS_TEST_CIPHER:
		exstr = lookup_id(subid);
		idstr = "Cipher";
		break;

		case FIPS_TEST_SIGNATURE:
		if (ex)
			{
			EVP_PKEY *pkey = ex;
			keytype = EVP_PKEY_base_id(pkey);
			if (keytype == EVP_PKEY_EC)
				{
				const EC_GROUP *grp;
				int cnid;
				grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey));
				cnid = EC_GROUP_get_curve_name(grp);
				sprintf(asctmp, "ECDSA %s", lookup_id(cnid));
				exstr = asctmp;
				}
			else
				exstr = lookup_id(keytype);
			}
		idstr = "Signature";
		break;

		case FIPS_TEST_HMAC:
		exstr = lookup_id(subid);
		idstr = "HMAC";
		break;

		case FIPS_TEST_CMAC:
		idstr = "CMAC";
		exstr = lookup_id(subid);
		break;

		case FIPS_TEST_GCM:
		idstr = "GCM";
		break;

		case FIPS_TEST_XTS:
		idstr = "XTS";
		exstr = lookup_id(subid);
		break;

		case FIPS_TEST_CCM:
		idstr = "CCM";
		break;

		case FIPS_TEST_X931:
		idstr = "X9.31 PRNG";
		sprintf(asctmp, "keylen=%d", subid);
		exstr = asctmp;
		break;

		case FIPS_TEST_DRBG:
		idstr = "DRBG";
		if (*(int *)ex & DRBG_FLAG_CTR_USE_DF)
			{
			sprintf(asctmp, "%s DF", lookup_id(subid));
			exstr = asctmp;
			}
		else if (subid >> 16)
			{
			sprintf(asctmp, "%s %s",
					lookup_id(subid >> 16),
					lookup_id(subid & 0xFFFF));
			exstr = asctmp;
			}
		else
			exstr = lookup_id(subid);
		break;

		case FIPS_TEST_PAIRWISE:
		if (ex)
			{
            if (subid == EVP_PKEY_DH){
                DH *pkey = ex;
                keytype = EVP_PKEY_base_id(pkey);
            } else {
                EC_KEY *pkey = ex;
                keytype = EVP_PKEY_base_id(pkey);
                if (keytype == 0)
                    {                    
                    const EC_GROUP *grp;
                    int cnid;                
                    keytype = EVP_PKEY_ECDH;
                    grp = EC_KEY_get0_group(pkey);
                    cnid = EC_GROUP_get_curve_name(grp);
                    sprintf(asctmp, "%s", lookup_id(cnid));
                    exstr = asctmp;
                    }
                else
                    exstr = lookup_id(keytype);
            }
			}
		idstr = "Pairwise Consistency";
		break;

		case FIPS_TEST_CONTINUOUS:
		idstr = "Continuous PRNG";
		break;

		case FIPS_TEST_ECDH:
		idstr = "ECDH";
		exstr = lookup_id(subid);
		break;

        case FIPS_TEST_TLS1:
		idstr = "TLS_PRF";		
		break;

        case FIPS_TEST_PBKDF:
		idstr = "PBKDF";		
		break;

		case FIPS_TEST_DH:
		idstr = "DH";		
		break;

        case FIPS_TEST_HKDF:
		idstr = "HKDF";		
		break;

        case FIPS_TEST_TLS13:
		idstr = "TLS13";
		break;
		case FIPS_TEST_KBKDF:
		idstr = "KBKDF";
		break;
		case FIPS_TEST_SSHKDF:
		idstr = "SSHKDF";
		break;

        case FIPS_TEST_DUP:
        idstr = "XTS DUP";
		break;

		default:
		idstr = "Unknown";
		break;

		}

	if (fail_id == id
		&& (fail_key == -1 || fail_key == keytype)
		&& (fail_sub == -1 || fail_sub == subid)) {
			exp_fail = 1;
		}

	switch(op)
		{
		case FIPS_POST_BEGIN:
#ifdef FIPS_POST_TIME
		clock_getres(CLOCK_REALTIME, &tstart);
		printf("\tTimer resolution %ld s, %ld ns\n",
				(long)tstart.tv_sec, (long)tstart.tv_nsec);
		clock_gettime(CLOCK_REALTIME, &tstart);
#endif
		printf("\tPOST started\n");
		break;

		case FIPS_POST_END:
		printf("\tPOST %s\n", id ? "Success" : "Failed");
#ifdef FIPS_POST_TIME
		clock_gettime(CLOCK_REALTIME, &tend);
		printf("\t\tTook %f seconds\n",
			(double)((tend.tv_sec+tend.tv_nsec*1e-9)
                        - (tstart.tv_sec+tstart.tv_nsec*1e-9)));
#endif
		break;

		case FIPS_POST_STARTED:
		if (!post_quiet && !exp_fail)
			printf("\t\t%s %s test started\n", idstr, exstr);
#ifdef FIPS_POST_TIME
		clock_gettime(CLOCK_REALTIME, &start);
#endif
		break;

		case FIPS_POST_SUCCESS:
		if (exp_fail)
			{
			printf("\t\t%s %s test OK but should've failed\n",
								idstr, exstr);
			st_err++;
			}
		else if (!post_quiet)
			printf("\t\t%s %s test OK\n", idstr, exstr);
#ifdef FIPS_POST_TIME
		clock_gettime(CLOCK_REALTIME, &end);
		printf("\t\t\tTook %f seconds\n",
			(double)((end.tv_sec+end.tv_nsec*1e-9)
                        - (start.tv_sec+start.tv_nsec*1e-9)));
#endif
		break;

		case FIPS_POST_FAIL:
		if (exp_fail) {
			printf("\t\t%s %s test failed as expected\n",
							idstr, exstr);
		} else	{
            printf("\t\t%s %s test Failed Incorrectly!!\n",  idstr, exstr);
            st_err++;
        }
		break;

		case FIPS_POST_CORRUPT:
		if (exp_fail)
			{
			printf("\t\t%s %s test failure induced\n", idstr, exstr);
			return 0;
			}
		break;

		}
	return 1;
	}

typedef struct 
	{
	const char *name;
	int id, subid, keyid;
	} fail_list;

static fail_list flist[] =
	{
	{"Integrity", FIPS_TEST_INTEGRITY, 1, -1},
	{"Integrity", FIPS_TEST_INTEGRITY, 2, -1},	
	{"AES", FIPS_TEST_CIPHER, NID_aes_128_ecb, -1},	
	{"AES-GCM", FIPS_TEST_GCM, -1, -1},
	{"AES-CCM", FIPS_TEST_CCM, -1, -1},
	{"AES-XTS", FIPS_TEST_XTS, -1, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_sha1, -1},
	//{"Digest", FIPS_TEST_DIGEST, NID_sha224, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_sha256, -1},
	//{"Digest", FIPS_TEST_DIGEST, NID_sha384, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_sha512, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_sha3_256, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_sha3_512, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_shake128, -1},
	{"Digest", FIPS_TEST_DIGEST, NID_shake256, -1},
	{"HMAC", FIPS_TEST_HMAC, -1, -1},
	//{"HMAC", FIPS_TEST_HMAC, NID_sha3_256, -1},
	//{"HMAC", FIPS_TEST_HMAC, NID_sha3_512, -1},
	{"CMAC", FIPS_TEST_CMAC, -1, -1},
	{"DRBG", FIPS_TEST_DRBG, -1, -1},
	{"DRBG", FIPS_TEST_DRBG, NID_aes_128_ctr, -1},
	{"DRBG", FIPS_TEST_DRBG, NID_aes_192_ctr, -1},
	{"RSA", FIPS_TEST_SIGNATURE, -1, EVP_PKEY_RSA},
    {"RSA", FIPS_TEST_RSA_ENCRYPT, -1, -1},
	{"RSA", FIPS_TEST_RSA_DECRYPT, -1, -1},	
	{"DSA", FIPS_TEST_SIGNATURE, -1, EVP_PKEY_DSA},
	{"DH", FIPS_TEST_DH, -1, -1},
	{"ECDSA", FIPS_TEST_SIGNATURE, NID_secp256k1, EVP_PKEY_EC},
	{"ECDH", FIPS_TEST_ECDH, NID_X9_62_prime256v1, -1},
    {"TLS_PRF", FIPS_TEST_TLS1, -1, -1},
    {"PBKDF", FIPS_TEST_PBKDF, -1, -1},
    {"HKDF", FIPS_TEST_HKDF, -1, -1},
    {"TLS13", FIPS_TEST_TLS13, -1, -1},
	{"SSHKDF", FIPS_TEST_SSHKDF, -1, -1},
	{"KBKDF", FIPS_TEST_KBKDF, -1, -1},
	{NULL, -1, -1, -1}
	};

static int no_err;

int main(int argc, char *argv[])
{
    FUNCTION f, *fp;
    LHASH_OF(FUNCTION) *prog = NULL;
    char **copied_argv = NULL;
    char *p, *pname;
    char buf[1024];
    const char *prompt;
    ARGS arg;
    int first, n, i, ret = 0;
    fail_list *ftmp;
    int rv;

    arg.argv = NULL;
    arg.size = 0;

    /* Set up some of the environment. */
    default_config_file = make_config_name();
    bio_in = dup_bio_in(FORMAT_TEXT);
    bio_out = dup_bio_out(FORMAT_TEXT);
    bio_err = dup_bio_err(FORMAT_TEXT);

#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
    copied_argv = argv = copy_argv(&argc, argv);
#elif defined(_WIN32)
    /*
     * Replace argv[] with UTF-8 encoded strings.
     */
    win32_utf8argv(&argc, &argv);
#endif

    printf("\nFIPS version string\n");
    printf("%s\n", FIPS_show_version());

    p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    
    prog = opt_init(argc, argv, list_options);
    setvbuf(stdout,NULL,_IONBF,0);
    FIPS_post_set_callback(post_cb);
    
    if (getenv("OPENSSL_FIPS_FAIL")) {
        post_quiet = 1;
        no_err = 1;
        for (ftmp = flist; ftmp->name; ftmp++) {
            printf("    Testing induced failure of %s test\n", ftmp->name);
            fail_id = ftmp->id;
            fail_sub = ftmp->subid;
            fail_key = ftmp->keyid;
            FIPS_mode_set(0);
            rv = FIPS_mode_set(1);
            if (rv)	{
                printf("\tFIPS mode incorrectly successful!!\n");
                st_err++;
            }
        }
        return rv;
    } else if (getenv("OPENSSL_FIPS_KAT")) {
    FIPS_mode_set(0);
    if (!FIPS_mode_set(1))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}
    } else {
        post_quiet = 1;	
		no_err = 1;
        if (!FIPS_mode_set(1))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}
        post_quiet = 0;	
		no_err = 0;
    }

    if (!apps_startup()) {
        BIO_printf(bio_err,
                   "FATAL: Startup failure (dev note: apps_startup() failed)\n");
        ERR_print_errors(bio_err);
        ret = 1;
        goto end;
    }

    prog = prog_init();
    if (prog == NULL) {
        BIO_printf(bio_err,
                   "FATAL: Startup failure (dev note: prog_init() failed)\n");
        ERR_print_errors(bio_err);
        ret = 1;
        goto end;
    }
    pname = opt_progname(argv[0]);

    /* first check the program name */
    f.name = pname;
    fp = lh_FUNCTION_retrieve(prog, &f);
    if (fp != NULL) {
        argv[0] = pname;
        ret = fp->func(argc, argv);
        goto end;
    }

    /* If there is stuff on the command line, run with that. */
    if (argc != 1) {
        argc--;
        argv++;
        ret = do_cmd(prog, argc, argv);
        if (ret < 0)
            ret = 0;
        goto end;
    }

    if (getenv("OPENSSL_PCT_API_DH")) {
        DH *a = NULL;
        a=DH_new_by_nid(NID_ffdhe2048);
        if (!DH_generate_key(a))
            printf("DH Keygen failed");
        goto end;          
    } else if (getenv("OPENSSL_PCT_API_DH_FAIL")) {
        DH *a = NULL;
        fail_id = FIPS_TEST_PAIRWISE;
        fail_key = -1;
        fail_sub = EVP_PKEY_DH;
        a=DH_new_by_nid(NID_ffdhe2048);
        if (!DH_generate_key(a))
            printf("DH Keygen failed");
        goto end;
    }

    /* ok, lets enter interactive mode */
    for (;;) {
        ret = 0;
        /* Read a line, continue reading if line ends with \ */
        for (p = buf, n = sizeof(buf), i = 0, first = 1; n > 0; first = 0) {
            prompt = first ? "OpenSSL> " : "> ";
            p[0] = '\0';
#ifndef READLINE
            fputs(prompt, stdout);
            fflush(stdout);
            if (!fgets(p, n, stdin))
                goto end;
            if (p[0] == '\0')
                goto end;
            i = strlen(p);
            if (i <= 1)
                break;
            if (p[i - 2] != '\\')
                break;
            i -= 2;
            p += i;
            n -= i;
#else
            {
                extern char *readline(const char *);
                extern void add_history(const char *cp);
                char *text;

                text = readline(prompt);
                if (text == NULL)
                    goto end;
                i = strlen(text);
                if (i == 0 || i > n)
                    break;
                if (text[i - 1] != '\\') {
                    p += strlen(strcpy(p, text));
                    free(text);
                    add_history(buf);
                    break;
                }

                text[i - 1] = '\0';
                p += strlen(strcpy(p, text));
                free(text);
                n -= i;
            }
#endif
        }

        if (!chopup_args(&arg, buf)) {
            BIO_printf(bio_err, "Can't parse (no memory?)\n");
            break;
        }

        ret = do_cmd(prog, arg.argc, arg.argv);
        if (ret == EXIT_THE_PROGRAM) {
            ret = 0;
            goto end;
        }
        if (ret != 0)
            BIO_printf(bio_err, "error in %s\n", arg.argv[0]);
        (void)BIO_flush(bio_out);
        (void)BIO_flush(bio_err);
    }
    ret = 1;
 end:
    OPENSSL_free(copied_argv);
    OPENSSL_free(default_config_file);
    if ( prog )
        lh_FUNCTION_free(prog);
    OPENSSL_free(arg.argv);
    app_RAND_write();

    BIO_free(bio_in);
    BIO_free_all(bio_out);
    apps_shutdown();
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(bio_err) <= 0)
        ret = 1;
#endif
    BIO_free(bio_err);
    EXIT(ret);
}

static void list_cipher_fn(const EVP_CIPHER *c,
                           const char *from, const char *to, void *arg)
{
    if (c != NULL) {
        BIO_printf(arg, "%s\n", EVP_CIPHER_name(c));
    } else {
        if (from == NULL)
            from = "<undefined>";
        if (to == NULL)
            to = "<undefined>";
        BIO_printf(arg, "%s => %s\n", from, to);
    }
}

static void list_md_fn(const EVP_MD *m,
                       const char *from, const char *to, void *arg)
{
    if (m != NULL) {
        BIO_printf(arg, "%s\n", EVP_MD_name(m));
    } else {
        if (from == NULL)
            from = "<undefined>";
        if (to == NULL)
            to = "<undefined>";
        BIO_printf((BIO *)arg, "%s => %s\n", from, to);
    }
}

static void list_missing_help(void)
{
    const FUNCTION *fp;
    const OPTIONS *o;

    for (fp = functions; fp->name != NULL; fp++) {
        if ((o = fp->help) != NULL) {
            /* If there is help, list what flags are not documented. */
            for ( ; o->name != NULL; o++) {
                if (o->helpstr == NULL)
                    BIO_printf(bio_out, "%s %s\n", fp->name, o->name);
            }
        } else if (fp->func != dgst_main) {
            /* If not aliased to the dgst command, */
            BIO_printf(bio_out, "%s *\n", fp->name);
        }
    }
}

static void list_options_for_command(const char *command)
{
    const FUNCTION *fp;
    const OPTIONS *o;

    for (fp = functions; fp->name != NULL; fp++)
        if (strcmp(fp->name, command) == 0)
            break;
    if (fp->name == NULL) {
        BIO_printf(bio_err, "Invalid command '%s'; type \"help\" for a list.\n",
                command);
        return;
    }

    if ((o = fp->help) == NULL)
        return;

    for ( ; o->name != NULL; o++) {
        if (o->name == OPT_HELP_STR
                || o->name == OPT_MORE_STR
                || o->name[0] == '\0')
            continue;
        BIO_printf(bio_out, "%s %c\n", o->name, o->valtype);
    }
}


/* Unified enum for help and list commands. */
typedef enum HELPLIST_CHOICE {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ONE,
    OPT_COMMANDS, OPT_DIGEST_COMMANDS, OPT_OPTIONS,
    OPT_DIGEST_ALGORITHMS, OPT_CIPHER_COMMANDS, OPT_CIPHER_ALGORITHMS,
    OPT_PK_ALGORITHMS, OPT_PK_METHOD, OPT_DISABLED, OPT_MISSING_HELP
} HELPLIST_CHOICE;

const OPTIONS list_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"1", OPT_ONE, '-', "List in one column"},
    {"commands", OPT_COMMANDS, '-', "List of standard commands"},
    {"digest-commands", OPT_DIGEST_COMMANDS, '-',
     "List of message digest commands"},
    {"digest-algorithms", OPT_DIGEST_ALGORITHMS, '-',
     "List of message digest algorithms"},
    {"cipher-commands", OPT_CIPHER_COMMANDS, '-', "List of cipher commands"},
    {"cipher-algorithms", OPT_CIPHER_ALGORITHMS, '-',
     "List of cipher algorithms"},
    {"public-key-algorithms", OPT_PK_ALGORITHMS, '-',
     "List of public key algorithms"},
    {"public-key-methods", OPT_PK_METHOD, '-',
     "List of public key methods"},
    {"disabled", OPT_DISABLED, '-',
     "List of disabled features"},
    {"missing-help", OPT_MISSING_HELP, '-',
     "List missing detailed help strings"},
    {"options", OPT_OPTIONS, 's',
     "List options for specified command"},
    {NULL}
};

int list_main(int argc, char **argv)
{
    char *prog;
    HELPLIST_CHOICE o;
    int one = 0, done = 0;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:  /* Never hit, but suppresses warning */
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            return 1;
        case OPT_HELP:
            opt_help(list_options);
            break;
        case OPT_ONE:
            one = 1;
            break;
        case OPT_COMMANDS:
            list_type(FT_general, one);
            break;
        case OPT_DIGEST_COMMANDS:
            list_type(FT_md, one);
            break;
        case OPT_DIGEST_ALGORITHMS:
            EVP_MD_do_all_sorted(list_md_fn, bio_out);
            break;
        case OPT_CIPHER_COMMANDS:
            list_type(FT_cipher, one);
            break;
        case OPT_CIPHER_ALGORITHMS:
            EVP_CIPHER_do_all_sorted(list_cipher_fn, bio_out);
            break;
        case OPT_PK_ALGORITHMS:
            list_pkey();
            break;
        case OPT_PK_METHOD:
            list_pkey_meth();
            break;
        case OPT_DISABLED:
            list_disabled();
            break;
        case OPT_MISSING_HELP:
            list_missing_help();
            break;
        case OPT_OPTIONS:
            list_options_for_command(opt_arg());
            break;
        }
        done = 1;
    }
    if (opt_num_rest() != 0) {
        BIO_printf(bio_err, "Extra arguments given.\n");
        goto opthelp;
    }

    if (!done)
        goto opthelp;

    return 0;
}

typedef enum HELP_CHOICE {
    OPT_hERR = -1, OPT_hEOF = 0, OPT_hHELP
} HELP_CHOICE;

const OPTIONS help_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: help [options]\n"},
    {OPT_HELP_STR, 1, '-', "       help [command]\n"},
    {"help", OPT_hHELP, '-', "Display this summary"},
    {NULL}
};


int help_main(int argc, char **argv)
{
    FUNCTION *fp;
    int i, nl;
    FUNC_TYPE tp;
    char *prog;
    HELP_CHOICE o;
    DISPLAY_COLUMNS dc;

    prog = opt_init(argc, argv, help_options);
    while ((o = opt_next()) != OPT_hEOF) {
        switch (o) {
        case OPT_hERR:
        case OPT_hEOF:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            return 1;
        case OPT_hHELP:
            opt_help(help_options);
            return 0;
        }
    }

    if (opt_num_rest() == 1) {
        char *new_argv[3];

        new_argv[0] = opt_rest()[0];
        new_argv[1] = "--help";
        new_argv[2] = NULL;
        return do_cmd(prog_init(), 2, new_argv);
    }
    if (opt_num_rest() != 0) {
        BIO_printf(bio_err, "Usage: %s\n", prog);
        return 1;
    }

    calculate_columns(&dc);
    BIO_printf(bio_err, "Standard commands");
    i = 0;
    tp = FT_none;
    for (fp = functions; fp->name != NULL; fp++) {
        nl = 0;
        if (i++ % dc.columns == 0) {
            BIO_printf(bio_err, "\n");
            nl = 1;
        }
        if (fp->type != tp) {
            tp = fp->type;
            if (!nl)
                BIO_printf(bio_err, "\n");
            if (tp == FT_md) {
                i = 1;
                BIO_printf(bio_err,
                           "\nMessage Digest commands (see the `dgst' command for more details)\n");
            } else if (tp == FT_cipher) {
                i = 1;
                BIO_printf(bio_err,
                           "\nCipher commands (see the `enc' command for more details)\n");
            }
        }
        BIO_printf(bio_err, "%-*s", dc.width, fp->name);
    }
    BIO_printf(bio_err, "\n\n");
    return 0;
}

static void list_type(FUNC_TYPE ft, int one)
{
    FUNCTION *fp;
    int i = 0;
    DISPLAY_COLUMNS dc = {0};

    if (!one)
        calculate_columns(&dc);

    for (fp = functions; fp->name != NULL; fp++) {
        if (fp->type != ft)
            continue;
        if (one) {
            BIO_printf(bio_out, "%s\n", fp->name);
        } else {
            if (i % dc.columns == 0 && i > 0)
                BIO_printf(bio_out, "\n");
            BIO_printf(bio_out, "%-*s", dc.width, fp->name);
            i++;
        }
    }
    if (!one)
        BIO_printf(bio_out, "\n\n");
}

static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[])
{
    FUNCTION f, *fp;

    if (argc <= 0 || argv[0] == NULL)
        return 0;
    /* NB POST will succeed with a pairwise test failures as
	 * it is not used during POST.
	 */
    if (getenv("OPENSSL_PCT_RSA_FAIL")) {    
        fail_id = FIPS_TEST_PAIRWISE;
        fail_key = EVP_PKEY_RSA;
        fail_sub = -1;
    }

    if (getenv("OPENSSL_PCT_DSA_FAIL")) {    
        fail_id = FIPS_TEST_PAIRWISE;
        fail_key = EVP_PKEY_DSA;
        fail_sub = -1;
    }

    if (getenv("OPENSSL_PCT_ECDSA_FAIL")) {    
        fail_id = FIPS_TEST_PAIRWISE;
        fail_key = EVP_PKEY_EC;
        fail_sub = -1;
    }

    if (getenv("OPENSSL_PCT_ECDH_FAIL")) {    
        fail_id = FIPS_TEST_PAIRWISE;
        fail_key = EVP_PKEY_ECDH;
        fail_sub = -1;
    }

    if (getenv("OPENSSL_PCT_DH_FAIL")) {
        fail_id = FIPS_TEST_PAIRWISE;
        fail_key = -1;
        fail_sub = EVP_PKEY_DH;
    }

    if (getenv("OPENSSL_DUP_XTS_FAIL")) {
        fail_id = FIPS_TEST_DUP;
        fail_key = -1;
        fail_sub = -1;
    }

    f.name = argv[0];
    fp = lh_FUNCTION_retrieve(prog, &f);
    if (fp == NULL) {
        if (EVP_get_digestbyname(argv[0])) {
            f.type = FT_md;
            f.func = dgst_main;
            fp = &f;
        } else if (EVP_get_cipherbyname(argv[0])) {
            f.type = FT_cipher;
            f.func = enc_main;
            fp = &f;
        }
    }
    if (fp != NULL) {
        return fp->func(argc, argv);
    }
    if ((strncmp(argv[0], "no-", 3)) == 0) {
        /*
         * User is asking if foo is unsupported, by trying to "run" the
         * no-foo command.  Strange.
         */
        f.name = argv[0] + 3;
        if (lh_FUNCTION_retrieve(prog, &f) == NULL) {
            BIO_printf(bio_out, "%s\n", argv[0]);
            return 0;
        }
        BIO_printf(bio_out, "%s\n", argv[0] + 3);
        return 1;
    }
    if (strcmp(argv[0], "quit") == 0 || strcmp(argv[0], "q") == 0 ||
        strcmp(argv[0], "exit") == 0 || strcmp(argv[0], "bye") == 0)
        /* Special value to mean "exit the program. */
        return EXIT_THE_PROGRAM;

    BIO_printf(bio_err, "Invalid command '%s'; type \"help\" for a list.\n",
               argv[0]);
    return 1;
}

static void list_pkey(void)
{
    int i;

    for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        int pkey_id, pkey_base_id, pkey_flags;
        const char *pinfo, *pem_str;
        ameth = EVP_PKEY_asn1_get0(i);
        EVP_PKEY_asn1_get0_info(&pkey_id, &pkey_base_id, &pkey_flags,
                                &pinfo, &pem_str, ameth);
        if (pkey_flags & ASN1_PKEY_ALIAS) {
            BIO_printf(bio_out, "Name: %s\n", OBJ_nid2ln(pkey_id));
            BIO_printf(bio_out, "\tAlias for: %s\n",
                       OBJ_nid2ln(pkey_base_id));
        } else {
            BIO_printf(bio_out, "Name: %s\n", pinfo);
            BIO_printf(bio_out, "\tType: %s Algorithm\n",
                       pkey_flags & ASN1_PKEY_DYNAMIC ?
                       "External" : "Builtin");
            BIO_printf(bio_out, "\tOID: %s\n", OBJ_nid2ln(pkey_id));
            if (pem_str == NULL)
                pem_str = "(none)";
            BIO_printf(bio_out, "\tPEM string: %s\n", pem_str);
        }

    }
}

static void list_pkey_meth(void)
{
    size_t i;
    size_t meth_count = EVP_PKEY_meth_get_count();

    for (i = 0; i < meth_count; i++) {
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_get0(i);
        int pkey_id, pkey_flags;

        EVP_PKEY_meth_get0_info(&pkey_id, &pkey_flags, pmeth);
        BIO_printf(bio_out, "%s\n", OBJ_nid2ln(pkey_id));
        BIO_printf(bio_out, "\tType: %s Algorithm\n",
                   pkey_flags & ASN1_PKEY_DYNAMIC ?  "External" : "Builtin");
    }
}

static int function_cmp(const FUNCTION * a, const FUNCTION * b)
{
    return strncmp(a->name, b->name, 8);
}

static unsigned long function_hash(const FUNCTION * a)
{
    return OPENSSL_LH_strhash(a->name);
}

static int SortFnByName(const void *_f1, const void *_f2)
{
    const FUNCTION *f1 = _f1;
    const FUNCTION *f2 = _f2;

    if (f1->type != f2->type)
        return f1->type - f2->type;
    return strcmp(f1->name, f2->name);
}

static void list_disabled(void)
{
    BIO_puts(bio_out, "Disabled algorithms:\n");
#ifdef OPENSSL_NO_ARIA
    BIO_puts(bio_out, "ARIA\n");
#endif
#ifdef OPENSSL_NO_BF
    BIO_puts(bio_out, "BF\n");
#endif
#ifdef OPENSSL_NO_BLAKE2
    BIO_puts(bio_out, "BLAKE2\n");
#endif
#ifdef OPENSSL_NO_CAMELLIA
    BIO_puts(bio_out, "CAMELLIA\n");
#endif
#ifdef OPENSSL_NO_CAST
    BIO_puts(bio_out, "CAST\n");
#endif
#ifdef OPENSSL_NO_CMAC
    BIO_puts(bio_out, "CMAC\n");
#endif
#ifdef OPENSSL_NO_CMS
    BIO_puts(bio_out, "CMS\n");
#endif
#ifdef OPENSSL_NO_COMP
    BIO_puts(bio_out, "COMP\n");
#endif
#ifdef OPENSSL_NO_DES
    BIO_puts(bio_out, "DES\n");
#endif
#ifdef OPENSSL_NO_DGRAM
    BIO_puts(bio_out, "DGRAM\n");
#endif
#ifdef OPENSSL_NO_DH
    BIO_puts(bio_out, "DH\n");
#endif
#ifdef OPENSSL_NO_DSA
    BIO_puts(bio_out, "DSA\n");
#endif
#if defined(OPENSSL_NO_DTLS)
    BIO_puts(bio_out, "DTLS\n");
#endif
#if defined(OPENSSL_NO_DTLS1)
    BIO_puts(bio_out, "DTLS1\n");
#endif
#if defined(OPENSSL_NO_DTLS1_2)
    BIO_puts(bio_out, "DTLS1_2\n");
#endif
#ifdef OPENSSL_NO_EC
    BIO_puts(bio_out, "EC\n");
#endif
#ifdef OPENSSL_NO_EC2M
    BIO_puts(bio_out, "EC2M\n");
#endif
#ifdef OPENSSL_NO_ENGINE
    BIO_puts(bio_out, "ENGINE\n");
#endif
#ifdef OPENSSL_NO_GOST
    BIO_puts(bio_out, "GOST\n");
#endif
#ifdef OPENSSL_NO_HEARTBEATS
    BIO_puts(bio_out, "HEARTBEATS\n");
#endif
#ifdef OPENSSL_NO_IDEA
    BIO_puts(bio_out, "IDEA\n");
#endif
#ifdef OPENSSL_NO_MD2
    BIO_puts(bio_out, "MD2\n");
#endif
#ifdef OPENSSL_NO_MD4
    BIO_puts(bio_out, "MD4\n");
#endif
#ifdef OPENSSL_NO_MD5
    BIO_puts(bio_out, "MD5\n");
#endif
#ifdef OPENSSL_NO_MDC2
    BIO_puts(bio_out, "MDC2\n");
#endif
#ifdef OPENSSL_NO_OCB
    BIO_puts(bio_out, "OCB\n");
#endif
#ifdef OPENSSL_NO_OCSP
    BIO_puts(bio_out, "OCSP\n");
#endif
#ifdef OPENSSL_NO_PSK
    BIO_puts(bio_out, "PSK\n");
#endif
#ifdef OPENSSL_NO_RC2
    BIO_puts(bio_out, "RC2\n");
#endif
#ifdef OPENSSL_NO_RC4
    BIO_puts(bio_out, "RC4\n");
#endif
#ifdef OPENSSL_NO_RC5
    BIO_puts(bio_out, "RC5\n");
#endif
#ifdef OPENSSL_NO_RMD160
    BIO_puts(bio_out, "RMD160\n");
#endif
#ifdef OPENSSL_NO_RSA
    BIO_puts(bio_out, "RSA\n");
#endif
#ifdef OPENSSL_NO_SCRYPT
    BIO_puts(bio_out, "SCRYPT\n");
#endif
#ifdef OPENSSL_NO_SCTP
    BIO_puts(bio_out, "SCTP\n");
#endif
#ifdef OPENSSL_NO_SEED
    BIO_puts(bio_out, "SEED\n");
#endif
#ifdef OPENSSL_NO_SM2
    BIO_puts(bio_out, "SM2\n");
#endif
#ifdef OPENSSL_NO_SM3
    BIO_puts(bio_out, "SM3\n");
#endif
#ifdef OPENSSL_NO_SM4
    BIO_puts(bio_out, "SM4\n");
#endif
#ifdef OPENSSL_NO_SOCK
    BIO_puts(bio_out, "SOCK\n");
#endif
#ifdef OPENSSL_NO_SRP
    BIO_puts(bio_out, "SRP\n");
#endif
#ifdef OPENSSL_NO_SRTP
    BIO_puts(bio_out, "SRTP\n");
#endif
#ifdef OPENSSL_NO_SSL3
    BIO_puts(bio_out, "SSL3\n");
#endif
#ifdef OPENSSL_NO_TLS1
    BIO_puts(bio_out, "TLS1\n");
#endif
#ifdef OPENSSL_NO_TLS1_1
    BIO_puts(bio_out, "TLS1_1\n");
#endif
#ifdef OPENSSL_NO_TLS1_2
    BIO_puts(bio_out, "TLS1_2\n");
#endif
#ifdef OPENSSL_NO_WHIRLPOOL
    BIO_puts(bio_out, "WHIRLPOOL\n");
#endif
#ifndef ZLIB
    BIO_puts(bio_out, "ZLIB\n");
#endif
}

static LHASH_OF(FUNCTION) *prog_init(void)
{
    static LHASH_OF(FUNCTION) *ret = NULL;
    static int prog_inited = 0;
    FUNCTION *f;
    size_t i;

    if (prog_inited)
        return ret;

    prog_inited = 1;

    /* Sort alphabetically within category. For nicer help displays. */
    for (i = 0, f = functions; f->name != NULL; ++f, ++i)
        ;
    qsort(functions, i, sizeof(*functions), SortFnByName);

    if ((ret = lh_FUNCTION_new(function_hash, function_cmp)) == NULL)
        return NULL;

    for (f = functions; f->name != NULL; f++)
        (void)lh_FUNCTION_insert(ret, f);
    return ret;
}
