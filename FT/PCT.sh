#!/bin/bash

#LD_DEBUG=symbols 
#OPENSSL_FORCE_FIPS_MODE=1 gdb --args ../INSTALL/bin/openssl genrsa -out rsa_key.pem 2048
#OPENSSL_FORCE_FIPS_MODE=1 ../INSTALL/bin/openssl genrsa -out rsa_key.pem 2048 -check
#LD_DEBUG=symbols OPENSSL_FORCE_FIPS_MODE=1 ../INSTALL/bin/openssl ecparam -name prime256v1 -genkey -noout -out ec_key.pem

OPENSSL_FORCE_FIPS_MODE=1 ../INSTALL/bin/openssl genpkey -algorithm rsa -out rsa_test.key -pkeyopt rsa_keygen_bits:2048

#OPENSSL_FORCE_FIPS_MODE=1 ../INSTALL/bin/openssl genpkey -algorithm rsa -out rsa_test.key -pkeyopt rsa_keygen_bits:256 -pkeyopt rsa_keygen_pubexp:3
#genpkey: Error setting rsa_keygen_bits:256 parameter:
#00EED87ADE7F0000:error:1C8000AB:Provider routines:rsa_gen_set_params:key size too small:providers/implementations/keymgmt/rsa_kmgmt.c:526:
#OPENSSL_FORCE_FIPS_MODE=1 ../INSTALL/bin/openssl genpkey -algorithm rsa -out rsa_test.key -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:18
#genpkey: Error generating rsa key
#006E64F4447F0000:error:020000B2:rsa routines:ossl_rsa_fips186_4_gen_prob_primes:pub exponent out of range:crypto/rsa/rsa_sp800_56b_gen.c:97: