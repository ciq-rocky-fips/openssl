#!/bin/sh

sslflags=enable-ec_nistp_64_gcc_128

RPM_OPT_FLAGS="-Wa,--noexecstack -Wa,--generate-missing-build-notes=yes -DPURIFY"

DEBUG_BUILD="shared no-asm 386 no-sse2 zlib-dynamic -g -gdwarf-4 -fno-inline -O0 -DDEBUG_SAFESTACK"

./Configure $DEBUG_BUILD \
	--openssldir=/etc/pki/tls $sslflags \
	--system-ciphers-file=/etc/crypto-policies/back-ends/openssl.config \
	zlib enable-camellia enable-seed enable-rfc3779 enable-sctp \
	enable-cms enable-md2 enable-rc5\
	enable-weak-ssl-ciphers \
	no-mdc2 no-ec2m no-sm2 no-sm4 \
	shared  linux-x86_64 $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\"" -DOPENSSL_VERSION_SERVICE_STR="\"Rocky Linux 8 OpenSSL Cryptographic Module Version Rocky8.20240321\""'

make clean
make all



crypto/fips/fips_standalone_hmac libcrypto.so.1.1 >.libcrypto.so.1.1.hmac
#ln -s .libcrypto.so.1.1.hmac .libcrypto.so.hmac
crypto/fips/fips_standalone_hmac libssl.so.1.1 >.libssl.so.1.1.hmac
#ln -s .libssl.so.1.1.hmac .libssl.so.hmac

# debug single test with gdb
# test/evp_test will be run and the test will ingest the evpkdf.txt file
# gdb --args test/evp_test test/recipes/30-test_evp_data/evpkdf.txt
# set the LD_PRELOAD var in gdb to the newly compiled openssl libraries 
# set environment LD_PRELOAD ./libcrypto.so.1.1 ./libssl.so.1.1


#optional
#set print pretty on
#prints the contents of the kmeth structure
#print *(ctx->kmeth)
