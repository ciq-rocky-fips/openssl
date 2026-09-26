./Configure \
        --prefix="`pwd`/INSTALLED" --openssldir="`pwd`/INSTALLED/pki/tls" \
        --system-ciphers-file="`pwd`/INSTALLED/crypto-policies/back-ends/openssl.config" \
        --debug \
	zlib enable-camellia enable-seed enable-rfc3779 enable-sctp enable-sslkeylog \
	enable-fips-jitter enable-cms enable-md2 enable-rc5 enable-ktls enable-fips -D_GNU_SOURCE \
	no-mdc2 no-ec2m no-sm2 no-sm4 no-atexit enable-buildtest-c++ \
	shared linux-x86_64 -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes \
	'-DDEVRANDOM="\"/dev/urandom\"" -DOPENSSL_PEDANTIC_ZEROIZATION \
	-DREDHAT_FIPS_VENDOR="\"Rocky Linux 10 - OpenSSL FIPS Provider\"" -DREDHAT_FIPS_VERSION="\"3.5.5-Rocky10.20260928\""' \
	-Wl,--allow-multiple-definition
make all
./fips-hmacify.sh
make install
