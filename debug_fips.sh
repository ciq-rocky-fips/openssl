./Configure \
        --prefix="`pwd`/INSTALLED" --openssldir="`pwd`/INSTALLED/pki/tls" enable-ec_nistp_64_gcc_128 \
        --system-ciphers-file="`pwd`/INSTALLED/crypto-policies/back-ends/openssl.config" \
        --debug zlib enable-camellia enable-seed enable-rfc3779 enable-sctp enable-sslkeylog \
        enable-cms enable-md2 enable-rc5 enable-ktls enable-fips -D_GNU_SOURCE \
        no-mdc2 no-ec2m no-sm2 no-sm4 no-atexit enable-buildtest-c++ \
        shared linux-x86_64 -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes \
        '-DDEVRANDOM="\"/dev/urandom\"" -DOPENSSL_PEDANTIC_ZEROIZATION \
	-DROCKY_FIPS_VENDOR="\"Rocky Linux 9 - OpenSSL FIPS Provider\"" \
        -DROCKY_FIPS_VERSION="\"Rocky9.20250613\""'\
        -Wl,--allow-multiple-definition
make all
./fips-hmacify.sh
make install
