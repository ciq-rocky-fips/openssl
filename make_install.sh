#!/bin/sh
version="3.0.7"
cwd=`pwd`/INSTALL
RPM_OPT_FLAGS="-flto=auto -ffat-lto-objects -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security -Wp,-D_GLIBCXX_ASSERTIONS -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -fstack-protector-strong -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1  -m64 -march=x86-64-v2 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection"
RPM_LD_FLAGS="-Wl,-z,relro -Wl,--as-needed  -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 "
RPM_ARCH="x86_64"
RPM_OS="linux"
RPM_BUILD_NCPUS="20"

# Add -Wa,--noexecstack here so that libcrypto's assembler modules will be
# marked as not requiring an executable stack.
# Also add -DPURIFY to make using valgrind with openssl easier as we do not
# want to depend on the uninitialized memory as a source of entropy anyway.
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes -DPURIFY $RPM_LD_FLAGS"
sslflags=enable-ec_nistp_64_gcc_128
sslarch=linux-x86_64
export HASHBANGPERL=/usr/bin/perl
# ia64, x86_64, ppc are OK by default
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.

./Configure \
	--prefix=$cwd --openssldir=/etc/pki/tls $sslflags \
	--system-ciphers-file=/etc/crypto-policies/back-ends/openssl.config \
	zlib enable-camellia enable-seed enable-rfc3779 enable-sctp \
	enable-cms enable-md2 enable-rc5 enable-ktls enable-fips \
	no-mdc2 no-ec2m no-sm2 no-sm4 enable-buildtest-c++\
	shared  $sslarch $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\"" -DROCKY_FIPS_NAME="\"Rocky Enterprise Linux 9 - OpenSSL FIPS Provider\"" -DROCKY_FIPS_VERSION="\"Rocky9.20240402\""'\
	-Wl,-rpath=$cwd/lib64 -Wl,--allow-multiple-definition --openssldir=$cwd

#if [ $? -eq 0 ]; then
#    echo OK
#else
#    exit 1
#fi

rm -rf $cwd
make clean
make all
make install
echo "****************************"
LD_LIBRARY_PATH=. $cwd/bin/openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813 < providers/fips.so > providers/fips.so.hmac
echo "****************************"
objcopy --update-section .rodata1=providers/fips.so.hmac providers/fips.so providers/fips.so.mac
echo "****************************"
mv providers/fips.so.mac INSTALL/lib64/ossl-modules/fips.so
