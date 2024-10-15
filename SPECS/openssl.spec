# For the curious:
# 0.9.8jk + EAP-FAST soversion = 8
# 1.0.0 soversion = 10
# 1.1.0 soversion = 1.1 (same as upstream although presence of some symbols
#                        depends on build configuration options)
# 3.0.0 soversion = 3 (same as upstream)
%define soversion 3

# Arches on which we need to prevent arch conflicts on opensslconf.h, must
# also be handled in opensslconf-new.h.
%define multilib_arches %{ix86} ia64 %{mips} ppc ppc64 s390 s390x sparcv9 sparc64 x86_64

%define srpmhash() %{lua:
local files = rpm.expand("%_specdir/openssl.spec")
for i, p in ipairs(patches) do
   files = files.." "..p
end
for i, p in ipairs(sources) do
   files = files.." "..p
end
local sha256sum = assert(io.popen("cat "..files.." 2>/dev/null | sha256sum"))
local hash = sha256sum:read("*a")
sha256sum: close()
print(string.sub(hash, 0, 16))
}

%global _performance_build 1

Summary: Utilities from the general purpose cryptography library with TLS implementation
Name: openssl
Version: 3.0.7
Release: 27%{?dist}.0.2.2
Epoch: 1
# We have to remove certain patented algorithms from the openssl source
# tarball with the hobble-openssl script which is included below.
# The original openssl upstream tarball cannot be shipped in the .src.rpm.
Source: openssl-%{version}.tar.gz
Source2: Makefile.certificate
Source3: genpatches
Source6: make-dummy-cert
Source7: renew-dummy-cert
Source9: configuration-switch.h
Source10: configuration-prefix.h
Source14: 0025-for-tests.patch

# Patches exported from source git
# Aarch64 and ppc64le use lib64
Patch1: 0001-Aarch64-and-ppc64le-use-lib64.patch
# Use more general default values in openssl.cnf
Patch2: 0002-Use-more-general-default-values-in-openssl.cnf.patch
# Do not install html docs
Patch3: 0003-Do-not-install-html-docs.patch
# Override default paths for the CA directory tree
Patch4: 0004-Override-default-paths-for-the-CA-directory-tree.patch
# apps/ca: fix md option help text
Patch5: 0005-apps-ca-fix-md-option-help-text.patch
# Disable signature verification with totally unsafe hash algorithms
Patch6: 0006-Disable-signature-verification-with-totally-unsafe-h.patch
# Add support for PROFILE=SYSTEM system default cipherlist
Patch7: 0007-Add-support-for-PROFILE-SYSTEM-system-default-cipher.patch
# Add FIPS_mode() compatibility macro
Patch8: 0008-Add-FIPS_mode-compatibility-macro.patch
# Add check to see if fips flag is enabled in kernel
Patch9: 0009-Add-Kernel-FIPS-mode-flag-support.patch
# Instead of replacing ectest.c and ec_curve.c, add the changes as a patch so
# that new modifications made to these files by upstream are not lost. 
Patch10: 0010-Add-changes-to-ectest-and-eccurve.patch
# remove unsupported EC curves
Patch11: 0011-Remove-EC-curves.patch
# Disable explicit EC curves
# https://bugzilla.redhat.com/show_bug.cgi?id=2066412
Patch12: 0012-Disable-explicit-ec.patch
#Skipped tests from former 0011-Remove-EC-curves.patch
Patch13: 0013-skipped-tests-EC-curves.patch
# Instructions to load legacy provider in openssl.cnf
Patch24: 0024-load-legacy-prov.patch
# Tmp: test name change
Patch31: 0031-tmp-Fix-test-names.patch
# We load FIPS provider and set FIPS properties implicitly
Patch32: 0032-Force-fips.patch
# Embed HMAC into the fips.so
Patch33: 0033-FIPS-embed-hmac.patch
# Comment out fipsinstall command-line utility
Patch34: 0034.fipsinstall_disable.patch
# Skip unavailable algorithms running `openssl speed`
Patch35: 0035-speed-skip-unavailable-dgst.patch
# Extra public/private key checks required by FIPS-140-3
Patch44: 0044-FIPS-140-3-keychecks.patch
# Minimize fips services
Patch45: 0045-FIPS-services-minimize.patch
# Execute KATS before HMAC verification
Patch47: 0047-FIPS-early-KATS.patch
# Selectively disallow SHA1 signatures
Patch49: 0049-Selectively-disallow-SHA1-signatures.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2049265
Patch50: 0050-FIPS-enable-pkcs12-mac.patch
# Backport of patch for RHEL for Edge rhbz #2027261
Patch51: 0051-Support-different-R_BITS-lengths-for-KBKDF.patch
# Allow SHA1 in seclevel 2 if rh-allow-sha1-signatures = yes
Patch52: 0052-Allow-SHA1-in-seclevel-2-if-rh-allow-sha1-signatures.patch
# Originally from https://github.com/openssl/openssl/pull/18103
# As we rebased to 3.0.7 and used the version of the function
# not matching the upstream one, we have to use aliasing.
# When we eliminate this patch, the `-Wl,--allow-multiple-definition`
# should also be removed
Patch56: 0056-strcasecmp.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2053289
Patch58: 0058-FIPS-limit-rsa-encrypt.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2069235
Patch60: 0060-FIPS-KAT-signature-tests.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2087147
Patch61: 0061-Deny-SHA-1-signature-verification-in-FIPS-provider.patch
Patch62: 0062-fips-Expose-a-FIPS-indicator.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2130708
# https://github.com/openssl/openssl/pull/18883
Patch67: 0067-ppc64le-Montgomery-multiply.patch
# https://github.com/openssl/openssl/commit/44a563dde1584cd9284e80b6e45ee5019be8d36c
# https://github.com/openssl/openssl/commit/345c99b6654b8313c792d54f829943068911ddbd
Patch71: 0071-AES-GCM-performance-optimization.patch
# https://github.com/openssl/openssl/commit/f596bbe4da779b56eea34d96168b557d78e1149
# https://github.com/openssl/openssl/commit/7e1f3ffcc5bc15fb9a12b9e3bb202f544c6ed5aa
# hunks in crypto/ppccap.c from https://github.com/openssl/openssl/commit/f5485b97b6c9977c0d39c7669b9f97a879312447
Patch72: 0072-ChaCha20-performance-optimizations-for-ppc64le.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102535
Patch73: 0073-FIPS-Use-OAEP-in-KATs-support-fixed-OAEP-seed.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102535
Patch74: 0074-FIPS-Use-digest_sign-digest_verify-in-self-test.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102535
Patch75: 0075-FIPS-Use-FFDHE2048-in-self-test.patch
# Downstream only. Reseed DRBG using getrandom(GRND_RANDOM)
# https://bugzilla.redhat.com/show_bug.cgi?id=2102541
Patch76: 0076-FIPS-140-3-DRBG.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102542
Patch77: 0077-FIPS-140-3-zeroization.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2114772
# https://bugzilla.redhat.com/show_bug.cgi?id=2141695
# https://bugzilla.redhat.com/show_bug.cgi?id=2160733
# https://bugzilla.redhat.com/show_bug.cgi?id=2164763
Patch78: 0078-KDF-Add-FIPS-indicators.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=2141748
Patch80: 0080-rand-Forbid-truncated-hashes-SHA-3-in-FIPS-prov.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142131
Patch81: 0081-signature-Remove-X9.31-padding-from-FIPS-prov.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2136250
Patch83: 0083-hmac-Add-explicit-FIPS-indicator-for-key-length.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2137557
Patch84: 0084-pbkdf2-Set-minimum-password-length-of-8-bytes.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=2142121
Patch85: 0085-FIPS-RSA-disable-shake.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142087
Patch88: 0088-signature-Add-indicator-for-PSS-salt-length.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142087
Patch89: 0089-PSS-salt-length-from-provider.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142087
Patch90: 0090-signature-Clamp-PSS-salt-len-to-MD-len.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2144561
Patch91: 0091-FIPS-RSA-encapsulate.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142517
Patch92: 0092-provider-improvements.patch
# FIPS-95
Patch93: 0093-DH-Disable-FIPS-186-4-type-parameters-in-FIPS-mode.patch

# OpenSSL 3.0.8 CVEs
Patch101: 0101-CVE-2022-4203-nc-match.patch
Patch102: 0102-CVE-2022-4304-RSA-time-oracle.patch
Patch103: 0103-CVE-2022-4450-pem-read-bio.patch
Patch104: 0104-CVE-2023-0215-UAF-bio.patch
Patch105: 0105-CVE-2023-0216-pkcs7-deref.patch
Patch106: 0106-CVE-2023-0217-dsa.patch
Patch107: 0107-CVE-2023-0286-X400.patch
Patch108: 0108-CVE-2023-0401-pkcs7-md.patch

# https://bugzilla.redhat.com/show_bug.cgi?id=2169314
Patch109: 0109-fips-Zeroize-out-in-fips-selftest.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2168289
Patch110: 0110-GCM-Implement-explicit-FIPS-indicator-for-IV-gen.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2175145
Patch111: 0111-fips-Use-salt-16-bytes-in-PBKDF2-selftest.patch
Patch112: 0112-pbdkf2-Set-indicator-if-pkcs5-param-disabled-checks.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2179331
Patch113: 0113-asymciphers-kem-Add-explicit-FIPS-indicator.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2157951
Patch114: 0114-FIPS-enforce-EMS-support.patch

# X.509 policies minor CVEs
Patch115: 0115-CVE-2023-0464.patch
Patch116: 0116-CVE-2023-0465.patch
Patch117: 0117-CVE-2023-0466.patch
# AES-XTS CVE
Patch118: 0118-CVE-2023-1255.patch

#https://github.com/openssl/openssl/pull/13817
#https://bugzilla.redhat.com/show_bug.cgi?id=2153471
Patch120: 0120-RSA-PKCS15-implicit-rejection.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2160797
Patch121: 0121-FIPS-cms-defaults.patch
Patch122: 0122-CVE-2023-2650.patch
# https://github.com/openssl/openssl/pull/19386
Patch123: 0123-ibmca-atexit-crash.patch
Patch125: 0125-CVE-2023-2975.patch
Patch126: 0126-CVE-2023-3446.patch
Patch127: 0127-CVE-2023-3817.patch
Patch128: 0128-CVE-2023-5363.patch
# https://github.com/openssl/openssl/pull/22403
Patch129: 0129-rsa-Add-SP800-56Br2-6.4.1.2.1-3.c-check.patch
Patch130: 0130-CVE-2023-5678.patch
# https://github.com/openssl/openssl/pull/20317
Patch131: 0131-sslgroups-memleak.patch
# https://github.com/openssl/openssl/commit/050d26383d4e264966fb83428e72d5d48f402d35
Patch132: 0132-CVE-2023-6129.patch
# https://github.com/openssl/openssl/commit/18c02492138d1eb8b6548cb26e7b625fb2414a2a
Patch133: 0133-CVE-2023-6237.patch
# https://github.com/openssl/openssl/pull/20780
Patch134: 0134-engine-based-ECDHE-kex.patch
# https://github.com/openssl/openssl/pull/23362
Patch135: 0135-CVE-2024-0727.patch
#FIPS PROVIDER rebranding
Patch200: rocky_fips_provider.patch
Patch201: rocky_fips_provider-2.patch

License: ASL 2.0
URL: http://www.openssl.org/
BuildRequires: gcc g++
BuildRequires: coreutils, perl-interpreter, sed, zlib-devel, /usr/bin/cmp
BuildRequires: lksctp-tools-devel
BuildRequires: /usr/bin/rename
BuildRequires: /usr/bin/pod2man
BuildRequires: /usr/sbin/sysctl
BuildRequires: perl(Test::Harness), perl(Test::More), perl(Math::BigInt)
BuildRequires: perl(Module::Load::Conditional), perl(File::Temp)
BuildRequires: perl(Time::HiRes), perl(IPC::Cmd), perl(Pod::Html), perl(Digest::SHA)
BuildRequires: perl(FindBin), perl(lib), perl(File::Compare), perl(File::Copy), perl(bigint)
BuildRequires: git-core
Requires: coreutils
Requires: %{name}-libs%{?_isa} = %{epoch}:%{version}-%{release}

%description
The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

%package libs
Summary: A general purpose cryptography library with TLS implementation
Requires: ca-certificates >= 2008-5
Requires: crypto-policies >= 20180730
%if ( %{defined rhel} && (! %{defined centos}) )
Requires: openssl-fips-provider
%endif

%description libs
OpenSSL is a toolkit for supporting cryptography. The openssl-libs
package contains the libraries that are used by various applications which
support cryptographic algorithms and protocols.

%package devel
Summary: Files for development of applications which will use OpenSSL
Requires: %{name}-libs%{?_isa} = %{epoch}:%{version}-%{release}
Requires: pkgconfig

%description devel
OpenSSL is a toolkit for supporting cryptography. The openssl-devel
package contains include files needed to develop applications which
support various cryptographic algorithms and protocols.

%package perl
Summary: Perl scripts provided with OpenSSL
Requires: perl-interpreter
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}

%description perl
OpenSSL is a toolkit for supporting cryptography. The openssl-perl
package provides Perl scripts for converting certificates and keys
from other formats to the formats used by the OpenSSL toolkit.

%prep
%autosetup -S git -n %{name}-%{version}

%build
# Figure out which flags we want to use.
# default
sslarch=%{_os}-%{_target_cpu}
%ifarch %ix86
sslarch=linux-elf
if ! echo %{_target} | grep -q i686 ; then
	sslflags="no-asm 386"
fi
%endif
%ifarch x86_64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch sparcv9
sslarch=linux-sparcv9
sslflags=no-asm
%endif
%ifarch sparc64
sslarch=linux64-sparcv9
sslflags=no-asm
%endif
%ifarch alpha alphaev56 alphaev6 alphaev67
sslarch=linux-alpha-gcc
%endif
%ifarch s390 sh3eb sh4eb
sslarch="linux-generic32 -DB_ENDIAN"
%endif
%ifarch s390x
sslarch="linux64-s390x"
%endif
%ifarch %{arm}
sslarch=linux-armv4
%endif
%ifarch aarch64
sslarch=linux-aarch64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch sh3 sh4
sslarch=linux-generic32
%endif
%ifarch ppc64 ppc64p7
sslarch=linux-ppc64
%endif
%ifarch ppc64le
sslarch="linux-ppc64le"
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch mips mipsel
sslarch="linux-mips32 -mips32r2"
%endif
%ifarch mips64 mips64el
sslarch="linux64-mips64 -mips64r2"
%endif
%ifarch mips64el
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch riscv64
sslarch=linux-generic64
%endif

# Add -Wa,--noexecstack here so that libcrypto's assembler modules will be
# marked as not requiring an executable stack.
# Also add -DPURIFY to make using valgrind with openssl easier as we do not
# want to depend on the uninitialized memory as a source of entropy anyway.
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes -DPURIFY $RPM_LD_FLAGS"

export HASHBANGPERL=/usr/bin/perl

%define fips %{version}-%{srpmhash}
# ia64, x86_64, ppc are OK by default
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.
./Configure \
	--prefix=%{_prefix} --openssldir=%{_sysconfdir}/pki/tls ${sslflags} \
	--system-ciphers-file=%{_sysconfdir}/crypto-policies/back-ends/openssl.config \
	zlib enable-camellia enable-seed enable-rfc3779 enable-sctp \
	enable-cms enable-md2 enable-rc5 enable-ktls enable-fips\
	no-mdc2 no-ec2m no-sm2 no-sm4 enable-buildtest-c++\
	shared  ${sslarch} $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\"" -DROCKY_FIPS_NAME="\"Rocky Linux 9 - OpenSSL FIPS Provider\"" -DROCKY_FIPS_VERSION="\"Rocky9.20241015\""'\
	-Wl,--allow-multiple-definition

# Do not run this in a production package the FIPS symbols must be patched-in
#util/mkdef.pl crypto update

make %{?_smp_mflags} all

# Clean up the .pc files
for i in libcrypto.pc libssl.pc openssl.pc ; do
  sed -i '/^Libs.private:/{s/-L[^ ]* //;s/-Wl[^ ]* //}' $i
done

%check
# Verify that what was compiled actually works.

# Hack - either enable SCTP AUTH chunks in kernel or disable sctp for check
(sysctl net.sctp.addip_enable=1 && sysctl net.sctp.auth_enable=1) || \
(echo 'Failed to enable SCTP AUTH chunks, disabling SCTP for tests...' &&
 sed '/"msan" => "default",/a\ \ "sctp" => "default",' configdata.pm > configdata.pm.new && \
 touch -r configdata.pm configdata.pm.new && \
 mv -f configdata.pm.new configdata.pm)

# We must revert patch4 before tests otherwise they will fail
patch -p1 -R < %{PATCH4}
#We must disable default provider before tests otherwise they will fail
patch -p1 < %{SOURCE14}

OPENSSL_ENABLE_MD5_VERIFY=
export OPENSSL_ENABLE_MD5_VERIFY
OPENSSL_ENABLE_SHA1_SIGNATURES=
export OPENSSL_ENABLE_SHA1_SIGNATURES
OPENSSL_SYSTEM_CIPHERS_OVERRIDE=xyz_nonexistent_file
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE
#embed HMAC into fips provider for test run
LD_LIBRARY_PATH=. apps/openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813 < providers/fips.so > providers/fips.so.hmac
objcopy --update-section .rodata1=providers/fips.so.hmac providers/fips.so providers/fips.so.mac
mv providers/fips.so.mac providers/fips.so
#run tests itself
make test HARNESS_JOBS=8

# Add generation of HMAC checksum of the final stripped library
# We manually copy standard definition of __spec_install_post
# and add hmac calculation/embedding to fips.so
%if ( %{defined rhel} && (! %{defined centos}) )
%define __spec_install_post \
    rm -rf $RPM_BUILD_ROOT/%{_libdir}/ossl-modules/fips.so \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
%{nil}
%else
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    LD_LIBRARY_PATH=. apps/openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813 < $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so > $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so.hmac \
    objcopy --update-section .rodata1=$RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so.hmac $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so.mac \
    mv $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so.mac $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so \
    rm $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so.hmac \
%{nil}
%endif

%define __provides_exclude_from %{_libdir}/openssl

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
# Install OpenSSL.
install -d $RPM_BUILD_ROOT{%{_bindir},%{_includedir},%{_libdir},%{_mandir},%{_libdir}/openssl,%{_pkgdocdir}}
%make_install
rename so.%{soversion} so.%{version} $RPM_BUILD_ROOT%{_libdir}/*.so.%{soversion}
for lib in $RPM_BUILD_ROOT%{_libdir}/*.so.%{version} ; do
	chmod 755 ${lib}
	ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`
	ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`.%{soversion}
done

# Remove static libraries
for lib in $RPM_BUILD_ROOT%{_libdir}/*.a ; do
	rm -f ${lib}
done

# Install a makefile for generating keys and self-signed certs, and a script
# for generating them on the fly.
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/certs
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.d
install -m644 %{SOURCE2} $RPM_BUILD_ROOT%{_pkgdocdir}/Makefile.certificate
install -m755 %{SOURCE6} $RPM_BUILD_ROOT%{_bindir}/make-dummy-cert
install -m755 %{SOURCE7} $RPM_BUILD_ROOT%{_bindir}/renew-dummy-cert

# Move runable perl scripts to bindir
mv $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/misc/*.pl $RPM_BUILD_ROOT%{_bindir}
mv $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/misc/tsget $RPM_BUILD_ROOT%{_bindir}

# Rename man pages so that they don't conflict with other system man pages.
pushd $RPM_BUILD_ROOT%{_mandir}
mv man5/config.5ossl man5/openssl.cnf.5
popd

mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA
mkdir -m700 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/private
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/certs
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/crl
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/newcerts

# Ensure the config file timestamps are identical across builds to avoid
# mulitlib conflicts and unnecessary renames on upgrade
touch -r %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf
touch -r %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/ct_log_list.cnf

rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.dist
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/ct_log_list.cnf.dist
#we don't use native fipsmodule.cnf because FIPS module is loaded automatically
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/fipsmodule.cnf

# Determine which arch opensslconf.h is going to try to #include.
basearch=%{_arch}
%ifarch %{ix86}
basearch=i386
%endif
%ifarch sparcv9
basearch=sparc
%endif
%ifarch sparc64
basearch=sparc64
%endif

# Next step of gradual disablement of SSL3.
# Make SSL3 disappear to newly built dependencies.
sed -i '/^\#ifndef OPENSSL_NO_SSL_TRACE/i\
#ifndef OPENSSL_NO_SSL3\
# define OPENSSL_NO_SSL3\
#endif' $RPM_BUILD_ROOT/%{_prefix}/include/openssl/opensslconf.h

%ifarch %{multilib_arches}
# Do an configuration.h switcheroo to avoid file conflicts on systems where you
# can have both a 32- and 64-bit version of the library, and they each need
# their own correct-but-different versions of opensslconf.h to be usable.
install -m644 %{SOURCE10} \
	$RPM_BUILD_ROOT/%{_prefix}/include/openssl/configuration-${basearch}.h
cat $RPM_BUILD_ROOT/%{_prefix}/include/openssl/configuration.h >> \
	$RPM_BUILD_ROOT/%{_prefix}/include/openssl/configuration-${basearch}.h
install -m644 %{SOURCE9} \
	$RPM_BUILD_ROOT/%{_prefix}/include/openssl/configuration.h
%endif
ln -s /etc/crypto-policies/back-ends/openssl_fips.config $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/fips_local.cnf

%files
%{!?_licensedir:%global license %%doc}
%license LICENSE.txt
%doc NEWS.md README.md
%{_bindir}/make-dummy-cert
%{_bindir}/renew-dummy-cert
%{_bindir}/openssl
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man7/*
%{_pkgdocdir}/Makefile.certificate
%exclude %{_mandir}/man1/*.pl*
%exclude %{_mandir}/man1/tsget*

%files libs
%{!?_licensedir:%global license %%doc}
%license LICENSE.txt
%dir %{_sysconfdir}/pki/tls
%dir %{_sysconfdir}/pki/tls/certs
%dir %{_sysconfdir}/pki/tls/misc
%dir %{_sysconfdir}/pki/tls/private
%dir %{_sysconfdir}/pki/tls/openssl.d
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.cnf
%config(noreplace) %{_sysconfdir}/pki/tls/ct_log_list.cnf
%config %{_sysconfdir}/pki/tls/fips_local.cnf
%attr(0755,root,root) %{_libdir}/libcrypto.so.%{version}
%{_libdir}/libcrypto.so.%{soversion}
%attr(0755,root,root) %{_libdir}/libssl.so.%{version}
%{_libdir}/libssl.so.%{soversion}
%attr(0755,root,root) %{_libdir}/engines-%{soversion}
%attr(0755,root,root) %{_libdir}/ossl-modules

%files devel
%doc CHANGES.md doc/dir-locals.example.el doc/openssl-c-indent.el
%{_prefix}/include/openssl
%{_libdir}/*.so
%{_mandir}/man3/*
%{_libdir}/pkgconfig/*.pc

%files perl
%{_bindir}/c_rehash
%{_bindir}/*.pl
%{_bindir}/tsget
%{_mandir}/man1/*.pl*
%{_mandir}/man1/tsget*
%dir %{_sysconfdir}/pki/CA
%dir %{_sysconfdir}/pki/CA/private
%dir %{_sysconfdir}/pki/CA/certs
%dir %{_sysconfdir}/pki/CA/crl
%dir %{_sysconfdir}/pki/CA/newcerts

%ldconfig_scriptlets libs

%changelog
* Thu Sep 7 2024 Jason Rodriguez <jrodriguez@ciq.com> - 3.0.7-27.0.2.2
- Rocky FIPS provider updating Rocky references 

* Thu Sep 7 2024 Jason Rodriguez <jrodriguez@ciq.com> - 3.0.7-27.0.2.1
- Rocky FIPS provider rebranding

* Thu Aug 01 2024 Release Engineering <releng@rockylinux.org> - 3.0.7-27.0.2
- Rebuild to address build system issue

* Wed Feb 21 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-27
- Use certified FIPS module instead of freshly built one in Red Hat distribution
  Related: RHEL-23474

* Tue Nov 21 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-26
- Avoid implicit function declaration when building openssl
  Related: RHEL-1780
- In FIPS mode, prevent any other operations when rsa_keygen_pairwise_test fails
  Resolves: RHEL-17104
- Add a directory for OpenSSL providers configuration
  Resolves: RHEL-17193
- Eliminate memory leak in OpenSSL when setting elliptic curves on SSL context
  Resolves: RHEL-19515
- POLY1305 MAC implementation corrupts vector registers on PowerPC (CVE-2023-6129)
  Resolves: RHEL-21151
- Excessive time spent checking invalid RSA public keys (CVE-2023-6237)
  Resolves: RHEL-21654
- SSL ECDHE Kex fails when pkcs11 engine is set in config file
  Resolves: RHEL-20249
- Denial of service via null dereference in PKCS#12
  Resolves: RHEL-22486
- Use certified FIPS module instead of freshly built one in Red Hat distribution
  Resolves: RHEL-23474

* Mon Oct 16 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-25
- Provide relevant diagnostics when FIPS checksum is corrupted
  Resolves: RHEL-5317
- Don't limit using SHA1 in KDFs in non-FIPS mode.
  Resolves: RHEL-5295
- Provide empty evp_properties section in main OpenSSL configuration file
  Resolves: RHEL-11439
- Avoid implicit function declaration when building openssl
  Resolves: RHEL-1780
- Forbid explicit curves when created via EVP_PKEY_fromdata
  Resolves: RHEL-5304
- AES-SIV cipher implementation contains a bug that causes it to ignore empty
  associated data entries (CVE-2023-2975)
  Resolves: RHEL-5302
- Excessive time spent checking DH keys and parameters (CVE-2023-3446)
  Resolves: RHEL-5306
- Excessive time spent checking DH q parameter value (CVE-2023-3817)
  Resolves: RHEL-5308
- Fix incorrect cipher key and IV length processing (CVE-2023-5363)
  Resolves: RHEL-13251
- Switch explicit FIPS indicator for RSA-OAEP to approved following
  clarification with CMVP
  Resolves: RHEL-14083
- Backport the check required by SP800-56Br2 6.4.1.2.1 (3.c)
  Resolves: RHEL-14083
- Add missing ECDH Public Key Check in FIPS mode
  Resolves: RHEL-15990
- Excessive time spent in DH check/generation with large Q parameter value (CVE-2023-5678)
  Resolves: RHEL-15954

* Wed Jul 12 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-24
- Make FIPS module configuration more crypto-policies friendly
  Related: rhbz#2216256

* Tue Jul 11 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-23
- Add a workaround for lack of EMS in FIPS mode
  Resolves: rhbz#2216256

* Thu Jul 06 2023 Sahana Prasad <sahana@redhat.com> - 1:3.0.7-22
- Remove unsupported curves from nist_curves.
  Resolves: rhbz#2069336

* Mon Jun 26 2023 Sahana Prasad <sahana@redhat.com> - 1:3.0.7-21
- Remove the listing of brainpool curves in FIPS mode.
  Related: rhbz#2188180

* Tue May 30 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-20
- Fix possible DoS translating ASN.1 object identifiers
  Resolves: CVE-2023-2650
- Release the DRBG in global default libctx early
  Resolves: rhbz#2211340

* Mon May 22 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-19
- Re-enable DHX keys in FIPS mode, disable FIPS 186-4 parameter validation and generation in FIPS mode
  Resolves: rhbz#2169757

* Thu May 18 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-18
- Use OAEP padding and aes-128-cbc by default in cms command in FIPS mode
  Resolves: rhbz#2160797

* Tue May 09 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-17
- Enforce using EMS in FIPS mode - better alerts
  Related: rhbz#2157951

* Tue May 02 2023 Sahana Prasad <sahana@redhat.com> - 1:3.0.7-16
- Upload new upstream sources without manually hobbling them.
- Remove the hobbling script as it is redundant. It is now allowed to ship
  the sources of patented EC curves, however it is still made unavailable to use
  by compiling with the 'no-ec2m' Configure option. The additional forbidden
  curves such as P-160, P-192, wap-tls curves are manually removed by updating
  0011-Remove-EC-curves.patch.
- Enable Brainpool curves.
- Apply the changes to ec_curve.c and  ectest.c as a new patch
  0010-Add-changes-to-ectest-and-eccurve.patch instead of replacing them.
- Modify 0011-Remove-EC-curves.patch to allow Brainpool curves.
- Modify 0011-Remove-EC-curves.patch to allow code under macro OPENSSL_NO_EC2M.
  Resolves: rhbz#2130618, rhbz#2188180

* Fri Apr 28 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-15
- Backport implicit rejection for RSA PKCS#1 v1.5 encryption
  Resolves: rhbz#2153471

* Fri Apr 21 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-14
- Input buffer over-read in AES-XTS implementation on 64 bit ARM
  Resolves: rhbz#2188554

* Tue Apr 18 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-13
- Enforce using EMS in FIPS mode
  Resolves: rhbz#2157951
- Fix excessive resource usage in verifying X509 policy constraints
  Resolves: rhbz#2186661
- Fix invalid certificate policies in leaf certificates check
  Resolves: rhbz#2187429
- Certificate policy check not enabled
  Resolves: rhbz#2187431
- OpenSSL rsa_verify_recover key length checks in FIPS mode
  Resolves: rhbz#2186819

* Fri Mar 24 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-12
- Change explicit FIPS indicator for RSA decryption to unapproved
  Resolves: rhbz#2179379

* Mon Mar 20 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-11
- Add missing reference to patchfile to add explicit FIPS indicator to RSA
  encryption and RSASVE and fix the gettable parameter list for the RSA
  asymmetric cipher implementation.
  Resolves: rhbz#2179379

* Fri Mar 17 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-10
- Add explicit FIPS indicator to RSA encryption and RSASVE
  Resolves: rhbz#2179379

* Thu Mar 16 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-9
- Fix explicit FIPS indicator for X9.42 KDF when used with output lengths < 14 bytes
  Resolves: rhbz#2175864

* Thu Mar 16 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-8
- Fix Wpointer-sign compiler warning 
  Resolves: rhbz#2178034

* Tue Mar 14 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-7
- Add explicit FIPS indicators to key derivation functions
  Resolves: rhbz#2175860 rhbz#2175864
- Zeroize FIPS module integrity check MAC after check
  Resolves: rhbz#2175873
- Add explicit FIPS indicator for IV generation in AES-GCM
  Resolves: rhbz#2175868
- Add explicit FIPS indicator for PBKDF2, use test vector with FIPS-compliant
  salt in PBKDF2 FIPS self-test
  Resolves: rhbz#2178137
- Limit RSA_NO_PADDING for encryption and signature in FIPS mode
  Resolves: rhbz#2178029
- Pairwise consistency tests should use Digest+Sign/Verify
  Resolves: rhbz#2178034
- Forbid DHX keys import in FIPS mode
  Resolves: rhbz#2178030
- DH PCT should abort on failure
  Resolves: rhbz#2178039
- Increase RNG seeding buffer size to 32
  Related: rhbz#2168224

* Wed Mar 08 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-6
- Fixes RNG slowdown in FIPS mode
  Resolves: rhbz#2168224

* Wed Feb 08 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-5
- Fixed X.509 Name Constraints Read Buffer Overflow
  Resolves: CVE-2022-4203
- Fixed Timing Oracle in RSA Decryption
  Resolves: CVE-2022-4304
- Fixed Double free after calling PEM_read_bio_ex
  Resolves: CVE-2022-4450
- Fixed Use-after-free following BIO_new_NDEF
  Resolves: CVE-2023-0215
- Fixed Invalid pointer dereference in d2i_PKCS7 functions
  Resolves: CVE-2023-0216
- Fixed NULL dereference validating DSA public key
  Resolves: CVE-2023-0217
- Fixed X.400 address type confusion in X.509 GeneralName
  Resolves: CVE-2023-0286
- Fixed NULL dereference during PKCS7 data verification
  Resolves: CVE-2023-0401

* Wed Jan 11 2023 Clemens Lang <cllang@redhat.com> - 1:3.0.7-4
- Disallow SHAKE in RSA-OAEP decryption in FIPS mode
  Resolves: rhbz#2142121

* Thu Jan 05 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-3
- Refactor OpenSSL fips module MAC verification
  Resolves: rhbz#2157965

* Thu Nov 24 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-2
- Various provider-related imrovements necessary for PKCS#11 provider correct operations
  Resolves: rhbz#2142517
- We should export 2 versions of OPENSSL_str[n]casecmp to be compatible with upstream
  Resolves: rhbz#2133809
- Removed recommended package for openssl-libs
  Resolves: rhbz#2093804
- Adjusting include for the FIPS_mode macro
  Resolves: rhbz#2083879
- Backport of ppc64le Montgomery multiply enhancement
  Resolves: rhbz#2130708
- Fix explicit indicator for PSS salt length in FIPS mode when used with
  negative magic values
  Resolves: rhbz#2142087
- Update change to default PSS salt length with patch state from upstream 
  Related: rhbz#2142087

* Tue Nov 22 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-1
- Rebasing to OpenSSL 3.0.7
  Resolves: rhbz#2129063

* Mon Nov 14 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-44
- SHAKE-128/256 are not allowed with RSA in FIPS mode
  Resolves: rhbz#2144010
- Avoid memory leaks in TLS
  Resolves: rhbz#2144008
- FIPS RSA CRT tests must use correct parameters
  Resolves: rhbz#2144006
- FIPS-140-3 permits only SHA1, SHA256, and SHA512 for DRBG-HASH/DRBG-HMAC
  Resolves: rhbz#2144017
- Remove support for X9.31 signature padding in FIPS mode
  Resolves: rhbz#2144015
- Add explicit indicator for SP 800-108 KDFs with short key lengths
  Resolves: rhbz#2144019
- Add explicit indicator for HMAC with short key lengths
  Resolves: rhbz#2144000
- Set minimum password length for PBKDF2 in FIPS mode
  Resolves: rhbz#2144003
- Add explicit indicator for PSS salt length in FIPS mode
  Resolves: rhbz#2144012
- Clamp default PSS salt length to digest size for FIPS 186-4 compliance
  Related: rhbz#2144012
- Forbid short RSA keys for key encapsulation/decapsulation in FIPS mode
  Resolves: rhbz#2145170

* Tue Nov 01 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-43
- CVE-2022-3602: X.509 Email Address Buffer Overflow
- CVE-2022-3786: X.509 Email Address Buffer Overflow
  Resolves: CVE-2022-3602

* Wed Oct 26 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-42
- CVE-2022-3602: X.509 Email Address Buffer Overflow
  Resolves: CVE-2022-3602 (rhbz#2137723)

* Thu Aug 11 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-41
- Zeroize public keys as required by FIPS 140-3
  Related: rhbz#2102542
- Add FIPS indicator for HKDF
  Related: rhbz#2114772

* Fri Aug 05 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-40
- Deal with DH keys in FIPS mode according FIPS-140-3 requirements
  Related: rhbz#2102536
- Deal with ECDH keys in FIPS mode according FIPS-140-3 requirements
  Related: rhbz#2102537
- Use signature for RSA pairwise test according FIPS-140-3 requirements
  Related: rhbz#2102540
- Reseed all the parent DRBGs in chain on reseeding a DRBG
  Related: rhbz#2102541

* Mon Aug 01 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-39
- Use RSA-OAEP in FIPS RSA encryption/decryption FIPS self-test
- Use Use digest_sign & digest_verify in FIPS signature self test
- Use FFDHE2048 in Diffie-Hellman FIPS self-test
  Resolves: rhbz#2102535

* Thu Jul 14 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-38
- Fix segfault in EVP_PKEY_Q_keygen() when OpenSSL was not previously
  initialized.
  Resolves: rhbz#2103289
- Improve AES-GCM performance on Power9 and Power10 ppc64le
  Resolves: rhbz#2051312
- Improve ChaCha20 performance on Power10 ppc64le
  Resolves: rhbz#2051312

* Tue Jul 05 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-37
- CVE-2022-2097: AES OCB fails to encrypt some bytes on 32-bit x86
  Resolves: CVE-2022-2097

* Thu Jun 16 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-36
- Ciphersuites with RSAPSK KX should be filterd in FIPS mode
- Related: rhbz#2085088
- FIPS provider should block RSA encryption for key transport.
- Other RSA encryption options should still be available if key length is enough
- Related: rhbz#2053289
- Improve diagnostics when passing unsupported groups in TLS
- Related: rhbz#2070197
- Fix PPC64 Montgomery multiplication bug
- Related: rhbz#2098199
- Strict certificates validation shouldn't allow explicit EC parameters
- Related: rhbz#2058663
- CVE-2022-2068: the c_rehash script allows command injection
- Related: rhbz#2098277

* Wed Jun 08 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-35
- Add explicit indicators for signatures in FIPS mode and mark signature
  primitives as unapproved.
  Resolves: rhbz#2087147

* Fri Jun 03 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-34
- Some OpenSSL test certificates are expired, updating
- Resolves: rhbz#2092456

* Thu May 26 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-33
- CVE-2022-1473 openssl: OPENSSL_LH_flush() breaks reuse of memory
- Resolves: rhbz#2089444
- CVE-2022-1343 openssl: Signer certificate verification returned
  inaccurate response when using OCSP_NOCHECKS
- Resolves: rhbz#2087911
- CVE-2022-1292 openssl: c_rehash script allows command injection
- Resolves: rhbz#2090362
- Revert "Disable EVP_PKEY_sign/EVP_PKEY_verify in FIPS mode"
  Related: rhbz#2087147
- Use KAT for ECDSA signature tests, s390 arch
- Resolves: rhbz#2069235

* Thu May 19 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-32
- `openssl ecparam -list_curves` lists only FIPS-approved curves in FIPS mode
- Resolves: rhbz#2083240
- Ciphersuites with RSA KX should be filterd in FIPS mode
- Related: rhbz#2085088
- In FIPS mode, signature verification works with keys of arbitrary size
  above 2048 bit, and only with 1024, 1280, 1536, 1792 bits for keys
  below 2048 bits
- Resolves: rhbz#2077884

* Wed May 18 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-31
- Disable SHA-1 signature verification in FIPS mode
- Disable EVP_PKEY_sign/EVP_PKEY_verify in FIPS mode
  Resolves: rhbz#2087147

* Mon May 16 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-30
- Use KAT for ECDSA signature tests
- Resolves: rhbz#2069235

* Thu May 12 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-29
- `-config` argument of openssl app should work properly in FIPS mode
- Resolves: rhbz#2083274
- openssl req defaults on PKCS#8 encryption changed to AES-256-CBC
- Resolves: rhbz#2063947

* Fri May 06 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-28
- OpenSSL should not accept custom elliptic curve parameters
- Resolves rhbz#2066412
- OpenSSL should not accept explicit curve parameters in FIPS mode
- Resolves rhbz#2058663

* Fri May 06 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-27
- Change FIPS module version to include hash of specfile, patches and sources
  Resolves: rhbz#2070550

* Thu May 05 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-26
- OpenSSL FIPS module should not build in non-approved algorithms
- Resolves: rhbz#2081378

* Mon May 02 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-25
- FIPS provider should block RSA encryption for key transport.
- Other RSA encryption options should still be available
- Resolves: rhbz#2053289

* Thu Apr 28 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-24
- Fix regression in evp_pkey_name2type caused by tr_TR locale fix
  Resolves: rhbz#2071631

* Wed Apr 20 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-23
- Fix openssl curl error with LANG=tr_TR.utf8
- Resolves: rhbz#2071631

* Mon Mar 28 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-22
- FIPS provider should block RSA encryption for key transport
- Resolves: rhbz#2053289

* Tue Mar 22 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-21
- Fix occasional internal error in TLS when DHE is used
- Resolves: rhbz#2004915

* Fri Mar 18 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-20
- Fix acceptance of SHA-1 certificates with rh-allow-sha1-signatures = yes when
  no OpenSSL library context is set
- Resolves: rhbz#2065400

* Fri Mar 18 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-19
- Fix TLS connections with SHA1 signatures if rh-allow-sha1-signatures = yes
- Resolves: rhbz#2065400

* Wed Mar 16 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-18
- CVE-2022-0778 fix
- Resolves: rhbz#2062315

* Thu Mar 10 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-17
- Fix invocation of EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_PSS_PADDING) before
  setting an allowed digest with EVP_PKEY_CTX_set_signature_md()
- Skipping 3.0.1-16 due to version numbering confusion with the RHEL-9.0 branch
- Resolves: rhbz#2062640

* Tue Mar 01 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-15
- Allow SHA1 in SECLEVEL 2 if rh-allow-sha1-signatures = yes
- Resolves: rhbz#2060510

* Fri Feb 25 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-14
- Prevent use of SHA1 with ECDSA
- Resolves: rhbz#2031742

* Fri Feb 25 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-13
- OpenSSL will generate keys with prime192v1 curve if it is provided using explicit parameters
- Resolves: rhbz#1977867

* Thu Feb 24 2022 Peter Robinson <pbrobinson@fedoraproject.org> - 1:3.0.1-12
- Support KBKDF (NIST SP800-108) with an R value of 8bits
- Resolves: rhbz#2027261

* Wed Feb 23 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-11
- Allow SHA1 usage in MGF1 for RSASSA-PSS signatures
- Resolves: rhbz#2031742

* Wed Feb 23 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-10
- rebuilt

* Tue Feb 22 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-9
- Allow SHA1 usage in HMAC in TLS
- Resolves: rhbz#2031742

* Tue Feb 22 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-8
- OpenSSL will generate keys with prime192v1 curve if it is provided using explicit parameters
- Resolves: rhbz#1977867
- pkcs12 export broken in FIPS mode
- Resolves: rhbz#2049265

* Tue Feb 22 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.1-8
- Disable SHA1 signature creation and verification by default
- Set rh-allow-sha1-signatures = yes to re-enable
- Resolves: rhbz#2031742

* Thu Feb 03 2022 Sahana Prasad <sahana@redhat.com> - 1:3.0.1-7
- s_server: correctly handle 2^14 byte long records
- Resolves: rhbz#2042011

* Tue Feb 01 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-6
- Adjust FIPS provider version
- Related: rhbz#2026445

* Wed Jan 26 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-5
- On the s390x, zeroize all the copies of TLS premaster secret
- Related: rhbz#2040448

* Fri Jan 21 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-4
- rebuilt

* Fri Jan 21 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.1-3
- KATS tests should be executed before HMAC verification
- Restoring fips=yes for SHA1
- Related: rhbz#2026445, rhbz#2041994

* Thu Jan 20 2022 Sahana Prasad <sahana@redhat.com> - 1:3.0.1-2
- Add enable-buildtest-c++ to the configure options.
- Related: rhbz#1990814

* Tue Jan 18 2022 Sahana Prasad <sahana@redhat.com> - 1:3.0.1-1
- Rebase to upstream version 3.0.1
- Fixes CVE-2021-4044 Invalid handling of X509_verify_cert() internal errors in libssl
- Resolves: rhbz#2038910, rhbz#2035148

* Mon Jan 17 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-7
- Remove algorithms we don't plan to certify from fips module
- Remove native fipsmodule.cnf
- Related: rhbz#2026445

* Tue Dec 21 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-6
- openssl speed should run in FIPS mode
- Related: rhbz#1977318

* Wed Nov 24 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-5
- rebuilt for spec cleanup
- Related: rhbz#1985362

* Thu Nov 18 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-4
- Embed FIPS HMAC in fips.so
- Enforce loading FIPS provider when FIPS kernel flag is on
- Related: rhbz#1985362

* Thu Oct 07 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-3
- Fix memory leak in s_client
- Related: rhbz#1996092

* Mon Sep 20 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-2
- Avoid double-free on error seeding the RNG.
- KTLS and FIPS may interfere, so tests need to be tuned
- Resolves: rhbz#1952844, rhbz#1961643

* Thu Sep 09 2021 Sahana Prasad <sahana@redhat.com> - 1:3.0.0-1
- Rebase to upstream version 3.0.0
- Related: rhbz#1990814

* Wed Aug 25 2021 Sahana Prasad <sahana@redhat.com> - 1:3.0.0-0.beta2.7
- Removes the dual-abi build as it not required anymore. The mass rebuild
  was completed and all packages are rebuilt against Beta version.
- Resolves: rhbz#1984097

* Mon Aug 23 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.0-0.beta2.6
- Correctly process CMS reading from /dev/stdin
- Resolves: rhbz#1986315

* Mon Aug 16 2021 Sahana Prasad <sahana@redhat.com> - 3.0.0-0.beta2.5
- Add instruction for loading legacy provider in openssl.cnf
- Resolves: rhbz#1975836

* Mon Aug 16 2021 Sahana Prasad <sahana@redhat.com> - 3.0.0-0.beta2.4
- Adds support for IDEA encryption.
- Resolves: rhbz#1990602

* Tue Aug 10 2021 Sahana Prasad <sahana@redhat.com> - 3.0.0-0.beta2.3
- Fixes core dump in openssl req -modulus
- Fixes 'openssl req' to not ask for password when non-encrypted private key
  is used
- cms: Do not try to check binary format on stdin and -rctform fix
- Resolves: rhbz#1988137, rhbz#1988468, rhbz#1988137

* Mon Aug 09 2021 Mohan Boddu <mboddu@redhat.com> - 1:3.0.0-0.beta2.2.1
- Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
  Related: rhbz#1991688

* Wed Aug 04 2021 Dmitry Belyavskiy <dbelyavs@redhat.com> - 3.0.0-0.beta2.2
- When signature_algorithm extension is omitted, use more relevant alerts
- Resolves: rhbz#1965017

* Tue Aug 03 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.beta2.1
- Rebase to upstream version beta2
- Related: rhbz#1903209

* Thu Jul 22 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.beta1.5
- Prevents creation of duplicate cert entries in PKCS #12 files
- Resolves: rhbz#1978670

* Wed Jul 21 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.beta1.4
- NVR bump to update to OpenSSL 3.0 Beta1

* Mon Jul 19 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.beta1.3
- Update patch dual-abi.patch to add the #define macros in implementation
  files instead of public header files

* Wed Jul 14 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.beta1.2
- Removes unused patch dual-abi.patch

* Wed Jul 14 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.beta1.1
- Update to Beta1 version
- Includes a patch to support dual-ABI, as Beta1 brekas ABI with alpha16

* Tue Jul 06 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha16.7
- Fixes override of openssl_conf in openssl.cnf
- Use AI_ADDRCONFIG only when explicit host name is given
- Temporarily remove fipsmodule.cnf for arch i686
- Fixes segmentation fault in BN_lebin2bn
- Resolves: rhbz#1975847, rhbz#1976845, rhbz#1973477, rhbz#1975855

* Fri Jul 02 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha16.6
- Adds FIPS mode compatibility patch (sahana@redhat.com)
- Related: rhbz#1977318

* Fri Jul 02 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha16.5
- Fixes system hang issue when booted in FIPS mode (sahana@redhat.com)
- Temporarily disable downstream FIPS patches
- Related: rhbz#1977318

* Fri Jun 11 2021 Mohan Boddu <mboddu@redhat.com> 3.0.0-0.alpha16.4
- Speeding up building openssl (dbelyavs@redhat.com)
  Resolves: rhbz#1903209

* Fri Jun 04 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha16.3
- Fix reading SPKAC data from stdin
- Fix incorrect OSSL_PKEY_PARAM_MAX_SIZE for ed25519 and ed448
- Return 0 after cleanup in OPENSSL_init_crypto()
- Cleanup the peer point formats on regotiation
- Fix default digest to SHA256

* Thu May 27 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha16.2
- Enable FIPS via config options

* Mon May 17 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha16.1
- Update to alpha 16 version
  Resolves: rhbz#1952901 openssl sends alert after orderly connection close

* Mon Apr 26 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha15.1
- Update to alpha 15 version
  Resolves: rhbz#1903209, rhbz#1952598, 

* Fri Apr 16 2021 Mohan Boddu <mboddu@redhat.com> - 1:3.0.0-0.alpha13.1.1
- Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

* Fri Apr 09 2021 Sahana Prasad <sahana@redhat.com> 3.0.0-0.alpha13.1
- Update to new major release OpenSSL 3.0.0 alpha 13
  Resolves: rhbz#1903209
