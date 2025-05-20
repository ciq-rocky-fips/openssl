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
sha256sum:close()
print(string.sub(hash, 0, 16))
}

%global _performance_build 1

Summary: Utilities from the general purpose cryptography library with TLS implementation
Name: openssl
Version: 3.5.0
Release: 3%{?dist}
Epoch: 1
Source0: openssl-%{version}.tar.gz
Source1: fips-hmacify.sh
Source3: genpatches
Source4: openssl.rpmlintrc
Source6: make-dummy-cert
Source7: renew-dummy-cert
Source9: configuration-switch.h
Source10: configuration-prefix.h

Patch0001: 0001-RH-Aarch64-and-ppc64le-use-lib64.patch
Patch0002: 0002-Add-a-separate-config-file-to-use-for-rpm-installs.patch
Patch0003: 0003-RH-Do-not-install-html-docs.patch
Patch0004: 0004-RH-apps-ca-fix-md-option-help-text.patch-DROP.patch
Patch0005: 0005-RH-Disable-signature-verification-with-bad-digests-R.patch
Patch0006: 0006-RH-Add-support-for-PROFILE-SYSTEM-system-default-cip.patch
Patch0007: 0007-RH-Add-FIPS_mode-compatibility-macro.patch
Patch0008: 0008-RH-Add-Kernel-FIPS-mode-flag-support-FIXSTYLE.patch
Patch0009: 0009-RH-Drop-weak-curve-definitions-RENAMED-SQUASHED.patch
Patch0010: 0010-RH-Disable-explicit-ec-curves.patch
Patch0011: 0011-RH-skipped-tests-EC-curves.patch
Patch0012: 0012-RH-skip-quic-pairwise.patch
Patch0013: 0013-RH-version-aliasing.patch
Patch0014: 0014-RH-Export-two-symbols-for-OPENSSL_str-n-casecmp.patch
Patch0015: 0015-RH-TMP-KTLS-test-skip.patch
Patch0016: 0016-RH-Allow-disabling-of-SHA1-signatures.patch
Patch0017: 0017-FIPS-Red-Hat-s-FIPS-module-name-and-version.patch
Patch0018: 0018-FIPS-disable-fipsinstall.patch
Patch0019: 0019-FIPS-Force-fips-provider-on.patch
Patch0020: 0020-FIPS-INTEG-CHECK-Embed-hmac-in-fips.so-NOTE.patch
Patch0021: 0021-FIPS-INTEG-CHECK-Add-script-to-hmac-ify-fips.so.patch
Patch0022: 0022-FIPS-INTEG-CHECK-Execute-KATS-before-HMAC-REVIEW.patch
Patch0023: 0023-FIPS-RSA-encrypt-limits-REVIEW.patch
Patch0024: 0024-FIPS-RSA-PCTs.patch
Patch0025: 0025-FIPS-RSA-encapsulate-limits.patch
Patch0026: 0026-FIPS-RSA-Disallow-SHAKE-in-OAEP-and-PSS.patch
Patch0027: 0027-FIPS-RSA-size-mode-restrictions.patch
Patch0028: 0028-FIPS-RSA-Mark-x931-as-not-approved-by-default.patch
Patch0029: 0029-FIPS-RSA-Remove-X9.31-padding-signatures-tests.patch
Patch0030: 0030-FIPS-RSA-NEEDS-REWORK-FIPS-Use-OAEP-in-KATs-support-.patch
Patch0031: 0031-FIPS-Deny-SHA-1-signature-verification.patch
Patch0032: 0032-FIPS-RAND-FIPS-140-3-DRBG-NEEDS-REVIEW.patch
Patch0033: 0033-FIPS-RAND-Forbid-truncated-hashes-SHA-3.patch
Patch0034: 0034-FIPS-PBKDF2-Set-minimum-password-length.patch
Patch0035: 0035-FIPS-DH-PCT.patch
Patch0036: 0036-FIPS-DH-Disable-FIPS-186-4-type-parameters.patch
Patch0037: 0037-FIPS-TLS-Enforce-EMS-in-TLS-1.2-NOTE.patch
Patch0038: 0038-FIPS-CMS-Set-default-padding-to-OAEP.patch
Patch0039: 0039-FIPS-PKCS12-PBMAC1-defaults.patch
Patch0040: 0040-FIPS-Fix-encoder-decoder-negative-test.patch
Patch0041: 0041-FIPS-EC-DH-DSA-PCTs.patch
Patch0042: 0042-FIPS-EC-disable-weak-curves.patch
Patch0043: 0043-FIPS-NO-DSA-Support.patch
Patch0044: 0044-FIPS-NO-DES-support.patch
Patch0045: 0045-FIPS-NO-Kmac.patch
Patch0046: 0046-FIPS-NO-PQ-ML-SLH-DSA.patch
Patch0047: 0047-FIPS-Fix-some-tests-due-to-our-versioning-change.patch
Patch0048: 0048-Current-Rebase-status.patch
Patch0049: 0049-FIPS-KDF-key-lenght-errors.patch
Patch0050: 0050-FIPS-fix-disallowed-digests-tests.patch
Patch0051: 0051-Make-openssl-speed-run-in-FIPS-mode.patch
Patch0052: 0052-Fixup-forbid-SHA1.patch
Patch0053: 0053-Backport-upstream-27483-for-PKCS11-needs.patch
Patch0054: 0054-Red-Hat-9-FIPS-indicator-defines.patch
Patch0055: 0055-crypto-disable-OSSL_PARAM_REAL-on-UEFI.patch
Patch0056: 0056-hashfunc-add-stddef.h-include.patch
Patch0057: 0057-rio-add-RIO_POLL_METHOD_NONE.patch


License: Apache-2.0
URL: http://www.openssl.org/
BuildRequires: gcc g++
BuildRequires: coreutils, perl-interpreter, sed, zlib-devel, /usr/bin/cmp
BuildRequires: lksctp-tools-devel
BuildRequires: /usr/bin/rename
BuildRequires: /usr/bin/pod2man
BuildRequires: /usr/sbin/sysctl
BuildRequires: perl(Test::Harness), perl(Test::More), perl(Math::BigInt)
BuildRequires: perl(Module::Load::Conditional), perl(File::Temp)
BuildRequires: perl(Time::HiRes), perl(Time::Piece), perl(IPC::Cmd), perl(Pod::Html), perl(Digest::SHA)
BuildRequires: perl(FindBin), perl(lib), perl(File::Compare), perl(File::Copy), perl(bigint)
BuildRequires: git-core
BuildRequires: systemtap-sdt-devel
Requires: coreutils
Requires: %{name}-libs%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: oqsprovider < 0.9.0

%description
The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

%package libs
Summary: A general purpose cryptography library with TLS implementation
Requires: ca-certificates >= 2008-5
#Requires: crypto-policies >= 20250404-3
%if (! %{defined provider})
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
sslarch=linux64-riscv64
%endif
ktlsopt=enable-ktls
%ifarch armv7hl
ktlsopt=disable-ktls
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
%ifarch riscv64
        --libdir=%{_lib} \
%endif
	--system-ciphers-file=%{_sysconfdir}/crypto-policies/back-ends/opensslcnf.config \
	zlib enable-camellia enable-seed enable-rfc3779 enable-sctp enable-sslkeylog \
	enable-cms enable-md2 enable-rc5 ${ktlsopt} enable-fips -D_GNU_SOURCE\
	no-mdc2 no-ec2m no-sm2 no-sm4 no-atexit enable-buildtest-c++\
	shared  ${sslarch} $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\""' -DOPENSSL_PEDANTIC_ZEROIZATION\
	-DREDHAT_FIPS_VENDOR='"\"Red Hat Enterprise Linux OpenSSL FIPS Provider\""' -DREDHAT_FIPS_VERSION='"\"%{fips}\""'\
	-Wl,--allow-multiple-definition

# Do not run this in a production package the FIPS symbols must be patched-in
#util/mkdef.pl crypto update

make -s %{?_smp_mflags} all

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

OPENSSL_ENABLE_MD5_VERIFY=
export OPENSSL_ENABLE_MD5_VERIFY
OPENSSL_ENABLE_SHA1_SIGNATURES=
export OPENSSL_ENABLE_SHA1_SIGNATURES
OPENSSL_SYSTEM_CIPHERS_OVERRIDE=xyz_nonexistent_file
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE
%{SOURCE1} providers/fips.so
#run tests itself
make test HARNESS_JOBS=8

# Add generation of HMAC checksum of the final stripped library
# We manually copy standard definition of __spec_install_post
# and add hmac calculation/embedding to fips.so
%if (! %{defined provider})
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
    %{SOURCE1} $RPM_BUILD_ROOT/%{_libdir}/ossl-modules/fips.so \
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
mv rh-openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf

# Remove static libraries
for lib in $RPM_BUILD_ROOT%{_libdir}/*.a ; do
	rm -f ${lib}
done

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/certs
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.d
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
touch -r %{SOURCE0} $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf
touch -r %{SOURCE0} $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/ct_log_list.cnf

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

sed -i '/^\# ifndef OPENSSL_NO_STATIC_ENGINE/i\
# ifndef OPENSSL_NO_ENGINE\
#  define OPENSSL_NO_ENGINE\
# endif' $RPM_BUILD_ROOT/%{_prefix}/include/openssl/configuration.h

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
rm -f $RPM_BUILD_ROOT/%{_prefix}/include/openssl/engine*.h
touch $RPM_BUILD_ROOT/%{_prefix}/include/openssl/engine.h

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
%exclude %{_mandir}/man3/ENGINE*
%{_libdir}/pkgconfig/*.pc
%{_libdir}/cmake/OpenSSL/OpenSSLConfig.cmake
%{_libdir}/cmake/OpenSSL/OpenSSLConfigVersion.cmake

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
* Wed May 14 2025 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.5.0-3
- Fix `openssl speed` running in FIPS mode
  Resolves: RHEL-88908
- pkeyutl ecdsa signature with sha1 shouldn't work by default
  Resolves: RHEL-88911
- Expose settable params for EVP_SKEY
  Resolves: RHEL-88913
- Restore RHEL9-style indicators defines
  Resolves: RHEL-88906
- Enable sslkeylog support
  Resolves: RHEL-90853
- Fix UEFI builds
  Resolves: RHEL-89137

* Thu Apr 17 2025 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.5.0-2
- Update depencency on crypto-policies
  Related: RHEL-80811

* Wed Apr 09 2025 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.5.0-1
- Rebasing OpenSSL to 3.5
  Resolves: RHEL-80811
  Resolves: RHEL-57022
  Resolves: RHEL-24098
  Resolves: RHEL-24097
  Resolves: RHEL-86865

* Wed Jan 29 2025 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-16
- Fix timing side-channel in ECDSA signature computation (CVE-2024-13176)
  Resolves: RHEL-70879
- Load system default cipher string from crypto-policies configuration file
  should ignore errors.
  Related: RHEL-71132
- RFC7250 handshakes with unauthenticated servers don't abort as expected (CVE-2024-12797)
  Resolves: RHEL-76754
- Fix segfault on printing the temp key from s_client when connection is not established
  Resolves: RHEL-79045

* Thu Jan 02 2025 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-15
- Fix providers no_cache behavior
  Resolves: RHEL-71903
- Fix pkcs12 command line segfault
  Resolves: RHEL-70878
- Print key exchange group for hybrid PQC
  Resolves: RHEL-66163
- Ensure correct fips.so checksum calculation
  Resolves: RHEL-73170
- Locally configured providers should not interfere with openssl build-time tests
  Resolves: RHEL-76182
- Load system default cipher string from crypto-policies configuration file
  include /etc/crypto-policies/back-ends/opensslcnf.config and remove
  /etc/crypto-policies/back-ends/openssl.config.
  Resolves: RHEL-71132

* Tue Oct 29 2024 Troy Dawson <tdawson@redhat.com> - 1:3.2.2-14
- Bump release for October 2024 mass rebuild:
  Resolves: RHEL-64018

* Thu Oct 17 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-13
- Ship dummy(empty) openssl/engine.h
  Resolves: RHEL-58178

* Wed Sep 04 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-12
- Fix CVE-2024-6119: Possible denial of service in X.509 name checks
  Resolves: RHEL-55303

* Wed Aug 21 2024 Clemens Lang <cllang@redhat.com> - 1:3.2.2-11
- Fix CVE-2024-5535: SSL_select_next_proto buffer overread
  Resolves: RHEL-45692

* Wed Aug 14 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-10
- Use PBMAC1 by default when creating PKCS#12 files in FIPS mode
  Related: RHEL-36659
- Support key encapsulation/decapsulation in openssl pkeyutl command
  Resolves: RHEL-54156
- Fix typo in the patch numeration
  Related: RHEL-41261
- Enable KTLS, temporary disable KTLS tests
  Related: RHEL-47335
- Speedup SSL_add_{file,dir}_cert_subjects_to_stack
  Resolves: RHEL-54232
- Resolve SAST package scan results
  Resolves: RHEL-37561

* Fri Aug 09 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-9
- An interface to create PKCS #12 files in FIPS compliant way
  Related: RHEL-36659

* Wed Aug 07 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-8
- An interface to create PKCS #12 files in FIPS compliant way
  Resolves: RHEL-36659

* Wed Jul 10 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-7
- Disallow SHA1 at SECLEVEL2 in OpenSSL
  Resolves: RHEL-39962
- SHA-1 signature shouldn't work in normal mode
  Resolves: RHEL-36677

* Mon Jul 01 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-6
- Do not install ENGINE headers, man pages, and define OPENSSL_NO_ENGINE
  Resolves: RHEL-45704

* Mon Jul  1 2024 Daiki Ueno <dueno@redhat.com> - 1:3.2.2-5
- Replace HKDF backward compatibility patch with the official one
  Related: RHEL-41261

* Mon Jun 24 2024 Troy Dawson <tdawson@redhat.com> - 1:3.2.2-4
- Bump release for June 2024 mass rebuild

* Sat Jun 15 2024 Daiki Ueno <dueno@redhat.com> - 1:3.2.2-3
- Add workaround for EVP_PKEY_CTX_add1_hkdf_info with older providers
  Resolves: RHEL-41261

* Wed Jun 12 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-2
- Build openssl with no-atexit
  Resolves: RHEL-40408

* Wed Jun 05 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.2.2-1
- Rebase to OpenSSL 3.2.2.
  Related: RHEL-31762

* Mon Jun 03 2024 Sahana Prasad <sahana@redhat.com> - 1:3.2.1-4
- Synchronize patches from c9s and Fedora
- Resolves: RHEL-31762

* Tue Feb 13 2024 Sahana Prasad <sahana@redhat.com> - 1:3.2.1-3
- Temporarily disable ktls to  unblock c10s builds
- Resolves: RHEL-25259

* Fri Feb 09 2024 Sahana Prasad <sahana@redhat.com> - 1:3.2.1-2
- Fix version aliasing issue
- https://github.com/openssl/openssl/issues/23534

* Tue Feb 06 2024 Sahana Prasad <sahana@redhat.com> - 1:3.2.1-1
- Rebase to upstream version 3.2.1

* Thu Jan 25 2024 Fedora Release Engineering <releng@fedoraproject.org> - 1:3.1.4-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Sun Jan 21 2024 Fedora Release Engineering <releng@fedoraproject.org> - 1:3.1.4-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Wed Jan 10 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.1.4-2
- We don't want to ship openssl-pkcs11 in RHEL10/Centos 10

* Thu Oct 26 2023 Sahana Prasad <sahana@redhat.com> - 1:3.1.4-1
- Rebase to upstream version 3.1.4

* Thu Oct 19 2023 Sahana Prasad <sahana@redhat.com> - 1:3.1.3-1
- Rebase to upstream version 3.1.3

* Thu Aug 31 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.1.1-4
- Drop duplicated patch and do some contamination

* Tue Aug 22 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.1.1-3
- Integrate FIPS patches from CentOS

* Fri Aug 04 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.1.1-2
- migrated to SPDX license

* Thu Jul 27 2023 Sahana Prasad <sahana@redhat.com> - 1:3.1.1-1
- Rebase to upstream version 3.1.1
  Resolves: CVE-2023-0464
  Resolves: CVE-2023-0465
  Resolves: CVE-2023-0466
  Resolves: CVE-2023-1255
  Resolves: CVE-2023-2650

* Thu Jul 27 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.8-4
- Forbid custom EC more completely
  Resolves: rhbz#2223953

* Thu Jul 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 1:3.0.8-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild

* Tue Mar 21 2023 Sahana Prasad <sahana@redhat.com> - 1:3.0.8-2
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
  Resolves: rhbz#2130618, rhbz#2141672

* Thu Feb 09 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.8-1
- Rebase to upstream version 3.0.8
  Resolves: CVE-2022-4203
  Resolves: CVE-2022-4304
  Resolves: CVE-2022-4450
  Resolves: CVE-2023-0215
  Resolves: CVE-2023-0216
  Resolves: CVE-2023-0217
  Resolves: CVE-2023-0286
  Resolves: CVE-2023-0401

* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 1:3.0.7-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild

* Thu Jan 05 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-3
- Backport implicit rejection for RSA PKCS#1 v1.5 encryption
  Resolves: rhbz#2153470

* Thu Jan 05 2023 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-2
- Refactor embedded mac verification in FIPS module
  Resolves: rhbz#2156045

* Fri Dec 23 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.7-1
- Rebase to upstream version 3.0.7
- C99 compatibility in downstream-only 0032-Force-fips.patch
  Resolves: rhbz#2152504
- Adjusting include for the FIPS_mode macro
  Resolves: rhbz#2083876

* Wed Nov 16 2022 Simo sorce <simo@redhat.com> - 1:3.0.5-7
- Backport patches to fix external providers compatibility issues

* Tue Nov 01 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.5-6
- CVE-2022-3602: X.509 Email Address Buffer Overflow
- CVE-2022-3786: X.509 Email Address Buffer Overflow
  Resolves: CVE-2022-3602
  Resolves: CVE-2022-3786

* Mon Sep 12 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.5-5
- Update patches to make ELN build happy
  Resolves: rhbz#2123755

* Fri Sep 09 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.5-4
- Fix AES-GCM on Power 8 CPUs
  Resolves: rhbz#2124845

* Thu Sep 01 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.5-3
- Sync patches with RHEL
  Related: rhbz#2123755
* Fri Jul 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 1:3.0.5-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild

* Tue Jul 05 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.5-1
- Rebase to upstream version 3.0.5
  Related: rhbz#2099972, CVE-2022-2097

* Wed Jun 01 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.3-1
- Rebase to upstream version 3.0.3

* Thu Apr 28 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.2-5
- Instrument with USDT probes related to SHA-1 deprecation

* Wed Apr 27 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.2-4
- Support rsa_pkcs1_md5_sha1 in TLS 1.0/1.1 with rh-allow-sha1-signatures = yes
  to restore TLS 1.0 and 1.1 support in LEGACY crypto-policy.
  Related: rhbz#2069239

* Tue Apr 26 2022 Alexander Sosedkin <asosedkin@redhat.com> - 1:3.0.2-4
- Instrument with USDT probes related to SHA-1 deprecation

* Wed Apr 20 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.2-3
- Disable SHA-1 by default in ELN using the patches from CentOS
- Fix a FIXME in the openssl.cnf(5) manpage

* Thu Apr 07 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.2-2
- Silence a few rpmlint false positives.

* Thu Apr 07 2022 Clemens Lang <cllang@redhat.com> - 1:3.0.2-2
- Allow disabling SHA1 signature creation and verification.
  Set rh-allow-sha1-signatures = no to disable.
  Allow SHA1 in TLS in SECLEVEL 1 if rh-allow-sha1-signatures = yes. This will
  support SHA1 in TLS in the LEGACY crypto-policy.
  Resolves: rhbz#2070977
  Related: rhbz#2031742, rhbz#2062640

* Fri Mar 18 2022 Dmitry Belyavskiy <dbelyavs@redhat.com> - 1:3.0.2-1
- Rebase to upstream version 3.0.2

* Thu Jan 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 1:3.0.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Thu Sep 09 2021 Sahana Prasad <sahana@redhat.com> - 1:3.0.0-1
- Rebase to upstream version 3.0.0
