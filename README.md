# SRC-GIT repository for the FIPS OpenSSL.

The modules are maintained in separate branches:

1.1.1k-FIPS:    Production FIPS OpenSSL module for Rocky EL8.
           Based on 1.1.1k

1.1.1k-FIPS-FT: Functional test module for Rocky EL8.
           Based on 1.1.1k
	   This module is only intended for Lab funcitonal testing
	   of the fips functionality and not to be used in production.
	   This branch is based ontop of FIPS-1.1.1k.

3.0.7-FIPS:    Production FIPS OpenSSL module for Rocky EL9.
           Based on 3.0.7-25

3.0.7-FIPS-FT: Functional test module for Rocky EL9.
           Based on 3.0.7-25
	   This module is only intended for Lab funcitonal testing
	   of the fips functionality and not to be used in production.
	   This branch is based on top of FIPS-3.0.7-25.

# To run the functional test scripts from the 1.1.1k-FIPS-FT branch.
Dependencies needed for build:
yum install git zlib zlib-devel make gcc lksctp-tools-devel

1). Build locally: 
$ debug_fips.sh

2). Execute FIPS functional tests and induce failures:
   $ ./ft_test.sh

# To run the functional test scripts from the 3.0.7-FIPS-FT branch.
1). Build locally: 
$ build.sh

2). Build functional tests:
   1) $ cd FT   
   3) $ make
   4) $ make install
   5) $ cd ..
      
3). Execute FIPS functional tests and induce failures:
   1) $ cd INSTALL
   2) $ FT.sh

