# SRC-GIT repository for the FIPS OpenSSL EL8.

This is the main repoository for the FIPS Rocky EL8 OpenSSL effort. 

The following branches will branch off of FIPS-X
* FIPS-CERTIFIED 
  - Current code base up for validation
  - Will be merged back into compliant as changes based on Lab or NIST requirements change
* FIPS-COMPLIANT 
  - Branched off of FIPS-CERTIFIED
  - CVE patches will be applied to this branch
  - Will be merged into FIPS-CERTIFIED as Lab or NIST requested
    - Once the FIPS-CERTIFIED branch has been algorithm validated the code can not longer be updated unless requested by the CMVP or the lab
* FIPS-CERTIFIED-NEXT - This branch will be used to integrate new FIPS/NIST requirements.
  - This branch will be used to integrate and test new FIPS features from the CMVP
  - As the features are up for certfication FIPS-CERTIFIED-NEXT will become FIPS-CERTIFIED or merged into FIPS-CERTIFIED
