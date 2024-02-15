#!/bin/bash

#gdb --args bin/openssl fipsinstall -module ./lib64/ossl-modules/fips.so -out fips.cnf -provider_name fips


gdb --args bin/openssl fipsinstall -module ./lib64/ossl-modules/fips.so -out fips.cnf -provider_name fips -corrupt_desc "RSA_PCT_PKCS1"
#exit 1
#gdb --args bin/openssl fipsinstall -module ./lib64/ossl-modules/fips.so -out fips.cnf -provider_name fips -corrupt_desc "RSA_PCT_PKCS1"
#gdb --args bin/openssl fipsinstall -module ./lib64/ossl-modules/fips.so -out fips.cnf -provider_name fips -corrupt_desc "ECDSA_PCT"
exit 1

declare -a array=("INTEGRITY"\
 "RSA_PCT_PKCS1"\
 "ECDSA_PCT"\
 "DSA_PCT"\
 "AES_GCM"\
 "AES_ECB_Decrypt"\
 "TDES"\
 "RSA_Encrypt"\
 "RSA_Decrypt"\
 "SHA1"\
 "SHA2"\
 "SHA3"\
 "DSA"\
 "RSA"\
 "ECDSA_SIGN"\
 "CTR"\
 "HASH"\
 "HMAC"\
 "DH"\
 "ECDH"\
 "HKDF"\
 "SSKDF"\
 "X963KDF"\
 "X942KDF"\
 "PBKDF2"\
 "SSHKDF"\
 "TLS12_PRF"\
 "KBKDF"\
 "TLS13_KDF_EXTRACT"\
 "TLS13_KDF_EXPAND"\
 "RNG")

echo "************************************"
for i in ${!array[@]}; do    
    echo ${array[$i]}
    echo "************************************"
    ./apps/openssl fipsinstall -module ./lib64/ossl-modules/fips.so -out fips.cnf -provider_name fips -corrupt_desc ${array[$i]}
    echo "************************************"
done

#./apps/openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
#./apps/openssl pkcs8 -topk8 -in private.ec.key -out private.pem
#./apps/openssl ec -in private.pem -pubout -out public.pem

#./apps/openssl genrsa -out private-key.pem 3072
#rsa_keygen_pairwise_test