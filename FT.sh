#!/bin/bash

./apps/openssl fipsinstall -module ./providers/fips.so -out fips.cnf -provider_name fips


declare -a array=("SHA1" "SHA2" "SHA3" "AES_GCM" "AES_ECB_Decrypt" "RSA" \
"ECDSA" "TLS13_KDF_EXTRACT" "TLS13_KDF_EXPAND" "TLS12_PRF" \
"PBKDF2" "SSHKDF" "KBKDF" "HKDF" "SSKDF" "X963KDF" "X942KDF" \
"HASH" "CTR" "HMAC" "DH" "ECDH" "RSA_Encrypt" "RSA_Decrypt" "INTEGRITY" "RNG")

echo "************************************"
for i in ${!array[@]}; do    
    echo ${array[$i]}
    echo "************************************"
    ./apps/openssl fipsinstall -module ./providers/fips.so -out fips.cnf -provider_name fips -corrupt_desc ${array[$i]}
    echo "************************************"
done