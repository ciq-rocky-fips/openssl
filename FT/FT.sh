#!/bin/bash


#env OPENSSL_FORCE_FIPS_MODE=1 ./gentest
#gdb --args ./gentest

declare -a array=("INTEGRITY"\
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
    env OPENSSL_FORCE_FIPS_MODE=1 ./gentest ${array[$i]}
    echo "************************************"
done


echo "************************************"
echo " PCTS "
echo "************************************"

declare -a array=("RSA_PCT_PKCS1"\
 "ECDSA_PCT"\
 "DSA_PCT")

echo "************************************"
for i in ${!array[@]}; do    
    echo ${array[$i]}
    echo "************************************"
    env OPENSSL_FORCE_FIPS_MODE=1 ./gentest ${array[$i]}
    echo "************************************"
done