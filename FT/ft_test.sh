echo "Functional test script started: " $(date)
echo "--------------------------------------------------------------------"
echo "Querying the operating system information:" $(cat /etc/*-release | egrep "PRETTY_NAME" | cut -d = -f 2 | tr -d '"')
echo "Querying the CPU model:" $(cat /proc/cpuinfo | grep "model name" | head -1)
echo "Querying the hardware information:" $(cat /sys/devices/virtual/dmi/id/chassis_vendor) $(cat /sys/devices/virtual/dmi/id/product_name)
echo "--------------------------------------------------------------------"
echo "Current working director:" $(pwd)
echo "Setting OPENSSL_ia32cap env var"
export OPENSSL_ia32cap="~0x200000200000000"
echo $OPENSSL_ia32cap
echo "Running the non-accelerated testing"
 
echo "**************************************************"
echo "KAT SUCCESS demo"
echo "**************************************************"
OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl exit
 
echo "**************************************************"
echo "KAT FAIL demo"
echo "**************************************************"
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
    export FT_INDUCE="${array[$i]}"
    env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl
    echo "************************************"
done
unset FT_INDUCE

echo "**************************************************"
echo "RSA PCT SUCCESS demo"
echo "**************************************************"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl genrsa -out private-key.pem 3072
 
echo "**************************************************"
echo "RSA PCT FAIL demo"
echo "**************************************************"
export FT_INDUCE="RSA_PCT_PKCS1"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl genrsa -out private-key.pem 3072
unset FT_INDUCE
 
echo "**************************************************"
echo "DSA PCT SUCCESS demo"
echo "**************************************************"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl gendsa -out dsaprivkey.pem dsaparam.pem
 
echo "**************************************************"
echo "DSA PCT FAIL demo"
echo "**************************************************"
export FT_INDUCE="DSA_PCT"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl gendsa -out dsaprivkey.pem dsaparam.pem
unset FT_INDUCE
 
echo "**************************************************"
echo "ECDSA PCT SUCCESS demo"
echo "**************************************************"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl ecparam -name secp521r1 -genkey -noout -out my.key.pem
 
echo "**************************************************"
echo "ECDSA PCT FAIL demo"
echo "**************************************************"
export FT_INDUCE="ECDSA_PCT"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl ecparam -name secp521r1 -genkey -noout -out my.key.pem
unset FT_INDUCE
 
echo "**************************************************"
echo "XTS DUP KEY SUCCESS demo"
echo "**************************************************"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl enc -e -aes-256-xts -iter 2 -salt -in config -out file.txt.aes256xts -pass pass:somepassword
 
echo "**************************************************"
echo "XTS DUP KEY FAIL demo"
echo "**************************************************"
export FT_INDUCE="XTS_DUP"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl enc -e -aes-256-xts -iter 2 -salt -in config -out file.txt.aes256xts -pass pass:somepassword
unset FT_INDUCE
 
echo "**************************************************"
echo "ECDH PCT SUCCESS demo"
echo "**************************************************"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl ecparam -out ecparam.pem -name prime256v1
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl genpkey -paramfile ecparam.pem -out ecdhkey.pem
 
echo "**************************************************"
echo "ECDH PCT FAIL demo"
echo "**************************************************"
export FT_INDUCE="ECDSA_PCT"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl genpkey -paramfile ecparam.pem -out ecdhkey.pem
unset FT_INDUCE
 
echo "**************************************************"
echo "DH PCT SUCCESS demo"
echo "**************************************************"
env OPENSSL_FORCE_FIPS_MODE=1 bin/openssl dhparam -out dhparam.pem 2048
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl genpkey -algorithm DH -out dhkey.pem -pkeyopt dh_param:ffdhe2048
 
echo "**************************************************"
echo "DH PCT FAIL demo"
echo "**************************************************"

export FT_INDUCE="DH_PCT"
env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl genpkey -algorithm DH -out dhkey.pem -pkeyopt dh_param:ffdhe2048
unset FT_INDUCE
 
echo "**************************************************"
echo "Non-approved crypto call (MD5) FAIL demo"
echo "**************************************************"
echo "TestText" | env OPENSSL_FORCE_FIPS_MODE=1 ./bin/openssl md5

echo "Functional test script completed: " $(date)