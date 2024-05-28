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
export OPENSSL_FIPS_KAT="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl exit
unset OPENSSL_FIPS_KAT
 
echo "**************************************************"
echo "KAT FAIL demo"
echo "**************************************************"
export OPENSSL_FIPS_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl exit
unset OPENSSL_FIPS_FAIL
 
echo "**************************************************"
echo "RSA PCT SUCCESS demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genrsa -out private-key.pem 3072
 
echo "**************************************************"
echo "RSA PCT FAIL demo"
echo "**************************************************"
export OPENSSL_PCT_RSA_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genrsa -out private-key.pem 3072
unset OPENSSL_PCT_RSA_FAIL
 
echo "**************************************************"
echo "DSA PCT SUCCESS demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl dsaparam -out dsaparam.pem 2048
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl gendsa -out dsaprivkey.pem dsaparam.pem
 
echo "**************************************************"
echo "DSA PCT FAIL demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl dsaparam -out dsaparam.pem 2048
export OPENSSL_PCT_DSA_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl gendsa -out dsaprivkey.pem dsaparam.pem
unset OPENSSL_PCT_DSA_FAIL
 
echo "**************************************************"
echo "ECDSA PCT SUCCESS demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl ecparam -name secp521r1 -genkey -noout -out my.key.pem
 
echo "**************************************************"
echo "ECDSA PCT FAIL demo"
echo "**************************************************"
export OPENSSL_PCT_ECDSA_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl ecparam -name secp521r1 -genkey -noout -out my.key.pem
unset OPENSSL_PCT_ECDSA_FAIL
 
echo "**************************************************"
echo "XTS DUP KEY SUCCESS demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl enc -e -aes-256-xts -iter 2 -salt -in config -out file.txt.aes256xts -pass pass:somepassword
 
echo "**************************************************"
echo "XTS DUP KEY FAIL demo"
echo "**************************************************"
export OPENSSL_DUP_XTS_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl enc -e -aes-256-xts -iter 2 -salt -in config -out file.txt.aes256xts -pass pass:somepassword
unset OPENSSL_DUP_XTS_FAIL
 
echo "**************************************************"
echo "ECDH PCT SUCCESS demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl ecparam -out ecparam.pem -name prime256v1
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genpkey -paramfile ecparam.pem -out ecdhkey.pem
 
echo "**************************************************"
echo "ECDH PCT FAIL demo"
echo "**************************************************"
export OPENSSL_PCT_ECDH_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genpkey -paramfile ecparam.pem -out ecdhkey.pem
unset OPENSSL_PCT_ECDH_FAIL
 
echo "**************************************************"
echo "DH PCT SUCCESS demo"
echo "**************************************************"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genpkey -algorithm DH -out dhkey.pem -pkeyopt dh_param:ffdhe2048
 
echo "**************************************************"
echo "DH PCT FAIL demo"
echo "**************************************************"
export OPENSSL_PCT_DH_FAIL="1"
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genpkey -algorithm DH -out dhkey.pem -pkeyopt dh_param:ffdhe2048
unset OPENSSL_PCT_DH_FAIL
 
echo "**************************************************"
echo "Non-approved crypto call (MD5) FAIL demo"
echo "**************************************************"
echo "TestText" | LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl md5

echo "**************************************************"
echo "Non-approved crypto call (x25519) FAIL demo"
echo "**************************************************"
echo "TestText" | LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genpkey -algorithm x25519 -out x25519-priv.pem

echo "**************************************************"
echo "Non-approved crypto call (x448) FAIL demo"
echo "**************************************************"
echo "TestText" | LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl genpkey -algorithm x448 -out x448-priv.pem

echo "Functional test script completed: " $(date)
