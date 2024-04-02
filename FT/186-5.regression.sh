#!/bin/sh -x

echo "*****************************************"
echo " DSA"
echo " non FIPS"
echo "*****************************************"
bin/openssl dsaparam -out dsaparam.pem 2048
bin/openssl gendsa -out dsaprivkey.pem dsaparam.pem

cat dsaprivkey.pem
cat dsaparam.pem

echo "*****************************************"
echo " FIPS"
echo "*****************************************"
echo "FAIL CASES"
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl dsaparam -out dsaparam1.pem 2048
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl gendsa -out dsaprivkey2.pem dsaparam.pem

echo "*****************************************"
echo " RSA"
echo " non FIPS"
echo "*****************************************"
bin/openssl genrsa -out rsa-private-key.pem 3072
bin/openssl genrsa -des3 -out rsaprivkey.pem 2048
bin/openssl pkeyutl -sign -inkey rsa-private-key.pem -pkeyopt rsa_padding_mode:x931 -rawin -in  ct_log_list.cnf -out sig.file

echo "*****************************************"
echo " FIPS"
echo "*****************************************"
echo "FAIL CASES"
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl genrsa -des3 -out rsaprivkey.pem 2048
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl genpkey -algorithm RSA -out key.pem
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl pkeyutl -sign -inkey key.pem -pkeyopt rsa_padding_mode:x931 -rawin -in  ct_log_list.cnf -out sigfips.file
echo "SUCCESS CASES"
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl genrsa -out rsa-private-key1.pem 3072
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl genpkey -algorithm RSA -out key.pem
OPENSSL_FORCE_FIPS_MODE=1 bin/openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048

