if [[ $1 == *"OPENSSL_"* ]]; then
   export $1="1"
   shift;
fi
LD_PRELOAD="./libcrypto.so.1.1 ./libssl.so.1.1" ./apps/openssl "$@"