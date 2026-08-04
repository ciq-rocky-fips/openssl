#!/bin/bash
# Build static libjitterentropy.a and install headers
make clean
make jitterentropy-static
mkdir -p install/lib install/include
cp libjitterentropy.a install/lib/
cp jitterentropy.h install/include/
cp jitterentropy-base-user.h install/include/
