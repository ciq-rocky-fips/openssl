default: gentest
LIBS= -lm 

LIBCRYPTO=/home/jrodriguez/FIPS/92/o3/src-git/INSTALL/lib64/libcrypto.so.3
LIBSSL=/home/jrodriguez/FIPS/92/o3/src-git/INSTALL/lib64/libssl.so.3

gentest.o: gentest.c $(HEADERS)
	gcc -c gentest.c -o gentest.o -g3

gentest: gentest.o
	gcc gentest.o -o gentest -Wl,-rpath=/home/jrodriguez/FIPS/92/o3/src-git/INSTALL/lib64 -Wl,$(LIBCRYPTO) -Wl,$(LIBSSL)

clean:
	-rm -f gentest.o
	-rm -f gentest
