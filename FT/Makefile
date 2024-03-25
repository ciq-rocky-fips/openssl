default: gentest
LIBS= -lm 

INSTALLDIR=../INSTALL

LIBCRYPTO=$(INSTALLDIR)/lib64/libcrypto.so.3
LIBSSL=$(INSTALLDIR)/lib64/libssl.so.3

CFLAGS = -DPROVIDER_SEREACHPATH=\"$(LIBCRYPTO)/lib64/ossl-modules\"
CFLAGS += -DSSL_CONFIG=\"$(INSTALLDIR)/gentest.cnf\"

gentest.o: gentest.c $(HEADERS)
	gcc $(CFLAGS) -c gentest.c -o gentest.o -g3

gentest: gentest.o
	gcc gentest.o -o gentest -Wl,-rpath=$(INSTALLDIR)/lib64 -Wl,$(LIBCRYPTO) -Wl,$(LIBSSL)


install:
	cp gentest $(INSTALLDIR)
	cp FT.sh $(INSTALLDIR)
	cp gentest.cnf $(INSTALLDIR)
	cp fips.cnf $(INSTALLDIR)

clean:
	-rm -f gentest.o
	-rm -f gentest
