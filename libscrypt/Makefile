SCRYPT = scrypt-1.1.6

CONFIG_H = $(SCRYPT)/config.h

CFLAGS=-g -O2 -fPIC -lcrypto -DHAVE_CONFIG_H \
       -I$(SCRYPT) \
       -I$(SCRYPT)/lib/crypto \
       -I$(SCRYPT)/lib/scryptenc \
       -I$(SCRYPT)/lib/util

SOURCES=$(SCRYPT)/lib/crypto/crypto_aesctr.c \
	$(SCRYPT)/lib/crypto/crypto_scrypt-nosse.c \
	$(SCRYPT)/lib/scryptenc/scryptenc.c \
	$(SCRYPT)/lib/scryptenc/scryptenc_cpuperf.c \
	$(SCRYPT)/lib/util/memlimit.c \
	$(SCRYPT)/lib/crypto/sha256.c \
	$(SCRYPT)/lib/util/warn.c

OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

all: libscrypt.a libscrypt.so
	cp $(SCRYPT)/lib/scryptenc/scryptenc.h scrypt.h

$(CONFIG_H):
	cd $(SCRYPT) && ./configure

libscrypt.a: $(CONFIG_H) $(OBJECTS)
	ar rcs $@ $(OBJECTS)
	ranlib $@

libscrypt.so: $(CONFIG_H) $(OBJECTS)
	$(CC) $(CFLAGS) -shared -o $@ $(OBJECTS)

clean:
	cd $(SCRYPT) && make clean && rm -rf .deps Makefile config.h config.log config.status stamp-h1
	rm -f libscrypt.a libscrypt.so scrypt.h
	rm -rf $(OBJECTS)
