SCRYPT = scrypt-1.2.0

CONFIG_H = $(SCRYPT)/config.h

CFLAGS=-g -O2 -fPIC -DHAVE_CONFIG_H

# Execute Make in the scrypt directory
SMAKE=$(MAKE) --no-print-directory -C $(SCRYPT)

# we don't want main, so remove it from objs
OBJS=$(filter-out scrypt-main.%, $(shell $(SMAKE) print-scrypt_OBJECTS))
DEPS=$(shell $(SMAKE) print-scrypt_DEPENDENCIES print-EXTRA_scrypt_DEPENDENCIES)
LIBS=$(shell $(SMAKE) print-LIBS) -lcrypto
AR=$(shell $(SMAKE) print-AR print-ARFLAGS)

LDADD=$(shell $(SMAKE) print-noinst_LIBRARIES) # aesni, sse2 (if applicable)
# extract the object files for any additional (static) libraries.
# Rather than futzing around with PIC, just get object list from the scrypt Makefile
LDOBJS=$(shell $(SMAKE) $(LDADD:%.a=print-%_a_OBJECTS))

all: libscrypt.a libscrypt.so
	cp $(SCRYPT)/lib/scryptenc/scryptenc.h scrypt.h
	cp $(SCRYPT)/lib/crypto/crypto_scrypt.h crypto_scrypt.h

$(CONFIG_H):
	cd $(SCRYPT) && ./configure

scrypt: $(CONFIG_H)
	$(SMAKE) cpusupport-config.h config.h
	$(SMAKE) $(LDADD) $(OBJS) $(DEPS)

# add scrypt directory prefix for object files
OBJSp=$(OBJS:%=$(SCRYPT)/%)
LDOBJSp=$(LDOBJS:%=$(SCRYPT)/%)

libscrypt.a: scrypt
	$(AR) $@ $(OBJSp) $(LDOBJSp)
	ranlib $@

# XXX make shared libs portable to OSX and Windows
libscrypt.so: scrypt
	$(CC) $(CFLAGS) $(LIBS) -shared -o $@ $(OBJSp) $(LDOBJSp)

clean:
	rm -f libscrypt.a libscrypt.so scrypt.h crypto_scrypt.h
	$(SMAKE) distclean
