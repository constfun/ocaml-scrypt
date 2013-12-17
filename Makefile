SCRYPT_PATH = libscrypt
SCRYPT_LIB = $(SCRYPT_PATH)/libscrypt.a

all: $(SCRYPT_LIB)
	# Comple just the stubs into an object file. The stubs expect to find "scrypt.h" on include path.
	ocamlfind ocamlopt -o scrypt_stubs scrypt_stubs.c -ccopt -I$(SCRYPT_PATH)
	# Take all C object files, and OCaml object files, including the object files extracted from libscrypt/libscrypt.a.
	# (scrypt.o, scrypt.cmo, and scrypt.cmx are created by from scrypt.ml by ocamlc and ocamlopt before linking)
	#
	# Make the following files:
	#	scrypt.cmo: OCaml bytecode object file.
	#	scrypt.cma containing scrypt.cmo: Bytecode library.
	#
	#	scrypt.a containing scrypt.o: c side of scrypt.ml, NOT the stubs, but probably related.
	#		  XXX: I'm not sure why this has to be a separate archive and isn't combined with libscrypt.a.
	#		       My guess is that it is created by ocamlopt compiling scrypt.ml and mklib not caring enough to combine it.
	#		       What happens when you have more files? Do you then have to install a bunch of .a files with your library?
	#	scrypt.cmx: extra linking information for clients of the library.
	#	scrypt.cmxa combines (not physically) scrypt.cmx and scrypt.a: Go hand in hand and are what you link to to use the library.
	#
	# -clib options are remembered in scrypt.cmxa and are automatically applied whenever a client links to this library.
	#
	ocamlfind ocamlmklib -v -o scrypt scrypt.ml scrypt_stubs.o $(SCRYPT_PATH)/*.o -cclib -lscrypt -cclib -lcrypto

$(SCRYPT_LIB):
	# Compile scrypt, but immediately explode the library into it's object files.
	# We do this to merge the objects with scrypt_stubs.o into a new, unified, library under the name libscrypt.a
	# The merging step happens during ocamlmklib linking.
	cd libscrypt && make && ar x libscrypt.a

install:
	ocamlfind install scrypt META *.cmi *.cmxa *.cma *.a

uninstall:
	ocamlfind remove scrypt

clean:
	rm -f *.cmi *.cmxa *.cma *.cmx *.cmo *.o *.so *.a
	cd libscrypt && make clean
