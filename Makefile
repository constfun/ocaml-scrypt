SCRYPT_PATH = libscrypt
SCRYPT_LIB = $(SCRYPT_PATH)/libscrypt.a

all: $(SCRYPT_LIB)
	# Comple just the stubs into an object file.
	#
	# The stubs expect to find "scrypt.h" on include path.
	ocamlfind ocamlopt -o scrypt_stubs scrypt_stubs.c -ccopt -I$(SCRYPT_PATH)

	# Compile scrypt.mli (the interface) to a cmi (compiled module interface).
	# Compile scrypt.ml to bytecode (cmo).
	#
	# The order of files matters here.
	# Since there is a module interface defined (mli), the compiler expects to find a compiled version of it (cmi) before compiling the ml file.
	ocamlfind ocamlc -c scrypt.mli scrypt.ml

	# Compile scrypt.ml to scrypt.o (native code) and scrypt.cmx (extra information for optimizing and linking the native code.)
	ocamlfind ocamlopt -c scrypt.ml

	# Take:
	#	* C object files, scrypt_stubs.o and all object files extracted from libscrypt/libscrypt.a.
	#	* Bytecode object file scrypt.cmo
	#	* Native object file scrypt.cmx + scrypt.o, we supply just the .cmx, but it points to the .o, and it is included in resulting scrypt.a.
	#
	# Link it all to produce the following files:
	#       libscrypt.a, contains scrypt_stubs.o and libscrypt/*.o:
	#		Most of the C portion of our library.
	#		libscrypt.a MUST be installed, see cmxa.
	#
	#	scrypt.a, contains scrypt.o:
	#		Native version of scrypt.ml, does NOT include the stubs.
	#		XXX: I'm not sure why this has to be a separate archive and isn't combined with libscrypt.a.
	#		     What happens when you have more files? Do you then have to install a bunch of .a files with your library?
	#		scrypt.a MUST be installed, see cmxa.
	#
	#	scrypt.cma, contains scrypt.cmo:
	#		Bytecode version of library.
	#		scrypt.cma MUST be installed.
	#		scrypt.cmo is NOT installed since it is fully comtained in scrypt.cma.
	#
	#	scrypt.cmxa, contains scrypt.cmx and combines it (without containing) with  scrypt.a, and libscrypt.a:
	#		These files comprise the native version of the library.
	#		scrypt.cmxa, scrypt.a, and libscrypt.a MUST be installed and linked together.
	#			The -cclib options accomplish this task transparently, since they
	#			are memoized in scrypt.cmxa and are automatically applied whenever a client links to the library.
	#		scrypt.cmx is NOT installed since it is fully contained in scrypt.cmxa.
	#
	#	-lcrypto is OpenSSL (scrypt dependency) and must be present on on the system, it will also link the resulting dllscrypt.so with libcrypto.so.
	ocamlfind ocamlmklib -v -o scrypt scrypt.cmo scrypt.cmx scrypt_stubs.o $(SCRYPT_PATH)/*.o -lcrypto -cclib -lscrypt -cclib -lcrypto

$(SCRYPT_LIB):
	# Compile scrypt, but immediately explode the library into it's object files.
	# We do this to merge the objects with scrypt_stubs.o into a new, unified, library under the name libscrypt.a
	# The merging step happens during ocamlmklib linking.
	cd libscrypt && make && ar x libscrypt.a

install:
	ocamlfind install scrypt META *.cmi *.cmxa *.cma *.a *.so

uninstall:
	ocamlfind remove scrypt

docs:
	rm -rf docs
	mkdir docs
	ocamlfind ocamldoc -html -d docs scrypt.mli

clean:
	rm -f *.cmi *.cmxa *.cma *.cmx *.cmo *.o *.so *.a
	rm -f libscrypt/*.o libscrypt/__.SYMDEF*
	cd libscrypt && make clean
