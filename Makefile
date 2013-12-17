all:
	ocamlfind ocamlopt -o scrypt_stubs scrypt_stubs.c
	ocamlfind ocamlmklib -v -o scrypt scrypt.ml scrypt_stubs.o -cclib -lscryptc -cclib -lcrypto

install:
	ocamlfind install scrypt META *.cmi *.cmxa *.cma scrypt.a libscrypt.a lib/libscryptc.a

uninstall:
	ocamlfind remove scrypt

clean:
	rm -f *.cmi *.cmxa *.cma *.cmx *.cmo *.o *.so *.a
