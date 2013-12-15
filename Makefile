all:
	ocamlfind ocamlmklib -o scrypt -package ctypes.foreign scrypt.ml lib/libscryptc.a

install:
	ocamlfind install scrypt META scrypt.cmi scrypt.cmxa scrypt.cma scrypt.cmx scrypt.o lib/libscryptc.a

uninstall:
	ocamlfind remove scrypt

clean:
	rm -f *.cmxa *.cma *.cmx *.cmo *.o *.so *.a
