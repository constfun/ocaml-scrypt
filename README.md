`Scrypt` OCaml library
======================

C bindings and a high level interface to the [official scrypt distribution](https://www.tarsnap.com/scrypt.html).
The original scrypt source is not modified in any way and is compiled directly using [this companion Makefile](https://github.com/pacemkr/libscrypt).

### Installation: <code>[opam](http://opam.ocaml.org/) install scrypt</code>

Or, using make:

    make
    make install

_Note_
* _The scrypt distribution requires OpenSSL._
* _The `make` installation method requires [ocamlfind](http://projects.camlcity.org/projects/findlib.html)._

### Example usage

A simple toplevel demo of the API:

```ocaml
# #require "scrypt";;
...scrypt: added to search path
...scrypt.cma: loaded

# let passwd = "testpass";;
val passwd : string = "testpass"

# let cyphertext = Scrypt.encrypt_exn "my secret data" passwd;;
val cyphertext : string =
  "scrypt\000\017\000\000\000\b\000\000\000\004Y??\144k\133?T??U\134\019? \135?\011\139u\030_??6\137???\137:sA?\"?K1\138P\148I?\025?2]?U??s?7?۵\148[H?Y\026{?f???\029m?\130?\026?>\157'*?z?OH\019{6\006\028u\144??O\135|?\"?H\146<\127\030?\130?\012-R ??P???{{\023\018\146\151"

# let decrypted_data = Scrypt.decrypt_exn cyphertext passwd;;
val decrypted_data : string = "my secret data"
```

There are also non-exn versions of `encrypt_exn` and `decrypt_exn` that return a `string option`.

### Full documentation: http://pacemkr.github.io/ocaml-scrypt/
