exception Scrypt_error of int

val encrypt : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string option
val encrypt_exn : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string

val decrypt : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string option
val decrypt_exn : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string
