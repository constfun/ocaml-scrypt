exception Scrypt_error of int

val encrypt : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string
val decrypt : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string
