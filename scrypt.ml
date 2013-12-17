external scryptenc_buf : string -> string -> int -> float -> float -> string = "scryptenc_buf_stub"


let encrypt ?(maxmem=0) ?(maxmemfrac=0.125) ?(maxtime=5.0) data passwd =
  scryptenc_buf data passwd maxmem maxmemfrac maxtime
