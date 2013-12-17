external scryptenc_buf : string -> string -> int -> float -> float -> string = "scryptenc_buf_stub"
external scryptdec_buf : string -> string -> int -> float -> float -> string = "scryptdec_buf_stub"

(* Default values for optional arguments are chosen to match the scrypt command line utility. *)

let encrypt ?(maxmem=0) ?(maxmemfrac=0.125) ?(maxtime=5.0) data passwd =
  scryptenc_buf data passwd maxmem maxmemfrac maxtime

let decrypt ?(maxmem=0) ?(maxmemfrac=0.5) ?(maxtime=300.0) data passwd =
  scryptdec_buf data passwd maxmem maxmemfrac maxtime
