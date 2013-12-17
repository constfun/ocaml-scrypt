external scryptenc_buf : string -> string -> int -> float -> float -> string = "scryptenc_buf_stub"


let encrypt ?(maxmem=0) ?(maxmemfrac=0.125) ?(maxtime=5.0) data passwd =
  scryptenc_buf data passwd maxmem maxmemfrac maxtime


(*let scryptenc_buf =
  foreign "scryptenc_buf" (
    ptr uint8_t @-> size_t [> inbuf, inbuflen <]
    @-> ptr uint8_t [> outbuf <]
    @-> ptr uint8_t @-> size_t [> passwd, passwdlen <]
    @-> size_t [> maxmem <]
    @-> double [> maxmemfrac <]
    @-> double [> maxtime <]
    @-> returning int)

let uint8_ptr_of_string s =
  coerce string (ptr char) s
  |> coerce (ptr char) (ptr uint8_t)

let encrypt ?(maxmem=0) ?(maxmemfrac=0.125) ?(maxtime=5.0) data passwd =
  let datalen = String.length data in
  let inbuf_ptr = uint8_ptr_of_string data in
  let inbuflen = Unsigned.Size_t.of_int datalen in
  let outbuf = Array.make uint8_t (datalen + 128) in
  let outbuf_ptr = Array.start outbuf in
  let p_ptr = uint8_ptr_of_string passwd in
  let plen = Unsigned.Size_t.of_int (String.length passwd) in
  let mm = Unsigned.Size_t.of_int maxmem in
  let ret = scryptenc_buf inbuf_ptr inbuflen outbuf_ptr p_ptr plen mm maxmemfrac maxtime in
  Printf.printf "%i\n" ret*)
