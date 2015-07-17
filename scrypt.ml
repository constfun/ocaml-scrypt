exception Scrypt_error of int
let _ = Callback.register_exception "Scrypt_error" (Scrypt_error 0)

external scryptenc_buf : string -> string -> int -> float -> float -> string = "scryptenc_buf_stub"
external scryptdec_buf : string -> string -> int -> float -> float -> string = "scryptdec_buf_stub"
external crypto_scrypt : string -> string -> int64 -> int -> int -> string ->
  unit = "crypto_scrypt_bytecode" "crypto_scrypt_native"

(* Default values for optional arguments are chosen to match the scrypt command line utility. *)

let encrypt_exn ?(maxmem=0) ?(maxmemfrac=0.125) ?(maxtime=5.0) data passwd =
  scryptenc_buf data passwd maxmem maxmemfrac maxtime

let encrypt ?(maxmem=0) ?(maxmemfrac=0.125) ?(maxtime=5.0) data passwd=
  try Some (encrypt_exn ~maxmem ~maxmemfrac ~maxtime data passwd)
  with Scrypt_error _ -> None

let decrypt_exn ?(maxmem=0) ?(maxmemfrac=0.5) ?(maxtime=300.0) cyphertext passwd =
  scryptdec_buf cyphertext passwd maxmem maxmemfrac maxtime

let decrypt ?(maxmem=0) ?(maxmemfrac=0.5) ?(maxtime=300.0) cyphertext passwd =
  try Some (decrypt_exn ~maxmem ~maxmemfrac ~maxtime cyphertext passwd)
  with Scrypt_error _ -> None

(* one day re-implement these to avoid int32 boxing; it is unnecessary here *)
(* given that the values we're setting/getting fit within a tagged int *)
external w32 : Bytes.t -> int -> int32 -> unit = "%caml_string_set32"
external swap32 : int32 -> int32 = "%bswap_int32"

external sha256 : Bytes.t -> String.t = "scrypt_sha256"
external hmac_sha256 : Bytes.t -> Bytes.t -> String.t = "scrypt_hmac_sha256"

let be32enc s off v =
  if Sys.big_endian
  then w32 s off v
  else w32 s off (swap32 v)

let hash_exn ?(logN=14) ?(r=8) ?(p=1) passwd =
  (* Prepare inputs to KDF *)
  let salt = String.init 32 (fun _ -> Char.chr (Random.int 256)) in
  let dk = Bytes.create 64 in
  let n = Int64.shift_left 1L logN in

  (* Generate the derived keys. *)
  crypto_scrypt passwd salt n r p dk;

  (* Create output string. *)
  let out = Bytes.create 96 in

  (* Blit header values into output string. *)
  Bytes.blit_string "scrypt\000" 0 out 0 7;
  let () = try
    Bytes.set out 7 (Char.chr logN)
  with _ -> raise (Scrypt_error (-1)) in
  be32enc out 8 (Int32.of_int r);
  be32enc out 12 (Int32.of_int p);
  Bytes.blit_string salt 0 out 16 32;

  (* Construct the header checksum. *)
  let checksum = sha256 (Bytes.sub out 0 48) in
  Bytes.blit_string checksum 0 out 48 16;

  (* Add header signature (used for verifying password). *)
  let signature = hmac_sha256 (Bytes.sub out 0 64) (Bytes.sub dk 32 32) in
  Bytes.blit_string signature 0 out 64 32;

  (* All done! *)
  Bytes.unsafe_to_string out

let hash ?logN ?r ?p passwd =
  try Some (hash_exn ?logN ?r ?p passwd)
  with Scrypt_error _ -> None
