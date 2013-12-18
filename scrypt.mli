(** Strong, password based encryption.

    No wheels invented. This module is a high level interface to the {{: https://www.tarsnap.com/scrypt.html } official scrypt distribution}.

    Scrypt is designed to make it costly to perform large scale custom hardware attacks by requiring large amounts of memory. {{: htps://en.wikipedia.org/wiki/Scrypt } (Wikipedia) }
*)

(** [Scrypt_error code] indicates an error during a call to the underlying C implementation of scrypt.

    [code] is the exact return code reported by the underlying implementation and is defined as one of the following:
    - [0] success
    - [1] getrlimit or sysctl(hw.usermem) failed
    - [2] clock_getres or clock_gettime failed
    - [3] error computing derived key
    - [4] could not read salt from /dev/urandom
    - [5] error in OpenSSL
    - [6] malloc failed
    - [7] data is not a valid scrypt-encrypted block
    - [8] unrecognized scrypt format
    - [9] decrypting file would take too much memory
    - [10] decrypting file would take too long
    - [11] password is incorrect
    - [12] error writing output file
    - [13] error reading input file
*)
exception Scrypt_error of int

(** [encrypt data passwd] encrypts [data] using [passwd] and returns [Some string] of the cyphertext or [None] if there was an error.

    The default values of [maxmem=0], [maxmemfrac=0.125], and [maxtime=5.0] are chosen to match the the reference scrypt implementation.

    See {!scrypt_params}.
*)
val encrypt : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string option

(** Same as {!encrypt} except raise {!Scrypt_error} in case of an error. *)
val encrypt_exn : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string

(** [decrypt cyphertext passwd] decrypts [cyphertext] using [passwd] and returns [Some string] of the decrypted data or [None] if there was an error.

    The default values of [maxmem=0], [maxmemfrac=0.5], and [maxtime=300.0] are chosen to match the the reference scrypt implementation.

    See {!scrypt_params}.
*)
val decrypt : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string option

(** Same as {!decrypt} except raise {!Scrypt_error} in case of an error. *)
val decrypt_exn : ?maxmem:int -> ?maxmemfrac:float -> ?maxtime:float -> string -> string -> string

(** {1:scrypt_params Meaning of [maxmem], [maxmemfrac], and [maxtime]}

    {ul
        {li [maxmem] is the maximum number of bytes of storage to use for V array (which is by far the largest consumer of memory).

            If [maxmem] is set to [0], no maximum will be enforced; any other value less than 1 MiB will be treated as 1 MiB.
        }
        {li [maxmemfrac] is the maximum fraction of available storage to use for the V array, where "available storage" is defined as the minimum out of the {{: http://man7.org/linux/man-pages/man2/getrlimit.2.html } RLIMIT_AS, RLIMIT_DATA and RLIMIT_RSS} resource limits (if any are set).

            If [maxmemfrac] is set to [0] or more than [0.5] it will be treated as [0.5]; and this value will never cause a limit of less than 1 MiB to be enforced.
        }
        {li [maxtime] is the maximum amount of CPU time to spend computing the derived keys, in seconds.

            This limit is only approximately enforced; the CPU performance is estimated and parameter limits are chosen accordingly.
        }
    }
*)
