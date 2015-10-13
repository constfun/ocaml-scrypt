#define CAML_NAME_SPACE

#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include "scrypt.h"

// for hashing
#include "crypto_scrypt.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define SCRYPT_MALLOC_ERROR 6

#define check_mem(A) if(!A) { goto error; }
#define check_err(A) if(A) { goto error; }

struct ScryptArgs {
	uint8_t *inbuf;
	size_t  inbuflen;
	uint8_t *passwd;
	size_t  passwdlen;
	size_t  maxmem;
	double  maxmemfrac;
	double  maxtime;
};

struct ScryptArgs scrypt_convert_args(value input, value passwd, value maxmem, value maxmemfrac, value maxtime) {

	struct ScryptArgs args = {
		.inbuf = &Byte_u(input, 0),
		.inbuflen = caml_string_length(input),
		.passwd = &Byte_u(passwd, 0),
		.passwdlen = caml_string_length(passwd),
		.maxmem = Unsigned_long_val(maxmem),
		.maxmemfrac = Double_val(maxmemfrac),
		.maxtime = Double_val(maxtime)
	};

	return args;
}

void scrypt_raise_scrypt_error(int err_code) {

	CAMLparam0();
	CAMLlocal1(code_val);

	static value *exn = NULL;
	if( !exn ) {

		exn = caml_named_value("Scrypt_error");
	}

	code_val = Val_int(err_code);
	caml_raise_with_arg(*exn, code_val);

	CAMLreturn0;
}

CAMLprim value scryptenc_buf_stub(value data, value passwd, value maxmem, value maxmemfrac, value maxtime) {

	CAMLparam5(data, passwd, maxmem, maxmemfrac, maxtime);
	CAMLlocal1(cyphertext);

	int err = SCRYPT_MALLOC_ERROR;
	uint8_t *outbuf = NULL;

	struct ScryptArgs args = scrypt_convert_args(data, passwd, maxmem, maxmemfrac, maxtime);

	/* From the horses mouth:
	 *
	 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen + 128
	 * bytes to outbuf.
	 *
	 * scryptenc_buf(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf,
	 *		 const uint8_t * passwd, size_t passwdlen,
	 *		 size_t maxmem, double maxmemfrac, double maxtime)
	 */

	cyphertext = caml_alloc_string(args.inbuflen + 128);
	// Output can be written directly to our ocaml string block.
	outbuf = &Byte_u(cyphertext, 0);

	err = scryptenc_buf(args.inbuf, args.inbuflen, outbuf, args.passwd, args.passwdlen,
		      args.maxmem, args.maxmemfrac, args.maxtime);
	check_err(err);

	CAMLreturn(cyphertext);

error:
	scrypt_raise_scrypt_error(err);
	CAMLreturn(cyphertext);
}

CAMLprim value scryptdec_buf_stub(value cyphertext, value passwd, value maxmem, value maxmemfrac, value maxtime) {

	CAMLparam5(cyphertext, passwd, maxmem, maxmemfrac, maxtime);
	CAMLlocal1(decrypted_data);

	int err = SCRYPT_MALLOC_ERROR;
	uint8_t *decrypted_data_start = NULL;
	uint8_t *outbuf = NULL;
	size_t outlen = 0;

	struct ScryptArgs args = scrypt_convert_args(cyphertext, passwd, maxmem, maxmemfrac, maxtime);

	/* From the horses mouth:
	 *
	 * Decrypt inbuflen bytes from inbuf, writing the result into outbuf and the
	 * decrypted data length to outlen.  The allocated length of outbuf must
	 * be at least inbuflen.
	 *
	 * scryptdec_buf(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf,
	 *		 size_t * outlen, const uint8_t * passwd, size_t passwdlen,
	 *		 size_t maxmem, double maxmemfrac, double maxtime)
	 */

	// An intermediate buffer is required, since we need to allocate more than the decrypted_data length for scrypt
	// and ocaml blocks cannot be resized once allocated (not easily anyway.)
	outbuf = malloc(sizeof(uint8_t) * args.inbuflen);
	check_mem(outbuf);

	err = scryptdec_buf(args.inbuf, args.inbuflen, outbuf, &outlen, args.passwd, args.passwdlen,
		      args.maxmem, args.maxmemfrac, args.maxtime);
	check_err(err);

	// Allocate the decrypted_data string and copy over outlen elements from our buffer into it.
	decrypted_data = caml_alloc_string(outlen);
	decrypted_data_start = &Byte_u(decrypted_data, 0);
	memcpy(decrypted_data_start, outbuf, outlen);

	free(outbuf);

	CAMLreturn(decrypted_data);

error:
	if(outbuf) free(outbuf);

	scrypt_raise_scrypt_error(err);
	CAMLreturn(decrypted_data);
}

CAMLprim value crypto_scrypt_native(value passwd, value salt, value N, value r, value p, value buf) {
    CAMLparam5(passwd, salt, N, r, p);
    CAMLxparam1(buf);
    const uint8_t* pwd_p = &Byte_u(passwd, 0);
    const uint8_t* slt_p = &Byte_u(salt, 0);
    uint8_t* buf_p = &Byte_u(buf, 0);

    int pwdlen = caml_string_length(passwd);
    int sltlen = caml_string_length(salt);
    int buflen = caml_string_length(buf);

    int64 N_p = Int64_val(N);
    int r_p = Val_int(r);
    int p_p = Val_int(p);

    int err = crypto_scrypt(pwd_p, pwdlen, slt_p, sltlen, N_p, r_p, p_p, buf_p, buflen);
    check_err(err);

    CAMLreturn(Val_unit);

error:
    scrypt_raise_scrypt_error(err);
    CAMLreturn(Val_unit);
}

CAMLprim value crypto_scrypt_bytecode(value *argv, int argc)
{
    return crypto_scrypt_native(argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
}

CAMLprim value scrypt_sha256(value str)
{
    CAMLparam1(str);
    CAMLlocal1(digest);

    uint8_t *sbuf, *dbuf;
    int slen;
    SHA256_CTX ctx;

    digest = caml_alloc_string(32);
    slen = caml_string_length(str);
    sbuf = &Byte_u(str, 0);
    dbuf = &Byte_u(digest, 0);

    /* Add header checksum. */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, sbuf, slen);
    SHA256_Final(dbuf, &ctx);

    CAMLreturn(digest);
}

CAMLprim value scrypt_hmac_sha256(value data, value key)
{
    CAMLparam2(data, key);
    CAMLlocal1(hmac);

    uint8_t *dbuf, *kbuf, *hbuf;
    int datalen, keylen;
    HMAC_CTX ctx;

    hmac = caml_alloc_string(32);
    datalen = caml_string_length(data);
    keylen = caml_string_length(key);
    kbuf = &Byte_u(key, 0);
    hbuf = &Byte_u(hmac, 0);
    dbuf = &Byte_u(data, 0);

    /* Add header signature. (used for verifying password). */
    HMAC_Init(&ctx, kbuf, keylen, EVP_sha256());
    HMAC_Update(&ctx, dbuf, datalen);
    HMAC_Final(&ctx, hbuf, NULL);

    CAMLreturn(hmac);
}
