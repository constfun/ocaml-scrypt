#define CAML_NAME_SPACE

#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include "scrypt.h"

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
