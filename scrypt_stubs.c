#define CAML_NAME_SPACE

#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include "scrypt.h"

#define check_mem(A) if(!A) { goto error; }

struct ScryptArgs {
	uint8_t *inbuf;
	size_t  inbuflen;
	uint8_t *passwd;
	size_t  passwdlen;
	size_t  maxmem;
	double  maxmemfrac;
	double  maxtime;
};

struct ScryptArgs scrypt_convert_args(value data, value passwd, value maxmem, value maxmemfrac, value maxtime) {

	struct ScryptArgs args = {
		.inbuf = &Byte_u(data, 0),
		.inbuflen = caml_string_length(data),
		.passwd = &Byte_u(passwd, 0),
		.passwdlen = caml_string_length(passwd),
		.maxmem = Unsigned_long_val(maxmem),
		.maxmemfrac = Double_val(maxmemfrac),
		.maxtime = Double_val(maxtime)
	};

	return args;
}

CAMLprim value scryptenc_buf_stub(value data, value passwd, value maxmem, value maxmemfrac, value maxtime) {

	CAMLparam5(data, passwd, maxmem, maxmemfrac, maxtime);
	CAMLlocal1(output);

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

	output = caml_alloc_string(args.inbuflen + 128);
	// Output can be written directly to our ocaml string block.
	outbuf = &Byte_u(output, 0);

	scryptenc_buf(args.inbuf, args.inbuflen, outbuf, args.passwd, args.passwdlen,
		      args.maxmem, args.maxmemfrac, args.maxtime);

	CAMLreturn(output);
}

CAMLprim value scryptdec_buf_stub(value data, value passwd, value maxmem, value maxmemfrac, value maxtime) {

	CAMLparam5(data, passwd, maxmem, maxmemfrac, maxtime);
	CAMLlocal1(output);

	uint8_t *output_start = NULL;
	uint8_t *outbuf = NULL;
	size_t outlen = 0;

	struct ScryptArgs args = scrypt_convert_args(data, passwd, maxmem, maxmemfrac, maxtime);

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

	// An intermediate buffer is required, since we need to allocate more than the output lenght for scrypt
	// and ocaml blocks cannot be resized once allocated (not easily anyway.)
	outbuf = malloc(sizeof(uint8_t) * args.inbuflen);
	check_mem(outbuf);

	scryptdec_buf(args.inbuf, args.inbuflen, outbuf, &outlen, args.passwd, args.passwdlen,
		      args.maxmem, args.maxmemfrac, args.maxtime);

	// Allocate the output string and copy over outlen elements from our buffer into it.
	output = caml_alloc_string(outlen);
	output_start = &Byte_u(output, 0);
	memcpy(output_start, outbuf, outlen);

	free(outbuf);

	CAMLreturn(output);

error:
	if(outbuf) free(outbuf);

	CAMLreturn(output);
}
