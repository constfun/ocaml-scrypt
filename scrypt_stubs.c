#define CAML_NAME_SPACE

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include "scrypt.h"

CAMLprim value scryptenc_buf_stub(value data_val, value key_val, value maxmem_val, value maxmemfrac_val, value maxtime_val) {

	CAMLparam5(data_val, key_val, maxmem_val, maxmemfrac_val, maxtime_val);
	CAMLlocal1(output);

	uint8_t *inbuf = &Byte_u(data_val, 0);
	size_t inbuflen = caml_string_length(data_val);
	uint8_t *passwd = &Byte_u(key_val, 0);
	size_t passwdlen = caml_string_length(key_val);
	size_t maxmem = Unsigned_long_val(maxmem_val);
	double maxmemfrac = Double_val(maxmemfrac_val);
	double maxtime = Double_val(maxtime_val);

	output = caml_alloc_string(inbuflen + 128);
	uint8_t *outbuf = &Byte_u(output, 0);

	scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen, maxmem, maxmemfrac, maxtime);

	CAMLreturn(output);
}
