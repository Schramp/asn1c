/* this is supposed to cover Section 13 of X.691 for Aligned PER */

#include <stdio.h>
#include <assert.h>

#include <INTEGER.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <per_support.c>
#include <per_support.h>
#include <uper_support.c>
#include <uper_support.h>

static int FailOut(const void *data, size_t size, void *op_key) {
    (void)data;
    (void)size;
    (void)op_key;
	assert(!"UNREACHABLE");
	return 0;
}

static void normalize(asn_per_outp_t *po) {
	if(po->nboff >= 8) {
		po->buffer += (po->nboff >> 3);
		po->nbits  -= (po->nboff & ~0x07);
		po->nboff  &= 0x07;
	}
}

static void
check_aper_encode_constrained(int lineno, int unsigned_, long value, long lbound, unsigned long ubound, int bit_range, size_t nbytes) {
	INTEGER_t st;
	INTEGER_t *reconstructed_st = 0;
	struct asn_INTEGER_specifics_s specs;
	struct asn_per_constraints_s cts;
	asn_enc_rval_t enc_rval;
	asn_dec_rval_t dec_rval;
	asn_per_outp_t po;
	asn_per_data_t pd;

	if(unsigned_)
		printf("%d: Recoding %s %lu [%ld..%lu]\n", lineno,
		  unsigned_ ? "unsigned" : "signed", value, lbound, ubound);
	else
		printf("%d: Recoding %s %ld [%ld..%lu]\n", lineno,
		  unsigned_ ? "unsigned" : "signed", value, lbound, ubound);

	if(ubound > LONG_MAX) {
		printf("Skipped test, unsupported\n");
		return;
	}

	memset(&st, 0, sizeof(st));
	memset(&po, 0, sizeof(po));
	memset(&pd, 0, sizeof(pd));
	memset(&cts, 0, sizeof(cts));
	memset(&specs, 0, sizeof(specs));

	cts.value.flags = APC_CONSTRAINED;
	cts.value.range_bits = bit_range;
	cts.value.effective_bits = bit_range;
	cts.value.lower_bound = lbound;
	cts.value.upper_bound = ubound;

	if(unsigned_)
		asn_ulong2INTEGER(&st, (unsigned long)value);
	else
		asn_long2INTEGER(&st, value);

	po.buffer = po.tmpspace;
	po.nboff = 0;
	po.nbits = 8 * sizeof(po.tmpspace);
	po.output = FailOut;

	specs.field_width = sizeof(long);
	specs.field_unsigned = unsigned_;

	asn_DEF_INTEGER.specifics = &specs;
	enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, &cts, &st, &po);
	assert(enc_rval.encoded == 0);
	/* APER can never have any bit-offset not at an octet boundary */
	assert(po.nboff % 8 == 0);

	normalize(&po);

	size_t bytes_used = po.buffer - po.tmpspace;
	if(bytes_used != nbytes) {
		fprintf(stderr, "bytes_used=%zu, nbytes_expected=%zu\n", bytes_used, nbytes);
		assert(po.buffer == &po.tmpspace[nbytes]);
	}

	assert(po.nboff % 8 == 0);
	assert(po.nbits ==  8 * (sizeof(po.tmpspace) - (po.buffer-po.tmpspace)));
	assert(po.flushed_bytes == 0);

	pd.buffer = po.tmpspace;
	pd.nboff = 0;
	pd.nbits = 8 * (po.buffer - po.tmpspace) + po.nboff;
	pd.moved = 0;
	dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts,
					(void **)&reconstructed_st, &pd);
	assert(dec_rval.code == RC_OK);
	if(unsigned_) {
		unsigned long reconstructed_value = 0;
		asn_INTEGER2ulong(reconstructed_st, &reconstructed_value);
		assert(reconstructed_value == (unsigned long)value);
	} else {
		long reconstructed_value = 0;
		asn_INTEGER2long(reconstructed_st, &reconstructed_value);
		assert(reconstructed_value == value);
	}
	ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
	ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
}

#define	CHECK(u, v, l, r, b, nb)	\
	check_aper_encode_constrained(__LINE__, u, v, l, r, b, nb)

int
main() {
	int unsigned_;
	for(unsigned_ = 0; unsigned_ < 2; unsigned_++) {
		int u = unsigned_;

		/* test zero-range encodings leading to no output */
		CHECK(u, 0, 0, 0, 0, 0);
		CHECK(u, 3, 3, 3, 0, 0);
		CHECK(u, 320000, 320000, 320000, 0, 0);

		/* test for bit-field cases of clause 11.5.7 a) */
		CHECK(u, 0, 0, 200, 8, 1);
		CHECK(u, 100, 0, 200, 8, 1);
		CHECK(u, 200, 0, 200, 8, 1);
		CHECK(u, 1000010, 1000000, 1000200, 8, 1);
		CHECK(u, 254, 0, 254, 8, 1);

		/* test for one-octet case of clause 11.5.7 b) */
		CHECK(u, 255, 0, 255, 8, 1);
		CHECK(u, 1000023, 1000000, 1000255, 8, 1);
		CHECK(u, 1000255, 1000000, 1000255, 8, 1);

		/* test for two-octet case of clause 11.5.7 c) */
		CHECK(u, 5, 0, 65535, 16, 2);
		CHECK(u, 65534, 0, 65534, 16, 2);
		CHECK(u, 65535, 0, 65535, 16, 2);
		CHECK(u, 1065534, 1000000, 1065534, 16, 2);
		CHECK(u, 1065535, 1000000, 1065535, 16, 2);

		/* test for indefinite length case of clause 11.5.7 d) */
		CHECK(u, 0, 0, 100000, 17, 2); 		/* one-byte length followed by one-byte value encoding zero */
		CHECK(u, 100000, 0, 100000, 17, 4);	/* one-byte length followed by three-byte value */
		CHECK(u, 0, 0, 16000000, 24, 2);	/* one-byte length followed by one-byte value */
		CHECK(u, 255, 0, 16000000, 24, 2);	/* one-byte length followed by one-byte value */
		CHECK(u, 256, 0, 16000000, 24, 3);	/* one-byte length followed by one-byte value */
		CHECK(u, 65534, 0, 16000000, 24, 3);	/* one-byte length followed by two-byte value */
		CHECK(u, 65535, 0, 16000000, 24, 3);	/* one-byte length followed by two-byte value */
		CHECK(u, 65536, 0, 16000000, 24, 4);	/* one-byte length followed by three-byte value */
		CHECK(u, 20000000, 0, 268435455, 28, 5);/* one-byte length followed by four--byte value */
		CHECK(u, 65536, 65535, 268435455, 12, 2);/* one-byte length followed by one-byte value */
		CHECK(u, 268369921, 268369920, 268435455, 16, 2);/* one-byte length followed by one-byte value */
	}

	return 0;
}
