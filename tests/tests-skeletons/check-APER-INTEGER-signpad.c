/*
 * Regression tests for PER INTEGER representations (APER).
 *
 * X.691 distinguishes three cases for a whole number that carries a
 * length determinant:
 *
 *   - Unconstrained whole number (X.691 11.8, formerly 10.8): the value
 *     n is encoded as a 2's-complement-binary-integer in the minimum
 *     number of octets. A positive value whose most significant octet
 *     has the high bit set therefore DOES carry a leading 0x00 sign
 *     octet, e.g. 65000 -> 03 00 fd e8.
 *
 *   - Semi-constrained whole number (X.691 11.7, formerly 10.7): the
 *     offset (n - lb) is encoded as a non-negative-binary-integer in the
 *     minimum number of octets, so the sign octet must NOT be emitted,
 *     e.g. 65000 in INTEGER (0..MAX) -> 02 fd e8.
 *
 *   - Constrained whole number (X.691 11.5): encoded as a bit-field or
 *     as a length-prefixed minimal value (offset from the lower bound),
 *     again with no sign octet, e.g. 65000 in INTEGER (0..100000) ->
 *     40 fd e8 (aligned).
 *
 * The bug this guards against: INTEGER_encode_aper() leaked the signed
 * two's-complement storage of a non-negative SEMI-CONSTRAINED value into
 * the length-determinant encoding (65000 -> 03 00 fd e8 instead of
 * 02 fd e8). The fix normalizes only the semi-constrained case and
 * leaves the unconstrained 2's-complement form untouched (verified
 * against the FFASN1 reference implementation).
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <INTEGER.h>
#include <der_encoder.h>
#include <ber_decoder.h>
#include <aper_encoder.h>
#include <aper_decoder.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <INTEGER_uper.c>
#include <uper_support.c>
#include <uper_support.h>
#include <per_support.c>
#include <aper_support.c>
#include <aper_support.h>

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
check_case(int lineno, const char *what, int unsigned_spec, intmax_t value,
           const asn_per_constraints_t *constraints,
           const uint8_t *expected, size_t expected_bytes, int roundtrip) {
	INTEGER_t st;
	INTEGER_t *reconstructed_st = 0;
	struct asn_INTEGER_specifics_s specs;
	asn_enc_rval_t enc_rval;
	asn_dec_rval_t dec_rval;
	asn_per_outp_t po;
	asn_per_data_t pd;
	size_t i;

	printf("%d: [%s] encoding %s %jd, expect", lineno, what,
		unsigned_spec ? "unsigned" : "signed", value);
	for(i = 0; i < expected_bytes; i++)
		printf(" %02x", expected[i]);
	printf("\n");

	memset(&st, 0, sizeof(st));
	memset(&po, 0, sizeof(po));
	memset(&specs, 0, sizeof(specs));

	if(unsigned_spec) {
		assert(value >= 0);
		asn_ulong2INTEGER(&st, (unsigned long)value);
	} else {
		asn_imax2INTEGER(&st, value);
	}

	po.buffer = po.tmpspace;
	po.nboff = 0;
	po.nbits = 8 * sizeof(po.tmpspace);
	po.output = FailOut;

	specs.field_width = sizeof(long);
	specs.field_unsigned = unsigned_spec;

	asn_DEF_INTEGER.specifics = &specs;
	enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, constraints, &st, &po);
	assert(enc_rval.encoded == 0);
	assert(po.nboff % 8 == 0);
	normalize(&po);

	size_t bytes_used = po.buffer - po.tmpspace;
	if(bytes_used != expected_bytes) {
		fprintf(stderr, "%d: encoded %zu octets, expected %zu\n",
			lineno, bytes_used, expected_bytes);
		assert(0);
	}
	if(memcmp(po.tmpspace, expected, expected_bytes) != 0) {
		fprintf(stderr, "%d:", lineno);
		for(i = 0; i < bytes_used; i++)
			fprintf(stderr, " %02x", po.tmpspace[i]);
		fprintf(stderr, " differs from the expected octets\n");
		assert(0);
	}

	if(roundtrip) {
		pd.buffer = po.tmpspace;
		pd.nboff = 0;
		pd.nbits = 8 * (po.buffer - po.tmpspace) + po.nboff;
		pd.moved = 0;
		dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, constraints,
						(void **)&reconstructed_st, &pd);
		assert(dec_rval.code == RC_OK);
		if(unsigned_spec) {
			unsigned long reconstructed_value = 0;
			asn_INTEGER2ulong(reconstructed_st, &reconstructed_value);
			if(reconstructed_value != (unsigned long)value) {
				fprintf(stderr, "%d: decoded %lu, expected %lu\n", lineno,
					reconstructed_value, (unsigned long)value);
				assert(0);
			}
		} else {
			long reconstructed_value = 0;
			asn_INTEGER2long(reconstructed_st, &reconstructed_value);
			assert(reconstructed_value == value);
		}
		ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
	}
	ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
}

static void
check_per_der_per(int aligned, int unsigned_spec, intmax_t signed_value,
                  uintmax_t unsigned_value) {
	INTEGER_t original;
	INTEGER_t *per_value = 0;
	INTEGER_t *der_value = 0;
	struct asn_INTEGER_specifics_s specs;
	uint8_t per_first[128];
	uint8_t per_second[128];
	uint8_t der[128];
	asn_enc_rval_t enc_rval;
	asn_dec_rval_t dec_rval;
	size_t per_bytes;
	ssize_t per_bits_first;
	ssize_t per_bits_second;

	memset(&original, 0, sizeof(original));
	memset(&specs, 0, sizeof(specs));
	memset(per_first, 0, sizeof(per_first));
	memset(per_second, 0, sizeof(per_second));
	specs.field_width = sizeof(long);
	specs.field_unsigned = unsigned_spec;
	asn_DEF_INTEGER.specifics = &specs;

	if(unsigned_spec) {
		assert(asn_umax2INTEGER(&original, unsigned_value) == 0);
	} else {
		assert(asn_imax2INTEGER(&original, signed_value) == 0);
	}

	if(aligned) {
		enc_rval = aper_encode_to_buffer(&asn_DEF_INTEGER, 0, &original,
			per_first, sizeof(per_first));
	} else {
		enc_rval = uper_encode_to_buffer(&asn_DEF_INTEGER, 0, &original,
			per_first, sizeof(per_first));
	}
	assert(enc_rval.encoded >= 0);
	per_bits_first = enc_rval.encoded;
	per_bytes = (size_t)((per_bits_first + 7) / 8);

	if(aligned) {
		dec_rval = aper_decode_complete(0, &asn_DEF_INTEGER,
			(void **)&per_value, per_first, per_bytes);
	} else {
		dec_rval = uper_decode_complete(0, &asn_DEF_INTEGER,
			(void **)&per_value, per_first, per_bytes);
	}
	assert(dec_rval.code == RC_OK);
	assert(per_value != 0);

	enc_rval = der_encode_to_buffer(&asn_DEF_INTEGER, per_value,
		der, sizeof(der));
	assert(enc_rval.encoded > 0);
	dec_rval = ber_decode(0, &asn_DEF_INTEGER, (void **)&der_value,
		der, (size_t)enc_rval.encoded);
	assert(dec_rval.code == RC_OK);
	assert(der_value != 0);

	if(unsigned_spec) {
		uintmax_t decoded;
		assert(asn_INTEGER2umax(der_value, &decoded) == 0);
		assert(decoded == unsigned_value);
	} else {
		intmax_t decoded;
		assert(asn_INTEGER2imax(der_value, &decoded) == 0);
		assert(decoded == signed_value);
	}

	if(aligned) {
		enc_rval = aper_encode_to_buffer(&asn_DEF_INTEGER, 0, der_value,
			per_second, sizeof(per_second));
	} else {
		enc_rval = uper_encode_to_buffer(&asn_DEF_INTEGER, 0, der_value,
			per_second, sizeof(per_second));
	}
	assert(enc_rval.encoded == per_bits_first);
	per_bits_second = enc_rval.encoded;
	assert(per_bits_second == per_bits_first);
	assert(memcmp(per_first, per_second, per_bytes) == 0);

	ASN_STRUCT_FREE(asn_DEF_INTEGER, per_value);
	ASN_STRUCT_FREE(asn_DEF_INTEGER, der_value);
	ASN_STRUCT_RESET(asn_DEF_INTEGER, &original);
}

static void
check_noncanonical_uper_rejected(void) {
	/* Length two followed by 00 01 is a non-minimal positive INTEGER. */
	static const uint8_t noncanonical[] = {0x02, 0x00, 0x01};
	asn_codec_ctx_t canonical = {0};
	INTEGER_t *decoded = 0;
	asn_dec_rval_t dec_rval;

	canonical.uper_canonical = 1;
	dec_rval = uper_decode_complete(&canonical, &asn_DEF_INTEGER,
		(void **)&decoded, noncanonical, sizeof(noncanonical));
	assert(dec_rval.code == RC_FAIL);
	if(decoded) ASN_STRUCT_FREE(asn_DEF_INTEGER, decoded);
}

static void
check_malformed_and_noncanonical(void) {
	static const uint8_t malformed_per[] = {0x00};
	static const uint8_t noncanonical_der[] = {0x02, 0x02, 0x00, 0x01};
	uint8_t canonical_der[16];
	INTEGER_t *decoded = 0;
	asn_dec_rval_t dec_rval;
	asn_enc_rval_t enc_rval;

	dec_rval = aper_decode_complete(0, &asn_DEF_INTEGER,
		(void **)&decoded, malformed_per, sizeof(malformed_per));
	assert(dec_rval.code == RC_FAIL);
	if(decoded) {
		ASN_STRUCT_FREE(asn_DEF_INTEGER, decoded);
		decoded = 0;
	}
	dec_rval = uper_decode_complete(0, &asn_DEF_INTEGER,
		(void **)&decoded, malformed_per, sizeof(malformed_per));
	assert(dec_rval.code == RC_FAIL);
	if(decoded) {
		ASN_STRUCT_FREE(asn_DEF_INTEGER, decoded);
		decoded = 0;
	}

	/* BER accepts the input, while DER re-encoding must remove padding. */
	dec_rval = ber_decode(0, &asn_DEF_INTEGER, (void **)&decoded,
		noncanonical_der, sizeof(noncanonical_der));
	assert(dec_rval.code == RC_OK);
	enc_rval = der_encode_to_buffer(&asn_DEF_INTEGER, decoded,
		canonical_der, sizeof(canonical_der));
	assert(enc_rval.encoded == 3);
	assert(canonical_der[0] == 0x02);
	assert(canonical_der[1] == 0x01);
	assert(canonical_der[2] == 0x01);
	ASN_STRUCT_FREE(asn_DEF_INTEGER, decoded);
}

int
main() {
	/* No PER constraints: unconstrained whole number (X.691 11.8). */
	static struct asn_per_constraints_s ct_unconstrained = {
		{APC_UNCONSTRAINED, -1, -1, 0, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (0..65535), 16-bit fully constrained (X.691 11.5). */
	static struct asn_per_constraints_s ct_0_65535 = {
		{APC_CONSTRAINED, 16, 16, 0, 65535},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (0..100000), 17-bit fully constrained (X.691 11.5). */
	static struct asn_per_constraints_s ct_0_100000 = {
		{APC_CONSTRAINED, 17, 17, 0, 100000},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (0..MAX), semi-constrained (X.691 11.7). */
	static struct asn_per_constraints_s ct_semi_0 = {
		{APC_SEMI_CONSTRAINED, -1, -1, 0, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (8..MAX), semi-constrained (X.691 11.7). */
	static struct asn_per_constraints_s ct_semi_8 = {
		{APC_SEMI_CONSTRAINED, -1, -1, 8, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (-8..MAX), semi-constrained (X.691 11.7). */
	static struct asn_per_constraints_s ct_semi_m8 = {
		{APC_SEMI_CONSTRAINED, -1, -1, -8, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* ---- Unconstrained: 2's-complement, sign octet significant ---- */
	/* 65000 = 0xfde8 needs the leading 0x00 sign octet here. */
	static const uint8_t un_65000[] = {0x03, 0x00, 0xfd, 0xe8};
	check_case(__LINE__, "unconstrained", 0, 65000, &ct_unconstrained,
		un_65000, sizeof(un_65000), 1);
	check_case(__LINE__, "unconstrained", 1, 65000, &ct_unconstrained,
		un_65000, sizeof(un_65000), 1);

	/* 128 = 0x80 also needs a sign octet; 32768 = 0x8000 likewise. */
	static const uint8_t un_128[] = {0x02, 0x00, 0x80};
	static const uint8_t un_32768[] = {0x03, 0x00, 0x80, 0x00};
	check_case(__LINE__, "unconstrained", 0, 128, &ct_unconstrained,
		un_128, sizeof(un_128), 1);
	check_case(__LINE__, "unconstrained", 0, 32768, &ct_unconstrained,
		un_32768, sizeof(un_32768), 1);

	/* Top bit clear: no sign octet needed (0x01000000). */
	static const uint8_t un_16777216[] = {0x04, 0x01, 0x00, 0x00, 0x00};
	check_case(__LINE__, "unconstrained", 0, 16777216, &ct_unconstrained,
		un_16777216, sizeof(un_16777216), 1);

	/* Negative values keep the minimal 2's-complement form. */
	static const uint8_t un_m129[] = {0x02, 0xff, 0x7f};
	static const uint8_t un_m300[] = {0x02, 0xfe, 0xd4};
	check_case(__LINE__, "unconstrained", 0, -129, &ct_unconstrained,
		un_m129, sizeof(un_m129), 1);
	check_case(__LINE__, "unconstrained", 0, -300, &ct_unconstrained,
		un_m300, sizeof(un_m300), 1);

	/* Zero needs exactly one content octet (X.691 13.2.6 / 12.2.3). */
	static const uint8_t un_zero[] = {0x01, 0x00};
	check_case(__LINE__, "unconstrained", 0, 0, &ct_unconstrained,
		un_zero, sizeof(un_zero), 1);

	/* ---- Fully constrained (X.691 11.5) ---- */
	static const uint8_t c16_65000[] = {0xfd, 0xe8};
	static const uint8_t c17_65000[] = {0x40, 0xfd, 0xe8};
	check_case(__LINE__, "constrained 16-bit", 0, 65000, &ct_0_65535,
		c16_65000, sizeof(c16_65000), 1);
	check_case(__LINE__, "constrained 17-bit", 0, 65000, &ct_0_100000,
		c17_65000, sizeof(c17_65000), 1);

	/* ---- Semi-constrained: non-negative offset, no sign octet ---- */
	/* INTEGER (0..MAX), 65000 -> offset 65000 = 0xfde8. */
	static const uint8_t semi_65000[] = {0x02, 0xfd, 0xe8};
	check_case(__LINE__, "semi (0..MAX)", 1, 65000, &ct_semi_0,
		semi_65000, sizeof(semi_65000), 1);
	/* 2147483648 = 0x80000000 -> offset 0x80000000, no 0x00 prefix. */
	static const uint8_t semi_2g[] = {0x04, 0x80, 0x00, 0x00, 0x00};
	check_case(__LINE__, "semi (0..MAX)", 1, 2147483648, &ct_semi_0,
		semi_2g, sizeof(semi_2g), 1);
	/* INTEGER (8..MAX), 65000 -> offset 64992 = 0xfde0. */
	static const uint8_t semi8_65000[] = {0x02, 0xfd, 0xe0};
	check_case(__LINE__, "semi (8..MAX)", 0, 65000, &ct_semi_8,
		semi8_65000, sizeof(semi8_65000), 1);
	/* INTEGER (-8..MAX), 0 -> offset 8; 64992 -> offset 65000. */
	static const uint8_t semi_m8_0[] = {0x01, 0x08};
	static const uint8_t semi_m8_64992[] = {0x02, 0xfd, 0xe8};
	check_case(__LINE__, "semi (-8..MAX)", 0, 0, &ct_semi_m8,
		semi_m8_0, sizeof(semi_m8_0), 1);
	check_case(__LINE__, "semi (-8..MAX)", 0, 64992, &ct_semi_m8,
		semi_m8_64992, sizeof(semi_m8_64992), 1);

	/* Exercise PER -> DER -> PER for both aligned and unaligned PER. */
	check_per_der_per(1, 0, INTMAX_MIN, 0);
	check_per_der_per(1, 0, -1, 0);
	check_per_der_per(1, 0, 0, 0);
	check_per_der_per(1, 0, INTMAX_MAX, 0);
	check_per_der_per(1, 1, 0, 0);
	check_per_der_per(1, 1, 0, (uintmax_t)0x80);
	check_per_der_per(1, 1, 0, (uintmax_t)UINTMAX_MAX);
	check_per_der_per(0, 0, INTMAX_MIN, 0);
	check_per_der_per(0, 0, -1, 0);
	check_per_der_per(0, 0, 0, 0);
	check_per_der_per(0, 0, INTMAX_MAX, 0);
	check_per_der_per(0, 1, 0, 0);
	check_per_der_per(0, 1, 0, (uintmax_t)0x80);
	check_per_der_per(0, 1, 0, (uintmax_t)UINTMAX_MAX);
	check_noncanonical_uper_rejected();
	check_malformed_and_noncanonical();

	return 0;
}
