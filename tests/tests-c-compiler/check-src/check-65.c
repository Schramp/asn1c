#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <T.h>
#include <T1.h>

static const uint8_t buf1[] = {
	32 | ((2 << 6) + 2),	/* [2], constructed */
	6,
	32 | ((2 << 6) + 3),	/* [3], constructed */
	4,
	32 | ((2 << 6) + 4),	/* [4], constructed */
	2,
	0  | ((2 << 6) + 6),	/* [6], primitive */
	0
};

/*
 * The two tagged REALs include a zero exponent and a one-octet mantissa.
 * m1 is -1, m2 is +1, and m3 is +4. Each enclosing length includes the
 * complete encoded child, including its tag and length octets.
 */
static const uint8_t buf2[] = {
	32 | ((2 << 6) + 0),	/* [0], constructed */
	25,

	32 | ((2 << 6) + 1),	/* [1], constructed */
	7,
	32 | ((2 << 6) + 4),	/* [4], constructed */
	5,
	0  | ((2 << 6) + 6),	/* [6], primitive */
	3,
	0xC0,
	0x00,
	0x01,

	32 | ((2 << 6) + 2),	/* [2], constructed */
	7,
	32 | ((2 << 6) + 4),	/* [4], constructed */
	5,
	0  | ((2 << 6) + 6),	/* [6], primitive */
	3,
	0x80,
	0x00,
	0x01,

	32 | ((2 << 6) + 3),	/* [3], constructed */
	5,
	0  | ((2 << 6) + 6),	/* [6], primitive */
	3,
	0x80,
	0x01,
	0x02,
};

/* Preserve the original absent-mantissa inputs as separate failures. */
static const uint8_t buf2_bad_m1[] = {
	32 | ((2 << 6) + 0), 24,
	32 | ((2 << 6) + 1), 6,
	32 | ((2 << 6) + 4), 4,
	0  | ((2 << 6) + 6), 2, 0xC0, 0x00,
	32 | ((2 << 6) + 2), 7,
	32 | ((2 << 6) + 4), 5,
	0  | ((2 << 6) + 6), 3, 0x80, 0x00, 0x01,
	32 | ((2 << 6) + 3), 5,
	0  | ((2 << 6) + 6), 3, 0x80, 0x01, 0x02
};

static const uint8_t buf2_bad_m2[] = {
	32 | ((2 << 6) + 0), 24,
	32 | ((2 << 6) + 1), 7,
	32 | ((2 << 6) + 4), 5,
	0  | ((2 << 6) + 6), 3, 0xC0, 0x00, 0x01,
	32 | ((2 << 6) + 2), 6,
	32 | ((2 << 6) + 4), 4,
	0  | ((2 << 6) + 6), 2, 0x80, 0x00,
	32 | ((2 << 6) + 3), 5,
	0  | ((2 << 6) + 6), 3, 0x80, 0x01, 0x02
};

/* A valid value without optional m2 confirms that the field stays optional. */
static const uint8_t buf2_without_m2[] = {
	32 | ((2 << 6) + 0), 16,
	32 | ((2 << 6) + 1), 7,
	32 | ((2 << 6) + 4), 5,
	0  | ((2 << 6) + 6), 3, 0xC0, 0x00, 0x01,
	32 | ((2 << 6) + 3), 5,
	0  | ((2 << 6) + 6), 3, 0x80, 0x01, 0x02
};

/*
 * Decode T1 and enforce the exact result expected for one input prefix.
 * Original source: Existing multi-tag BER compiler regression, extended here.
 * Version/date: 1.1, 2026-10-22.
 * Parameters: name labels the case; buf/size are the encoded input;
 * expected is the required decoder result; consumed is exact on success.
 * Returns: No value; assertions fail on a result or consumption mismatch.
 * Exceptions: None; a failed assertion aborts the test process.
 * Responsible party: asn1c maintainers.
 * History: Replaced permissive success checks with exact result checks.
 * Example: checks the complete T1 vector and every truncated prefix.
 */
static void
check_t1_result(const char *name, const uint8_t *buf, size_t size,
                enum asn_dec_rval_code_e expected, size_t consumed) {
	asn_dec_rval_t result;
	T1_t *decoded = 0;

	/* Check both the decoder status and its exact full-input consumption. */
	result = ber_decode(0, &asn_DEF_T1, (void **)&decoded, buf, size);
	if(result.code != expected) {
		fprintf(stderr, "%s: result %d, expected %d\n", name, result.code,
		        expected);
	}
	assert(result.code == expected);
	assert(result.consumed <= size);
	if(expected == RC_OK) {
		assert(result.consumed == consumed);
		assert(decoded && *decoded == 0.0);
	}

	/* Free partial or complete values through the generated descriptor. */
	if(decoded) ASN_STRUCT_FREE(asn_DEF_T1, decoded);
}

/*
 * Decode a T value and require a non-success result such as RC_WMORE or RC_FAIL.
 * Original source: Existing multi-tag BER compiler regression, extended here.
 * Version/date: 1.1, 2026-10-22.
 * Parameters: name labels the case; buf/size are the encoded input;
 * expected is the exact required decoder result.
 * Returns: No value; assertions fail on an unexpected result or over-consumption.
 * Exceptions: None; a failed assertion aborts the test process.
 * Responsible party: asn1c maintainers.
 * History: Added exact malformed-input and truncation result checks.
 * Example: requires an absent REAL mantissa to return RC_FAIL.
 */
static void
check_t_result(const char *name, const uint8_t *buf, size_t size,
               enum asn_dec_rval_code_e expected) {
	asn_dec_rval_t result;
	T_t *decoded = 0;

	/* Decode once so each malformed or truncated form has an exact expectation. */
	result = ber_decode(0, &asn_DEF_T, (void **)&decoded, buf, size);
	if(result.code != expected) {
		fprintf(stderr, "%s: result %d, expected %d (consumed %zu/%zu)\n",
		        name, result.code, expected, result.consumed, size);
	}
	assert(result.code == expected);
	assert(result.consumed <= size);

	/* The decoder may leave partial state on RC_WMORE or RC_FAIL. */
	if(decoded) ASN_STRUCT_FREE(asn_DEF_T, decoded);
}

/*
 * Decode a complete T value and verify each native REAL member.
 * Original source: Existing multi-tag BER compiler regression, extended here.
 * Version/date: 1.1, 2026-10-22.
 * Parameters: buf/size hold the complete encoding; m1/m2/m3 are expected
 * values; has_m2 says whether the optional member must be present.
 * Returns: No value; assertions fail on decoding, value, or presence mismatch.
 * Exceptions: None; a failed assertion aborts the test process.
 * Responsible party: asn1c maintainers.
 * History: Added field-level checks for the native REAL BER paths.
 * Example: validates m1=-1, m2=1, and m3=4 in buf2.
 */
static void
check_t_values(const uint8_t *buf, size_t size, double m1, double m2,
               double m3, int has_m2) {
	asn_dec_rval_t result;
	T_t *decoded = 0;

	/* A successful BER result must consume the complete top-level value. */
	result = ber_decode(0, &asn_DEF_T, (void **)&decoded, buf, size);
	if(result.code != RC_OK) {
		fprintf(stderr, "T value decode failed: code=%d consumed=%zu/%zu\n",
		        result.code, result.consumed, size);
	}
	assert(result.code == RC_OK);
	assert(result.consumed == size);
	assert(decoded);

	/* Assert each tagged REAL's value, including optional-member presence. */
	assert(decoded->m1 == m1);
	assert((decoded->m2 != 0) == has_m2);
	if(has_m2) assert(*decoded->m2 == m2);
	assert(decoded->m3 == m3);

	/* Free the allocated result after all member assertions have completed. */
	ASN_STRUCT_FREE(asn_DEF_T, decoded);
}

/*
 * Exercise the original T1 value and require starvation at every shorter prefix.
 * Original source: Existing multi-tag BER compiler regression.
 * Version/date: 1.1, 2026-10-22.
 * Parameters: None; the T1 fixture is file-local.
 * Returns: No value; assertions fail if a prefix succeeds or fails outright.
 * Exceptions: None; a failed assertion aborts the test process.
 * Responsible party: asn1c maintainers.
 * History: Replaced one permissive truncation check with an exact prefix sweep.
 * Example: called by main to cover every split of buf1.
 */
static void
check_t1_prefixes(void) {
	size_t prefix;

	/* Every incomplete prefix must request more bytes; the full value is zero. */
	check_t1_result("complete T1", buf1, sizeof(buf1), RC_OK, sizeof(buf1));
	for(prefix = 0; prefix < sizeof(buf1); prefix++) {
		check_t1_result("truncated T1", buf1, prefix, RC_WMORE, 0);
	}
}

/*
 * Exercise valid T decoding, every truncated prefix, and malformed fixtures.
 * Original source: Existing multi-tag BER compiler regression, extended here.
 * Version/date: 1.1, 2026-10-22.
 * Parameters: None; all encoded fixtures are file-local.
 * Returns: No value; assertions fail when a BER expectation is violated.
 * Exceptions: None; a failed assertion aborts the test process.
 * Responsible party: asn1c maintainers.
 * History: Added native REAL values, optional omission, and precise negatives.
 * Example: called by main after the T1 tag-chain regression.
 */
static void
check_t_values_and_failures(void) {
	uint8_t wrong_tag[sizeof(buf2)];
	uint8_t wrong_length[sizeof(buf2)];
	size_t prefix;

	/* Check all three decoded REAL values and the valid optional-absent case. */
	check_t_values(buf2, sizeof(buf2), -1.0, 1.0, 4.0, 1);
	check_t_values(buf2_without_m2, sizeof(buf2_without_m2), -1.0, 0.0,
	               4.0, 0);

	/* A valid encoding truncated at any byte boundary must report RC_WMORE. */
	for(prefix = 0; prefix < sizeof(buf2); prefix++) {
		check_t_result("truncated T", buf2, prefix, RC_WMORE);
	}

	/* Each original missing-mantissa field is tested with the other valid. */
	check_t_result("m1 has no mantissa", buf2_bad_m1, sizeof(buf2_bad_m1),
	               RC_FAIL);
	check_t_result("m2 has no mantissa", buf2_bad_m2, sizeof(buf2_bad_m2),
	               RC_FAIL);

	/* A bad nested tag and a short explicit wrapper must both fail exactly. */
	memcpy(wrong_tag, buf2, sizeof(wrong_tag));
	wrong_tag[22] = 0x87;
	check_t_result("wrong m3 REAL tag", wrong_tag, sizeof(wrong_tag), RC_FAIL);
	memcpy(wrong_length, buf2, sizeof(wrong_length));
	wrong_length[5] = 4;
	check_t_result("short m1 explicit wrapper", wrong_length,
	               sizeof(wrong_length), RC_FAIL);
}

/*
 * Run all multi-tag BER compiler regressions.
 * Original source: Existing check-65.c test entry point.
 * Version/date: 1.1, 2026-10-22.
 * Parameters: None.
 * Returns: 0 after all assertions pass.
 * Exceptions: None; a failed assertion aborts the test process.
 * Responsible party: asn1c maintainers.
 * History: Adds precise binary REAL decoding and malformed-value coverage.
 * Example: check-assembly.sh invokes check-src/check-65.c from its test directory.
 */
int
main(void) {
	check_t1_prefixes();
	check_t_values_and_failures();
	return 0;
}
