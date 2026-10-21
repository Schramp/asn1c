#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <T1.h>
#include <T2.h>

static unsigned char buf[4096];
static int buf_offset;

/*
 * Write DER encoder output into the shared test buffer and print each chunk.
 * Original source: Existing check-60 encoding diagnostic helper.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: buffer/size are the encoded chunk; app_key is unused context.
 * Returns: 0 after copying and printing the chunk.
 * Errors: Asserts that the append stays within the fixed buffer capacity.
 * Responsible party: asn1c maintainers. History: Documented for check-60.
 * Example: der_encode calls this helper for each emitted T2 encoding chunk.
 */
static int
_buf_writer(const void *buffer, size_t size, void *app_key) {
	unsigned char *b, *bend;
	(void)app_key;
	assert(buf_offset + size < sizeof(buf));
	if (buffer) {
		memcpy(buf + buf_offset, buffer, size);
	}
	b = buf + buf_offset;
	bend = b + size;
	printf("=> [");
	for(; b < bend; b++)
		printf(" %02X", *b);
	printf("]:%zd\n", size);
	buf_offset += size;
	return 0;
}

/*
 * DER-encode an object, retain its bytes, and print the decoded value.
 * Original source: Existing check-60 round-trip test helper.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: bs points to the object; td describes its ASN.1 type.
 * Returns: 0 when encoding succeeds, otherwise -1 when encoding fails.
 * Errors: Reports encoder failure and asserts in debug builds; output overflow
 *         is asserted by _buf_writer.
 * Responsible party: asn1c maintainers. History: Documented for check-60.
 * Example: save_object(&t2, &asn_DEF_T2) stores T2 DER bytes in buf.
 */
static int
save_object(void *bs, asn_TYPE_descriptor_t *td) {
	asn_enc_rval_t rval; /* Return value */
	int i;

	buf_offset = 0;
	
	rval = der_encode(td, bs, _buf_writer, 0);
	if (rval.encoded == -1) {
		fprintf(stderr,
			"Cannot encode %s: %s\n",
			rval.failed_type->name, strerror(errno));
		assert(rval.encoded != -1);
		return -1;	/* JIC */
	}

	buf[buf_offset++] = 0xab;	/* Finalize with garbage */

	asn_fprint(stderr, td, bs);

	printf("OUT: [");
	for(i = 0; i < buf_offset; i++)
		printf(" %02x", buf[i]);
	printf("]\n");

	return 0;
}

/*
 * BER-decode the object retained by save_object and print its value.
 * Original source: Existing check-60 round-trip test helper.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: bs receives the decoder's object pointer locally; td describes
 *             the ASN.1 type to decode from the shared test buffer.
 * Returns: 0 when decoding succeeds, otherwise -1 when the decoder rejects it.
 * Errors: Asserts that the test encoding decodes with RC_OK.
 * Responsible party: asn1c maintainers. History: Documented for check-60.
 * Example: load_object(&t2_new, &asn_DEF_T2) checks saved T2 DER bytes.
 */
static int
load_object(void *bs, asn_TYPE_descriptor_t *td) {
	asn_dec_rval_t rval;

	fprintf(stderr, "\nLOADING OBJECT OF SIZE %d\n", buf_offset);

	rval = ber_decode(0, td, (void **)&bs, buf, buf_offset);
	assert(rval.code == RC_OK);

	asn_fprint(stderr, td, bs);

	return (rval.code == RC_OK)?0:-1;
}

/*
 * Decode one T2 value from incrementally supplied BER input.
 * Original source: New check-60 helper for explicit ANY BER regressions.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: encoded/size are the input bytes; value receives a complete T2.
 * Returns: 0 for complete input, 1 for rejected/incomplete BER, -1 on bad API
 *          use or impossible decoder progress.
 * Errors: Partial decoded values are freed before returning a nonzero result.
 * Responsible party: asn1c maintainers. History: Added segmented ANY coverage
 * and removed a negative check on size_t decoder progress.
 * Example: feeds a zero-length explicit ANY wrapper one byte at a time.
 */
static int
decode_t2_any_chunks(const uint8_t *encoded, size_t size, T2_t **value) {
	T2_t *decoded = 0; /* state variable: partial or complete decoded T2 value. */
	asn_dec_rval_t rval;
	size_t offset = 0; /* state variable: consumed stream offset. */
	size_t chunk_limit = 1; /* state variable: next bounded feed size. */
	int result = 1;

	if((!encoded && size) || !value) return -1;
	*value = 0;
	while(offset < size) {
		size_t remaining = size - offset;
		size_t chunk = chunk_limit < remaining ? chunk_limit : remaining;

		/* Feed a bounded prefix, then retry unconsumed bytes with more input. */
		rval = ber_decode(0, &asn_DEF_T2, (void **)&decoded,
			encoded + offset, chunk);
		if(rval.consumed > chunk) {
			result = -1;
			break;
		}
		offset += (size_t)rval.consumed;
		if(rval.code == RC_OK) {
			if(offset == size) {
				*value = decoded;
				return 0;
			}
			break;
		}
		if(rval.code != RC_WMORE) break;
		if(rval.consumed) {
			chunk_limit = 1;
		} else if(chunk < remaining) {
			chunk_limit = chunk + 1;
		} else {
			break;
		}
	}
	if(decoded) ASN_STRUCT_FREE(asn_DEF_T2, decoded);
	return result;
}

/*
 * Check segmented T2 input against its expected ANY payload or rejection.
 * Original source: New check-60 assertion helper for opaque ANY bytes.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: encoded/size give BER input; accept selects expected result;
 *             payload/payload_size give raw ANY bytes when accepted.
 * Returns: 0 when decoding and payload match the expectation, otherwise -1.
 * Errors: Frees decoded T2 values on every successful decode path.
 * Responsible party: asn1c maintainers. History: Added segmented and malformed
 * ANY coverage.
 * Example: verifies two nested TLVs survive inside an explicit ANY wrapper.
 */
static int
check_t2_any_case(const uint8_t *encoded, size_t size, int accept,
		  const uint8_t *payload, size_t payload_size) {
	T2_t *decoded = 0; /* state variable: decoded T2 value for assertions. */
	int status;
	int result = -1;

	status = decode_t2_any_chunks(encoded, size, &decoded);
	if(accept) {
		if(status || !decoded || !decoded->any
		|| decoded->i != 1 || decoded->any->size != (ssize_t)payload_size
		|| (payload_size && (!payload || !decoded->any->buf
			|| memcmp(decoded->any->buf, payload, payload_size))))
			goto cleanup;
	} else if(status != 1) {
		goto cleanup;
	}
	result = 0;

cleanup:
	if(decoded) ASN_STRUCT_FREE(asn_DEF_T2, decoded);
	return result;
}

/*
 * Require a complete T2 input with an invalid ANY tag zero to fail decoding.
 * Original source: New check-60 assertion helper for reserved BER tag zero.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: encoded/size contain the complete malformed BER value.
 * Returns: 0 only when ber_decode returns RC_FAIL; otherwise -1.
 * Errors: Frees any partially decoded T2 value before returning.
 * Responsible party: asn1c maintainers. History: Added exact malformed-EOC
 * rejection checks.
 * Example: rejects universal tag zero with nonzero length inside an ANY value.
 */
static int
check_t2_any_failure(const uint8_t *encoded, size_t size) {
	T2_t *decoded = 0; /* state variable: partial T2 value owned by decoder. */
	asn_dec_rval_t rval;

	rval = ber_decode(0, &asn_DEF_T2, (void **)&decoded, encoded, size);
	if(decoded) ASN_STRUCT_FREE(asn_DEF_T2, decoded);
	return rval.code == RC_FAIL ? 0 : -1;
}

/*
 * Exercise empty, multi-TLV, and malformed explicit ANY values incrementally.
 * Original source: New check-60 regression matrix for OCTET_STRING BER.
 * Version/date: 1.3, 2026-10-12.
 * Parameters: None; cases are encoded locally to isolate ANY wrapper behavior.
 * Returns: 0 when all compatibility and rejection cases pass, otherwise -1.
 * Errors: Decoder failures or unexpected payload bytes return -1.
 * Responsible party: asn1c maintainers. History: Added malformed EOC, definite
 * ANY zero-pair compatibility, and exact overrun failure checks.
 * Example: verifies A0 00 decodes as present ANY with an empty payload.
 */
static int
check_any_opaque_regressions(void) {
	static const uint8_t empty_any[] = {
		0x30, 0x05, 0x02, 0x01, 0x01, 0xa0, 0x00
	};
	static const uint8_t multiple_any[] = {
		0x30, 0x0d, 0x02, 0x01, 0x01, 0xa0, 0x08,
		0xa1, 0x80, 0x00, 0x00, 0xa1, 0x80, 0x00, 0x00
	};
	static const uint8_t multiple_payload[] = {
		0xa1, 0x80, 0x00, 0x00, 0xa1, 0x80, 0x00, 0x00
	};
	static const uint8_t zero_payload_any[] = {
		0x30, 0x09, 0x02, 0x01, 0x01, 0xa0, 0x04, 0x04, 0x02, 0x00, 0x00
	};
	static const uint8_t zero_payload[] = {0x04, 0x02, 0x00, 0x00};
	static const uint8_t bad_eoc[] = {
		0x30, 0x80, 0x02, 0x01, 0x01, 0xa0, 0x80,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	static const uint8_t definite_any_zero_pair[] = {
		0x30, 0x07, 0x02, 0x01, 0x01, 0xa0, 0x02, 0x00, 0x00
	};
	static const uint8_t legacy_any_zero_pair[] = {0x00, 0x00};
	static const uint8_t bad_child_length[] = {
		0x30, 0x09, 0x02, 0x01, 0x01, 0xa0, 0x04,
		0xa1, 0x05, 0x00, 0x00
	};
	/* The trailing NULL supplies bytes outside the declared ANY wrapper. */
	static const uint8_t bad_child_length_with_following_bytes[] = {
		0x30, 0x0c, 0x02, 0x01, 0x01, 0xa0, 0x04,
		0xa1, 0x05, 0x00, 0x00, 0x05, 0x01, 0x00
	};
	static const uint8_t bad_parent_bound[] = {
		0x30, 0x06, 0x02, 0x01, 0x01, 0xa0, 0x01, 0xa1
	};

	if(check_t2_any_case(empty_any, sizeof(empty_any), 1, 0, 0)) return -1;
	if(check_t2_any_case(multiple_any, sizeof(multiple_any), 1,
			      multiple_payload, sizeof(multiple_payload)))
		return -1;
	if(check_t2_any_case(zero_payload_any, sizeof(zero_payload_any), 1,
			      zero_payload, sizeof(zero_payload)))
		return -1;
	if(check_t2_any_case(definite_any_zero_pair,
			      sizeof(definite_any_zero_pair), 1,
			      legacy_any_zero_pair, sizeof(legacy_any_zero_pair)))
		return -1;
	if(check_t2_any_case(bad_eoc, sizeof(bad_eoc), 0, 0, 0)) return -1;
	if(check_t2_any_failure(bad_eoc, sizeof(bad_eoc))) return -1;
	if(check_t2_any_case(bad_child_length, sizeof(bad_child_length), 0, 0, 0))
		return -1;
	if(check_t2_any_failure(bad_child_length, sizeof(bad_child_length)))
		return -1;
	if(check_t2_any_case(bad_child_length_with_following_bytes,
			      sizeof(bad_child_length_with_following_bytes), 0, 0, 0))
		return -1;
	if(check_t2_any_failure(bad_child_length_with_following_bytes,
				sizeof(bad_child_length_with_following_bytes)))
		return -1;
	if(check_t2_any_case(bad_parent_bound, sizeof(bad_parent_bound), 0, 0, 0))
		return -1;
	return 0;
}

/* [3] IMPLICIT SEQUENCE { b BOOLEAN } */
uint8_t test_any_buf1[] = { 0xa3, 0x80, /* [3], constructed, indefinite */
	0x01, 0x01, 0xff,	/* b BOOLEAN ::= TRUE */
	0x00, 0x00 /* End of content octets */ };

/* b BOOLEAN */
uint8_t test_any_buf2[] = { 0x01, 0x01, 0x13 };

/*
 * Run check-60's BER ANY and DER round-trip regression cases.
 * Original source: Existing check-60 executable test entry point.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: None; ASN.1 descriptors and fixtures are defined in this file.
 * Returns: 0 when all assertions and the final round trip pass, otherwise the
 *          last helper's nonzero status.
 * Errors: Failed test expectations terminate through assert; codec failures
 *         are returned by the called helpers.
 * Responsible party: asn1c maintainers. History: Documented for check-60.
 * Example: the test runner calls main() to exercise T1 and T2 ANY encodings.
 */
int
main() {
	asn_TYPE_descriptor_t *td1 = &asn_DEF_T1;
	asn_TYPE_descriptor_t *td2 = &asn_DEF_T2;
	T1_t t1, t1_new;
	T2_t t2, t2_new;
	int ret;

	/*
	 * Test the T1 with constructed indefinite length ANY encoding.
	 */
	memset(&t1, 0, sizeof(t1));
	memset(&t1_new, 0, sizeof(t1_new));

	t1.i = 112233;
	t1.any.buf = test_any_buf1;
	t1.any.size = sizeof(test_any_buf1);

	/* Save->Load must succeed */
	save_object(&t1, td1);
	ret = load_object(&t1_new, td1);

	assert(ret == 0);
	assert(t1_new.i == 112233);
	assert(t1_new.any.size == (ssize_t)sizeof(test_any_buf1));
	assert(memcmp(t1_new.any.buf, test_any_buf1, sizeof(test_any_buf1)) == 0);

	/*
	 * Test the T1 with primitive encoding.
	 */
	memset(&t1, 0, sizeof(t1));
	ASN_STRUCT_RESET(asn_DEF_T1, &t1_new);

	t1.i = -112233;
	t1.any.buf = test_any_buf2;
	t1.any.size = sizeof(test_any_buf2);

	/* Save->Load must succeed */
	save_object(&t1, td1);
	ret = load_object(&t1_new, td1);

	assert(ret == 0);
	assert(t1_new.i == -112233);
	assert(t1_new.any.size == (ssize_t)sizeof(test_any_buf2));
	assert(memcmp(t1_new.any.buf, test_any_buf2, sizeof(test_any_buf2)) == 0);
	ASN_STRUCT_RESET(asn_DEF_T1, &t1_new);

	/*
	 * Test the T2 empty sequence.
	 */
	memset(&t2, 0, sizeof(t2));
	memset(&t2_new, 0, sizeof(t2_new));

	t2.i = 332211;
	t2.any = calloc(1, sizeof(*t2.any));
	t2.any->buf = 0;
	t2.any->size = 0;

	/* Save->Load must succeed */
	save_object(&t2, td2);
	ret = load_object(&t2_new, td2);

	assert(ret == 0);
	assert(t2_new.i == 332211);
	assert(t2_new.any->size == 0);

	/*
	 * Test the T2 sequence.
	 */
	ASN_STRUCT_RESET(asn_DEF_T2, &t2);
	ASN_STRUCT_RESET(asn_DEF_T2, &t2_new);

	t2.i = 332211;
	t2.any = calloc(1, sizeof(*t2.any));
	t2.any->buf = test_any_buf1;
	t2.any->size = sizeof(test_any_buf1);

	/* Save->Load must succeed */
	save_object(&t2, td2);
	ret = load_object(&t2_new, td2);

	assert(ret == 0);
	assert(t2_new.i == 332211);
	assert(t2_new.any->size == (ssize_t)sizeof(test_any_buf1));
	assert(memcmp(t2_new.any->buf, test_any_buf1, sizeof(test_any_buf1)) == 0);

	/*
	 * Test the T2 sequence with primitive encoding.
	 */
	t2.any->buf = NULL;
	t2.any->size = 0;
	ASN_STRUCT_RESET(asn_DEF_T2, &t2);
	ASN_STRUCT_RESET(asn_DEF_T2, &t2_new);

	t2.i = 0;
	t2.any = calloc(1, sizeof(*t2.any));
	t2.any->buf = test_any_buf2;
	t2.any->size = sizeof(test_any_buf2);

	/* Save->Load must succeed */
	save_object(&t2, td2);
	ret = load_object(&t2_new, td2);

	assert(ret == 0);
	assert(t2_new.i == 0);
	assert(t2_new.any->size == (ssize_t)sizeof(test_any_buf2));
	assert(memcmp(t2_new.any->buf, test_any_buf2, sizeof(test_any_buf2)) == 0);

	/*
	 * Test T2 with ANY element omitted.
	 */
	free(t2.any);
	t2.any = 0;
	ASN_STRUCT_RESET(asn_DEF_T2, &t2_new);

	save_object(&t2, td2);
	ret = load_object(&t2_new, td2);

	assert(ret == 0);
	assert(t2_new.i == 0);
	assert(t2_new.any == 0);
	assert(check_any_opaque_regressions() == 0);

	printf("OK\n");

	return ret;
}
