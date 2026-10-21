#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <T.h>

/*
 * Valid BER SEQUENCE fixture with nested OCTET STRING components.
 * Source: Existing check-25 fixture, corrected on 2026-10-21 using
 * X.690 (2021) 8.14.4, 8.23.3 and 8.7.3.2. An IMPLICIT VisibleString
 * changes its outer tag; every constructed component still uses tag 4.
 */
uint8_t buf1[] = {
	32 | 16,		/* [UNIVERSAL 16], constructed */
	128,	/* L */
	/* a INTEGER */
	2,			/* [UNIVERSAL 2] */
	2,	/* L */
  150,
  70,
	/* b [2] IMPLICIT BOOLEAN */
	128 | 2,		/* [2] */
	1,	/* L */
  0xff,
	/* c NULL */
	5,			/* [UNIVERSAL 5] */
	0,	/* L */
	/* d ENUMERATED */
	10,			/* [UNIVERSAL 10] */
	1,	/* L */
  222,
	/* e OCTET STRING */
	4,			/* [UNIVERSAL 4] */
	3,	/* L */
	'x',
	'y',
	'z',
	/*
	 * X.690 8.14.4 replaces only the outer tag. Clauses 8.23.3 and
	 * 8.7.3.2 require universal OCTET STRING components at every depth.
	 */
	/* f [5] IMPLICIT VisibleString */
	128 | 32 | 5,		/* [5], constructed */
	128,	/* L indefinite */
		4,	/* [UNIVERSAL 4] (OCTET STRING), primitive */
		2,
  'l',
  'o',
		32 | 4,	/* [UNIVERSAL 4], recursively constructed */
		128,
			4,	/* [UNIVERSAL 4] (OCTET STRING), primitive */
			1,
  'v',
			4,	/* [UNIVERSAL 4], primitive */
			2,
  'e',
  '_',
		0,
		0,
		4,	/* [UNIVERSAL 4], primitive */
		2,
  'i',
  't',
	0,
	0,
	/* g BIT STRING */
	3,			/* [UNIVERSAL 3], primitive */
	3,	/* L */
	2,	/* Skip 2 bits */
	147,
	150,	/* => 148 */
	/* h [7] BIT STRING */
	128 | 32 | 7,			/* [7], constructed */
	128,	/* L indefinite */
		3,			/* [UNIVERSAL 3], primitive */
		3,	/* L */
		0,	/* Skip 0 bits */
		140,
		141,
		3,			/* [UNIVERSAL 3], primitive */
		2,	/* L */
		1,	/* Skip 1 bit */
		143,	/* => 142 */
	0,	/* End of h */
	0,
	0,	/* End of the whole structure */
	0,
	/* Three bytes of planned leftover */
	111, 222, 223
};

/*
 * Decode one test input and verify its value or bounded failure behavior.
 * Original source: Existing check-25 BER regression helper.
 * Version/date: 1.2, 2026-10-21.
 * Parameters: is_ok selects value checks; buf/size provide encoded input;
 *   consumed is the expected full length or the maximum allowed on failure.
 * Returns: No value; assertions terminate the test on status/value mismatch.
 * Errors: Decoder failures are checked when is_ok is false; assertion failures
 *   abort the test. The temporary decoded structure is reset before return.
 * Responsible party: asn1c maintainers. History: Used for seeded BER mutations.
 * Example: check(1, buf1, sizeof(buf1), sizeof(buf1) - 3).
 */
static void
check(int is_ok, uint8_t *buf, size_t size, size_t consumed) {
	T_t t, *tp;
	asn_dec_rval_t rval;

	tp = memset(&t, 0, sizeof(t));

	fprintf(stderr, "Buf %p (%zd)\n", buf, size);
	rval = ber_decode(0, &asn_DEF_T, (void **)&tp, buf, size);
	fprintf(stderr, "Returned code %d, consumed %zd, expected %zd\n",
		(int)rval.code, rval.consumed, consumed);

	if(is_ok) {
		assert(rval.code == RC_OK);
		assert(rval.consumed == consumed);

		assert(strcmp((char *)t.e->buf, "xyz") == 0);
		assert(strcmp((char *)t.f->buf, "love_it") == 0);

		assert(t.g->size == 2);
		assert(t.g->bits_unused == 2);
		fprintf(stderr, "%d %d\n", t.g->buf[0], t.g->buf[1]);
		assert(t.g->buf[0] == 147);
		assert(t.g->buf[1] != 150);
		assert(t.g->buf[1] == 148);

		assert(t.h->size == 3);
		assert(t.h->bits_unused == 1);
		assert(t.h->buf[0] == 140);
		assert(t.h->buf[1] == 141);
		assert(t.h->buf[2] == 142);
	} else {
		if(rval.code == RC_OK) {
			assert(t.a.size != 2
			|| !t.d
			|| t.d->size != 1
			|| !t.e
			|| t.e->size != 3
			|| !t.f
			|| t.f->size != 7
			|| !t.g
			|| t.g->size != 2
			|| !t.h
			|| t.h->size != 3
			);
		}
		fprintf(stderr, "%zd %zd\n", rval.consumed, consumed);
		assert(rval.consumed <= consumed);
	}

	ASN_STRUCT_RESET(asn_DEF_T, &t);
}

/*
 * Decode one fixed mutation and require its exact BER status.
 * Original source: New check-25 regression helper for malformed BER vectors.
 * Version/date: 1.0, 2026-10-12.
 * Parameters: name labels the case; buf/size bound the original; offset and
 *   replacement define one changed octet; expected_code is the decoder result.
 * Returns: No value; the test aborts if the decoder status differs.
 * Errors: Assertion failure terminates the test; the partial value is freed.
 * Responsible party: asn1c maintainers. History: Added for CER BER regressions.
 * Example: require a VisibleString fragment-tag mutation to return RC_FAIL.
 */
static void
expect_mutation_code(const char *name, const uint8_t *buf, size_t size,
		     size_t offset, uint8_t replacement,
		     enum asn_dec_rval_code_e expected_code) {
	uint8_t tmp[size];
	T_t t, *tp;
	asn_dec_rval_t rval;

	assert(size > 0);
	assert(offset < size);
	memcpy(tmp, buf, size);
	tmp[offset] = replacement;
	tp = memset(&t, 0, sizeof(t));
	rval = ber_decode(0, &asn_DEF_T, (void **)&tp, tmp, size);
	fprintf(stderr, "%s: returned code %d, consumed %zd\n",
		name, (int)rval.code, rval.consumed);
	assert(rval.code == expected_code);
	ASN_STRUCT_RESET(asn_DEF_T, &t);
}

/*
 * Decode a valid alternative OCTET-fragment split for the same VisibleString.
 * Original source: New check-25 positive BER regression vector.
 * Version/date: 1.0, 2026-10-12.
 * Parameters: None; the fixed source buffer is split as "ve" followed by "_".
 * Returns: No value; check() verifies all decoded members and string contents.
 * Errors: Assertion failure terminates the test and reports the mismatch.
 * Responsible party: asn1c maintainers. History: Added beside malformed tags.
 * Example: called after the canonical OCTET-fragment layout in main().
 */
static void
check_alternative_visible_fragments(void) {
	uint8_t alternate[sizeof(buf1) - 3];
	const size_t size = sizeof(alternate);

	memcpy(alternate, buf1, size);
	/* Keep the abstract "ve_" value while using a different legal split. */
	alternate[28] = 2;
	alternate[30] = 'e';
	alternate[31] = 4;
	alternate[32] = 1;
	alternate[33] = '_';
	check(1, alternate, size, size);
}

/*
 * Exercise 1000 deterministic random mutations of non-payload BER octets.
 * Original source: Existing check-25 malformed-input regression helper.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: buf/size identify the original encoding; allow_consume bounds
 *   the bytes a mutated value may consume before failure.
 * Returns: No value; check() asserts rejection or incomplete consumption.
 * Errors: Assertion failures terminate the test; tmp uses a size-bounded VLA.
 * Responsible party: asn1c maintainers. History: Retains broad seeded coverage.
 * Example: try_corrupt(buf1, sizeof(buf1) - 3, sizeof(buf1) - 3).
 */
static void
try_corrupt(uint8_t *buf, size_t size, int allow_consume) {
	uint8_t tmp[size];

	fprintf(stderr, "\nCorrupting...\n");

	for(int i = 0; i < 1000; i++) {
		int loc;
		memcpy(tmp, buf, size);

		/* Corrupt random _non-value_ location. */
		do { loc = random() % size; } while(
			loc == 44	/* bit skips */
			|| loc == 51	/* bit skips */
			|| loc == 56	/* bit skips */
			|| tmp[loc] >= 70);
		do { tmp[loc] = buf[loc] ^ random(); } while(
			(tmp[loc] == buf[loc])
			|| (buf[loc] == 0 && tmp[loc] == 0x80));

		fprintf(stderr, "\nTry %d: corrupting byte %d (%d->%d)\n",
			i, loc, buf[loc], tmp[loc]);

		check(0, tmp, size, allow_consume);
	}
}

/*
 * Verify BER decoding resumes across tested three-chunk input partitions.
 * Original source: Existing check-25 incremental-decoding regression helper.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: buf/size identify the complete encoding split into three feeds.
 * Returns: No value; assertions require RC_WMORE twice, then a complete value.
 * Errors: Assertion failures terminate the test; each decoded value is reset.
 * Responsible party: asn1c maintainers. History: Covers all tested two-cut
 * positions while retaining a nonempty final feed.
 * Example: partial_read(buf1, sizeof(buf1) - 3).
 */
static void
partial_read(uint8_t *buf, size_t size) {
	T_t t, *tp;
	asn_dec_rval_t rval;
	uint8_t tbuf1[size];
	uint8_t tbuf2[size];
	uint8_t tbuf3[size];

	fprintf(stderr, "\nPartial read sequence...\n");

	/*
	 * Divide the space (size) into three blocks in various combinations:
	 *   |<----->i1<----->i2<----->|
	 *   ^ buf                     ^ buf+size
	 * Try to read block by block.
	 */
	for(size_t i1 = 0; i1 < size; i1++) {
		for(size_t i2 = i1; i2 < size; i2++) {
			uint8_t *chunk1 = buf;
			size_t size1 = i1;
			uint8_t *chunk2 = buf + size1;
			size_t size2 = i2 - i1;
			uint8_t *chunk3 = buf + size1 + size2;
			size_t size3 = size - size1 - size2;

			fprintf(stderr, "\n%d:{%d, %d, %d}...\n",
				(int)size, (int)size1, (int)size2, (int)size3);

			memset(tbuf1, 0, size);
			memset(tbuf2, 0, size);
			memset(tbuf3, 0, size);
			memcpy(tbuf1, chunk1, size1);
			memcpy(tbuf2, chunk2, size2);
			memcpy(tbuf3, chunk3, size3);

			tp = memset(&t, 0, sizeof(t));

			fprintf(stderr, "=> Chunk 1 (%d):\n", (int)size1);
			rval = ber_decode(0, &asn_DEF_T, (void **)&tp,
				tbuf1, size1);
			assert(rval.code == RC_WMORE);
			assert(rval.consumed <= size1);
			if(rval.consumed < size1) {
				int leftover = size1 - rval.consumed;
				memcpy(tbuf2, tbuf1 + rval.consumed, leftover);
				memcpy(tbuf2 + leftover, chunk2, size2);
				size2 += leftover;
			}

			fprintf(stderr, "=> Chunk 2 (%d):\n", (int)size2);
			rval = ber_decode(0, &asn_DEF_T, (void **)&tp,
				tbuf2, size2);
			assert(rval.code == RC_WMORE);
			assert(rval.consumed <= size2);
			if(rval.consumed < size2) {
				int leftover = size2 - rval.consumed;
				memcpy(tbuf3, tbuf2 + rval.consumed, leftover);
				memcpy(tbuf3 + leftover, chunk3, size3);
				size3 += leftover;
			}

			fprintf(stderr, "=> Chunk 3 (%d):\n", (int)size3);
			rval = ber_decode(0, &asn_DEF_T, (void **)&tp,
				tbuf3, size3);
			assert(rval.code == RC_OK);
			assert(rval.consumed == size3);

			ASN_STRUCT_RESET(asn_DEF_T, &t);
		}
	}
}

/*
 * Run positive, deterministic negative, random-mutation, and restartability tests.
 * Original source: Existing check-25 generated-type regression program.
 * Version/date: 1.2, 2026-10-21.
 * Parameters: ac/av are ignored command-line arguments from the test runner.
 * Returns: Zero after all checks pass; the process aborts on assertion failure.
 * Errors: Decoder mismatches and malformed-input acceptance fail assertions.
 * Responsible party: asn1c maintainers. History: Adds CER fragment-tag vectors;
 * version 1.2 rejects the legacy fixture's invalid outer-tag components.
 * Example: invoked as `./check-program` by the generated test directory.
 */
int
main(int ac, char **av) {
	size_t size = sizeof(buf1) - 3;

	(void)ac;	/* Unused argument */
	(void)av;	/* Unused argument */
	srandom(1);

	/* Check that the full buffer may be decoded normally */
	check(1, buf1, sizeof(buf1), size);
	check_alternative_visible_fragments();

	/* Reject wrong outer/fragment tags, truncated lengths, and malformed EOCs. */
	expect_mutation_code("wrong SEQUENCE wrapper", buf1, size,
			     0, 0x31, RC_FAIL);
	expect_mutation_code("VisibleString tag at first implicit fragment", buf1,
			     size, 21, 26, RC_FAIL);
	expect_mutation_code("VisibleString constructor as OCTET component", buf1,
			     size, 25, 0x3a, RC_FAIL);
	expect_mutation_code("VisibleString tag at final implicit fragment", buf1,
			     size, 36, 26, RC_FAIL);
	expect_mutation_code("VisibleString chunk used as OCTET fragment", buf1,
			     size, 27, 26, RC_FAIL);
	expect_mutation_code("truncated OCTET fragment", buf1, size,
			     28, 0x7f, RC_WMORE);
	expect_mutation_code("malformed nested EOC", buf1, size,
			     34, 1, RC_FAIL);

	/* Check that some types of buffer corruptions will lead to failure */
	try_corrupt(buf1, size, size);

	/* Split the buffer in parts and check decoder restartability */
	partial_read(buf1, size);

	return 0;
}
