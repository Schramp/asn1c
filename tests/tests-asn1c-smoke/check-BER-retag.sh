#!/usr/bin/env bash
#
# Compile generated retagged-string descriptors and verify BER decoding, DER output,
# and empty-value comparisons.
# Original source: New issue #581 compiler-to-skeleton regression.
# Version/date: 1.1, 2026-10-21. Responsible party: asn1c maintainers.
# Inputs: Automake top_builddir/top_srcdir, CC, and MAKE variables.
# Returns/errors: zero for accepted valid BER and rejected superseded [9] input;
#   compiler, linker, converter, or byte-comparison failures exit nonzero.
# History: Added beside check-BER-expected-tag for issue #581 and PR #580 review.
#   Extended with deterministic empty-value regressions on 2026-10-21.
# Example: make -C tests/tests-asn1c-smoke check TESTS=check-BER-retag.sh
set -eu

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-ber-retag.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

# Purpose: Decode and canonicalize a fixed BER vector through a generated PDU.
# Source: Generated-code regression for empty retagged strings.
# Version/date: 1.1, 2026-10-21.
# Parameters: $1 is the generated ASN.1 type; $2 is the fixture basename.
# Returns/errors: Zero for an exact DER byte match; nonzero on decode or mismatch.
# Responsible party: asn1c maintainers.
# History: Added deterministic empty-string BER vectors on 2026-10-21.
# Example: run_empty_roundtrip ZeroExplicit empty-explicit-utf8.
run_empty_roundtrip() {
    local type_name=$1
    local fixture_name=$2

    "$test_directory/generated/converter-example" -p "$type_name" -iber -oder \
        "$test_directory/$fixture_name.ber" > "$test_directory/$fixture_name.actual"
    cmp "$test_directory/$fixture_name.expected" \
        "$test_directory/$fixture_name.actual"
}

cat > "$test_directory/retag.asn1" <<'ASN1'
RetagReview DEFINITIONS IMPLICIT TAGS ::= BEGIN
Label ::= [9] EXPLICIT UTF8String
Label2 ::= [1] Label
ZeroImplicit ::= [2] IMPLICIT UTF8String (SIZE(0))
ZeroExplicit ::= [4] EXPLICIT UTF8String (SIZE(0))
ZeroOctets ::= [5] EXPLICIT OCTET STRING (SIZE(0))
ZeroBits ::= [6] EXPLICIT BIT STRING (SIZE(0))
Nested ::= SEQUENCE { x [1] EXPLICIT SEQUENCE { y [2] IMPLICIT UTF8String (SIZE(0)) } }
END
ASN1

# Compile and link the actual compiler-generated descriptor tag arrays.
mkdir "$test_directory/generated"
"$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
    -D "$test_directory/generated" -pdu=all -no-gen-UPER -no-gen-APER \
    -no-gen-OER -no-gen-JER -no-gen-CBOR "$test_directory/retag.asn1"
"${MAKE:-make}" -C "$test_directory/generated" -f converter-example.mk \
    CC="${CC:-cc}"

# The effective [1] tag wraps UTF8String directly; [9] was superseded by IMPLICIT.
printf '\241\005\014\003ABC' > "$test_directory/valid.der"
printf '\241\005\014\003ABC' > "$test_directory/valid.expected"
"$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/valid.der" > "$test_directory/valid.actual"
cmp "$test_directory/valid.expected" "$test_directory/valid.actual"

# X.690 8.23.3 and 8.7.3.2 use OCTET STRING tag 4 at every fragment depth.
printf '\241\007\054\005\044\003\004\001A' > "$test_directory/constructed.ber"
printf '\241\003\014\001A' > "$test_directory/constructed.expected"
"$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/constructed.ber" > "$test_directory/constructed.actual"
cmp "$test_directory/constructed.expected" "$test_directory/constructed.actual"

# Reject the UTF8String outer tag when it is repeated as a fragment tag.
printf '\241\005\054\003\014\001A' > "$test_directory/wrong-fragment.ber"
if "$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/wrong-fragment.ber" > "$test_directory/wrong-fragment.actual" \
    2> "$test_directory/wrong-fragment.err"; then
    echo 'FAIL: decoder accepted UTF8String tag 12 as an OCTET STRING fragment' >&2
    exit 1
fi

# An indefinite effective wrapper must also decode and canonicalize to DER.
printf '\241\200\014\003ABC\000\000' > "$test_directory/indefinite.ber"
"$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/indefinite.ber" > "$test_directory/indefinite.actual"
cmp "$test_directory/valid.expected" "$test_directory/indefinite.actual"

# Indefinite constructed UTF8String contents must retain the natural tag 4.
printf '\241\200\054\200\044\200\004\001A\000\000\000\000\000\000' \
    > "$test_directory/constructed-indefinite.ber"
"$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/constructed-indefinite.ber" \
    > "$test_directory/constructed-indefinite.actual"
cmp "$test_directory/constructed.expected" \
    "$test_directory/constructed-indefinite.actual"

# The same repeated UTF8String tag is invalid in an indefinite value.
printf '\241\200\054\200\014\001A\000\000\000\000' \
    > "$test_directory/wrong-fragment-indefinite.ber"
if "$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/wrong-fragment-indefinite.ber" \
    > "$test_directory/wrong-fragment-indefinite.actual" \
    2> "$test_directory/wrong-fragment-indefinite.err"; then
    echo 'FAIL: decoder accepted indefinite UTF8String tag 12 fragment' >&2
    exit 1
fi

# A superseded [9] wrapper is not part of the effective BER type.
printf '\241\005\251\003\014\001A' > "$test_directory/superseded.ber"
if "$test_directory/generated/converter-example" -p Label2 -iber -oder \
    "$test_directory/superseded.ber" > "$test_directory/superseded.actual" \
    2> "$test_directory/superseded.err"; then
    echo 'FAIL: decoder accepted the superseded [9] wrapper' >&2
    exit 1
fi

# Empty DER values retain their effective tags and nested wrapper structure.
printf '\241\002\014\000' > "$test_directory/empty-label2.ber"
cp "$test_directory/empty-label2.ber" "$test_directory/empty-label2.expected"
printf '\244\002\014\000' > "$test_directory/empty-explicit-utf8.ber"
cp "$test_directory/empty-explicit-utf8.ber" \
    "$test_directory/empty-explicit-utf8.expected"
printf '\202\000' > "$test_directory/empty-implicit-utf8.ber"
cp "$test_directory/empty-implicit-utf8.ber" \
    "$test_directory/empty-implicit-utf8.expected"
printf '\245\002\004\000' > "$test_directory/empty-explicit-octets.ber"
cp "$test_directory/empty-explicit-octets.ber" \
    "$test_directory/empty-explicit-octets.expected"
printf '\246\003\003\001\000' > "$test_directory/empty-explicit-bits.ber"
cp "$test_directory/empty-explicit-bits.ber" \
    "$test_directory/empty-explicit-bits.expected"
printf '\060\006\241\004\060\002\202\000' > "$test_directory/empty-nested.ber"
cp "$test_directory/empty-nested.ber" "$test_directory/empty-nested.expected"
run_empty_roundtrip Label2 empty-label2
run_empty_roundtrip ZeroExplicit empty-explicit-utf8
run_empty_roundtrip ZeroImplicit empty-implicit-utf8
run_empty_roundtrip ZeroOctets empty-explicit-octets
run_empty_roundtrip ZeroBits empty-explicit-bits
run_empty_roundtrip Nested empty-nested

# Exercise generated alias comparison with both allocated and null empty buffers.
cat > "$test_directory/generated/check-empty-compare.c" <<'C'
/*
 * Purpose: Compare empty generated string aliases with allocated and null buffers.
 * Source: Generated descriptor regression for zero-length BER roundtrips.
 * Version/date: 1.1, 2026-10-21.
 * Parameters: None.
 * Returns/errors: Zero if UTF8String and BIT STRING aliases compare equal.
 * Responsible: asn1c maintainers.
 * History: Added for the zero-length BER comparison failure on 2026-10-21.
 * Example: Built and run by check-BER-retag.sh.
 */
#include "Label2.h"
#include "ZeroBits.h"
#include "ZeroExplicit.h"

#include <stdio.h>
#include <stdint.h>

int
main(void) {
    uint8_t empty_byte = 0;
    Label2_t retagged_allocated = {0};
    Label2_t retagged_null = {0};
    ZeroExplicit_t explicit_allocated = {0};
    ZeroExplicit_t explicit_null = {0};
    ZeroBits_t bits_allocated = {0};
    ZeroBits_t bits_null = {0};

    /* Provide one real byte of storage while preserving an empty ASN.1 value. */
    retagged_allocated.buf = &empty_byte;
    explicit_allocated.buf = &empty_byte;
    bits_allocated.buf = &empty_byte;
    bits_allocated.bits_unused = 0;

    /* Compare each generated alias in both operand orders to check symmetry. */
    if(asn_DEF_Label2.op->compare_struct(&asn_DEF_Label2, &retagged_allocated,
                                         &retagged_null) != 0
       || asn_DEF_Label2.op->compare_struct(&asn_DEF_Label2, &retagged_null,
                                            &retagged_allocated) != 0
       || asn_DEF_ZeroExplicit.op->compare_struct(&asn_DEF_ZeroExplicit,
                                                  &explicit_allocated,
                                                  &explicit_null) != 0
       || asn_DEF_ZeroBits.op->compare_struct(&asn_DEF_ZeroBits, &bits_allocated,
                                              &bits_null) != 0) {
        fprintf(stderr, "FAIL: empty generated aliases compared as unequal\n");
        return 1;
    }

    return 0;
}
C
"${MAKE:-make}" -C "$test_directory/generated" -f converter-example.mk \
    CC="${CC:-cc}" ASN_PROGRAM=check-empty-compare \
    "ASN_PROGRAM_SRCS=$test_directory/generated/check-empty-compare.c"
"$test_directory/generated/check-empty-compare"

echo 'BER retag smoke test passed'
