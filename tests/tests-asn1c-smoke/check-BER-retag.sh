#!/usr/bin/env bash
#
# Compile generated descriptors for Label2 ::= [1] Label and verify BER retagging.
# Original source: New issue #581 compiler-to-skeleton regression.
# Version/date: 1.0, 2026-10-21. Responsible party: asn1c maintainers.
# Inputs: Automake top_builddir/top_srcdir, CC, and MAKE variables.
# Returns/errors: zero for accepted valid BER and rejected superseded [9] input;
#   compiler, linker, converter, or byte-comparison failures exit nonzero.
# History: Added beside check-BER-expected-tag for issue #581 and PR #580 review.
# Example: make -C tests/tests-asn1c-smoke check TESTS=check-BER-retag.sh
set -eu

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-ber-retag.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

cat > "$test_directory/retag.asn1" <<'ASN1'
RetagReview DEFINITIONS IMPLICIT TAGS ::= BEGIN
Label ::= [9] EXPLICIT UTF8String
Label2 ::= [1] Label
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

echo 'BER retag smoke test passed'
