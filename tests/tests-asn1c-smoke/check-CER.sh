#!/usr/bin/env bash
# Verify generated descriptor semantics and converter CER codec selection.
# Source: new asn1c regression, independently derived X.690 sections 9/11 bytes.
# Version/date: 2026-10-11. Responsible: asn1c maintainers.
# Inputs: top_builddir/top_srcdir, CC, MAKE from the Automake environment.
# Returns/errors: zero when all comparisons pass; build/codec failures are fatal.
# History: initial native CER encoder integration. No external dependencies.
# Example: make check TESTS=check-CER.sh
set -eu

# Keep generated files isolated and remove only this test's temporary directory.
test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-cer-smoke.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

cat > "$test_directory/review.asn1" <<'ASN1'
CERReview DEFINITIONS IMPLICIT TAGS ::= BEGIN
Blob ::= OCTET STRING
LongVisible ::= VisibleString
LongBMP ::= BMPString
Lower ::= CHOICE { late [8] INTEGER, early [0] BOOLEAN }
ChoiceSet ::= SET { plain [4] INTEGER, selected Lower }
MixedSet ::= SET {
    selected CHOICE { app [APPLICATION 20] INTEGER, ctx [0] INTEGER },
    peer [APPLICATION 21] INTEGER
}
Triple ::= SEQUENCE { flag BOOLEAN DEFAULT FALSE, blob [5] EXPLICIT Blob }
Tagged ::= [7] IMPLICIT OCTET STRING
Bag ::= SET OF Blob
TaggedChoice ::= [3] EXPLICIT Lower
NestedChoice ::= [6] EXPLICIT TaggedChoice
RetagOctets ::= [UNIVERSAL 2] IMPLICIT OCTET STRING
RetagUTF8 ::= [UNIVERSAL 4] IMPLICIT UTF8String
RetagBits ::= [UNIVERSAL 4] IMPLICIT BIT STRING
RetagInteger ::= [UNIVERSAL 4] IMPLICIT INTEGER
DeepInteger ::= [5] EXPLICIT DeepInteger2
DeepInteger2 ::= [6] EXPLICIT DeepInteger3
DeepInteger3 ::= [7] EXPLICIT DeepInteger4
DeepInteger4 ::= [8] EXPLICIT INTEGER
TESTCLASS ::= CLASS { &id INTEGER UNIQUE, &Type }
    WITH SYNTAX { ID &id TYPE &Type }
TestSet TESTCLASS ::= { { ID 42 TYPE Packet }, ... }
Packet ::= SEQUENCE { count INTEGER (0..127), data OCTET STRING (SIZE(1..32)) }
Frame ::= SEQUENCE {
    msgId [0] TESTCLASS.&id({TestSet}),
    value [1] EXPLICIT TESTCLASS.&Type({TestSet}{@msgId})
}
END
ASN1

# Build real generated descriptors, with only the codecs used by this test.
mkdir -p "$test_directory/enabled" "$test_directory/disabled" "$test_directory/no-ber"
"$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
    -D "$test_directory/enabled" -pdu=all -gen-CER \
    -no-gen-UPER -no-gen-APER -no-gen-OER -no-gen-JER -no-gen-CBOR \
    "$test_directory/review.asn1"
"${MAKE:-make}" -C "$test_directory/enabled" -f converter-example.mk \
    CC="${CC:-cc}"

# SET ordering uses the least possible CHOICE tag, even when another is selected.
printf '%s\n' '<ChoiceSet><plain>9</plain><selected><late>7</late></selected></ChoiceSet>' \
    > "$test_directory/choice.xml"
printf '\061\200\210\001\007\204\001\011\000\000' > "$test_directory/choice.expected"
"$test_directory/enabled/converter-example" -p ChoiceSet -ixer -ocer \
    "$test_directory/choice.xml" > "$test_directory/choice.actual"
cmp "$test_directory/choice.expected" "$test_directory/choice.actual"

# Compare tag class before tag number when finding an untagged CHOICE minimum.
printf '%s\n' '<MixedSet><selected><ctx>7</ctx></selected><peer>9</peer></MixedSet>' \
    > "$test_directory/mixed.xml"
printf '\061\200\200\001\007\125\001\011\000\000' > "$test_directory/mixed.expected"
"$test_directory/enabled/converter-example" -p MixedSet -ixer -ocer \
    "$test_directory/mixed.xml" > "$test_directory/mixed.actual"
cmp "$test_directory/mixed.expected" "$test_directory/mixed.actual"

# Equal DEFAULTs disappear; the explicit tag and SEQUENCE use indefinite lengths.
printf '%s\n' '<Triple><flag><false/></flag><blob>5A</blob></Triple>' \
    > "$test_directory/triple.xml"
printf '\060\200\245\200\004\001\132\000\000\000\000' > "$test_directory/triple.expected"
"$test_directory/enabled/converter-example" -p Triple -ixer -ocer \
    "$test_directory/triple.xml" > "$test_directory/triple.actual"
cmp "$test_directory/triple.expected" "$test_directory/triple.actual"

# A primitive implicit tag replaces the universal tag without changing contents.
printf '%s\n' '<Tagged>5A</Tagged>' > "$test_directory/tagged.xml"
printf '\207\001\132' > "$test_directory/tagged.expected"
"$test_directory/enabled/converter-example" -p Tagged -ixer -ocer \
    "$test_directory/tagged.xml" > "$test_directory/tagged.actual"
cmp "$test_directory/tagged.expected" "$test_directory/tagged.actual"

# Long implicitly tagged OCTET STRINGs use universal tag 4 for each fragment.
awk 'BEGIN { printf "<Tagged>"; for (i=0; i<1001; i++) printf "5A"; print "</Tagged>" }' \
    > "$test_directory/tagged-long.xml"
{ printf '\247\200\004\202\003\350';
  awk 'BEGIN { for (i=0; i<1000; i++) printf "Z" }';
  printf '\004\001Z\000\000'; } > "$test_directory/tagged-long.expected"
"$test_directory/enabled/converter-example" -p Tagged -ixer -ocer \
    "$test_directory/tagged-long.xml" > "$test_directory/tagged-long.actual"
cmp "$test_directory/tagged-long.expected" "$test_directory/tagged-long.actual"

# SET OF ordering compares final encodings and keeps the source values intact.
printf '%s\n' '<Bag><Blob>5A</Blob><Blob>41</Blob></Bag>' > "$test_directory/bag.xml"
printf '\061\200\004\001\101\004\001\132\000\000' > "$test_directory/bag.expected"
"$test_directory/enabled/converter-example" -p Bag -ixer -ocer \
    "$test_directory/bag.xml" > "$test_directory/bag.actual"
cmp "$test_directory/bag.expected" "$test_directory/bag.actual"

# Tagged CHOICEs wrap the selected alternative once for each explicit tag.
printf '%s\n' '<TaggedChoice><late>7</late></TaggedChoice>' > "$test_directory/tchoice.xml"
printf '\243\200\210\001\007\000\000' > "$test_directory/tchoice.expected"
"$test_directory/enabled/converter-example" -p TaggedChoice -ixer -ocer \
    "$test_directory/tchoice.xml" > "$test_directory/tchoice.actual"
cmp "$test_directory/tchoice.expected" "$test_directory/tchoice.actual"
printf '%s\n' '<NestedChoice><late>7</late></NestedChoice>' > "$test_directory/nchoice.xml"
printf '\246\200\243\200\210\001\007\000\000\000\000' > "$test_directory/nchoice.expected"
"$test_directory/enabled/converter-example" -p NestedChoice -ixer -ocer \
    "$test_directory/nchoice.xml" > "$test_directory/nchoice.actual"
cmp "$test_directory/nchoice.expected" "$test_directory/nchoice.actual"

# Named primitive tag chains use CER wrappers independently of DER's tag limit.
printf '\245\200\246\200\247\200\250\200\002\001\177\000\000\000\000\000\000\000\000' \
    > "$test_directory/deep.expected"

# Universal retagging must retain the original value's storage and content rules.
printf '%s\n' '<RetagOctets>0001</RetagOctets>' > "$test_directory/roctets.xml"
printf '\002\002\000\001' > "$test_directory/roctets.expected"
printf '%s\n' '<RetagBits>10000000</RetagBits>' > "$test_directory/rbits.xml"
printf '\004\002\000\200' > "$test_directory/rbits.expected"
for retag_case in Octets Bits; do
    case_lower=$(printf '%s' "$retag_case" | tr '[:upper:]' '[:lower:]')
    "$test_directory/enabled/converter-example" -p "Retag$retag_case" -ixer -ocer \
        "$test_directory/r$case_lower.xml" > "$test_directory/r$case_lower.actual"
    cmp "$test_directory/r$case_lower.expected" "$test_directory/r$case_lower.actual"
done

# CER character-string fragments use OCTET STRING identifiers after retagging.
awk 'BEGIN { printf "<RetagUTF8>"; for (i=0; i<1001; i++) printf "A"; print "</RetagUTF8>" }' \
    > "$test_directory/rutf8.xml"
{ printf '\044\200\004\202\003\350';
  awk 'BEGIN { for (i=0; i<1000; i++) printf "A" }';
  printf '\004\001A\000\000'; } > "$test_directory/rutf8.expected"
"$test_directory/enabled/converter-example" -p RetagUTF8 -ixer -ocer \
    "$test_directory/rutf8.xml" > "$test_directory/rutf8.actual"
cmp "$test_directory/rutf8.expected" "$test_directory/rutf8.actual"
printf '\044\200\014\001A\000\000' > "$test_directory/rutf8-natural.bin"
if "$test_directory/enabled/converter-example" -p RetagUTF8 -icer -ocer \
    "$test_directory/rutf8-natural.bin" > "$test_directory/rutf8-natural.out" \
    2> "$test_directory/rutf8-natural.err"; then
    echo 'FAIL: decoder accepted UTF8String fragment tags inside a constructed string' >&2
    exit 1
fi

# VisibleString and BMPString use OCTET STRING fragment identifiers at CER boundaries.
awk 'BEGIN { printf "<LongVisible>"; for (i=0; i<1001; i++) printf "A";
    print "</LongVisible>" }' > "$test_directory/visible-long.xml"
{ printf '\072\200\004\202\003\350';
  awk 'BEGIN { for (i=0; i<1000; i++) printf "A" }';
  printf '\004\001A\000\000'; } > "$test_directory/visible-long.expected"
"$test_directory/enabled/converter-example" -p LongVisible -ixer -ocer \
    "$test_directory/visible-long.xml" > "$test_directory/visible-long.actual"
cmp "$test_directory/visible-long.expected" "$test_directory/visible-long.actual"
awk 'BEGIN { printf "<LongBMP>"; for (i=0; i<501; i++) printf "A";
    print "</LongBMP>" }' > "$test_directory/bmp-long.xml"
{ printf '\076\200\004\202\003\350';
  for ((i=0; i<500; i++)); do printf '\000A'; done;
  printf '\004\002\000A\000\000'; } > "$test_directory/bmp-long.expected"
"$test_directory/enabled/converter-example" -p LongBMP -ixer -ocer \
    "$test_directory/bmp-long.xml" > "$test_directory/bmp-long.actual"
cmp "$test_directory/bmp-long.expected" "$test_directory/bmp-long.actual"

# Retagged BIT STRING fragments use tag 3 and include their unused-bit octet.
awk 'BEGIN { printf "<RetagBits>"; for (i=0; i<8000; i++) printf "1"; print "</RetagBits>" }' \
    > "$test_directory/rbits-long.xml"
{ printf '\044\200\003\202\003\350\000';
  awk 'BEGIN { for (i=0; i<999; i++) printf "%c", 255 }';
  printf '\003\002\000\377\000\000'; } > "$test_directory/rbits-long.expected"
"$test_directory/enabled/converter-example" -p RetagBits -ixer -ocer \
    "$test_directory/rbits-long.xml" > "$test_directory/rbits-long.actual"
cmp "$test_directory/rbits-long.expected" "$test_directory/rbits-long.actual"

# Resolve an information-object-selected open type through real generated C metadata.
cat > "$test_directory/open.c" <<'C'
#include <Frame.h>
#include <RetagInteger.h>
#include <DeepInteger.h>
#include <cer_encoder.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
/*
 * Emit CER from a generated INTEGER carrying four explicit named-alias tags.
 * Source: new generated CER regression. Version/date: 2026-10-11.
 * Inputs: none; the generated DeepInteger value is fixed at 127.
 * Returns: zero after writing bytes to stdout, one on encoding/write failure.
 * Errors: C has no exceptions; the caller reports failure through its exit code.
 * Owner: asn1c maintainers. History: bypass unrelated XER alias-tag behavior.
 * Example: check-CER.sh compares stdout with independent deep.expected bytes.
 */
static int check_deep_integer(void) {
    DeepInteger_t value = 127;
    unsigned char bytes[32];
    asn_enc_rval_t result;

    /* Exercise the compiler's descriptor rather than a hand-built tag array. */
    result = cer_encode_to_buffer(NULL, &asn_DEF_DeepInteger, &value, bytes, sizeof(bytes));
    if(result.encoded < 0 || (size_t)result.encoded > sizeof(bytes)) return 1;
    return fwrite(bytes, 1, (size_t)result.encoded, stdout) == (size_t)result.encoded ? 0 : 1;
}

/*
 * Verify typed open encoding and safe rejection of inconsistent selectors.
 * Source: new generated CER regression. Version/date: 2026-10-11.
 * Inputs: none; fixed Frame and independent X.690 expected bytes.
 * Returns: zero on equality, one on allocation/encoding/rejection failure.
 * Errors: reports a test failure; C has no exceptions. Owner: asn1c maintainers.
 * History: initial typed-open CER coverage. Example: invoked by check-CER.sh.
 */
int main(void) {
    Frame_t frame = {0};
    RetagInteger_t integer = 128;
    unsigned char bytes[32];
    static const unsigned char integer_expected[] = {0x04, 0x02, 0x00, 0x80};
    static const unsigned char expected[] = {
        0x30, 0x80, 0x80, 0x01, 0x2a, 0xa1, 0x80, 0x30, 0x80,
        0x02, 0x01, 0x07, 0x04, 0x01, 0x5a, 0, 0, 0, 0, 0, 0
    };
    asn_enc_rval_t result;
    int failed = 0; /* state variable: any vector or rejection failed. */

    if(check_deep_integer()) return 1;

    /* A universal override retains native INTEGER storage and sign padding. */
    result = cer_encode_to_buffer(NULL, &asn_DEF_RetagInteger, &integer, bytes, sizeof(bytes));
    failed |= result.encoded != (ssize_t)sizeof(integer_expected)
              || memcmp(bytes, integer_expected, sizeof(integer_expected));

    /* Populate the generated selected-CHOICE storage and compare canonical bytes. */
    frame.msgId = 42;
    frame.value.present = value_PR_Packet;
    frame.value.choice.Packet.count = 7;
    if(OCTET_STRING_fromBuf(&frame.value.choice.Packet.data, "Z", 1)) return 1;
    result = cer_encode_to_buffer(NULL, &asn_DEF_Frame, &frame, bytes, sizeof(bytes));
    failed |= result.encoded != (ssize_t)sizeof(expected) || memcmp(bytes, expected, sizeof(expected));

    /* An unknown selector must fail without interpreting an unrelated layout. */
    frame.msgId = 99;
    result = cer_encode_to_buffer(NULL, &asn_DEF_Frame, &frame, bytes, sizeof(bytes));
    if(result.encoded != -1 || errno != ENOENT) failed = 1;
    frame.msgId = 42;
    frame.value.present = 0;
    result = cer_encode_to_buffer(NULL, &asn_DEF_Frame, &frame, bytes, sizeof(bytes));
    if(result.encoded != -1) failed = 1;

    /* Restore ownership metadata so generated cleanup releases the packet bytes. */
    frame.value.present = value_PR_Packet;
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Frame, &frame);
    if(failed) fprintf(stderr, "FAIL: selected open-type CER vector/rejection\n");
    return failed ? 1 : 0;
}
C
"${CC:-cc}" -I"$test_directory/enabled" "$test_directory/open.c" \
    "$test_directory/enabled/libasncodec.a" -lm -o "$test_directory/open-test"
"$test_directory/open-test" > "$test_directory/deep.actual"
cmp "$test_directory/deep.expected" "$test_directory/deep.actual"

# Every generated structural vector must also decode through the CER selector.
for decode_case in choice mixed triple tagged tagged-long bag tchoice nchoice deep \
    roctets rbits rbits-long rutf8 visible-long bmp-long; do
    case "$decode_case" in
        choice) decode_type=ChoiceSet ;;
        mixed) decode_type=MixedSet ;;
        triple) decode_type=Triple ;;
        tagged|tagged-long) decode_type=Tagged ;;
        bag) decode_type=Bag ;;
        tchoice) decode_type=TaggedChoice ;;
        nchoice) decode_type=NestedChoice ;;
        deep) decode_type=DeepInteger ;;
        roctets) decode_type=RetagOctets ;;
        rbits|rbits-long) decode_type=RetagBits ;;
        rutf8) decode_type=RetagUTF8 ;;
        visible-long) decode_type=LongVisible ;;
        bmp-long) decode_type=LongBMP ;;
    esac
    "$test_directory/enabled/converter-example" -p "$decode_type" -icer -ocer \
        "$test_directory/$decode_case.actual" > "$test_directory/$decode_case.reencoded"
    cmp "$test_directory/$decode_case.expected" "$test_directory/$decode_case.reencoded"
done

# Disabling the encoder retains CER-compatible input decoding through BER.
printf 'FlagModule DEFINITIONS ::= BEGIN Flag ::= BOOLEAN END\n' > "$test_directory/flag.asn1"
printf '\001\001\377' > "$test_directory/true.bin"
"$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
    -D "$test_directory/disabled" -pdu=Flag -no-gen-CER \
    -no-gen-UPER -no-gen-APER -no-gen-OER -no-gen-JER -no-gen-CBOR \
    "$test_directory/flag.asn1"
"${MAKE:-make}" -C "$test_directory/disabled" -f converter-example.mk \
    CC="${CC:-cc}"
"$test_directory/disabled/converter-example" -icer -oder \
    "$test_directory/true.bin" > "$test_directory/decoded.der"
cmp "$test_directory/true.bin" "$test_directory/decoded.der"
if "$test_directory/disabled/converter-example" -iber -ocer "$test_directory/true.bin" \
    > "$test_directory/rejected.out" 2> "$test_directory/rejected.err"; then
    echo 'FAIL: converter accepted CER output with CER encoding disabled' >&2
    exit 1
fi

# Without BER, generated code still links and rejects both CER directions.
"$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
    -D "$test_directory/no-ber" -pdu=Flag -gen-CER -no-gen-BER \
    -no-gen-UPER -no-gen-APER -no-gen-OER -no-gen-JER -no-gen-CBOR \
    "$test_directory/flag.asn1"
"${MAKE:-make}" -C "$test_directory/no-ber" -f converter-example.mk \
    CC="${CC:-cc}"
for disabled_direction in -icer -ocer; do
    if "$test_directory/no-ber/converter-example" "$disabled_direction" \
        "$test_directory/true.bin" > "$test_directory/no-ber.out" 2> "$test_directory/no-ber.err"; then
        echo "FAIL: converter accepted $disabled_direction with BER disabled" >&2
        exit 1
    fi
done
