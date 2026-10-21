#!/usr/bin/env sh
#
# Purpose: Verify converter-example preserves all PDUs in large and streamed JER.
# Source: Regression for issue #578 and PR #579, with checked-buffer cases.
# Version/date: 2026-10-21.
# Inputs: Generated ASN.1 converter; configured CC, MAKE, top_builddir, top_srcdir.
# Returns/errors: Zero on success; nonzero on generation, build, or decode failure.
# Responsible: asn1c maintainers.
# History: Adds multi-PDU, large-token, pipe, whitespace, and input-overflow checks.
# Example: make check TESTS=check-JER-multi-pdu.sh

set -eu

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-jer-multi-pdu.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
converter="$test_directory/generated/converter-example"

mkdir -p "$test_directory/generated"
cat > "$test_directory/jer-smoke.asn1" <<'ASN1'
JERSmoke DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Record ::= SEQUENCE {
    id INTEGER,
    payload OCTET STRING
}
END
ASN1

"$test_build_root/asn1c/asn1c" -fcompound-names -findirect-choice -gen-JER \
    -no-gen-BER -no-gen-CER -no-gen-CBOR -no-gen-UPER -no-gen-APER \
    -no-gen-OER -no-gen-random-fill -pdu=Record \
    -S "$test_source_root/skeletons" \
    -D "$test_directory/generated" "$test_directory/jer-smoke.asn1" \
    >/dev/null
"${MAKE:-make}" -C "$test_directory/generated" -f converter-example.mk \
    CC="${CC:-cc}" >/dev/null

# A small first PDU exposes the former early return before the large middle PDU.
{
    printf '%s\n' '{"id":1,"payload":"41"}'
    printf '%s' '{"id":2,"payload":"'
    awk 'BEGIN { for(i = 0; i < 5000; i++) printf "41" }'
    printf '%s\n' '" }'
    printf '%s\n' '{"id":3,"payload":"43"}'
    printf '%s\n' '  '
} > "$test_directory/large-multi.jer"
"$converter" -p Record -ijer -oxer "$test_directory/large-multi.jer" \
    > "$test_directory/large-multi.xer"
large_count=$(grep -c '<Record>' "$test_directory/large-multi.xer" || true)
if [ "$large_count" -ne 3 ]; then
    echo "FAIL: large multi-PDU JER produced $large_count records, expected 3" >&2
    exit 1
fi
awk -F'[<>]' '/<id>/{ print $3 }' "$test_directory/large-multi.xer" \
    > "$test_directory/large-multi.ids"
printf '1\n2\n3\n' > "$test_directory/large-multi.expected-ids"
cmp "$test_directory/large-multi.expected-ids" "$test_directory/large-multi.ids"

# Many small records also exceed 8 KiB, without relying on one large token.
awk 'BEGIN { for(i = 1; i <= 400; i++)
    printf "{\"id\":%d,\"payload\":\"41\"}\n", i }' \
    > "$test_directory/many-small.jer"
"$converter" -p Record -ijer -oxer "$test_directory/many-small.jer" \
    > "$test_directory/many-small.xer"
many_count=$(grep -c '<Record>' "$test_directory/many-small.xer" || true)
if [ "$many_count" -ne 400 ]; then
    echo "FAIL: many-small-PDU JER produced $many_count records, expected 400" >&2
    exit 1
fi
awk -F'[<>]' '/<id>/{ print $3 }' "$test_directory/many-small.xer" \
    > "$test_directory/many-small.ids"
awk 'BEGIN { for(i = 1; i <= 400; i++) print i }' \
    > "$test_directory/many-small.expected-ids"
cmp "$test_directory/many-small.expected-ids" "$test_directory/many-small.ids"

# A single token larger than the usual 8 KiB read buffer must still decode.
{
    printf '%s' '{"id":4,"payload":"'
    awk 'BEGIN { for(i = 0; i < 5000; i++) printf "42" }'
    printf '%s\n' '" }'
} > "$test_directory/large-single.jer"
"$converter" -p Record -ijer -oxer "$test_directory/large-single.jer" \
    > "$test_directory/large-single.xer"
single_count=$(grep -c '<Record>' "$test_directory/large-single.xer" || true)
if [ "$single_count" -ne 1 ]; then
    echo "FAIL: large single-PDU JER produced $single_count records, expected 1" >&2
    exit 1
fi
awk -F'[<>]' '/<id>/{ print $3 }' "$test_directory/large-single.xer" \
    > "$test_directory/large-single.ids"
printf '4\n' > "$test_directory/large-single.expected-ids"
cmp "$test_directory/large-single.expected-ids" "$test_directory/large-single.ids"

# Ordinary whitespace separates values and may follow the final value.
printf '\n%s\n \n%s\n\t \n%s\n\n' \
    '{"id":5,"payload":"45"}' \
    '{"id":6,"payload":"46"}' \
    '{"id":7,"payload":"47"}' > "$test_directory/small-multi.jer"
"$converter" -p Record -ijer -oxer "$test_directory/small-multi.jer" \
    > "$test_directory/small-multi.xer"
small_count=$(grep -c '<Record>' "$test_directory/small-multi.xer" || true)
if [ "$small_count" -ne 3 ]; then
    echo "FAIL: small multi-PDU JER produced $small_count records, expected 3" >&2
    exit 1
fi

# A single-PDU option must return only the first record from a multi-PDU stream.
"$converter" -1 -p Record -ijer -oxer "$test_directory/large-multi.jer" \
    > "$test_directory/first-only.xer"
first_only_count=$(grep -c '<Record>' "$test_directory/first-only.xer" || true)
if [ "$first_only_count" -ne 1 ]; then
    echo "FAIL: -1 decoded $first_only_count records, expected 1" >&2
    exit 1
fi
awk -F'[<>]' '/<id>/{ print $3 }' "$test_directory/first-only.xer" \
    > "$test_directory/first-only.ids"
printf '1\n' > "$test_directory/first-only.expected-ids"
cmp "$test_directory/first-only.expected-ids" "$test_directory/first-only.ids"

# Reopening the same input between iterations must reset retained buffer state.
"$converter" -n 2 -p Record -ijer -oxer "$test_directory/small-multi.jer" \
    > "$test_directory/repeated.xer"
repeated_count=$(grep -c '<Record>' "$test_directory/repeated.xer" || true)
if [ "$repeated_count" -ne 6 ]; then
    echo "FAIL: -n 2 decoded $repeated_count records, expected 6" >&2
    exit 1
fi
awk -F'[<>]' '/<id>/{ print $3 }' "$test_directory/repeated.xer" \
    > "$test_directory/repeated.ids"
printf '5\n6\n7\n5\n6\n7\n' > "$test_directory/repeated.expected-ids"
cmp "$test_directory/repeated.expected-ids" "$test_directory/repeated.ids"

# Several files in one invocation must each start with a fresh input buffer.
printf '%s\n' '{"id":10,"payload":"4a"}' > "$test_directory/first-file.jer"
printf '%s\n' '{"id":11,"payload":"4b"}' > "$test_directory/second-file.jer"
"$converter" -p Record -ijer -oxer "$test_directory/first-file.jer" \
    "$test_directory/second-file.jer" > "$test_directory/multiple-files.xer"
awk -F'[<>]' '/<id>/{ print $3 }' "$test_directory/multiple-files.xer" \
    > "$test_directory/multiple-files.ids"
printf '10\n11\n' > "$test_directory/multiple-files.expected-ids"
cmp "$test_directory/multiple-files.expected-ids" "$test_directory/multiple-files.ids"

# Reading from a pipe exercises the nonseekable path with the same large input.
cat "$test_directory/large-multi.jer" \
    | "$converter" -p Record -ijer -oxer - > "$test_directory/pipe.xer"
pipe_count=$(grep -c '<Record>' "$test_directory/pipe.xer" || true)
if [ "$pipe_count" -ne 3 ]; then
    echo "FAIL: piped JER produced $pipe_count records, expected 3" >&2
    exit 1
fi

# Read errors must terminate the shared non-JER file loop instead of retrying EOF.
if "$converter" -p Record -ixer "$test_directory" \
    > /dev/null 2> "$test_directory/read-error.err"; then
    echo 'FAIL: directory input was unexpectedly accepted as XER' >&2
    exit 1
fi
if ! grep -q 'Cannot read input:' "$test_directory/read-error.err"; then
    echo 'FAIL: XER read error did not reach the checked fread error path' >&2
    exit 1
fi

# A valid prefix followed by a truncated final PDU must report a decode failure.
printf '%s\n%s' '{"id":8,"payload":"48"}' \
    '{"id":9,"payload":"49"' > "$test_directory/truncated.jer"
if "$converter" -p Record -ijer -oxer "$test_directory/truncated.jer" \
    > "$test_directory/truncated.xer" 2> "$test_directory/truncated.err"; then
    echo 'FAIL: truncated final JER PDU was accepted' >&2
    exit 1
fi

# A truncated first value larger than 8 KiB must not be returned as a structure.
{
    printf '%s' '{"id":12,"payload":"'
    awk 'BEGIN { for(i = 0; i < 5000; i++) printf "4c" }'
    printf '%s' '"'
} > "$test_directory/large-truncated.jer"
if "$converter" -p Record -ijer -oxer "$test_directory/large-truncated.jer" \
    > "$test_directory/large-truncated.xer" \
    2> "$test_directory/large-truncated.err"; then
    echo 'FAIL: truncated large JER PDU was accepted' >&2
    exit 1
fi
if [ -s "$test_directory/large-truncated.xer" ]; then
    echo 'FAIL: truncated large JER PDU produced output' >&2
    exit 1
fi

# Malformed -b text and out-of-range values must fail before file decoding.
if "$converter" -b 999999999999999999999999 -p Record -ijer \
    "$test_directory/large-single.jer" >/dev/null 2>&1; then
    echo 'FAIL: out-of-range -b argument was accepted' >&2
    exit 1
fi

# Include the converter in this translation unit to exercise static growth logic.
cat > "$test_directory/generated/check_buffer_growth.c" <<'C'
/*
 * Purpose: Verify checked append arithmetic rejects overflowing buffer states.
 * Source: converter-example.c helper regression for JER input buffering.
 * Version/date: 2026-10-21.
 * Parameters: None.
 * Returns/errors: Zero if overflow is rejected without state mutation.
 * Responsible: asn1c maintainers.
 * History: Added with the JER multi-PDU smoke test on 2026-10-21.
 * Example: Built and run by check-JER-multi-pdu.sh.
 */
#define main converter_example_entry
#include "converter-example.c"
#undef main

int
main(void) {
    static const char byte = 'x';

    DynamicBuffer.data = 0;
    DynamicBuffer.offset = SIZE_MAX;
    DynamicBuffer.length = 1;
    DynamicBuffer.allocated = 0;
    errno = 0;
    if(add_bytes_to_buffer(&byte, 1) == 0 || errno != EOVERFLOW
       || DynamicBuffer.data != 0 || DynamicBuffer.offset != SIZE_MAX
       || DynamicBuffer.length != 1 || DynamicBuffer.allocated != 0) {
        fprintf(stderr, "FAIL: offset overflow was not rejected safely\n");
        return 1;
    }

    DynamicBuffer.offset = 0;
    DynamicBuffer.length = SIZE_MAX;
    errno = 0;
    if(add_bytes_to_buffer(&byte, 1) == 0 || errno != EOVERFLOW
       || DynamicBuffer.data != 0 || DynamicBuffer.offset != 0
       || DynamicBuffer.length != SIZE_MAX || DynamicBuffer.allocated != 0) {
        fprintf(stderr, "FAIL: length overflow was not rejected safely\n");
        return 1;
    }

    DynamicBuffer.data = 0;
    DynamicBuffer.offset = 0;
    DynamicBuffer.length = 0;
    DynamicBuffer.allocated = 0;
    if(add_bytes_to_buffer("ab", 2) != 0
       || add_bytes_to_buffer("cd", 2) != 0
       || DynamicBuffer.length != 4
       || memcmp(DynamicBuffer.data, "abcd", 4) != 0) {
        fprintf(stderr, "FAIL: buffer append or doubling failed\n");
        return 1;
    }

    DynamicBuffer.offset = 2;
    DynamicBuffer.length = 2;
    if(add_bytes_to_buffer("ef", 2) != 0
       || DynamicBuffer.offset != 0
       || DynamicBuffer.length != 4
       || memcmp(DynamicBuffer.data, "cdef", 4) != 0) {
        fprintf(stderr, "FAIL: buffer compaction failed\n");
        return 1;
    }
    if(add_bytes_to_buffer("ghij", 4) != 0
       || DynamicBuffer.length != 8
       || memcmp(DynamicBuffer.data, "cdefghij", 8) != 0) {
        fprintf(stderr, "FAIL: buffer growth after compaction failed\n");
        return 1;
    }

    errno = 0;
    if(add_bytes_to_buffer(0, 1) == 0 || errno != EINVAL) {
        fprintf(stderr, "FAIL: null append data was not rejected\n");
        return 1;
    }
    errno = 0;
    if(read_jer_input(0, "test", DynamicBuffer.data, 1) == 0
       || errno != EINVAL) {
        fprintf(stderr, "FAIL: null JER stream was not rejected\n");
        return 1;
    }
    errno = 0;
    if(read_jer_input(stdin, "test", DynamicBuffer.data, 0) == 0
       || errno != EINVAL) {
        fprintf(stderr, "FAIL: zero-sized JER scratch buffer was accepted\n");
        return 1;
    }

    {
        void *bad_structure = 0;
        asn_dec_rval_t bad_result = { RC_OK, 2 };

        errno = 0;
        if(retain_and_advance("test", &asn_DEF_Record, &bad_structure,
                              (uint8_t *)&byte, 1, 1, &bad_result) == 0
           || errno != EINVAL || bad_structure != 0) {
            fprintf(stderr, "FAIL: over-consumption was not rejected safely\n");
            return 1;
        }
    }

    return 0;
}
C
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:-} -DPDU=Record \
    -I"$test_directory/generated" \
    -o "$test_directory/generated/check_buffer_growth" \
    "$test_directory/generated/check_buffer_growth.c" \
    "$test_directory/generated/libasncodec.a" -lm
"$test_directory/generated/check_buffer_growth"

echo "JER multi-PDU converter smoke test passed"
