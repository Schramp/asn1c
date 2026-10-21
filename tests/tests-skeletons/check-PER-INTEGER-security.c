/* Security regressions for PR #576 and its INTEGER arithmetic follow-ups.
 * Source/version: local security review, 2026-10-20.
 * Responsible party: asn1c maintainers. Run with make check.
 */
#include <assert.h>
#include <string.h>
#include <INTEGER.h>
#include <NativeInteger.h>
#include <aper_encoder.h>
#include <aper_decoder.h>
#include <uper_encoder.h>
#include <uper_decoder.h>

/* Include the changed implementation so the test suite's sanitizers cover it. */
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <INTEGER_uper.c>
#include <per_support.c>
#include <aper_support.c>
#include <uper_support.c>

/*
 * Purpose: decode with the selected PER flavor and descriptor's storage type.
 * Source/version: security regression harness, 2026-10-20.
 * Inputs: td, type descriptor; target, allocated result; wire/size, input bytes;
 * aligned, selects APER. Returns: decoder status. Exceptions: none.
 * Responsible party: asn1c maintainers. History: initial regression coverage.
 * Example: decode_value(&td, &value, wire, sizeof(wire), 1).
 */
static asn_dec_rval_t
decode_value(const asn_TYPE_descriptor_t *td, void **target,
             const uint8_t *wire, size_t size, int aligned) {
    if(aligned) return aper_decode_complete(0, td, target, wire, size);
    return uper_decode_complete(0, td, target, wire, size);
}

/*
 * Purpose: round-trip unsigned boundaries and verify independent wire fixtures.
 * Source/version: security regression harness, 2026-10-20.
 * Inputs: lb/ub, unsigned bounds; bits, range width; value, original number;
 * aligned, selects APER. Returns: none. Exceptions: failed assertions abort.
 * Responsible party: asn1c maintainers. History: covers signed metadata slots.
 * Example: check_unsigned_case(0, UINTMAX_MAX, 64, 32, 0).
 */
static void
check_unsigned_case(uintmax_t lb, uintmax_t ub, int bits,
                    uintmax_t value, int aligned) {
    asn_per_constraints_t constraints = {
        {APC_CONSTRAINED, 0, -1, 0, 0},
        {APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};
    asn_INTEGER_specifics_t specifics = {0};
    asn_TYPE_descriptor_t td = asn_DEF_INTEGER;
    INTEGER_t original = {0};
    INTEGER_t *decoded = 0;
    uint8_t wire[32] = {0};
    uintmax_t recovered = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t size;
    size_t prefix;

    /* Reproduce the compiler's unsigned bounds in signed metadata fields. */
    constraints.value.lower_bound = (intmax_t)lb;
    constraints.value.upper_bound = (intmax_t)ub;
    constraints.value.range_bits = bits;
    specifics.field_unsigned = 1;
    td.specifics = &specifics;
    td.encoding_constraints.per_constraints = &constraints;

    /* Compare decoded values, including the unsigned maximum and high bounds. */
    assert(asn_umax2INTEGER(&original, value) == 0);
    encoded = aligned
        ? aper_encode_to_buffer(&td, 0, &original, wire, sizeof(wire))
        : uper_encode_to_buffer(&td, 0, &original, wire, sizeof(wire));
    assert(encoded.encoded >= 0);
    size = (size_t)(encoded.encoded + 7) / 8;
    result = decode_value(&td, (void **)&decoded, wire, size, aligned);
    assert(result.code == RC_OK);
    assert(asn_INTEGER2umax(decoded, &recovered) == 0);
    assert(recovered == value);

    /* A full-width maximum consumes every determinant/payload octet. */
    if(lb == 0 && ub == UINTMAX_MAX && value == UINTMAX_MAX) {
        for(prefix = 0; prefix < size; prefix++) {
            INTEGER_t *partial = 0;
            result = decode_value(&td, (void **)&partial, wire, prefix, aligned);
            assert(result.code != RC_OK);
            ASN_STRUCT_FREE(td, partial);
        }
    }

    /* Independent fixtures catch matching bugs in encoder and decoder offsets. */
    if(lb == 0 && ub == UINTMAX_MAX && value == 32) {
        if(aligned) {
            static const uint8_t expected[] = {0, 32};
            assert(size == sizeof(expected));
            assert(memcmp(wire, expected, sizeof(expected)) == 0);
        } else {
            size_t i;
            assert(size == sizeof(uintmax_t));
            for(i = 0; i + 1 < size; i++) assert(wire[i] == 0);
            assert(wire[size - 1] == 32);
        }
    }
    ASN_STRUCT_RESET(td, &original);
    ASN_STRUCT_FREE(td, decoded);
}

/*
 * Purpose: exercise signed-range encoding at both ends and across zero.
 * Source/version: independent signed-overflow reproduction, 2026-10-20.
 * Inputs: value, signed boundary; aligned, selects APER. Returns: none.
 * Exceptions: failed assertions abort. Responsible party: asn1c maintainers.
 * History: extends existing full-range decode tests to encoding under UBSan.
 * Example: check_signed_case(INTMAX_MIN, 1).
 */
static void
check_signed_case(intmax_t value, int aligned) {
    asn_per_constraints_t constraints = {
        {APC_CONSTRAINED, 8 * sizeof(uintmax_t), -1, INTMAX_MIN, INTMAX_MAX},
        {APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};
    asn_TYPE_descriptor_t td = asn_DEF_INTEGER;
    INTEGER_t original = {0};
    INTEGER_t *decoded = 0;
    uint8_t wire[32] = {0};
    intmax_t recovered = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;

    /* The full signed span must never be calculated in signed arithmetic. */
    td.encoding_constraints.per_constraints = &constraints;
    assert(asn_imax2INTEGER(&original, value) == 0);
    encoded = aligned
        ? aper_encode_to_buffer(&td, 0, &original, wire, sizeof(wire))
        : uper_encode_to_buffer(&td, 0, &original, wire, sizeof(wire));
    assert(encoded.encoded >= 0);
    result = decode_value(&td, (void **)&decoded, wire,
                          (size_t)(encoded.encoded + 7) / 8, aligned);
    assert(result.code == RC_OK);
    assert(asn_INTEGER2imax(decoded, &recovered) == 0);
    assert(recovered == value);
    ASN_STRUCT_RESET(td, &original);
    ASN_STRUCT_FREE(td, decoded);
}

/*
 * Purpose: keep large zero-bound INTEGER buffers while rejecting native overflow.
 * Source/version: independent 2^64 decoder reproduction, 2026-10-20.
 * Inputs: aligned, selects APER. Returns: none. Exceptions: assertions abort.
 * Responsible party: asn1c maintainers. History: native checks stay at storage conversion.
 * Example: check_large_offset(1).
 */
static void
check_large_offset(int aligned) {
    const uint8_t wire[] = {9, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t expected[] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    asn_per_constraints_t constraints = {
        {APC_SEMI_CONSTRAINED, -1, -1, 0, 0},
        {APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};
    asn_INTEGER_specifics_t specifics = {0};
    asn_TYPE_descriptor_t td = asn_DEF_INTEGER;
    INTEGER_t *decoded = 0;
    asn_dec_rval_t result;
    int unsigned_spec;
    size_t size;

    /* Generic storage must preserve a valid positive value above uint64_t. */
    td.encoding_constraints.per_constraints = &constraints;
    result = decode_value(&td, (void **)&decoded, wire, sizeof(wire), aligned);
    assert(result.code == RC_OK);
    assert(decoded->size == sizeof(expected));
    assert(memcmp(decoded->buf, expected, sizeof(expected)) == 0);
    ASN_STRUCT_FREE(td, decoded);

    /* Every truncated prefix, including an empty length, must remain rejected. */
    for(size = 0; size < sizeof(wire); size++) {
        decoded = 0;
        result = decode_value(&td, (void **)&decoded, wire, size, aligned);
        assert(result.code != RC_OK);
        ASN_STRUCT_FREE(td, decoded);
    }
    {
        const uint8_t empty[] = {0};
        decoded = 0;
        result = decode_value(&td, (void **)&decoded, empty, sizeof(empty), aligned);
        assert(result.code == RC_FAIL);
        ASN_STRUCT_FREE(td, decoded);
    }

    /* Both signed and unsigned native storage must still reject this value. */
    td.op = &asn_OP_NativeInteger;
    td.specifics = &specifics;
    specifics.field_width = 8;
    for(unsigned_spec = 0; unsigned_spec <= 1; unsigned_spec++) {
        void *native = 0;
        specifics.field_unsigned = unsigned_spec;
        result = decode_value(&td, &native, wire, sizeof(wire), aligned);
        assert(result.code == RC_FAIL);
        ASN_STRUCT_FREE(td, native);
    }
}

/*
 * Purpose: reject malformed API arguments and negative unsigned values safely.
 * Source/version: security regression input-validation coverage, 2026-10-20.
 * Inputs: aligned, selects APER. Returns: none. Exceptions: assertions abort.
 * Responsible party: asn1c maintainers. History: guards entry-point validation.
 * Example: check_invalid_arguments(1).
 */
static void
check_invalid_arguments(int aligned) {
    asn_per_constraints_t constraints = {
        {APC_CONSTRAINED, 8 * sizeof(uintmax_t), -1, 0, (intmax_t)UINTMAX_MAX},
        {APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};
    asn_INTEGER_specifics_t specifics = {0};
    asn_TYPE_descriptor_t td = asn_DEF_INTEGER;
    INTEGER_t invalid = {0, 1};
    INTEGER_t negative = {0};
    asn_per_outp_t output = {0}; /* Encoder bit-position state variable. */
    asn_per_data_t input = {0}; /* Decoder bit-position state variable. */
    void *decoded = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;

    /* The public codec functions must validate pointers before dereferencing them. */
    specifics.field_unsigned = 1;
    td.specifics = &specifics;
    td.encoding_constraints.per_constraints = &constraints;
    if(aligned) {
        result = INTEGER_decode_aper(0, 0, 0, &decoded, &input);
        assert(result.code == RC_FAIL);
        result = INTEGER_decode_aper(0, &td, 0, 0, &input);
        assert(result.code == RC_FAIL);
        result = INTEGER_decode_aper(0, &td, 0, &decoded, 0);
        assert(result.code == RC_FAIL);
        encoded = INTEGER_encode_aper(0, 0, &invalid, &output);
        assert(encoded.encoded == -1);
        encoded = INTEGER_encode_aper(&td, 0, &invalid, 0);
        assert(encoded.encoded == -1);
    } else {
        result = INTEGER_decode_uper(0, 0, 0, &decoded, &input);
        assert(result.code == RC_FAIL);
        result = INTEGER_decode_uper(0, &td, 0, 0, &input);
        assert(result.code == RC_FAIL);
        result = INTEGER_decode_uper(0, &td, 0, &decoded, 0);
        assert(result.code == RC_FAIL);
        encoded = INTEGER_encode_uper(0, 0, &invalid, &output);
        assert(encoded.encoded == -1);
        encoded = INTEGER_encode_uper(&td, 0, &invalid, 0);
        assert(encoded.encoded == -1);
    }

    /* Null contents and negative signed storage must never encode as unsigned. */
    encoded = aligned ? aper_encode_to_buffer(&td, 0, &invalid, 0, 0)
                      : uper_encode_to_buffer(&td, 0, &invalid, 0, 0);
    assert(encoded.encoded == -1);
    assert(asn_imax2INTEGER(&negative, -1) == 0);
    output.buffer = output.tmpspace;
    output.nbits = sizeof(output.tmpspace) * 8;
    encoded = aligned ? INTEGER_encode_aper(&td, 0, &negative, &output)
                      : INTEGER_encode_uper(&td, 0, &negative, &output);
    assert(encoded.encoded == -1);
    ASN_STRUCT_RESET(td, &negative);
}

/*
 * Purpose: exhaust every one-octet input for a high unsigned 101-value range.
 * Source/version: deterministic malformed-input mutation coverage, 2026-10-20.
 * Inputs: aligned, selects APER. Returns: none. Exceptions: assertions abort.
 * Responsible party: asn1c maintainers. History: guards offset overflow/range bypass.
 * Example: check_invalid_offsets(0).
 */
static void
check_invalid_offsets(int aligned) {
    asn_per_constraints_t constraints = {
        {APC_CONSTRAINED, 7, 7, 0, (intmax_t)UINTMAX_MAX},
        {APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};
    asn_INTEGER_specifics_t specifics = {0};
    asn_TYPE_descriptor_t td = asn_DEF_INTEGER;
    unsigned octet;

    /* The top seven bits are the offset; the low bit is ignored PER padding. */
    constraints.value.lower_bound = (intmax_t)(UINTMAX_MAX - 100);
    specifics.field_unsigned = 1;
    td.specifics = &specifics;
    td.encoding_constraints.per_constraints = &constraints;
    for(octet = 0; octet <= 255; octet++) {
        uint8_t wire = (uint8_t)octet;
        INTEGER_t *decoded = 0;
        asn_dec_rval_t result = decode_value(&td, (void **)&decoded, &wire, 1, aligned);
        if((octet >> 1) <= 100) {
            uintmax_t value;
            assert(result.code == RC_OK);
            assert(asn_INTEGER2umax(decoded, &value) == 0);
            assert(value == UINTMAX_MAX - 100 + (octet >> 1));
        } else {
            assert(result.code == RC_FAIL);
        }
        ASN_STRUCT_FREE(td, decoded);
    }
}

/*
 * Purpose: reject malformed helper inputs without modifying the output.
 * Source/version: checked unsigned-range API tests, 2026-10-20.
 * Inputs: none. Returns: none. Exceptions: assertions abort.
 * Responsible party: asn1c maintainers. History: covers null/reversed/overflow cases.
 * Example: check_unsigned_helpers().
 */
static void
check_unsigned_helpers(void) {
    uintmax_t output = 42;

    /* Invalid bounds, offsets and outputs must be rejected before arithmetic. */
    assert(per_unsigned_range_rebase(0, 0, 0, 0) == -1);
    assert(per_unsigned_range_unrebase(0, 0, 0, 0) == -1);
    assert(per_unsigned_range_rebase(5, 6, 4, &output) == -1);
    assert(per_unsigned_range_unrebase(0, 6, 4, &output) == -1);
    assert(per_unsigned_range_rebase(4, 5, 10, &output) == -1);
    assert(per_unsigned_range_rebase(11, 5, 10, &output) == -1);
    assert(per_unsigned_range_unrebase(3, UINTMAX_MAX - 2, UINTMAX_MAX, &output) == -1);
    assert(output == 42);

    /* Full-width ranges are valid even though their inclusive size cannot fit. */
    assert(per_unsigned_range_rebase(UINTMAX_MAX, 0, UINTMAX_MAX, &output) == 0);
    assert(output == UINTMAX_MAX);
    assert(per_unsigned_range_unrebase(output, 0, UINTMAX_MAX, &output) == 0);
    assert(output == UINTMAX_MAX);
}

/*
 * Purpose: execute boundary and malformed-input regressions for both PER flavors.
 * Source/version: security review regression suite, 2026-10-20.
 * Inputs: none. Returns: zero on success. Exceptions: assertions abort.
 * Responsible party: asn1c maintainers. History: initial coverage for three findings.
 * Example: make check TESTS=check-PER-INTEGER-security.
 */
int
main(void) {
    const uintmax_t values[] = {0, 32, INTMAX_MAX, (uintmax_t)INTMAX_MAX + 1, UINTMAX_MAX};
    const intmax_t signed_values[] = {INTMAX_MIN, -1, 0, INTMAX_MAX};
    int aligned;
    size_t i;

    /* Test signed/unsigned extrema and unsigned lower bounds above INTMAX_MAX. */
    check_unsigned_helpers();
    for(aligned = 0; aligned <= 1; aligned++) {
        for(i = 0; i < sizeof(values) / sizeof(values[0]); i++)
            check_unsigned_case(0, UINTMAX_MAX, 8 * sizeof(uintmax_t), values[i], aligned);
        for(i = 0; i < sizeof(signed_values) / sizeof(signed_values[0]); i++)
            check_signed_case(signed_values[i], aligned);
        check_unsigned_case((uintmax_t)INTMAX_MAX + 1, UINTMAX_MAX,
                            8 * sizeof(uintmax_t) - 1, UINTMAX_MAX, aligned);
        check_unsigned_case(UINTMAX_MAX - 255, UINTMAX_MAX, 8, UINTMAX_MAX, aligned);
        check_unsigned_case(UINTMAX_MAX - 100, UINTMAX_MAX, 7, UINTMAX_MAX - 32, aligned);
        check_large_offset(aligned);
        check_invalid_offsets(aligned);
        check_invalid_arguments(aligned);
    }
    return 0;
}
