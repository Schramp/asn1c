/*
 * Purpose: exercise APER extensible IOC open types through generated code.
 * Original source: issue #586 regression requirements and ASN.1 vector.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none for the test driver; LLVMFuzzerTestOneInput accepts one
 *             bounded arbitrary APER input when ISSUE586_FUZZ is defined.
 * Returns: zero when all regression assertions pass; nonzero on test failure.
 * Errors: allocation, encoding, decoding, or semantic mismatches fail tests;
 *         there are no C++ exceptions.
 * Responsible party: asn1c maintainers.
 * History: added issue #586 known/unknown, framing, and mutation regressions.
 * Example: compile against generated code and libasncodec.a, then run.
 */

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ANY.h"
#include "EmptyField.h"
#include "Field.h"
#include "Message.h"
#include "OptionalField.h"
#include "Placeholder.h"
#include "PlaceholderSender.h"
#include "SealedField.h"
#include "OCTET_STRING.h"
#include "aper_decoder.h"
#include "aper_encoder.h"
#include "constr_TYPE.h"

_Static_assert(Field__value_PR_INTEGER_0_255_ == 1,
               "known IOC alternative index must remain 1");
_Static_assert(Field__value_PR_asn1cUnknown == 2,
               "opaque IOC alternative must be appended after known values");
_Static_assert(EmptyField__value_PR_asn1cUnknown == 1,
               "empty extensible object sets still need an opaque alternative");
_Static_assert(OptionalField__value_PR_INTEGER_0_255_ == 1,
               "optional wrapper preserves its known alternative index");
_Static_assert(OptionalField__value_PR_asn1cUnknown == 2,
               "optional wrapper appends the opaque alternative");
_Static_assert(ATF_OPEN_TYPE_UNKNOWN == 0x10,
               "opaque APER table rows use the dedicated 0x10 flag");

#ifdef ISSUE586_FUZZ

/*
 * Purpose: provide a bounded libFuzzer entry point for generated Field APER.
 * Original source: issue #586 regression harness.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: data/size are one arbitrary encoded Field input, capped at 256 KiB.
 * Returns: zero after safely decoding and checking any opaque round trip.
 * Errors: decoder errors are ordinary inputs; allocation failures return zero.
 * Responsible party: asn1c maintainers.
 * History: added as a reusable sanitizer/libFuzzer target.
 * Example: clang -DISSUE586_FUZZ -fsanitize=fuzzer,address,undefined ...
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Field_t *decoded = NULL;
    Field_t *roundtrip = NULL;
    uint8_t *encoded = NULL;
    asn_dec_rval_t dr;
    asn_enc_rval_t er;
    size_t capacity;

    /* A hard input ceiling bounds decoder and round-trip allocation work. */
    if(size > 262144) {
        return 0;
    }
    dr = aper_decode_complete(NULL, &asn_DEF_Field, (void **)&decoded,
                              data, size);
    if(dr.code != RC_OK || !decoded) {
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Field, decoded);
        return 0;
    }

    /* Preserve semantic opaque bytes across one encode/decode cycle. */
    if(decoded->value.present == Field__value_PR_asn1cUnknown) {
        capacity = size + 64;
        encoded = (uint8_t *)malloc(capacity);
        if(!encoded) {
            ASN_STRUCT_FREE(asn_DEF_Field, decoded);
            return 0;
        }
        er = aper_encode_to_buffer(&asn_DEF_Field, NULL, decoded, encoded,
                                   capacity);
        assert(er.encoded >= 0);
        if(er.encoded < 0) goto cleanup;

        dr = aper_decode_complete(NULL, &asn_DEF_Field, (void **)&roundtrip,
                                  encoded, (size_t)(er.encoded + 7) / 8);
        assert(dr.code == RC_OK && roundtrip != NULL);
        if(dr.code != RC_OK || !roundtrip) goto cleanup;

        /* Re-decoding must reproduce the complete semantic Field value. */
        assert(asn_DEF_Field.op->compare_struct(&asn_DEF_Field, decoded,
                                                roundtrip) == 0);
        assert(roundtrip->id == decoded->id);
        assert(roundtrip->value.present == Field__value_PR_asn1cUnknown);
        assert(roundtrip->value.choice.asn1cUnknown.size
               == decoded->value.choice.asn1cUnknown.size);
        assert(roundtrip->value.choice.asn1cUnknown.size == 0
               || (roundtrip->value.choice.asn1cUnknown.buf != NULL
                   && decoded->value.choice.asn1cUnknown.buf != NULL
                   && memcmp(roundtrip->value.choice.asn1cUnknown.buf,
                             decoded->value.choice.asn1cUnknown.buf,
                             (size_t)decoded->value.choice.asn1cUnknown.size)
                       == 0));
    }

cleanup:
    free(encoded);
    if(roundtrip) ASN_STRUCT_FREE(asn_DEF_Field, roundtrip);
    ASN_STRUCT_FREE(asn_DEF_Field, decoded);
    return 0;
}

#else

#ifndef ASN_DISABLE_PRINT_SUPPORT
/* Capture bounded print callback bytes for exact ANY output assertions. */
typedef struct issue586_print_capture_s {
    char text[8]; /* state variable: collected print output bytes. */
    size_t length; /* state variable: number of collected output bytes. */
    int overflow; /* state variable: callback rejected output past capacity. */
} issue586_print_capture_t;

/*
 * Purpose: collect print callback bytes without allowing test-buffer overflow.
 * Original source: issue #586 ANY print regression harness.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: buffer and size contain output; key points to bounded capture.
 * Returns: zero after copying, -1 for invalid input or insufficient capacity.
 * Errors: oversized output is recorded and rejected before copying.
 * Responsible party: asn1c maintainers.
 * History: added to verify ANY print uses its signed size field.
 * Example: passed to asn_DEF_ANY.op->print_struct().
 */
static int
capture_print_bytes(const void *buffer, size_t size, void *key) {
    issue586_print_capture_t *capture = (issue586_print_capture_t *)key;

    if(!capture || (!buffer && size)) return -1;
    if(capture->length > sizeof(capture->text)
       || size > sizeof(capture->text) - capture->length) {
        capture->overflow = 1;
        return -1;
    }
    if(size) memcpy(capture->text + capture->length, buffer, size);
    capture->length += size;
    return 0;
}
#endif /* !ASN_DISABLE_PRINT_SUPPORT */

/*
 * Purpose: report one failed regression assertion and return its failure count.
 * Original source: issue #586 regression harness.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: condition is the expected result; message identifies the check.
 * Returns: zero on success, one after printing a failure diagnostic.
 * Errors: writes the diagnostic to stderr; no exceptions are generated.
 * Responsible party: asn1c maintainers.
 * History: added with the issue #586 integration tests.
 * Example: failures += expect(decoded != NULL, "decoder allocated a value").
 */
static int
expect(int condition, const char *message) {
    if(condition) {
        return 0;
    }
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

/*
 * Purpose: decode one complete APER Field and return its allocated result.
 * Original source: issue #586 regression harness.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: wire/wire_size describe input; decoded receives a partial or full
 *             result and must be freed by the caller when non-null.
 * Returns: zero only for RC_OK; one for incomplete or invalid input.
 * Errors: leaves a decoder-allocated partial result for caller cleanup.
 * Responsible party: asn1c maintainers.
 * History: added for known/unknown vectors and malformed-input checks.
 * Example: decode_field(vector, sizeof(vector), &field).
 */
static int
decode_field(const uint8_t *wire, size_t wire_size, Field_t **decoded) {
    asn_dec_rval_t result;

    *decoded = NULL;
    result = aper_decode_complete(NULL, &asn_DEF_Field, (void **)decoded,
                                  wire, wire_size);
    return result.code == RC_OK && *decoded ? 0 : 1;
}

/*
 * Purpose: encode a Field into a caller-owned dynamically sized APER buffer.
 * Original source: issue #586 regression harness.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: value is the Field; wire/wire_size receive allocated bytes.
 * Returns: zero on success; one for allocation or encoding failure.
 * Errors: output pointers are reset before work and remain null/zero on failure.
 * Responsible party: asn1c maintainers.
 * History: added for exact wire and semantic round-trip checks.
 * Example: encode_field(decoded, &wire, &wire_size).
 */
static int
encode_field(const Field_t *value, uint8_t **wire, size_t *wire_size) {
    const size_t capacity = 65536 + 64;
    asn_enc_rval_t result;

    *wire = (uint8_t *)malloc(capacity);
    *wire_size = 0;
    if(!*wire) {
        return 1;
    }
    result = aper_encode_to_buffer(&asn_DEF_Field, NULL, value, *wire,
                                   capacity);
    if(result.encoded < 0) {
        free(*wire);
        *wire = NULL;
        return 1;
    }
    *wire_size = (size_t)(result.encoded + 7) / 8;
    return 0;
}

/*
 * Purpose: verify APER open-type length fragments and their final determinant.
 * Original source: issue #586 regression harness.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: wire/wire_size are the encoded Field; payload/size are expected
 *             opaque contents octets, without an open-type length determinant.
 * Returns: zero when framing and contents match; one otherwise.
 * Errors: malformed or noncanonical framing returns one without reading past
 *         the supplied wire buffer.
 * Responsible party: asn1c maintainers.
 * History: added to check 16 KiB PER fragments and exact zero terminators.
 * Example: check_fragment_framing(wire, wire_size, payload, 16384).
 */
static int
check_fragment_framing(const uint8_t *wire, size_t wire_size,
                       const uint8_t *payload, size_t payload_size) {
    size_t offset = 2; /* state variable: next encoded length/data byte. */
    size_t copied = 0; /* state variable: opaque octets already checked. */
    int saw_final_determinant = 0; /* state variable: final length was present. */

    if(wire_size < 3 || wire[0] != 0 || wire[1] != 2) {
        return 1;
    }
    while(offset < wire_size) {
        uint8_t determinant = wire[offset++];
        size_t chunk_size;

        if((determinant & 0xc0) == 0xc0) {
            size_t fragment_count = (size_t)(determinant & 0x3f);
            size_t remaining_fragments = (payload_size - copied) / 16384;

            /* X.691 permits greedy fragment multipliers from one through four. */
            if(remaining_fragments > 4) remaining_fragments = 4;
            if(fragment_count == 0 || fragment_count > 4
               || fragment_count != remaining_fragments) {
                return 1;
            }
            chunk_size = fragment_count * 16384;
            if(wire_size - offset < chunk_size) {
                return 1;
            }
        } else if((determinant & 0x80) == 0) {
            chunk_size = determinant;
            saw_final_determinant = 1;
        } else {
            if(offset >= wire_size) {
                return 1;
            }
            chunk_size = ((size_t)(determinant & 0x3f) << 8) | wire[offset++];
            saw_final_determinant = 1;
        }

        if(chunk_size != payload_size - copied
           && chunk_size != 16384) {
            return 1;
        }
        if(chunk_size > payload_size - copied
           || chunk_size > wire_size - offset
           || (chunk_size && memcmp(wire + offset, payload + copied,
                                    chunk_size) != 0)) {
            return 1;
        }
        offset += chunk_size;
        copied += chunk_size;
        if((determinant & 0xc0) != 0xc0) {
            break;
        }
    }

    /* A final determinant, including zero after exact fragments, is mandatory. */
    return saw_final_determinant && copied == payload_size
           && offset == wire_size ? 0 : 1;
}

/*
 * Purpose: validate the published known and unknown OpenV1 byte vectors.
 * Original source: issue #586 vectors 00010107 and 00020180.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; the routine contributes failures to the returned count.
 * Returns: number of failed checks.
 * Errors: reports decode, encode, copy, compare, or reset mismatches.
 * Responsible party: asn1c maintainers.
 * History: added known choice stability and opaque ownership checks.
 * Example: main adds test_vectors() to its overall failure count.
 */
static int
test_vectors(void) {
    static const uint8_t known_wire[] = {0x00, 0x01, 0x01, 0x07};
    static const uint8_t unknown_wire[] = {0x00, 0x02, 0x01, 0x80};
    Field_t *decoded = NULL;
    Field_t *copy = NULL;
    uint8_t *encoded = NULL;
    size_t encoded_size = 0;
    int failures = 0;

    failures += expect(decode_field(known_wire, sizeof(known_wire), &decoded)
                       == 0, "known vector decodes");
    if(decoded) {
        failures += expect(decoded->id == 1
                           && decoded->value.present
                               == Field__value_PR_INTEGER_0_255_
                           && decoded->value.choice.INTEGER_0_255_ == 7,
                           "known value and choice index are preserved");
        failures += expect(encode_field(decoded, &encoded, &encoded_size) == 0,
                           "known vector re-encodes");
        if(encoded) {
            failures += expect(encoded_size == sizeof(known_wire)
                               && memcmp(encoded, known_wire,
                                         sizeof(known_wire)) == 0,
                               "known vector bytes remain stable");
            free(encoded);
            encoded = NULL;
        }
        ASN_STRUCT_FREE(asn_DEF_Field, decoded);
        decoded = NULL;
    }

    failures += expect(decode_field(unknown_wire, sizeof(unknown_wire),
                                    &decoded) == 0,
                       "unknown vector decodes");
    if(decoded) {
        int opaque_ok = decoded->id == 2
                        && decoded->value.present
                            == Field__value_PR_asn1cUnknown
                        && decoded->value.choice.asn1cUnknown.size == 1
                        && decoded->value.choice.asn1cUnknown.buf != NULL
                        && decoded->value.choice.asn1cUnknown.buf[0] == 0x80;

        failures += expect(opaque_ok,
                           "unknown contents omit the outer length determinant");
        if(opaque_ok) {
            failures += expect(asn_copy(&asn_DEF_Field, (void **)&copy,
                                        decoded) == 0,
                               "opaque Field deep copy succeeds");
        }
        if(copy) {
            failures += expect(asn_DEF_Field.op->compare_struct(
                                   &asn_DEF_Field, decoded, copy) == 0,
                               "opaque Field copy compares equal");
            decoded->value.choice.asn1cUnknown.buf[0] = 0x81;
            failures += expect(copy->value.choice.asn1cUnknown.buf != NULL
                               && copy->value.choice.asn1cUnknown.buf[0] == 0x80,
                               "opaque copy owns independent contents");
            ASN_STRUCT_RESET(asn_DEF_Field, decoded);
            failures += expect(decoded->value.present == Field__value_PR_NOTHING,
                               "reset clears the selected opaque alternative");
        }
        if(copy) ASN_STRUCT_FREE(asn_DEF_Field, copy);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Field, decoded);
    }
    return failures;
}

/*
 * Purpose: exercise opaque payload sizes around short, long, and fragment bounds.
 * Original source: issue #586 boundary requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: payload_size is one tested contents-octet count, up to 65536.
 * Returns: number of failed allocation, codec, framing, or content assertions.
 * Errors: all allocated structures and buffers are released on every path.
 * Responsible party: asn1c maintainers.
 * History: added exact 16 KiB fragment and terminator coverage.
 * Example: test_payload_size(16384) checks C1 plus its zero terminator.
 */
static int
test_payload_size(size_t payload_size) {
    Field_t source = {0};
    Field_t *decoded = NULL;
    uint8_t *payload = payload_size ? (uint8_t *)malloc(payload_size) : NULL;
    uint8_t *wire = NULL;
    uint8_t *reencoded = NULL;
    size_t wire_size = 0;
    size_t reencoded_size = 0;
    size_t index;
    int failures = 0;

    if(payload_size && !payload) {
        return expect(0, "payload allocation succeeds");
    }
    for(index = 0; index < payload_size; index++) {
        payload[index] = (uint8_t)(index * 37u + 11u);
    }

    /* The generated ANY owns the test contents for the rest of this function. */
    source.id = 2;
    source.value.present = Field__value_PR_asn1cUnknown;
    source.value.choice.asn1cUnknown.buf = payload;
    source.value.choice.asn1cUnknown.size = (int)payload_size;
    failures += expect(encode_field(&source, &wire, &wire_size) == 0,
                       "opaque payload encodes");
    if(wire) {
        char framing_message[96];
        int framing_ok = check_fragment_framing(wire, wire_size, payload,
                                                payload_size) == 0;

        snprintf(framing_message, sizeof(framing_message),
                 "APER framing is exact for payload size %zu", payload_size);
        failures += expect(framing_ok, framing_message);
        failures += expect(decode_field(wire, wire_size, &decoded) == 0,
                           "opaque payload decodes");
    }
    if(decoded) {
        failures += expect(decoded->value.present
                               == Field__value_PR_asn1cUnknown
                           && decoded->value.choice.asn1cUnknown.size
                               == (int)payload_size
                           && (payload_size == 0
                               || decoded->value.choice.asn1cUnknown.buf != NULL)
                           && (payload_size == 0
                               || memcmp(decoded->value.choice.asn1cUnknown.buf,
                                         payload, payload_size) == 0),
                           "decoded opaque contents preserve every octet");
        failures += expect(encode_field(decoded, &reencoded,
                                        &reencoded_size) == 0,
                           "decoded opaque contents re-encode");
        if(reencoded) {
            failures += expect(wire_size == reencoded_size
                               && memcmp(wire, reencoded, wire_size) == 0,
                               "canonical open-type framing is stable");
        }
    }

    free(wire);
    free(reencoded);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Field, decoded);
    ASN_STRUCT_RESET(asn_DEF_Field, &source);
    return failures;
}

/*
 * Purpose: reject invalid ANY storage and accept a valid empty opaque value.
 * Original source: issue #586 input-validation requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; constructs negative size and missing-buffer values.
 * Returns: number of invalid encodes accepted or valid empty encode rejected.
 * Errors: encoding failures are expected for malformed in-memory values.
 * Responsible party: asn1c maintainers.
 * History: added checks for negative size and nonempty NULL content.
 * Example: main adds test_opaque_validation() to its overall failure count.
 */
static int
test_opaque_validation(void) {
    Field_t negative_size = {0};
    Field_t missing_buffer = {0};
    Field_t empty_value = {0};
    uint8_t byte = 0x80;
    uint8_t wire[32];
    asn_enc_rval_t result;
    int failures = 0;

    negative_size.id = 2;
    negative_size.value.present = Field__value_PR_asn1cUnknown;
    negative_size.value.choice.asn1cUnknown.buf = &byte;
    negative_size.value.choice.asn1cUnknown.size = -1;
    result = aper_encode_to_buffer(&asn_DEF_Field, NULL, &negative_size,
                                   wire, sizeof(wire));
    failures += expect(result.encoded < 0,
                       "negative opaque size fails encoding");

    missing_buffer.id = 2;
    missing_buffer.value.present = Field__value_PR_asn1cUnknown;
    missing_buffer.value.choice.asn1cUnknown.buf = NULL;
    missing_buffer.value.choice.asn1cUnknown.size = 1;
    result = aper_encode_to_buffer(&asn_DEF_Field, NULL, &missing_buffer,
                                   wire, sizeof(wire));
    failures += expect(result.encoded < 0,
                       "nonempty opaque value with NULL buffer fails encoding");

    empty_value.id = 2;
    empty_value.value.present = Field__value_PR_asn1cUnknown;
    empty_value.value.choice.asn1cUnknown.buf = NULL;
    empty_value.value.choice.asn1cUnknown.size = 0;
    result = aper_encode_to_buffer(&asn_DEF_Field, NULL, &empty_value,
                                   wire, sizeof(wire));
    failures += expect(result.encoded >= 0,
                       "empty opaque value with NULL buffer encodes");
    return failures;
}

#ifndef ASN_DISABLE_PRINT_SUPPORT
/*
 * Purpose: validate ANY printing across signed size and padding edge cases.
 * Original source: issue #586 ANY_t versus OCTET_STRING_t layout regression.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; the value's inter-member padding is deliberately poisoned.
 * Returns: number of print text, error, empty-output, or overflow failures.
 * Errors: test storage is heap-owned separately from the poisoned ANY value.
 * Responsible party: asn1c maintainers.
 * History: added for portable printing of ANY_t opaque alternatives.
 * Example: main adds test_any_print() to its overall failure count.
 */
static int
test_any_print(void) {
    ANY_t value = {0};
    issue586_print_capture_t capture = {{0}, 0, 0};
    uint8_t *owned_buffer = (uint8_t *)malloc(1);
    size_t padding_start = offsetof(ANY_t, size) + sizeof(value.size);
    size_t padding_end = offsetof(ANY_t, _asn_ctx);
    int result;
    int failures = 0;

    if(!owned_buffer) return expect(0, "ANY print buffer allocation succeeds");
    owned_buffer[0] = 0x80;
    value.buf = owned_buffer;
    value.size = 1;
    if(padding_end > padding_start) {
        memset((char *)&value + padding_start, 0xA5,
               padding_end - padding_start);
    }

    result = asn_DEF_ANY.op->print_struct(&asn_DEF_ANY, &value, 0,
                                          capture_print_bytes, &capture);
    failures += expect(result == 0 && capture.length == 2
                       && memcmp(capture.text, "80", 2) == 0
                       && !capture.overflow,
                       "ANY print emits exactly 80 despite poisoned padding");

    memset(&capture, 0, sizeof(capture));
    value.buf = NULL;
    result = asn_DEF_ANY.op->print_struct(&asn_DEF_ANY, &value, 0,
                                          capture_print_bytes, &capture);
    failures += expect(result == -1 && capture.length == 0
                       && !capture.overflow,
                       "ANY print rejects positive size with no buffer");

    memset(&capture, 0, sizeof(capture));
    value.buf = owned_buffer;
    value.size = -1;
    result = asn_DEF_ANY.op->print_struct(&asn_DEF_ANY, &value, 0,
                                          capture_print_bytes, &capture);
    failures += expect(result == -1 && capture.length == 0
                       && !capture.overflow,
                       "ANY print rejects negative size");

    memset(&capture, 0, sizeof(capture));
    value.buf = NULL;
    value.size = 0;
    result = asn_DEF_ANY.op->print_struct(&asn_DEF_ANY, &value, 0,
                                          capture_print_bytes, &capture);
    failures += expect(result == 0 && capture.length == 0
                       && !capture.overflow,
                       "empty ANY print emits zero bytes");

    free(owned_buffer);
    return failures;
}
#endif /* !ASN_DISABLE_PRINT_SUPPORT */

/*
 * Purpose: copy between known and unknown CHOICE arms in both directions.
 * Original source: issue #586 ownership and copy/reset requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; begins with a known destination and copies opaque then known.
 * Returns: number of copy, arm-selection, contents, or reset failures.
 * Errors: source and destination descriptors are freed after either copy path.
 * Responsible party: asn1c maintainers.
 * History: added to expose stale union ownership across active alternatives.
 * Example: main adds test_cross_arm_copy() to its overall failure count.
 */
static int
test_cross_arm_copy(void) {
    static const uint8_t unknown_wire[] = {0x00, 0x02, 0x01, 0x80};
    Field_t known_source = {0};
    Field_t *unknown_source = NULL;
    Field_t *destination = (Field_t *)calloc(1, sizeof(*destination));
    int failures = 0;

    if(!destination) return expect(0, "copy destination allocation succeeds");
    known_source.id = 1;
    known_source.value.present = Field__value_PR_INTEGER_0_255_;
    known_source.value.choice.INTEGER_0_255_ = 7;
    destination->id = 1;
    destination->value.present = Field__value_PR_INTEGER_0_255_;
    destination->value.choice.INTEGER_0_255_ = 9;

    failures += expect(decode_field(unknown_wire, sizeof(unknown_wire),
                                    &unknown_source) == 0,
                       "cross-arm unknown source decodes");
    if(unknown_source) {
        int copied_unknown = asn_copy(&asn_DEF_Field, (void **)&destination,
                                      unknown_source) == 0;

        failures += expect(copied_unknown,
                           "copy replaces a populated known arm with opaque");
        if(copied_unknown) {
            failures += expect(destination->value.present
                                   == Field__value_PR_asn1cUnknown
                               && destination->value.choice.asn1cUnknown.size == 1
                               && destination->value.choice.asn1cUnknown.buf != NULL
                               && destination->value.choice.asn1cUnknown.buf[0]
                                   == 0x80,
                               "known-to-opaque copy retains contents");
            /* Replacing it again checks cleanup of the previous opaque arm. */
            {
                int copied_known = asn_copy(&asn_DEF_Field,
                                            (void **)&destination,
                                            &known_source) == 0;

                failures += expect(copied_known,
                                   "copy replaces opaque arm with known value");
                if(copied_known) {
                    failures += expect(destination->value.present
                                           == Field__value_PR_INTEGER_0_255_
                                       && destination->value.choice
                                               .INTEGER_0_255_ == 7,
                                       "opaque-to-known copy clears the old arm");
                }
            }
        }
    }

    ASN_STRUCT_RESET(asn_DEF_Field, destination);
    failures += expect(destination->value.present == Field__value_PR_NOTHING,
                       "cross-arm destination resets safely");
    if(unknown_source) ASN_STRUCT_FREE(asn_DEF_Field, unknown_source);
    ASN_STRUCT_FREE(asn_DEF_Field, destination);
    return failures;
}

/*
 * Purpose: reject invalid CHOICE indexes and clear a reused destination for an
 * empty source choice.
 * Original source: issue #586 runtime validation and CHOICE copy requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; the routine constructs empty and out-of-range source values.
 * Returns: number of incorrect copy results or destination-state mismatches.
 * Errors: all heap-backed test structures are released after the copy attempts.
 * Responsible party: asn1c maintainers.
 * History: added after review of malformed in-memory CHOICE handling.
 * Example: main adds test_invalid_choice_copy() to its overall failure count.
 */
static int
test_invalid_choice_copy(void) {
    static const uint8_t unknown_wire[] = {0x00, 0x02, 0x01, 0x80};
    Field_t empty_source = {0};
    Field_t invalid_source = {0};
    Field_t *empty_destination = NULL;
    Field_t *invalid_destination = (Field_t *)calloc(1, sizeof(*invalid_destination));
    int empty_decoded;
    int failures = 0;

    if(!invalid_destination) {
        return expect(0, "invalid-choice destination allocation succeeds");
    }
    empty_decoded = decode_field(unknown_wire, sizeof(unknown_wire),
                                 &empty_destination) == 0;
    failures += expect(empty_decoded,
                       "empty-choice destination starts with an opaque arm");
    if(empty_decoded && empty_destination) {
        empty_source.id = 2;
        failures += expect(asn_copy(&asn_DEF_Field,
                                    (void **)&empty_destination,
                                    &empty_source) == 0,
                           "copy accepts a source with no selected choice");
        failures += expect(empty_destination->value.present
                               == Field__value_PR_NOTHING,
                           "empty-choice copy clears the previous opaque arm");
    }

    invalid_destination->id = 1;
    invalid_destination->value.present = Field__value_PR_INTEGER_0_255_;
    invalid_destination->value.choice.INTEGER_0_255_ = 7;
    invalid_source.id = 2;
    invalid_source.value.present = (Field__value_PR)999;
    failures += expect(asn_copy(&asn_DEF_Field,
                                (void **)&invalid_destination,
                                &invalid_source) == -1,
                       "copy rejects an out-of-range CHOICE index");
    if(empty_destination) ASN_STRUCT_FREE(asn_DEF_Field, empty_destination);
    ASN_STRUCT_FREE(asn_DEF_Field, invalid_destination);
    return failures;
}

/*
 * Purpose: preserve acceptance of a non-empty extension at a NULL placeholder.
 * Original source: issue #586 regression for SEQUENCE extension skipping.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; an OCTET STRING sender schema emits the unknown extension.
 * Returns: number of encode, decode, or root-value preservation failures.
 * Errors: allocated sender and partial receiver values are reset or freed.
 * Responsible party: asn1c maintainers.
 * History: guards the SEQUENCE decoder's NULL-placeholder success path.
 * Example: main adds test_null_extension_placeholder() to its failure count.
 */
static int
test_null_extension_placeholder(void) {
    static const uint8_t payload[] = {0x53, 0xa7};
    PlaceholderSender_t source = {0};
    Placeholder_t *decoded = NULL;
    uint8_t wire[64];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failures = 0;

    source.root = 7;
    source.hole = (OCTET_STRING_t *)calloc(1, sizeof(*source.hole));
    if(!source.hole) {
        return expect(0, "placeholder sender allocation succeeds");
    }
    failures += expect(OCTET_STRING_fromBuf(source.hole,
                                            (const char *)payload,
                                            sizeof(payload)) == 0,
                       "placeholder sender holds non-empty extension bytes");
    encoded = aper_encode_to_buffer(&asn_DEF_PlaceholderSender, NULL,
                                    &source, wire, sizeof(wire));
    failures += expect(encoded.encoded >= 0,
                       "placeholder sender APER encoding succeeds");
    if(encoded.encoded >= 0) {
        size_t wire_size = (size_t)(encoded.encoded + 7) / 8;

        result = aper_decode_complete(NULL, &asn_DEF_Placeholder,
                                      (void **)&decoded, wire, wire_size);
        failures += expect(result.code == RC_OK && decoded != NULL,
                           "NULL-placeholder receiver accepts extension payload");
        if(result.code == RC_OK && decoded) {
            failures += expect(decoded->root == 7,
                               "root member survives skipped extension payload");
        }
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Placeholder, decoded);
    ASN_STRUCT_RESET(asn_DEF_PlaceholderSender, &source);
    return failures;
}

/*
 * Purpose: require malformed and truncated APER open-type envelopes to fail.
 * Original source: issue #586 malformed-length requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; each vector is a deliberately incomplete or invalid envelope.
 * Returns: number of vectors unexpectedly accepted by the decoder.
 * Errors: partial decoder outputs are freed after every attempted decode.
 * Responsible party: asn1c maintainers.
 * History: includes reserved C0/C5 fragment determinants and missing data.
 * Example: main adds test_malformed() to its overall failure count.
 */
static int
test_malformed(void) {
    static const uint8_t truncated_id[] = {0x00};
    static const uint8_t missing_length[] = {0x00, 0x02};
    static const uint8_t missing_contents[] = {0x00, 0x02, 0x02, 0x80};
    static const uint8_t reserved_zero_fragment[] = {0x00, 0x02, 0xc0};
    static const uint8_t reserved_five_fragment[] = {0x00, 0x02, 0xc5};
    static const uint8_t missing_fragment_data[] = {0x00, 0x02, 0xc1};
    /* Each case records malformed bytes and the diagnostic used for rejection. */
    static const struct {
        const uint8_t *wire; /* Input APER bytes for one malformed envelope. */
        size_t size; /* Number of bytes available to the decoder. */
        const char *name; /* Short assertion label for this input. */
    } cases[] = {
        {truncated_id, sizeof(truncated_id), "truncated id"},
        {missing_length, sizeof(missing_length), "missing open-type length"},
        {missing_contents, sizeof(missing_contents), "truncated contents"},
        {reserved_zero_fragment, sizeof(reserved_zero_fragment), "C0 fragment"},
        {reserved_five_fragment, sizeof(reserved_five_fragment), "C5 fragment"},
        {missing_fragment_data, sizeof(missing_fragment_data), "missing fragment"}
    };
    size_t index;
    int failures = 0;

    for(index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        Field_t *decoded = NULL;
        int rejected = decode_field(cases[index].wire, cases[index].size,
                                    &decoded) != 0;
        failures += expect(rejected, cases[index].name);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Field, decoded);
    }
    return failures;
}

/*
 * Purpose: check empty and sealed IOC tables plus mismatched id/choice encoding.
 * Original source: issue #586 extensible-table and correlation requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; uses the fixture's three generated Field variants.
 * Returns: number of failed decode, encode, or representation checks.
 * Errors: partial decoder values and stack-owned opaque bytes are cleaned up.
 * Responsible party: asn1c maintainers.
 * History: covers empty extensible Known and sealed-table rejection.
 * Example: main adds test_table_modes() to its overall failure count.
 */
static int
test_table_modes(void) {
    static const uint8_t unknown_wire[] = {0x00, 0x02, 0x01, 0x80};
    EmptyField_t empty_source = {0};
    EmptyField_t *empty = NULL;
    SealedField_t *sealed = NULL;
    Field_t unknown_choice = {0};
    Field_t known_choice = {0};
    uint8_t opaque_byte = 0x80;
    uint8_t buffer[32];
    asn_enc_rval_t empty_encoded;
    asn_enc_rval_t result;
    int failures = 0;

    /* With no known rows, the IOC selector is null and the opaque arm applies. */
    empty_source.id = 2;
    empty_source.value.present = EmptyField__value_PR_asn1cUnknown;
    empty_source.value.choice.asn1cUnknown.buf = &opaque_byte;
    empty_source.value.choice.asn1cUnknown.size = 1;
    empty_encoded = aper_encode_to_buffer(&asn_DEF_EmptyField, NULL,
                                         &empty_source, buffer, sizeof(buffer));
    failures += expect(empty_encoded.encoded >= 0
                       && (size_t)(empty_encoded.encoded + 7) / 8
                           == sizeof(unknown_wire)
                       && memcmp(buffer, unknown_wire, sizeof(unknown_wire)) == 0,
                       "empty object set null selector encodes opaque data");

    failures += expect(aper_decode_complete(NULL, &asn_DEF_EmptyField,
                                             (void **)&empty, unknown_wire,
                                             sizeof(unknown_wire)).code == RC_OK,
                       "empty extensible object set accepts opaque values");
    if(empty) {
        failures += expect(empty->value.present
                               == EmptyField__value_PR_asn1cUnknown
                           && empty->value.choice.asn1cUnknown.size == 1
                           && empty->value.choice.asn1cUnknown.buf != NULL
                           && empty->value.choice.asn1cUnknown.buf[0] == 0x80,
                           "empty object set retains unknown contents");
        ASN_STRUCT_FREE(asn_DEF_EmptyField, empty);
    }

    failures += expect(aper_decode_complete(NULL, &asn_DEF_SealedField,
                                             (void **)&sealed, unknown_wire,
                                             sizeof(unknown_wire)).code != RC_OK,
                       "sealed table rejects unknown identifiers");
    if(sealed) ASN_STRUCT_FREE(asn_DEF_SealedField, sealed);

    /* A selected opaque alternative must agree with its identifier table row. */
    unknown_choice.id = 1;
    unknown_choice.value.present = Field__value_PR_asn1cUnknown;
    unknown_choice.value.choice.asn1cUnknown.buf = &opaque_byte;
    unknown_choice.value.choice.asn1cUnknown.size = 1;
    result = aper_encode_to_buffer(&asn_DEF_Field, NULL, &unknown_choice,
                                  buffer, sizeof(buffer));
    failures += expect(result.encoded < 0,
                       "unknown alternative cannot encode with known id");

    /* A known alternative must not be used to encode an unknown identifier. */
    known_choice.id = 2;
    known_choice.value.present = Field__value_PR_INTEGER_0_255_;
    known_choice.value.choice.INTEGER_0_255_ = 7;
    result = aper_encode_to_buffer(&asn_DEF_Field, NULL, &known_choice,
                                   buffer, sizeof(buffer));
    failures += expect(result.encoded < 0,
                       "known alternative cannot encode with unknown id");
    return failures;
}

/*
 * Purpose: exercise pointer-backed optional open-type encode, copy, reset, and
 *          truncated-decode cleanup through generated OptionalField metadata.
 * Original source: issue #586 optional-wrapper ATF_POINTER regression.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; uses a three-byte unknown contents value.
 * Returns: number of failed pointer metadata, round-trip, copy, reset, or error
 *          cleanup checks.
 * Errors: partial decoded values are freed after the deliberately truncated read.
 * Responsible party: asn1c maintainers.
 * History: added after verifying OPTIONAL emits ATF_POINTER metadata.
 * Example: main adds test_optional_open_type() to its overall failure count.
 */
static int
test_optional_open_type(void) {
    static const uint8_t opaque[] = {0x31, 0x80, 0x7f};
    OptionalField_t source = {0};
    OptionalField_t *decoded = NULL;
    OptionalField_t *copy = NULL;
    OptionalField_t *truncated = NULL;
    uint8_t wire[64];
    asn_enc_rval_t encoded;
    asn_dec_rval_t decoded_result;
    size_t wire_size = 0;
    int failures = 0;

    failures += expect(asn_DEF_OptionalField.elements_count == 2
                       && (asn_DEF_OptionalField.elements[1].flags
                           & (ATF_OPEN_TYPE | ATF_POINTER))
                           == (ATF_OPEN_TYPE | ATF_POINTER),
                       "optional open type uses pointer metadata");
    source.value = (OptionalField__value *)calloc(1, sizeof(*source.value));
    if(!source.value) {
        failures += expect(0, "optional open-type wrapper allocation succeeds");
        return failures;
    }
    source.value->present = OptionalField__value_PR_asn1cUnknown;
    source.value->choice.asn1cUnknown.buf = (uint8_t *)malloc(sizeof(opaque));
    if(!source.value->choice.asn1cUnknown.buf) {
        failures += expect(0, "optional opaque contents allocation succeeds");
        ASN_STRUCT_RESET(asn_DEF_OptionalField, &source);
        return failures;
    }
    memcpy(source.value->choice.asn1cUnknown.buf, opaque, sizeof(opaque));
    source.value->choice.asn1cUnknown.size = (int)sizeof(opaque);
    source.id = 2;

    encoded = aper_encode_to_buffer(&asn_DEF_OptionalField, NULL, &source,
                                    wire, sizeof(wire));
    failures += expect(encoded.encoded >= 0,
                       "optional opaque open type encodes");
    if(encoded.encoded >= 0) {
        wire_size = (size_t)(encoded.encoded + 7) / 8;
        decoded_result = aper_decode_complete(NULL, &asn_DEF_OptionalField,
                                               (void **)&decoded, wire,
                                               wire_size);
        failures += expect(decoded_result.code == RC_OK && decoded != NULL,
                           "optional opaque open type decodes");
    }
    if(decoded) {
        failures += expect(decoded->value != NULL,
                           "decoded optional wrapper is allocated");
    }
    if(decoded && decoded->value) {
        failures += expect(decoded->id == 2
                           && decoded->value->present
                               == OptionalField__value_PR_asn1cUnknown
                           && decoded->value->choice.asn1cUnknown.size
                               == (int)sizeof(opaque)
                           && decoded->value->choice.asn1cUnknown.buf != NULL
                           && memcmp(decoded->value->choice.asn1cUnknown.buf,
                                     opaque, sizeof(opaque)) == 0,
                           "optional opaque contents survive decode");
        failures += expect(asn_copy(&asn_DEF_OptionalField, (void **)&copy,
                                    decoded) == 0,
                           "optional opaque value deep copy succeeds");
        if(copy) {
            failures += expect(asn_DEF_OptionalField.op->compare_struct(
                                   &asn_DEF_OptionalField, decoded, copy) == 0,
                               "optional opaque deep copy compares equal");
            ASN_STRUCT_RESET(asn_DEF_OptionalField, decoded);
            failures += expect(decoded->value == NULL,
                               "optional wrapper reset clears its pointer");
        }
    }

    if(wire_size > 1) {
        decoded_result = aper_decode_complete(NULL, &asn_DEF_OptionalField,
                                               (void **)&truncated, wire,
                                               wire_size - 1);
        failures += expect(decoded_result.code != RC_OK,
                           "truncated optional opaque contents are rejected");
    } else {
        failures += expect(0, "optional encoding has contents to truncate");
    }

    if(copy) ASN_STRUCT_FREE(asn_DEF_OptionalField, copy);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_OptionalField, decoded);
    if(truncated) ASN_STRUCT_FREE(asn_DEF_OptionalField, truncated);
    ASN_STRUCT_RESET(asn_DEF_OptionalField, &source);
    return failures;
}

/*
 * Purpose: mutate one known sibling and prove another opaque sibling survives.
 * Original source: issue #586 unknown-content ownership regression.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; constructs a Message containing one known and one unknown.
 * Returns: number of failed list, encode/decode, or preserved-content checks.
 * Errors: each owned message, Field, and decoder allocation is released.
 * Responsible party: asn1c maintainers.
 * History: added regression for modifying a decoded known sibling.
 * Example: main adds test_sibling_mutation() to its overall failure count.
 */
static int
test_sibling_mutation(void) {
    static const uint8_t opaque[] = {0x31, 0x80, 0x7f};
    Message_t source = {0};
    Message_t *decoded = NULL;
    Message_t *changed = NULL;
    Field_t *unknown = NULL;
    Field_t *known = NULL;
    uint8_t first_wire[128];
    uint8_t second_wire[128];
    asn_enc_rval_t encoded;
    asn_dec_rval_t decoded_result;
    int failures = 0;

    unknown = (Field_t *)calloc(1, sizeof(*unknown));
    known = (Field_t *)calloc(1, sizeof(*known));
    if(!unknown || !known) {
        failures += expect(0, "sibling allocations succeed");
        free(unknown);
        free(known);
        return failures;
    }
    unknown->id = 2;
    unknown->value.present = Field__value_PR_asn1cUnknown;
    unknown->value.choice.asn1cUnknown.buf = (uint8_t *)malloc(sizeof(opaque));
    if(!unknown->value.choice.asn1cUnknown.buf) {
        failures += expect(0, "opaque sibling allocation succeeds");
        free(known);
        free(unknown);
        return failures;
    }
    memcpy(unknown->value.choice.asn1cUnknown.buf, opaque, sizeof(opaque));
    unknown->value.choice.asn1cUnknown.size = (int)sizeof(opaque);
    known->id = 1;
    known->value.present = Field__value_PR_INTEGER_0_255_;
    known->value.choice.INTEGER_0_255_ = 7;

    /* Adding both entries transfers their ownership to the Message list. */
    if(ASN_SEQUENCE_ADD(&source.fields.list, unknown) != 0) {
        failures += expect(0, "message list accepts both sibling values");
        ASN_STRUCT_FREE(asn_DEF_Field, unknown);
        ASN_STRUCT_FREE(asn_DEF_Field, known);
        return failures;
    }
    if(ASN_SEQUENCE_ADD(&source.fields.list, known) != 0) {
        failures += expect(0, "message list accepts both sibling values");
        ASN_STRUCT_FREE(asn_DEF_Field, known);
        ASN_STRUCT_RESET(asn_DEF_Message, &source);
        return failures;
    }

    encoded = aper_encode_to_buffer(&asn_DEF_Message, NULL, &source,
                                    first_wire, sizeof(first_wire));
    failures += expect(encoded.encoded >= 0, "message with unknown sibling encodes");
    if(encoded.encoded >= 0) {
        size_t first_size = (size_t)(encoded.encoded + 7) / 8;
        decoded_result = aper_decode_complete(NULL, &asn_DEF_Message,
                                               (void **)&decoded, first_wire,
                                               first_size);
        failures += expect(decoded_result.code == RC_OK && decoded != NULL,
                           "message with unknown sibling decodes");
    }
    if(decoded && decoded->fields.list.count == 2) {
        decoded->fields.list.array[1]->value.choice.INTEGER_0_255_ = 9;
        encoded = aper_encode_to_buffer(&asn_DEF_Message, NULL, decoded,
                                        second_wire, sizeof(second_wire));
        failures += expect(encoded.encoded >= 0,
                           "modified known sibling message encodes");
        if(encoded.encoded >= 0) {
            size_t second_size = (size_t)(encoded.encoded + 7) / 8;
            decoded_result = aper_decode_complete(NULL, &asn_DEF_Message,
                                                   (void **)&changed,
                                                   second_wire, second_size);
            failures += expect(decoded_result.code == RC_OK && changed != NULL,
                               "modified message decodes again");
        }
    } else if(decoded) {
        failures += expect(0, "decoded message contains both siblings");
    }
    if(changed && changed->fields.list.count == 2) {
        Field_t *changed_unknown = changed->fields.list.array[0];
        Field_t *changed_known = changed->fields.list.array[1];

        failures += expect(changed_unknown->value.present
                               == Field__value_PR_asn1cUnknown
                           && changed_unknown->value.choice.asn1cUnknown.size
                               == (int)sizeof(opaque)
                           && changed_unknown->value.choice.asn1cUnknown.buf
                               != NULL
                           && memcmp(changed_unknown->value.choice.asn1cUnknown.buf,
                                     opaque, sizeof(opaque)) == 0,
                           "unknown sibling survives known sibling mutation");
        failures += expect(changed_known->value.choice.INTEGER_0_255_ == 9,
                           "known sibling mutation is retained");
    }

    if(decoded) ASN_STRUCT_FREE(asn_DEF_Message, decoded);
    if(changed) ASN_STRUCT_FREE(asn_DEF_Message, changed);
    ASN_STRUCT_RESET(asn_DEF_Message, &source);
    return failures;
}

/*
 * Purpose: run a bounded mutation sweep through complete APER decoding/freeing.
 * Original source: issue #586 malformed-input robustness requirements.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none; mutates each byte of a valid unknown vector over 256 values.
 * Returns: zero unless all 1024 mutations complete without process failure.
 * Errors: all partial decoder values are released; any crash fails the test.
 * Responsible party: asn1c maintainers.
 * History: complements LLVMFuzzerTestOneInput with deterministic smoke coverage.
 * Example: main adds test_bounded_mutations() to its overall failure count.
 */
static int
test_bounded_mutations(void) {
    static const uint8_t seed[] = {0x00, 0x02, 0x01, 0x80};
    uint8_t candidate[sizeof(seed)];
    size_t position;
    unsigned value;

    for(position = 0; position < sizeof(seed); position++) {
        for(value = 0; value < 256; value++) {
            Field_t *decoded = NULL;

            memcpy(candidate, seed, sizeof(seed));
            candidate[position] = (uint8_t)value;
            (void)aper_decode_complete(NULL, &asn_DEF_Field,
                                       (void **)&decoded, candidate,
                                       sizeof(candidate));
            if(decoded) ASN_STRUCT_FREE(asn_DEF_Field, decoded);
        }
    }
    return 0;
}

/*
 * Purpose: run the issue #586 fixed vectors, boundary sizes, and negative cases.
 * Original source: issue #586 integration regression suite.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: none.
 * Returns: process status zero on success, one when any assertion fails.
 * Errors: prints the count of failed checks; codec failures are test failures.
 * Responsible party: asn1c maintainers.
 * History: added all-codecs and APER-only-PER integration entry point.
 * Example: ./issue-586-test.
 */
int
main(void) {
    static const size_t sizes[] = {
        0, 1, 127, 128, 255, 256, 2560, 2561, 16383, 16384, 16385, 65536
    };
    size_t index;
    int failures = 0;

    failures += test_vectors();
    for(index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
        failures += test_payload_size(sizes[index]);
    }
    failures += test_opaque_validation();
#ifndef ASN_DISABLE_PRINT_SUPPORT
    failures += test_any_print();
#endif /* !ASN_DISABLE_PRINT_SUPPORT */
    failures += test_malformed();
    failures += test_table_modes();
    failures += test_optional_open_type();
    failures += test_cross_arm_copy();
    failures += test_invalid_choice_copy();
    failures += test_null_extension_placeholder();
    failures += test_sibling_mutation();
    failures += test_bounded_mutations();
    if(failures) {
        fprintf(stderr, "%d issue #586 check(s) failed\n", failures);
        return 1;
    }
    puts("issue #586 APER open-type tests passed");
    return 0;
}

#endif /* ISSUE586_FUZZ */
