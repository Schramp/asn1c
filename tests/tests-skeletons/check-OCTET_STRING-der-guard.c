/*
 * Regression tests for defensive OCTET STRING DER encoder input checks.
 * Original source: New standalone skeleton regression for issue #583 review.
 * Version/date: 1.0, 2026-10-21. Responsible party: asn1c maintainers.
 * History: Covers null storage, lengths, BIT STRING metadata, and callbacks.
 * Example: an empty OCTET STRING with a null buffer encodes as 04 00.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <BIT_STRING.h>
#include <OCTET_STRING.h>
#include <der_encoder.h>

/* Collected DER callback bytes and callback fault-injection state. */
struct der_capture {
    uint8_t bytes[16]; /* state variable: emitted DER bytes. */
    size_t size; /* state variable: bytes stored in bytes. */
    size_t calls; /* state variable: callback invocation count. */
    size_t null_empty_calls; /* state variable: null zero-length invocations. */
    int fail; /* state variable: force callback failure when nonzero. */
};

static unsigned failures; /* state variable: number of failed checks. */

/*
 * Record a regression assertion without hiding later independent failures.
 * Original source: New standalone DER guard test helper.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: condition is expected truth; label identifies the checked behavior.
 * Returns: 0 for success, -1 after recording a failed assertion.
 * Errors: None; failure increments the file-local test counter.
 * Responsible party: asn1c maintainers. History: Added for issue #583 review.
 * Example: check(result.encoded >= 0, "empty OCTET STRING encodes").
 */
static int
check(int condition, const char *label) {
    if(condition) return 0;
    fprintf(stderr, "FAIL: %s\n", label);
    failures++;
    return -1;
}

/*
 * Collect one callback chunk, with optional failure injection.
 * Original source: New standalone DER guard test helper.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: buffer/size are an encoder chunk; key points to the capture state.
 * Returns: 0 on success or -1 for injected failure, invalid input, or overflow.
 * Errors: A null nonempty chunk and capture-buffer overflow are rejected.
 * Responsible party: asn1c maintainers. History: Added for issue #583 review.
 * Example: der_encode(td, value, capture_bytes, &capture).
 */
static int
capture_bytes(const void *buffer, size_t size, void *key) {
    struct der_capture *capture = (struct der_capture *)key;

    capture->calls++;
    if(!buffer && !size) capture->null_empty_calls++;
    if(capture->fail || (size && !buffer)
       || size > sizeof(capture->bytes) - capture->size)
        return -1;
    if(size) memcpy(capture->bytes + capture->size, buffer, size);
    capture->size += size;
    return 0;
}

/*
 * Check a DER encoding against a fixed expected byte sequence.
 * Original source: New standalone DER guard test helper.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td/value select the value; expected/size specify its wire form.
 * Returns: 0 for exact output and no null-empty callback; otherwise -1.
 * Errors: Encoder errors and output mismatches are recorded through check().
 * Responsible party: asn1c maintainers. History: Added for issue #583 review.
 * Example: check_encoding(&asn_DEF_OCTET_STRING, &empty, octets, 2).
 */
static int
check_encoding(asn_TYPE_descriptor_t *td, const void *value,
               const uint8_t *expected, size_t expected_size) {
    struct der_capture capture = {{0}, 0, 0, 0, 0};
    asn_enc_rval_t result = der_encode(td, value, capture_bytes, &capture);
    int failed = 0;

    failed |= check(result.encoded == (ssize_t)expected_size,
                    "DER encoded size matches expected size");
    failed |= check(capture.size == expected_size
                    && memcmp(capture.bytes, expected, expected_size) == 0,
                    "DER bytes match expected value");
    failed |= check(capture.null_empty_calls == 0,
                    "encoder avoids null zero-length callback");
    return failed;
}

/*
 * Require invalid storage to fail before the first output callback.
 * Original source: New standalone DER guard test helper.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td/value select the encoder input; label names the rejected case.
 * Returns: 0 when failure is early; otherwise -1.
 * Errors: Unexpected output or successful encoding is a failed assertion.
 * Responsible party: asn1c maintainers. History: Added for issue #583 review.
 * Example: check_rejected(&asn_DEF_BIT_STRING, &bad_bits, "bad unused bits").
 */
static int
check_rejected(asn_TYPE_descriptor_t *td, const void *value,
               const char *label) {
    struct der_capture capture = {{0}, 0, 0, 0, 0};
    asn_enc_rval_t result = der_encode(td, value, capture_bytes, &capture);

    return check(result.encoded < 0 && capture.calls == 0, label);
}

/*
 * Exercise valid empty values, malformed metadata, large sizes, and callback
 * failure. Original source: New standalone DER guard regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: None; uses fixed descriptors and local values.
 * Returns: 0 after all checks pass; 1 if any assertion fails.
 * Errors: Assertions are accumulated and reported on stderr.
 * Responsible party: asn1c maintainers. History: Added for issue #583 review.
 * Example: make check-OCTET_STRING-der-guard runs this test.
 */
int
main(void) {
    static const uint8_t empty_octets[] = {0x04, 0x00};
    static const uint8_t empty_bits[] = {0x03, 0x01, 0x00};
    static const uint8_t partial_bits[] = {0x03, 0x02, 0x03, 0xf8};
    uint8_t last_byte = 0xff;
    OCTET_STRING_t octets = {0};
    OCTET_STRING_t nonempty = {0};
    BIT_STRING_t bits = {0};
    BIT_STRING_t partial = {0};
    BIT_STRING_t invalid = {0};
    struct der_capture capture = {{0}, 0, 0, 0, 1};
    asn_enc_rval_t result;

    partial.buf = &last_byte;
    partial.size = 1;
    partial.bits_unused = 3;
    invalid.buf = &last_byte;
    invalid.size = 1;
    invalid.bits_unused = -1;
    check_encoding(&asn_DEF_OCTET_STRING, &octets, empty_octets, 2);
    check_encoding(&asn_DEF_BIT_STRING, &bits, empty_bits, 3);
    check_encoding(&asn_DEF_BIT_STRING, &partial, partial_bits, 4);
    check_rejected(&asn_DEF_OCTET_STRING, NULL, "null OCTET STRING value rejected");
    check_rejected(&asn_DEF_BIT_STRING, NULL, "null BIT STRING value rejected");

    octets.size = 1;
    check_rejected(&asn_DEF_OCTET_STRING, &octets,
                   "nonempty OCTET STRING without buffer rejected");
    octets.buf = (uint8_t *)(uintptr_t)1;
    octets.size = SIZE_MAX;
    check_rejected(&asn_DEF_OCTET_STRING, &octets,
                   "SIZE_MAX OCTET STRING length rejected before read");

    check_rejected(&asn_DEF_BIT_STRING, &invalid, "negative unused-bit count rejected");
    invalid.bits_unused = 8;
    check_rejected(&asn_DEF_BIT_STRING, &invalid, "unused-bit count above seven rejected");
    invalid.size = 0;
    invalid.bits_unused = 1;
    check_rejected(&asn_DEF_BIT_STRING, &invalid, "empty BIT STRING unused bits rejected");

    nonempty.buf = &last_byte;
    nonempty.size = 1;
    result = der_encode(&asn_DEF_OCTET_STRING, &nonempty, capture_bytes,
                        &capture);
    check(result.encoded < 0 && capture.calls > 0,
          "callback failure is reported without a crash");

    if(failures) fprintf(stderr, "%u DER guard checks failed\n", failures);
    return failures ? 1 : 0;
}
