/*
 * Strict CER decoder tests: canonical acceptance, non-canonical rejection,
 * ownership/cleanup on failure, and generic dispatch equivalence.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asn_application.h>
#include <cer_decoder.h>
#include <ANY.h>
#include <BIT_STRING.h>
#include <BOOLEAN.h>
#include <GeneralizedTime.h>
#include <INTEGER.h>
#include <NULL.h>
#include <NativeInteger.h>
#include <OCTET_STRING.h>
#include <UTCTime.h>
#include <UTF8String.h>

static int failures; /* Count of failed checks across the whole run. */

/*
 * Record a failed check with its label.
 * Original source: New asn1c strict CER decoder test helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ok is the check result; label names the check.
 * Returns: No value; increments the global failure count when ok is zero.
 * Errors: None. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: check(rv.code == RC_OK, "NULL accepted").
 */
static void
check(int ok, const char *label) {
    if(!ok) {
        fprintf(stderr, "FAIL: %s\n", label);
        failures++;
    }
}

/*
 * Decode bytes strictly, expect success, and verify consumed length.
 * Original source: New asn1c strict CER decoder test helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td is the type; bytes/size the input; consumed is the expected
 *   consumed count; label names the case.
 * Returns: The decoded structure (caller frees) or NULL on failure.
 * Errors: Failures are recorded through check(). C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: v = expect_ok(&asn_DEF_NULL, "\x05\x00", 2, 2, "NULL").
 */
static void *
expect_ok(const asn_TYPE_descriptor_t *td, const void *bytes, size_t size,
          size_t consumed, const char *label) {
    void *value = NULL;
    void *generic = NULL;
    asn_dec_rval_t rv = cer_decode(NULL, td, &value, bytes, size);
    asn_dec_rval_t grv =
        asn_decode(NULL, ATS_CER, td, &generic, bytes, size);

    check(rv.code == RC_OK && rv.consumed == consumed && value != NULL,
          label);
    check(grv.code == rv.code && grv.consumed == rv.consumed
              && generic != NULL,
          "asn_decode(ATS_CER) matches cer_decode on canonical input");
    ASN_STRUCT_FREE(*td, generic);
    if(rv.code != RC_OK) {
        ASN_STRUCT_FREE(*td, value);
        return NULL;
    }
    return value;
}

/*
 * Decode bytes strictly and expect rejection with no residual allocation.
 * Original source: New asn1c strict CER decoder test helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td is the type; bytes/size the input; code is the expected
 *   result code; err is the expected errno (0 to skip); label names the case.
 * Returns: No value.
 * Errors: Failures are recorded through check(). C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: expect_reject(&asn_DEF_BOOLEAN, "\1\1\1", 3, RC_FAIL, EBADF, "").
 */
static void
expect_reject(const asn_TYPE_descriptor_t *td, const void *bytes,
              size_t size, enum asn_dec_rval_code_e code, int err,
              const char *label) {
    void *value = NULL;
    void *generic = NULL;
    asn_dec_rval_t rv;
    asn_dec_rval_t grv;

    errno = 0;
    rv = cer_decode(NULL, td, &value, bytes, size);
    check(rv.code == code && rv.consumed == 0 && value == NULL, label);
    if(err != 0) check(errno == err, label);
    grv = asn_decode(NULL, ATS_CER, td, &generic, bytes, size);
    check(grv.code == rv.code && grv.consumed == 0 && generic == NULL,
          "asn_decode(ATS_CER) matches cer_decode on rejected input");
    ASN_STRUCT_FREE(*td, value);
    ASN_STRUCT_FREE(*td, generic);
}

/*
 * Build a primitive or fragmented OCTET STRING encoding of n bytes.
 * Original source: New asn1c strict CER decoder test helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: out receives the encoding (caller-sized); n is the content
 *   length; fragmented selects CER 1000-byte segmentation.
 * Returns: The encoded length.
 * Errors: None. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: len = build_octets(buf, 1001, 1).
 */
static size_t
build_octets(uint8_t *out, size_t n, int fragmented) {
    size_t pos = 0;
    size_t done = 0;

    if(!fragmented) {
        out[pos++] = 0x04;
        out[pos++] = 0x82;
        out[pos++] = (uint8_t)(n >> 8);
        out[pos++] = (uint8_t)n;
        memset(out + pos, 'A', n);
        return pos + n;
    }
    out[pos++] = 0x24;
    out[pos++] = 0x80;
    while(done < n) {
        size_t chunk = (n - done) > 1000 ? 1000 : (n - done);
        out[pos++] = 0x04;
        if(chunk < 128) {
            out[pos++] = (uint8_t)chunk;
        } else {
            out[pos++] = 0x82;
            out[pos++] = (uint8_t)(chunk >> 8);
            out[pos++] = (uint8_t)chunk;
        }
        memset(out + pos, 'A', chunk);
        pos += chunk;
        done += chunk;
    }
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    return pos;
}

/*
 * Exercise canonical acceptance for primitive and fragmented types.
 * Original source: New asn1c strict CER decoder test.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None. Returns: No value.
 * Errors: Failures are recorded through check(). C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: test_accept().
 */
static void
test_accept(void) {
    static const uint8_t null_trailing[] = {0x05, 0x00, 0xFF};
    static const uint8_t bool_true[] = {0x01, 0x01, 0xFF};
    static const uint8_t bool_false[] = {0x01, 0x01, 0x00};
    static const uint8_t integer[] = {0x02, 0x02, 0x00, 0x80};
    static const uint8_t native[] = {0x02, 0x01, 0x85};
    static const uint8_t octets[] = {0x04, 0x03, 'a', 'b', 'c'};
    static const uint8_t bits[] = {0x03, 0x02, 0x07, 0x80};
    static const uint8_t utf8[] = {0x0C, 0x02, 'h', 'i'};
    static const uint8_t gtime[] = {0x18, 0x11, '1', '9', '8', '5', '1', '1',
                                    '0', '6', '2', '1', '0', '6', '2', '7',
                                    '.', '3', 'Z'};
    static const uint8_t utime[] = {0x17, 0x0D, '8', '5', '1', '1', '0', '6',
                                    '2', '1', '0', '6', '2', '7', 'Z'};
    uint8_t big[1100];
    size_t big_len;
    void *v;

    v = expect_ok(&asn_DEF_NULL, null_trailing, sizeof(null_trailing), 2,
                  "NULL accepted, trailing byte not consumed");
    ASN_STRUCT_FREE(asn_DEF_NULL, v);

    v = expect_ok(&asn_DEF_BOOLEAN, bool_true, sizeof(bool_true), 3,
                  "BOOLEAN TRUE (FF) accepted");
    check(v && *(BOOLEAN_t *)v != 0, "BOOLEAN TRUE value");
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, v);
    v = expect_ok(&asn_DEF_BOOLEAN, bool_false, sizeof(bool_false), 3,
                  "BOOLEAN FALSE accepted");
    check(v && *(BOOLEAN_t *)v == 0, "BOOLEAN FALSE value");
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, v);

    v = expect_ok(&asn_DEF_INTEGER, integer, sizeof(integer), 4,
                  "INTEGER 128 with required sign octet accepted");
    ASN_STRUCT_FREE(asn_DEF_INTEGER, v);
    v = expect_ok(&asn_DEF_NativeInteger, native, sizeof(native), 3,
                  "NativeInteger -123 accepted");
    check(v && *(long *)v == -123, "NativeInteger value");
    ASN_STRUCT_FREE(asn_DEF_NativeInteger, v);

    v = expect_ok(&asn_DEF_OCTET_STRING, octets, sizeof(octets), 5,
                  "short primitive OCTET STRING accepted");
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, v);
    v = expect_ok(&asn_DEF_BIT_STRING, bits, sizeof(bits), 4,
                  "BIT STRING with zero padding accepted");
    ASN_STRUCT_FREE(asn_DEF_BIT_STRING, v);
    v = expect_ok(&asn_DEF_UTF8String, utf8, sizeof(utf8), 4,
                  "UTF8String accepted");
    ASN_STRUCT_FREE(asn_DEF_UTF8String, v);
    v = expect_ok(&asn_DEF_GeneralizedTime, gtime, sizeof(gtime),
                  sizeof(gtime), "canonical GeneralizedTime accepted");
    ASN_STRUCT_FREE(asn_DEF_GeneralizedTime, v);
    v = expect_ok(&asn_DEF_UTCTime, utime, sizeof(utime), sizeof(utime),
                  "canonical UTCTime accepted");
    ASN_STRUCT_FREE(asn_DEF_UTCTime, v);

    big_len = build_octets(big, 1001, 1);
    v = expect_ok(&asn_DEF_OCTET_STRING, big, big_len, big_len,
                  "1001-byte OCTET STRING fragmented 1000+1 accepted");
    check(v && ((OCTET_STRING_t *)v)->size == 1001,
          "fragmented OCTET STRING length");
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, v);
}

/*
 * Exercise rejection of BER-valid but non-canonical encodings.
 * Original source: New asn1c strict CER decoder test.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None. Returns: No value.
 * Errors: Failures are recorded through check(). C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: test_reject().
 */
static void
test_reject(void) {
    static const uint8_t bool_one[] = {0x01, 0x01, 0x01};
    static const uint8_t long_length[] = {0x01, 0x81, 0x01, 0xFF};
    static const uint8_t integer_pad[] = {0x02, 0x02, 0x00, 0x01};
    static const uint8_t native_pad[] = {0x02, 0x02, 0xFF, 0x85};
    static const uint8_t definite_cons[] = {0x24, 0x03, 0x04, 0x01, 0x5A};
    static const uint8_t short_cons[] = {0x24, 0x80, 0x04, 0x01,
                                         0x5A, 0x00, 0x00};
    static const uint8_t utime_no_sec[] = {0x17, 0x0B, '8', '5', '1', '1',
                                           '0', '6', '2', '1', '0', '6', 'Z'};
    static const uint8_t truncated[] = {0x01, 0x01};
    static const uint8_t wrong_tag[] = {0x02, 0x01, 0xFF};
    uint8_t big[1100];
    size_t big_len;

    expect_reject(&asn_DEF_BOOLEAN, bool_one, sizeof(bool_one), RC_FAIL,
                  EBADF, "BOOLEAN TRUE as 01 rejected");
    expect_reject(&asn_DEF_BOOLEAN, long_length, sizeof(long_length),
                  RC_FAIL, EBADF, "non-minimal long-form length rejected");
    expect_reject(&asn_DEF_INTEGER, integer_pad, sizeof(integer_pad),
                  RC_FAIL, EBADF, "INTEGER redundant leading 00 rejected");
    expect_reject(&asn_DEF_NativeInteger, native_pad, sizeof(native_pad),
                  RC_FAIL, EBADF, "NativeInteger redundant leading FF rejected");
    expect_reject(&asn_DEF_OCTET_STRING, definite_cons,
                  sizeof(definite_cons), RC_FAIL, EBADF,
                  "definite-length constructed OCTET STRING rejected");
    expect_reject(&asn_DEF_OCTET_STRING, short_cons, sizeof(short_cons),
                  RC_FAIL, EBADF,
                  "constructed OCTET STRING of <=1000 bytes rejected");
    expect_reject(&asn_DEF_UTCTime, utime_no_sec, sizeof(utime_no_sec),
                  RC_FAIL, 0, "UTCTime without seconds rejected");

    big_len = build_octets(big, 1001, 0);
    expect_reject(&asn_DEF_OCTET_STRING, big, big_len, RC_FAIL, EBADF,
                  "primitive OCTET STRING of >1000 bytes rejected");

    expect_reject(&asn_DEF_BOOLEAN, truncated, sizeof(truncated), RC_WMORE,
                  0, "truncated input reports RC_WMORE, consumed 0");
    expect_reject(&asn_DEF_BOOLEAN, wrong_tag, sizeof(wrong_tag), RC_FAIL,
                  0, "wrong tag rejected");
}

/*
 * Exercise argument validation, unsupported types, and caller storage reset.
 * Original source: New asn1c strict CER decoder test.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None. Returns: No value.
 * Errors: Failures are recorded through check(). C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: test_ownership().
 */
static void
test_ownership(void) {
    static const uint8_t short_cons[] = {0x24, 0x80, 0x04, 0x01,
                                         0x5A, 0x00, 0x00};
    static const uint8_t any_bytes[] = {0x05, 0x00};
    OCTET_STRING_t caller;
    void *caller_ptr = &caller;
    void *value = NULL;
    asn_dec_rval_t rv;

    memset(&caller, 0, sizeof(caller));
    rv = cer_decode(NULL, &asn_DEF_OCTET_STRING, &caller_ptr, short_cons,
                    sizeof(short_cons));
    check(rv.code == RC_FAIL && rv.consumed == 0,
          "caller-provided storage: decode rejected");
    check(caller_ptr == &caller && caller.buf == NULL && caller.size == 0,
          "caller-provided storage reset, not freed");

    errno = 0;
    rv = cer_decode(NULL, NULL, &value, any_bytes, sizeof(any_bytes));
    check(rv.code == RC_FAIL && errno == EINVAL, "NULL descriptor -> EINVAL");
    errno = 0;
    rv = cer_decode(NULL, &asn_DEF_NULL, NULL, any_bytes, sizeof(any_bytes));
    check(rv.code == RC_FAIL && errno == EINVAL, "NULL struct_ptr -> EINVAL");
    errno = 0;
    rv = cer_decode(NULL, &asn_DEF_NULL, &value, NULL, 2);
    check(rv.code == RC_FAIL && errno == EINVAL && value == NULL,
          "NULL buffer with nonzero size -> EINVAL");

    errno = 0;
    rv = cer_decode(NULL, &asn_DEF_ANY, &value, any_bytes,
                    sizeof(any_bytes));
    check(rv.code == RC_FAIL && rv.consumed == 0 && value == NULL,
          "ANY (no canonical form) rejected");
    check(errno == ENOENT, "ANY rejection reports ENOENT");
}

int
main(void) {
    test_accept();
    test_reject();
    test_ownership();
    if(failures) {
        fprintf(stderr, "%d CER decode check(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("check-CER-decode: all checks passed\n");
    return EXIT_SUCCESS;
}
