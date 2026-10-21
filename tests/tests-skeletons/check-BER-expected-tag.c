/*
 * BER string tag selection regressions for effective and containment tags.
 *
 * `tags` describes effective descriptor wrappers, while `all_tags` may also
 * end in the natural component tag used by constructed string fragments.
 * These vectors reproduce issue #581, PR #580's over-broad fallback, and
 * natural UTF8String, OCTET STRING, VisibleString, and BIT STRING fragments.
 */
#include <stdio.h>
#include <string.h>

#include <asn_application.h>
#include <BIT_STRING.h>
#include <OCTET_STRING.h>
#include <UTF8String.h>
#include <VisibleString.h>

static int failures; /* state variable: number of failed regression checks. */

/*
 * Record a test result and keep running later independent vectors.
 * Original source: New BER expected-tag regression test.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: condition is the result; label identifies expected behavior.
 * Returns: Zero when condition is true, otherwise -1.
 * Errors: None; a false result increments the file-local failure state.
 * Responsible party: asn1c maintainers. History: Added for issues #581 and PR #580.
 * Example: check(rv.code == RC_OK, "retagged string accepts its own DER").
 */
static int
check(int condition, const char *label) {
    if(condition) return 0;
    fprintf(stderr, "FAIL: %s\n", label);
    failures++;
    return -1;
}

/*
 * Decode one buffer through the descriptor's BER entry point.
 * Original source: New BER expected-tag regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td describes the value; input/size bound encoded bytes;
 *   value receives the allocated or partially decoded value.
 * Returns: The decoder result, or RC_FAIL for bad arguments.
 * Errors: Decoder errors are returned as RC_FAIL, RC_WMORE, or RC_OK.
 * Responsible party: asn1c maintainers. History: Added for issue #581 vectors.
 * Example: result = decode(&td, bytes, sizeof(bytes), &value).
 */
static asn_dec_rval_t
decode(const asn_TYPE_descriptor_t *td, const void *input, size_t size,
       void **value) {
    asn_dec_rval_t result;

    if(!value) {
        result.code = RC_FAIL;
        result.consumed = 0;
        return result;
    }
    *value = NULL;
    if(!td || !td->op || !td->op->ber_decoder || (!input && size)) {
        result.code = RC_FAIL;
        result.consumed = 0;
        return result;
    }
    return td->op->ber_decoder(NULL, td, value, input, size, 0);
}

/*
 * Release any value returned by one of the primitive string decoders.
 * Original source: New BER expected-tag regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td owns the value; value may be NULL after an early failure.
 * Returns: No value.
 * Errors: None; the descriptor's free routine owns storage cleanup.
 * Responsible party: asn1c maintainers. History: Added for issue #581 vectors.
 * Example: free_value(&asn_DEF_UTF8String, decoded).
 */
static void
free_value(const asn_TYPE_descriptor_t *td, void *value) {
    if(value && td && td->op && td->op->free_struct) {
        td->op->free_struct(td, value, ASFM_FREE_EVERYTHING);
    }
}

/*
 * Require a decoder status and complete consumption for a fixed TLV.
 * Original source: New BER expected-tag regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td/input/size select the decode; expected is the required status;
 *   label identifies the vector in failure output.
 * Returns: Zero when status and consumption match; otherwise -1.
 * Errors: Decoder failures are reported as a failed expectation.
 * Responsible party: asn1c maintainers. History: Added for issue #581 vectors.
 * Example: check_status(&td, bytes, n, RC_FAIL, "wrong tag rejected").
 */
static int
check_status(const asn_TYPE_descriptor_t *td, const void *input, size_t size,
             enum asn_dec_rval_code_e expected, const char *label) {
    void *value = NULL;
    asn_dec_rval_t result = decode(td, input, size, &value);
    int failed = check(result.code == expected, label);

    if(expected == RC_OK) failed |= check(result.consumed == size, label);
    free_value(td, value);
    return failed;
}

/*
 * Require a decoded string to contain the exact expected octets.
 * Original source: New BER expected-tag regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td/input/size select the value; expected/expected_size provide
 *   the exact payload; label identifies the assertion.
 * Returns: Zero for a complete byte-for-byte match, otherwise -1.
 * Errors: A decode or payload mismatch is recorded through check().
 * Responsible party: asn1c maintainers. History: Added for issue #581 vectors.
 * Example: check_octets(&td, bytes, n, "AB", 2, "fragments join").
 */
static int
check_octets(const asn_TYPE_descriptor_t *td, const void *input, size_t size,
             const void *expected, size_t expected_size, const char *label) {
    void *decoded = NULL;
    asn_dec_rval_t result = decode(td, input, size, &decoded);
    const OCTET_STRING_t *value = (const OCTET_STRING_t *)decoded;
    int failed = 0;

    failed |= check(result.code == RC_OK && result.consumed == size, label);
    failed |= check(value && value->size == expected_size
                    && (!expected_size
                        || memcmp(value->buf, expected, expected_size) == 0),
                    label);
    free_value(td, decoded);
    return failed;
}

/*
 * Decode a complete indefinite string one byte at a time.
 * Original source: New BER expected-tag regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td describes the value; input/size are the TLV;
 *   expected/expected_size provide the payload; label names the assertion.
 * Returns: Zero when incremental decoding completes at the final byte.
 * Errors: Rejects decoder failure, overconsumption, incomplete input, or data
 *   mismatch. A fixed pending buffer bounds each input retry.
 * Responsible party: asn1c maintainers. History: Added for PR #580 coverage.
 * Example: checks an indefinite nested OCTET STRING one byte per call.
 */
static int
check_bytewise(const asn_TYPE_descriptor_t *td, const uint8_t *input,
               size_t size, const void *expected, size_t expected_size,
               const char *label) {
    uint8_t pending[32]; /* state variable: bytes not yet consumed. */
    size_t pending_size = 0; /* state variable: buffered byte count. */
    size_t input_index = 0; /* state variable: next source byte. */
    void *decoded = NULL; /* state variable: incremental decoder value. */
    int complete = 0; /* state variable: decoder completed the full TLV. */
    int failed = 0;

    while(input_index < size && !complete && !failed) {
        asn_dec_rval_t result;
        int retry = 1;

        if(pending_size == sizeof(pending)) {
            failed |= check(0, label);
            break;
        }
        pending[pending_size++] = input[input_index++];
        while(retry && !complete && !failed) {
            size_t consumed;

            result = td->op->ber_decoder(NULL, td, &decoded, pending,
                                         pending_size, 0);
            if(result.consumed > pending_size) {
                failed |= check(0, label);
                break;
            }
            consumed = result.consumed;
            if(consumed) {
                pending_size -= consumed;
                memmove(pending, pending + consumed, pending_size);
            }
            if(result.code == RC_OK) {
                complete = 1;
                failed |= check(input_index == size && pending_size == 0,
                                label);
            } else if(result.code == RC_FAIL) {
                failed |= check(0, label);
            } else if(result.code == RC_WMORE) {
                retry = consumed && pending_size;
            } else {
                failed |= check(0, label);
            }
        }
    }
    failed |= check(complete, label);
    if(complete) {
        const OCTET_STRING_t *value = (const OCTET_STRING_t *)decoded;
        failed |= check(value && value->size == expected_size
                        && (!expected_size
                            || memcmp(value->buf, expected, expected_size) == 0),
                        label);
    }
    free_value(td, decoded);
    return failed;
}

/*
 * Reproduce issue #581 with generated-style effective and containment chains.
 * Original source: New BER expected-tag regression fixture.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: None; local arrays model Label2 ::= [1] Label and
 *   Label ::= [9] EXPLICIT UTF8String.
 * Returns: Zero when valid DER is accepted and the superseded [9] tag fails.
 * Errors: Failed expectations are reported through check_status/check_octets.
 * Responsible party: asn1c maintainers. History: Added for issue #581.
 * Example: [1] { UTF8String "ABC" } decodes without an obsolete [9] wrapper.
 */
static int
check_explicit_retag(void) {
    static const ber_tlv_tag_t effective_tags[] = {
        ASN_TAG_CLASS_CONTEXT | (1u << 2),
        ASN_TAG_CLASS_UNIVERSAL | (12u << 2)
    };
    static const ber_tlv_tag_t containment_tags[] = {
        ASN_TAG_CLASS_CONTEXT | (1u << 2),
        ASN_TAG_CLASS_CONTEXT | (9u << 2),
        ASN_TAG_CLASS_UNIVERSAL | (12u << 2)
    };
    static const uint8_t valid[] = {
        0xa1, 0x05, 0x0c, 0x03, 'A', 'B', 'C'
    };
    static const uint8_t superseded[] = {
        0xa1, 0x05, 0xa9, 0x03, 0x0c, 0x01, 'A'
    };
    static const uint8_t constructed[] = {
        0xa1, 0x05, 0x2c, 0x03, 0x04, 0x01, 'A'
    };
    asn_TYPE_descriptor_t td = asn_DEF_UTF8String;
    int failed = 0;

    td.tags = effective_tags;
    td.tags_count = sizeof(effective_tags) / sizeof(effective_tags[0]);
    td.all_tags = containment_tags;
    td.all_tags_count = sizeof(containment_tags) / sizeof(containment_tags[0]);

    failed |= check_octets(&td, valid, sizeof(valid), "ABC", 3,
                           "effective [1] UTF8String chain accepts DER");
    failed |= check_status(&td, superseded, sizeof(superseded), RC_FAIL,
                           "superseded explicit [9] tag is rejected");
    failed |= check_octets(&td, constructed, sizeof(constructed), "A", 1,
                           "retagged constructed UTF8String accepts OCTET fragment");
    return failed;
}

/*
 * Reproduce PR #580's widened acceptance for an implicit string descriptor.
 * Original source: New BER expected-tag regression fixture.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: None; arrays model generated [7] IMPLICIT OCTET STRING metadata.
 * Returns: Zero when natural fragments pass and a context-tag mutation fails.
 * Errors: Failed expectations are reported through check helpers.
 * Responsible party: asn1c maintainers. History: Added for PR #580 regression.
 * Example: nested constructed [7] values end in universal OCTET STRING 04.
 */
static int
check_implicit_octets(void) {
    static const ber_tlv_tag_t effective_tags[] = {
        ASN_TAG_CLASS_CONTEXT | (7u << 2),
        ASN_TAG_CLASS_UNIVERSAL | (4u << 2)
    };
    static const uint8_t definite[] = {
        0xa7, 0x07, 0x24, 0x05, 0x24, 0x03, 0x04, 0x01, 'A'
    };
    static const uint8_t wrong_definite[] = {
        0xa7, 0x07, 0x24, 0x05, 0x24, 0x03, 0x87, 0x01, 'A'
    };
    static const uint8_t indefinite[] = {
        0xa7, 0x80, 0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 'A',
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t wrong_indefinite[] = {
        0xa7, 0x80, 0x24, 0x80, 0x24, 0x80, 0x87, 0x01, 'A',
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    asn_TYPE_descriptor_t td = asn_DEF_OCTET_STRING;
    int failed = 0;

    td.tags = effective_tags;
    td.tags_count = 1;
    td.all_tags = effective_tags;
    td.all_tags_count = sizeof(effective_tags) / sizeof(effective_tags[0]);

    failed |= check_octets(&td, definite, sizeof(definite), "A", 1,
                           "definite implicit OCTET fragments use natural tag");
    failed |= check_status(&td, wrong_definite, sizeof(wrong_definite), RC_FAIL,
                           "definite implicit OCTET rejects context fragment tag");
    failed |= check_octets(&td, indefinite, sizeof(indefinite), "A", 1,
                           "indefinite implicit OCTET fragments use natural tag");
    failed |= check_status(&td, wrong_indefinite, sizeof(wrong_indefinite),
                           RC_FAIL, "indefinite implicit OCTET rejects context fragment");
    failed |= check_status(&td, indefinite, sizeof(indefinite) - 2, RC_WMORE,
                           "indefinite implicit OCTET requests missing outer EOC");
    failed |= check_bytewise(&td, indefinite, sizeof(indefinite), "A", 1,
                             "indefinite implicit OCTET streams bytewise");
    return failed;
}

/*
 * Check built-in UTF8String and VisibleString natural component tags.
 * Original source: New BER expected-tag regression fixture.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: None; fixed definite nested constructed values exercise depth.
 * Returns: Zero when natural OCTET STRING fragments pass and wrong tags fail.
 * Errors: Failed expectations are reported through check helpers.
 * Responsible party: asn1c maintainers. History: Covers PR #580 mutation.
 * Example: VisibleString fragments use tag 04; an inner tag 1a is rejected.
 */
static int
check_character_string_fragments(void) {
    static const uint8_t utf8[] = {
        0x2c, 0x07, 0x24, 0x05, 0x24, 0x03, 0x04, 0x01, 'A'
    };
    static const uint8_t wrong_utf8[] = {
        0x2c, 0x07, 0x24, 0x05, 0x24, 0x03, 0x0c, 0x01, 'A'
    };
    static const uint8_t visible[] = {
        0x3a, 0x07, 0x24, 0x05, 0x24, 0x03, 0x04, 0x01, 'A'
    };
    static const uint8_t wrong_visible[] = {
        0x3a, 0x07, 0x24, 0x05, 0x24, 0x03, 0x1a, 0x01, 'A'
    };
    int failed = 0;

    failed |= check_octets(&asn_DEF_UTF8String, utf8, sizeof(utf8), "A", 1,
                           "UTF8String constructed fragments use tag 04");
    failed |= check_status(&asn_DEF_UTF8String, wrong_utf8, sizeof(wrong_utf8),
                           RC_FAIL, "UTF8String rejects its wrapper tag as a fragment");
    failed |= check_octets(&asn_DEF_VisibleString, visible, sizeof(visible),
                           "A", 1, "VisibleString constructed fragments use tag 04");
    failed |= check_status(&asn_DEF_VisibleString, wrong_visible,
                           sizeof(wrong_visible), RC_FAIL,
                           "VisibleString rejects tag 1a at fragment depth");
    return failed;
}

/*
 * Check OCTET STRING and BIT STRING universal component tags.
 * Original source: New BER expected-tag regression fixture.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: None; fixed definite nested TLVs contain one data octet.
 * Returns: Zero when natural fragments decode and wrong fragment tags fail.
 * Errors: Failed expectations are reported through check helpers.
 * Responsible party: asn1c maintainers. History: Added for issue #581 coverage.
 * Example: constructed BIT STRING fragments retain universal tag 03.
 */
static int
check_octet_and_bit_fragments(void) {
    static const uint8_t octets[] = {
        0x24, 0x07, 0x24, 0x05, 0x24, 0x03, 0x04, 0x01, 'A'
    };
    static const uint8_t wrong_octets[] = {
        0x24, 0x07, 0x24, 0x05, 0x24, 0x03, 0x84, 0x01, 'A'
    };
    static const uint8_t bits[] = {
        0x23, 0x08, 0x23, 0x06, 0x23, 0x04, 0x03, 0x02, 0x00, 0xa0
    };
    static const uint8_t wrong_bits[] = {
        0x23, 0x08, 0x23, 0x06, 0x23, 0x04, 0x83, 0x02, 0x00, 0xa0
    };
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    failed |= check_octets(&asn_DEF_OCTET_STRING, octets, sizeof(octets),
                           "A", 1, "OCTET STRING nested fragments use tag 04");
    failed |= check_status(&asn_DEF_OCTET_STRING, wrong_octets,
                           sizeof(wrong_octets), RC_FAIL,
                           "OCTET STRING rejects context fragment tag");
    result = decode(&asn_DEF_BIT_STRING, bits, sizeof(bits), &decoded);
    failed |= check(result.code == RC_OK && result.consumed == sizeof(bits),
                    "BIT STRING nested fragments use tag 03");
    failed |= check(decoded && ((BIT_STRING_t *)decoded)->size == 1
                    && ((BIT_STRING_t *)decoded)->bits_unused == 0
                    && ((BIT_STRING_t *)decoded)->buf[0] == 0xa0,
                    "BIT STRING fragment payload and unused-bit count match");
    free_value(&asn_DEF_BIT_STRING, decoded);
    failed |= check_status(&asn_DEF_BIT_STRING, wrong_bits, sizeof(wrong_bits),
                           RC_FAIL, "BIT STRING rejects context fragment tag");
    return failed;
}

/*
 * Reject a descriptor with a missing effective-tag array before input access.
 * Original source: New BER expected-tag descriptor validation regression.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: None; a copied descriptor is deliberately made inconsistent.
 * Returns: Zero when the malformed descriptor yields RC_FAIL without progress.
 * Errors: Failed status or consumption expectations are reported through check.
 * Responsible party: asn1c maintainers. History: Added for descriptor safety.
 * Example: tags_count=1 with tags=NULL fails at decoder entry.
 */
static int
check_malformed_descriptor(void) {
    static const uint8_t input[] = {0x04, 0x01, 'A'};
    asn_TYPE_descriptor_t td = asn_DEF_OCTET_STRING;
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    td.tags = NULL;
    result = decode(&td, input, sizeof(input), &decoded);
    failed |= check(result.code == RC_FAIL && result.consumed == 0
                    && decoded == NULL,
                    "malformed string descriptor fails before consuming input");
    free_value(&td, decoded);
    return failed;
}

/*
 * Run every expected-tag vector and return a conventional test status.
 * Original source: New BER expected-tag regression test.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: None.
 * Returns: Zero when every positive, negative, streaming, and malformed-input
 *   check passes; otherwise one.
 * Errors: Test failures are counted and printed by check().
 * Responsible party: asn1c maintainers. History: Added for issues #581 and PR #580.
 * Example: invoked as `check-BER-expected-tag` by the skeleton test suite.
 */
int
main(void) {
    check_explicit_retag();
    check_implicit_octets();
    check_character_string_fragments();
    check_octet_and_bit_fragments();
    check_malformed_descriptor();
    if(failures) fprintf(stderr, "%d BER tag check(s) failed\n", failures);
    return failures ? 1 : 0;
}
