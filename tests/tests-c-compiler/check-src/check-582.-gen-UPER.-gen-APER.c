/*
 * Purpose: verify issue #582 alphabet extension encodings with UPER and APER.
 * Original source: issue #582 reproduction from Ruud Schramp (@Schramp).
 * Version/date: 2026-10-21.
 * Inputs: the Rec value containing "ab" in each extensible FROM field.
 * Returns: process status zero when all assertions pass.
 * Exceptions: assertions abort on an incorrect encoding or decode result.
 * Responsible party: asn1c maintainers; reported UPER vector cross-checked
 *                    against the issue reporter's independent implementation.
 * History: added for issue #582.
 * Example: make check runs this test with -gen-UPER -gen-APER.
 */
#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <aper_decoder.h>
#include <aper_encoder.h>
#include <constraints.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

#include "ClosedVisible.h"
#include "ClosedUniversal.h"
#include "AllExceptSpace.h"
#include "ExceptAll.h"
#include "ExceptX.h"
#include "IntersectionVisible.h"
#include "NarrowVisible.h"
#include "OpenBMP.h"
#include "OpenIA5.h"
#include "OpenNumeric.h"
#include "OpenPrintable.h"
#include "OpenUniversal.h"
#include "OpenVisible.h"
#include "OpenVisibleAdditions.h"
#include "SerialClosedVisible.h"
#include "SerialSizeVisible.h"
#include "AliasSizeVisible.h"
#include "Rec.h"

/* Keep codec variants interchangeable for the shared golden-vector check. */
typedef asn_enc_rval_t (*encode_f)(const asn_TYPE_descriptor_t *,
    const asn_per_constraints_t *, const void *, void *, size_t);
typedef asn_dec_rval_t (*decode_f)(const asn_codec_ctx_t *,
    const asn_TYPE_descriptor_t *, void **, const void *, size_t);

/*
 * Purpose: check one generated string constraint against a byte sequence.
 * Original source: issue #582 security regressions for abstract alphabet rules.
 * Version/date: 2026-10-21.
 * Inputs: descriptor identifies the ASN.1 type; bytes/size form the string.
 * Returns: One if constraints accept the value, zero if they reject it.
 * Exceptions: None; asn_check_constraints reports malformed values as failure.
 * Responsible party: asn1c maintainers.
 * History: added for issue #582.
 * Example: constraint_accepts(&asn_DEF_ExceptX, "y", 1).
 */
static int
constraint_accepts(asn_TYPE_descriptor_t *descriptor, const void *bytes,
                   size_t size) {
    OCTET_STRING_t value = { (uint8_t *)bytes, size };
    size_t error_size = 0;

    return asn_check_constraints(descriptor, &value, NULL, &error_size) == 0;
}

/*
 * Purpose: assert whether a generated abstract alphabet accepts a value.
 * Original source: issue #582 positive and negative validation cases.
 * Version/date: 2026-10-21.
 * Inputs: descriptor identifies the ASN.1 type; bytes/size form the value;
 *         expected is one for acceptance and zero for rejection.
 * Returns: no value.
 * Exceptions: assert aborts when validation differs from expectation.
 * Responsible party: asn1c maintainers.
 * History: added for issue #582.
 * Example: check_constraint(&asn_DEF_ClosedVisible, "b", 1, 1).
 */
static void
check_constraint(asn_TYPE_descriptor_t *descriptor, const void *bytes,
                 size_t size, int expected) {
    assert(constraint_accepts(descriptor, bytes, size) == expected);
}

/*
 * Purpose: verify PER alphabet metadata has no alphabet extension bit.
 * Original source: X.691 10.3.11 and 30.5.1-30.5.4.
 * Version/date: 2026-10-21.
 * Inputs: descriptor is a generated string type; map_expected selects whether
 *         its effective alphabet requires a value/code map.
 * Returns: no value.
 * Exceptions: assertions abort on incorrect flags or map pointers.
 * Responsible party: asn1c maintainers.
 * History: added for issue #582's effective alphabet controls.
 * Example: check_per_alphabet(&asn_DEF_OpenNumeric, 1).
 */
static void
check_per_alphabet(const asn_TYPE_descriptor_t *descriptor, int map_expected) {
    const asn_per_constraints_t *constraints =
        descriptor->encoding_constraints.per_constraints;

    assert(constraints != NULL);
    assert(!!constraints->value2code == !!map_expected);
    assert(!!constraints->code2value == !!map_expected);
    assert(!(constraints->value.flags & APC_EXTENSIBLE));
}

/*
 * Purpose: encode and decode the reporter's issue #582 value.
 * Original source: issue #582 expected vector and X.691 alphabet rules.
 * Version/date: 2026-10-21.
 * Inputs: encode/decode select the PER variant; expected is its golden bytes.
 * Returns: no value.
 * Exceptions: assertions abort on length, bytes, or round-trip mismatches.
 * Responsible party: asn1c maintainers.
 * History: added with the issue #582 regression test.
 * Example: check_rec(uper_encode_to_buffer, uper_decode_complete, expected).
 */
static void
check_rec(encode_f encode, decode_f decode, const uint8_t *expected,
          size_t expected_size, ssize_t expected_bits) {
    static const char letters[] = "ab";
    Rec_t source = { 0 };
    Rec_t *decoded = NULL;
    uint8_t encoded_buf[16] = { 0 };
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;

    assert(OCTET_STRING_fromBuf(&source.word, letters, 2) == 0);
    assert(OCTET_STRING_fromBuf(&source.ia5, letters, 2) == 0);
    assert(OCTET_STRING_fromBuf(&source.sizedFrom, letters, 2) == 0);

    encoded = encode(&asn_DEF_Rec, NULL, &source, encoded_buf,
                     sizeof(encoded_buf));
    assert(encoded.encoded == expected_bits);
    assert(memcmp(encoded_buf, expected, expected_size) == 0);

    result = decode(NULL, &asn_DEF_Rec, (void **)&decoded,
                    expected, expected_size);
    assert(result.code == RC_OK);
    assert(decoded != NULL);
    assert(decoded->word.size == 2);
    assert(memcmp(decoded->word.buf, letters, 2) == 0);
    assert(decoded->ia5.size == 2);
    assert(memcmp(decoded->ia5.buf, letters, 2) == 0);
    assert(decoded->sizedFrom.size == 2);
    assert(memcmp(decoded->sizedFrom.buf, letters, 2) == 0);

    ASN_STRUCT_FREE(asn_DEF_Rec, decoded);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Rec, &source);
}

/*
 * Purpose: verify that an extensible FROM root does not restrict validation.
 * Original source: X.691 extensible permitted-alphabet rules and issue #582.
 * Version/date: 2026-10-21.
 * Inputs: none; the test values include base, extension, and invalid characters.
 * Returns: no value.
 * Exceptions: assert aborts if an open or closed alphabet is misapplied.
 * Responsible party: asn1c maintainers.
 * History: added for issue #582, including the EXCEPT validation security fix.
 * Example: An uppercase VisibleString character is in the extension repertoire.
 */
static void
check_abstract_constraints(void) {
    static const uint8_t uppercase = 'A';
    static const uint8_t in_closed = 'b';
    static const uint8_t after_closed = 'e';
    static const uint8_t invalid_visible = 0x7f;
    static const uint8_t invalid_ia5 = 0x80;
    static const uint8_t bmp_upper[] = { 0x00, 'A' };
    static const uint8_t universal_upper[] = { 0, 0, 0, 'A' };
    static const uint8_t universal_high_bit[] = { 0x80, 0, 0, 0 };
    static const uint8_t universal_max[] = { 0xff, 0xff, 0xff, 0xff };
    static const uint8_t universal_closed[] = { 0, 0, 0, 'b' };
    static const uint8_t bmp_space[] = { 0x00, ' ' };
    static const uint8_t excepted = 'x';
    static const uint8_t retained = 'y';
    static const uint8_t numeric[] = " 19";
    static const uint8_t printable[] = "AZ";

    check_constraint(&asn_DEF_OpenVisible, &uppercase, 1, 1);
    check_constraint(&asn_DEF_OpenVisible, &invalid_visible, 1, 0);
    check_constraint(&asn_DEF_OpenVisibleAdditions, &uppercase, 1, 1);
    check_constraint(&asn_DEF_OpenIA5, &uppercase, 1, 1);
    check_constraint(&asn_DEF_OpenIA5, &invalid_ia5, 1, 0);
    check_constraint(&asn_DEF_OpenBMP, bmp_upper, sizeof(bmp_upper), 1);
    check_constraint(&asn_DEF_OpenUniversal, universal_upper,
                     sizeof(universal_upper), 1);
    check_constraint(&asn_DEF_ClosedUniversal, universal_closed,
                     sizeof(universal_closed), 1);
    check_constraint(&asn_DEF_ClosedUniversal, universal_high_bit,
                     sizeof(universal_high_bit), 0);
    check_constraint(&asn_DEF_ClosedUniversal, universal_max,
                     sizeof(universal_max), 0);
    check_constraint(&asn_DEF_AllExceptSpace, bmp_upper, sizeof(bmp_upper), 1);
    check_constraint(&asn_DEF_AllExceptSpace, bmp_space, sizeof(bmp_space), 0);
    check_constraint(&asn_DEF_ClosedVisible, &in_closed, 1, 1);
    check_constraint(&asn_DEF_ClosedVisible, &after_closed, 1, 0);
    check_constraint(&asn_DEF_ClosedVisible, &uppercase, 1, 0);
    check_constraint(&asn_DEF_SerialClosedVisible, &in_closed, 1, 1);
    check_constraint(&asn_DEF_SerialClosedVisible, &after_closed, 1, 0);
    check_constraint(&asn_DEF_SerialClosedVisible, &uppercase, 1, 0);
    check_constraint(&asn_DEF_IntersectionVisible, &in_closed, 1, 1);
    check_constraint(&asn_DEF_IntersectionVisible, &after_closed, 1, 0);
    check_constraint(&asn_DEF_SerialSizeVisible, "ab", 2, 1);
    check_constraint(&asn_DEF_AliasSizeVisible, "ab", 2, 1);
    check_constraint(&asn_DEF_SerialSizeVisible, "", 0, 0);
    check_constraint(&asn_DEF_AliasSizeVisible, "", 0, 0);
    check_constraint(&asn_DEF_SerialSizeVisible, "123456789", 9, 0);
    check_constraint(&asn_DEF_AliasSizeVisible, "123456789", 9, 0);
    check_constraint(&asn_DEF_NarrowVisible, &uppercase, 1, 0);
    check_constraint(&asn_DEF_ExceptX, &retained, 1, 1);
    check_constraint(&asn_DEF_ExceptX, &excepted, 1, 0);
    check_constraint(&asn_DEF_ExceptAll, NULL, 0, 1);
    check_constraint(&asn_DEF_ExceptAll, &retained, 1, 0);
    check_constraint(&asn_DEF_OpenNumeric, numeric, sizeof(numeric) - 1, 1);
    check_constraint(&asn_DEF_OpenPrintable, printable,
                     sizeof(printable) - 1, 1);
}

/*
 * Purpose: verify that sparse built-in alphabet maps round-trip safely.
 * Original source: X.691 known-multiplier alphabet coding rules.
 * Version/date: 2026-10-21.
 * Inputs: descriptor and text select a sparse alphabet type and valid value;
 *         encode/decode select the codec.
 * Returns: no value.
 * Exceptions: assertions abort on an invalid map or changed value.
 * Responsible party: asn1c maintainers.
 * History: added for issue #582's NumericString/PrintableString controls.
 * Example: check_string_map(&asn_DEF_OpenNumeric, " 19",
 *                           uper_encode_to_buffer, uper_decode_complete).
 */
static void
check_string_map(asn_TYPE_descriptor_t *descriptor, const char *text,
                 encode_f encode, decode_f decode) {
    OCTET_STRING_t source = { 0 };
    OCTET_STRING_t *decoded = NULL;
    uint8_t buffer[16] = { 0 };
    size_t text_size = strlen(text);
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;

    assert(OCTET_STRING_fromBuf(&source, text, (int)text_size) == 0);
    encoded = encode(descriptor, NULL, &source, buffer,
                     sizeof(buffer));
    assert(encoded.encoded > 0);
    result = decode(NULL, descriptor, (void **)&decoded,
                    buffer, (size_t)(encoded.encoded + 7) / 8);
    assert(result.code == RC_OK);
    assert(decoded != NULL);
    assert(decoded->size == text_size);
    assert(memcmp(decoded->buf, text, text_size) == 0);

    ASN_STRUCT_FREE(*descriptor, decoded);
    ASN_STRUCT_FREE_CONTENTS_ONLY(*descriptor, &source);
}

/*
 * Purpose: reject invalid NumericString alphabet indexes and truncated Rec data.
 * Original source: malformed-input security regression cases for issue #582.
 * Version/date: 2026-10-21.
 * Inputs: decode selects UPER or APER; the invalid index uses code 11 of 11.
 * Returns: no value.
 * Exceptions: partial decoder allocations are freed before return.
 * Responsible party: asn1c maintainers.
 * History: added to cover map bounds and truncated string decoding.
 * Example: check_malformed(uper_decode_complete, expected_uper, sizeof(...)).
 */
static void
check_malformed(decode_f decode, const uint8_t *valid, size_t valid_size) {
    static const uint8_t invalid_index[] = { 0x01, 0xb0 };
    NumericString_t *bad_numeric = NULL;
    Rec_t *partial = NULL;
    asn_dec_rval_t result;

    result = decode(NULL, &asn_DEF_OpenNumeric, (void **)&bad_numeric,
                    invalid_index, sizeof(invalid_index));
    assert(result.code != RC_OK);
    if(bad_numeric) ASN_STRUCT_FREE(asn_DEF_OpenNumeric, bad_numeric);

    result = decode(NULL, &asn_DEF_Rec, (void **)&partial, valid,
                    valid_size - 1);
    assert(result.code != RC_OK);
    if(partial) ASN_STRUCT_FREE(asn_DEF_Rec, partial);
}

/*
 * Purpose: run the independently known UPER and APER regression cases.
 * Original source: issue #582 reproduction.
 * Version/date: 2026-10-21.
 * Inputs: none; test vectors are fixed to the reproduced schema and value.
 * Returns: zero when both codecs round-trip correctly.
 * Exceptions: assertions abort on a failure.
 * Responsible party: asn1c maintainers.
 * History: added for issue #582.
 * Example: main();
 */
int
main(void) {
    static const uint8_t expected_uper[] = {
        0x02, 0xc3, 0x88, 0x0b, 0x0e, 0x21, 0xc3, 0x88
    };
    static const uint8_t expected_aper[] = {
        0x02, 0x61, 0x62, 0x02, 0x61, 0x62, 0x10, 0x61, 0x62
    };

    check_rec(uper_encode_to_buffer, uper_decode_complete,
              expected_uper, sizeof(expected_uper), 62);
    check_rec(aper_encode_to_buffer, aper_decode_complete,
              expected_aper, sizeof(expected_aper), 72);
    check_abstract_constraints();
    check_per_alphabet(&asn_DEF_OpenVisible, 0);
    check_per_alphabet(&asn_DEF_OpenNumeric, 1);
    check_per_alphabet(&asn_DEF_OpenPrintable, 0);
    check_per_alphabet(&asn_DEF_OpenBMP, 0);
    check_per_alphabet(&asn_DEF_OpenUniversal, 0);
    check_string_map(&asn_DEF_OpenNumeric, " 19",
                     uper_encode_to_buffer, uper_decode_complete);
    check_string_map(&asn_DEF_OpenNumeric, " 19",
                     aper_encode_to_buffer, aper_decode_complete);
    check_string_map(&asn_DEF_OpenPrintable, "AZ",
                     uper_encode_to_buffer, uper_decode_complete);
    check_string_map(&asn_DEF_OpenPrintable, "AZ",
                     aper_encode_to_buffer, aper_decode_complete);
    check_malformed(uper_decode_complete, expected_uper,
                    sizeof(expected_uper));
    check_malformed(aper_decode_complete, expected_aper,
                    sizeof(expected_aper));
    return 0;
}
