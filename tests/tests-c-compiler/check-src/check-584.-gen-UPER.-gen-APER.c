/*
 * Purpose: verify issue #584 implied ENUMERATED normalization and PER behavior.
 * Original source: issue #584 reproduction from Ruud Schramp (@Schramp).
 * Version/date: 2026-10-21.
 * Inputs: generated descriptors and valid, unknown-extension, and truncated
 *         UPER/APER encodings from 584-implied-enum-OK.asn1.
 * Returns: process status zero when all assertions pass.
 * Exceptions: assertions abort on mismatches; any partial decode is freed.
 * Responsible party: asn1c maintainers; report cross-validated with
 *                    gambas-asn1 assisted by Claude Code.
 * History: added for issue #584.
 * Example: make check runs this test with -gen-UPER -gen-APER.
 */
#undef NDEBUG

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <aper_decoder.h>
#include <aper_encoder.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

#include "AliasRec.h"
#include "Colour.h"
#include "ColourAlias.h"
#include "Explicit.h"
#include "ImpliedEnum.h"
#include "ImportedImpliedRec.h"
#include "ImportedPlainRec.h"
#include "NamedBits.h"
#include "NamedInt.h"
#include "PlainEnum.h"
#include "Rec.h"

/* These signatures let the same checks exercise both PER codec variants. */
typedef asn_enc_rval_t (*encode_to_buffer_f)(
    const asn_TYPE_descriptor_t *, const asn_per_constraints_t *, const void *,
    void *, size_t);
typedef asn_dec_rval_t (*decode_complete_f)(
    const asn_codec_ctx_t *, const asn_TYPE_descriptor_t *, void **,
    const void *, size_t);
typedef asn_dec_rval_t (*decode_partial_f)(
    const asn_codec_ctx_t *, const asn_TYPE_descriptor_t *, void **,
    const void *, size_t, int, int);

/*
 * Purpose: require a descriptor's PER value constraint to match expectation.
 * Original source: new descriptor checks for issue #584.
 * Version/date: 2026-10-21.
 * Inputs: descriptor is the generated type; expected is nonzero if extensible.
 * Returns: no value.
 * Exceptions: assert aborts if the descriptor or flag is incorrect.
 * Responsible party: asn1c maintainers.
 * History: added with the issue #584 regression test.
 * Example: check_extensible(&asn_DEF_Colour, 1);
 */
static void
check_extensible(const asn_TYPE_descriptor_t *descriptor, int expected) {
    const asn_per_constraints_t *constraints =
        descriptor->encoding_constraints.per_constraints;

    assert(constraints != NULL);
    assert(!!(constraints->value.flags & APC_EXTENSIBLE) == !!expected);
}

/*
 * Purpose: verify a value is encoded to and decoded from the golden Rec bytes.
 * Original source: issue #584's green/high reproduction and X.691 bit layout.
 * Version/date: 2026-10-21.
 * Inputs: encode and decode select UPER or APER; expected is the golden byte.
 * Returns: no value.
 * Exceptions: assert aborts on a wrong length, byte, decode result, or value.
 * Responsible party: asn1c maintainers; the expected UPER vector is cross-
 *                    validated against the issue reporter's independent case.
 * History: added with the issue #584 regression test.
 * Example: check_rec_codec(uper_encode_to_buffer, uper_decode_complete, 0x14);
 */
static void
check_rec_codec(encode_to_buffer_f encode, decode_complete_f decode,
                uint8_t expected) {
    Rec_t source = { .colour = 1, .priority = 1 };
    Rec_t *decoded = NULL;
    uint8_t buffer[1] = { 0 };
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;

    encoded = encode(&asn_DEF_Rec, NULL, &source, buffer, sizeof(buffer));
    assert(encoded.encoded == 6);
    assert(buffer[0] == expected);

    result = decode(NULL, &asn_DEF_Rec, (void **)&decoded, buffer,
                    sizeof(buffer));
    assert(result.code == RC_OK);
    assert(decoded != NULL);
    assert(decoded->colour == source.colour);
    assert(decoded->priority == source.priority);
    ASN_STRUCT_FREE(asn_DEF_Rec, decoded);
}

/*
 * Purpose: require unknown extension index zero to decode and relay losslessly.
 * Original source: existing NativeEnumerated unknown-extension vectors.
 * Version/date: 2026-10-21.
 * Inputs: decode and encode select UPER or APER.
 * Returns: no value.
 * Exceptions: assert aborts on a decode mismatch or non-identical relay.
 * Responsible party: asn1c maintainers.
 * History: added to check implied enum extension support through both codecs.
 * Example: check_unknown_extension(uper_decode_complete,
 *                                  uper_encode_to_buffer);
 */
static void
check_unknown_extension(decode_complete_f decode, encode_to_buffer_f encode) {
    static const uint8_t unknown[] = { 0x80 };
    long *decoded = NULL;
    uint8_t relayed[sizeof(unknown)] = { 0 };
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;

    result = decode(NULL, &asn_DEF_Colour, (void **)&decoded, unknown,
                    sizeof(unknown));
    assert(result.code == RC_OK);
    assert(decoded != NULL);
    assert(*decoded == LONG_MAX);
    encoded = encode(&asn_DEF_Colour, NULL, decoded, relayed,
                     sizeof(relayed));
    assert(encoded.encoded == 8);
    assert(memcmp(relayed, unknown, sizeof(unknown)) == 0);
    ASN_STRUCT_FREE(asn_DEF_Colour, decoded);
}

/*
 * Purpose: ensure a lone extension bit is rejected as a truncated index.
 * Original source: malformed-input regression for issue #584.
 * Version/date: 2026-10-21.
 * Inputs: decode selects UPER or APER.
 * Returns: no value.
 * Exceptions: assert aborts if truncated input succeeds; partial allocations
 *             are released before the check returns.
 * Responsible party: asn1c maintainers.
 * History: added to guard PER decoders against incomplete extension ordinals.
 * Example: check_truncated_extension(uper_decode);
 */
static void
check_truncated_extension(decode_partial_f decode) {
    static const uint8_t truncated[] = { 0x80 };
    long *decoded = NULL;
    asn_dec_rval_t result;

    result = decode(NULL, &asn_DEF_Colour, (void **)&decoded, truncated,
                    sizeof(truncated), 0, 7);
    assert(result.code != RC_OK);
    if(decoded != NULL)
        ASN_STRUCT_FREE(asn_DEF_Colour, decoded);
}

/*
 * Purpose: reject incomplete and out-of-range root enumeration indexes.
 * Original source: negative PER cases derived from the issue #584 schema.
 * Version/date: 2026-10-21.
 * Inputs: decode selects UPER or APER.
 * Returns: no value.
 * Exceptions: assert aborts on an accepted invalid index; partial objects are
 *             released before the check returns.
 * Responsible party: asn1c maintainers.
 * History: added to cover decoder bounds and truncation for both codecs.
 * Example: check_root_indexes(uper_decode);
 */
static void
check_root_indexes(decode_partial_f decode) {
    static const uint8_t incomplete_root[] = { 0x00 };
    static const uint8_t invalid_root[] = { 0x60 };
    long *decoded = NULL;
    asn_dec_rval_t result;

    /* One of the two root-index bits is missing. */
    result = decode(NULL, &asn_DEF_Colour, (void **)&decoded,
                    incomplete_root, sizeof(incomplete_root), 0, 6);
    assert(result.code != RC_OK);
    if(decoded != NULL) {
        ASN_STRUCT_FREE(asn_DEF_Colour, decoded);
        decoded = NULL;
    }

    /* Root ordinal three is outside the three-member enumeration. */
    result = decode(NULL, &asn_DEF_Colour, (void **)&decoded,
                    invalid_root, sizeof(invalid_root), 0, 5);
    assert(result.code != RC_OK);
    if(decoded != NULL)
        ASN_STRUCT_FREE(asn_DEF_Colour, decoded);
}

/*
 * Purpose: run descriptor, golden-vector, and malformed-input checks.
 * Original source: issue #584 reproduction plus related ownership controls.
 * Version/date: 2026-10-21.
 * Inputs: no parameters.
 * Returns: zero if every check passes.
 * Exceptions: assertions abort on regressions.
 * Responsible party: asn1c maintainers.
 * History: added for issue #584.
 * Example: main();
 */
int
main(void) {
    const asn_TYPE_descriptor_t *inline_priority =
        asn_DEF_Rec.elements[1].type;
    const asn_TYPE_descriptor_t *imported_plain =
        asn_DEF_ImportedPlainRec.elements[0].type;
    const asn_TYPE_descriptor_t *imported_implied =
        asn_DEF_ImportedImpliedRec.elements[0].type;

    check_extensible(&asn_DEF_Colour, 1);
    check_extensible(&asn_DEF_ColourAlias, 1);
    check_extensible(inline_priority, 1);
    check_extensible(&asn_DEF_Explicit, 1);
    check_extensible(&asn_DEF_PlainEnum, 0);
    check_extensible(&asn_DEF_ImpliedEnum, 1);
    check_extensible(imported_plain, 0);
    check_extensible(imported_implied, 1);

    assert(asn_DEF_NamedInt.encoding_constraints.per_constraints == NULL);
    assert(asn_DEF_NamedBits.encoding_constraints.per_constraints == NULL);

    check_rec_codec(uper_encode_to_buffer, uper_decode_complete, 0x14);
    check_rec_codec(aper_encode_to_buffer, aper_decode_complete, 0x14);
    check_unknown_extension(uper_decode_complete, uper_encode_to_buffer);
    check_unknown_extension(aper_decode_complete, aper_encode_to_buffer);
    check_truncated_extension(uper_decode);
    check_truncated_extension(aper_decode);
    check_root_indexes(uper_decode);
    check_root_indexes(aper_decode);
    return 0;
}
