/*
 * Purpose: verify transparent SET extension-group encoding and decoding.
 * Original source: X.680 SET extension additions and issue #583 group behavior.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: generated SetRec descriptors and canonical BER/CER/XER vectors.
 * Returns: zero when all regression, malformed-input, and recovery checks pass.
 * Exceptions: assertions abort on mismatch; decoded values are always freed.
 * Responsible party: asn1c maintainers; no SET reporter is attributed.
 * History: added with flattened SET extension-group support.
 * Example: check-assembly.sh runs this test with -fcompound-names.
 */
#undef NDEBUG

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <asn_internal.h>
#include <ber_decoder.h>
#include <cer_decoder.h>
#include <cer_encoder.h>
#include <der_encoder.h>
#include <xer_decoder.h>
#include <xer_encoder.h>

#include "SetRec.h"
#include "Node.h"

#if defined(__SANITIZE_ADDRESS__) || defined(ASN_DISABLE_STACK_OVERFLOW_CHECK)
#define SET_TEST_STACK_CHECK_DISABLED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SET_TEST_STACK_CHECK_DISABLED 1
#endif
#endif

#ifdef ENABLE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/*
 * Purpose: fuzz BER, CER, and XER decoding of the generated SET descriptor.
 * Original source: SET extension-group decoder regression coverage.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: Data is arbitrary bytes; Size is the available input length.
 * Returns: zero after all decoders complete one attempt.
 * Exceptions: assertions flag over-consumption; every partial value is freed.
 * Responsible party: asn1c maintainers.
 * History: added as the libFuzzer entry point for test 585.
 * Example: libFuzzer calls this function with corpus and generated inputs.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static asn_dec_rval_t (*const decoders[])(const asn_codec_ctx_t *,
            const asn_TYPE_descriptor_t *, void **, const void *, size_t) = {
        ber_decode, cer_decode, xer_decode
    };
    size_t index;

    for(index = 0; index < sizeof(decoders) / sizeof(decoders[0]); index++) {
        SetRec_t *decoded = NULL;
        asn_dec_rval_t result = decoders[index](NULL, &asn_DEF_SetRec,
                (void **)&decoded, Data, Size);
        assert(result.consumed <= Size);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
    }
    return 0;
}

#else

/* Canonical DER uses selected CHOICE tag 9; CER uses its static minimum tag 1. */
static const uint8_t expected_der[] = {
    0x31, 0x0f, 0x82, 0x01, 0xff, 0x85, 0x01, 0x02,
    0x86, 0x01, 0x03, 0x89, 0x01, 0xff, 0x94, 0x01, 0x01
};
static const uint8_t expected_cer[] = {
    0x31, 0x80, 0x89, 0x01, 0xff, 0x82, 0x01, 0xff,
    0x85, 0x01, 0x02, 0x86, 0x01, 0x03, 0x94, 0x01, 0x01,
    0x00, 0x00
};
static const uint8_t absent_group_der[] = {
    0x31, 0x06, 0x81, 0x01, 0x01, 0x94, 0x01, 0x02
};
static const uint8_t missing_group_leaf_ber[] = {
    0x31, 0x09, 0x81, 0x01, 0x01, 0x94, 0x01, 0x02,
    0x83, 0x01, 0xff
};
static const uint8_t old_group_wrapper_ber[] = {
    0x31, 0x0b, 0x81, 0x01, 0x01, 0x94, 0x01, 0x02,
    0xa2, 0x03, 0x85, 0x01, 0x02
};

static unsigned find_member(const asn_TYPE_descriptor_t *, const char *);

/* Bounded callback state used by output checks and deliberate failures. */
typedef struct output_buffer_s {
    uint8_t bytes[512]; /* Collected encoded representation. */
    size_t size;         /* Number of bytes currently stored. */
    int fail;            /* state variable: request callback failure. */
} output_buffer_t;

/*
 * Purpose: collect callback output into a fixed-size test buffer.
 * Original source: test 585 encoder callback support.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: bytes/size are the callback chunk; key points to output_buffer_t.
 * Returns: zero on success; -1 when configured to fail or capacity is exceeded.
 * Exceptions: none.
 * Responsible party: asn1c maintainers.
 * History: added for golden encodings and failure recovery.
 * Example: der_encode(&asn_DEF_SetRec, value, collect_bytes, &output).
 */
static int
collect_bytes(const void *bytes, size_t size, void *key) {
    output_buffer_t *output = (output_buffer_t *)key;

    if(output->fail || size > sizeof(output->bytes) - output->size) return -1;
    if(size) memcpy(output->bytes + output->size, bytes, size);
    output->size += size;
    return 0;
}

/*
 * Purpose: find a byte sequence without requiring a trailing NUL byte.
 * Original source: test 585 bounded-output assertions.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: haystack/size describe output bytes; needle/needle_size describe text.
 * Returns: pointer to the first match or NULL if it is absent.
 * Exceptions: none.
 * Responsible party: asn1c maintainers.
 * History: added instead of relying on nonstandard memmem().
 * Example: find_bytes(output.bytes, output.size, "<SetRec>", 8).
 */
static const uint8_t *
find_bytes(const uint8_t *haystack, size_t size,
           const char *needle, size_t needle_size) {
    size_t offset;

    if(needle_size > size) return NULL;
    for(offset = 0; offset <= size - needle_size; offset++) {
        if(memcmp(haystack + offset, needle, needle_size) == 0) {
            return haystack + offset;
        }
    }
    return NULL;
}

/*
 * Purpose: append a constant XML fragment within a fixed test buffer.
 * Original source: test 585 recursive-XER stack-limit input builder.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: target/capacity own the buffer; used tracks its end; text is appended.
 * Returns: no value; used advances by the appended fragment length.
 * Exceptions: assertion failure reports a test-fixture capacity error.
 * Responsible party: asn1c maintainers.
 * History: added for bounded recursive SET decoder coverage.
 * Example: append_xml(xml, sizeof(xml), &used, "<Node>").
 */
static void
append_xml(char *target, size_t capacity, size_t *used, const char *text) {
    size_t length = strlen(text);

    assert(length <= capacity - *used);
    memcpy(target + *used, text, length);
    *used += length;
}

/*
 * Purpose: initialize a populated value with two present SET extension groups.
 * Original source: test 585 canonical SET value.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: value receives the value; before points to its optional root boolean.
 * Returns: no value; caller owns and frees ext1/ext2 allocations.
 * Exceptions: allocation failure is an assertion failure in this test.
 * Responsible party: asn1c maintainers.
 * History: added to exercise a missing first optional leaf and later required.
 * Example: SetRec_t value = {0}; BOOLEAN_t before; init_value(&value, &before).
 */
static void
init_value(SetRec_t *value, BOOLEAN_t *before) {
    memset(value, 0, sizeof(*value));
    *before = 1;
    value->selectedRoot.present = SetRec__selectedRoot_PR_nested;
    value->selectedRoot.choice.nested.present =
        SetRec__selectedRoot__nested_PR_high;
    value->selectedRoot.choice.nested.choice.high = 1;
    value->rootValue = 1;
    value->before = before;
    value->ext1 = calloc(1, sizeof(*value->ext1));
    value->ext2 = calloc(1, sizeof(*value->ext2));
    assert(value->ext1 != NULL && value->ext2 != NULL);
    value->ext1->first = 2;
    value->ext2->selected.present = SetRec__ext2__selected_PR_number;
    value->ext2->selected.choice.number = 3;
}

/*
 * Purpose: release synthetic group allocations owned by an encoder test value.
 * Original source: test 585 value ownership helper.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: value is the initialized object whose group pointers are owned here.
 * Returns: no value.
 * Exceptions: none.
 * Responsible party: asn1c maintainers.
 * History: added to keep callback failure tests leak-free.
 * Example: free_groups(&value) after the encoders return.
 */
static void
free_groups(SetRec_t *value) {
    free(value->ext1);
    free(value->ext2);
}

/*
 * Purpose: verify exact DER/CER ordering and flat BER/CER decoding.
 * Original source: X.690 8.11, 9.3, and 10.3 SET ordering requirements.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; expected vectors distinguish static and selected tags.
 * Returns: no value.
 * Exceptions: assertions indicate malformed bytes or values; decoded values free.
 * Responsible party: asn1c maintainers.
 * History: added for SET groups with interleaving CHOICE, root, and group leaves.
 * Example: check_binary_codecs().
 */
static void
check_binary_codecs(void) {
    SetRec_t value;
    SetRec_t *decoded = NULL;
    BOOLEAN_t before;
    uint8_t encoded[sizeof(expected_cer)];
    asn_enc_rval_t encode_result;
    asn_dec_rval_t decode_result;

    init_value(&value, &before);
    encode_result = der_encode_to_buffer(&asn_DEF_SetRec, &value,
                                         encoded, sizeof(encoded));
    assert(encode_result.encoded == (ssize_t)sizeof(expected_der));
    assert(memcmp(encoded, expected_der, sizeof(expected_der)) == 0);
    encode_result = cer_encode_to_buffer(NULL, &asn_DEF_SetRec, &value,
                                         encoded, sizeof(encoded));
    assert(encode_result.encoded == (ssize_t)sizeof(expected_cer));
    assert(memcmp(encoded, expected_cer, sizeof(expected_cer)) == 0);

    decode_result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                               expected_der, sizeof(expected_der));
    assert(decode_result.code == RC_OK);
    assert(decode_result.consumed == sizeof(expected_der));
    assert(decoded->selectedRoot.present == SetRec__selectedRoot_PR_nested);
    assert(decoded->selectedRoot.choice.nested.present ==
           SetRec__selectedRoot__nested_PR_high);
    assert(decoded->rootValue == 1 && decoded->before && *decoded->before);
    assert(decoded->ext1 && decoded->ext1->first == 2);
    assert(decoded->ext1->optionalFlag == NULL);
    assert(decoded->ext2 && decoded->ext2->selected.present ==
           SetRec__ext2__selected_PR_number);
    assert(decoded->ext2->selected.choice.number == 3);
    ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);

    decoded = NULL;
    decode_result = cer_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                               expected_cer, sizeof(expected_cer));
    assert(decode_result.code == RC_OK);
    assert(decode_result.consumed == sizeof(expected_cer));
    assert(decoded->ext1 && decoded->ext1->first == 2);
    assert(decoded->ext2 && decoded->ext2->selected.choice.number == 3);
    ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);

    decoded = NULL;
    decode_result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                               absent_group_der, sizeof(absent_group_der));
    assert(decode_result.code == RC_OK);
    assert(decoded->ext1 == NULL && decoded->ext2 == NULL);
    ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);

    decoded = NULL;
    decode_result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                               missing_group_leaf_ber,
                               sizeof(missing_group_leaf_ber));
    assert(decode_result.code != RC_OK);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);

    decoded = NULL;
    decode_result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                               old_group_wrapper_ber,
                               sizeof(old_group_wrapper_ber));
    assert(decode_result.code != RC_OK);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
    free_groups(&value);
}

/*
 * Purpose: bound BER truncation/mutation handling and preserve following PDUs.
 * Original source: test 585 malformed flat SET vectors and decoder framing.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; every prefix and byte mutation of the DER vector runs.
 * Returns: no value.
 * Exceptions: assertions detect over-consumption or wrong PDU boundaries.
 * Responsible party: asn1c maintainers.
 * History: added for malformed-input and unknown-extension coverage.
 * Example: check_ber_malformed().
 */
static void
check_ber_malformed(void) {
    uint8_t joined[sizeof(expected_der) + sizeof(absent_group_der)];
    size_t prefix;
    size_t position;
    unsigned replacement;
    SetRec_t *decoded = NULL;
    asn_dec_rval_t result;

    for(prefix = 0; prefix < sizeof(expected_der); prefix++) {
        result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                            expected_der, prefix);
        assert(result.code != RC_OK && result.consumed <= prefix);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
        decoded = NULL;
    }
    for(position = 0; position < sizeof(expected_der); position++) {
        for(replacement = 0; replacement <= UINT8_MAX; replacement++) {
            uint8_t changed[sizeof(expected_der)];
            memcpy(changed, expected_der, sizeof(changed));
            changed[position] = (uint8_t)replacement;
            result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                                changed, sizeof(changed));
            assert(result.code == RC_OK || result.code == RC_WMORE ||
                   result.code == RC_FAIL);
            assert(result.consumed <= sizeof(changed));
            if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
            decoded = NULL;
        }
    }

    memcpy(joined, expected_der, sizeof(expected_der));
    memcpy(joined + sizeof(expected_der), absent_group_der,
           sizeof(absent_group_der));
    result = ber_decode(NULL, &asn_DEF_SetRec, (void **)&decoded,
                        joined, sizeof(joined));
    assert(result.code == RC_OK && result.consumed == sizeof(expected_der));
    ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
}

/*
 * Purpose: test incremental BER and CER decoding at every input split.
 * Original source: test 585 flat encoding vectors and decoder chunk contract.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; all prefixes of each complete golden vector are tried.
 * Returns: no value.
 * Exceptions: assertions flag lost or over-consumed bytes; partial values freed.
 * Responsible party: asn1c maintainers.
 * History: added for split-boundary coverage of flat group leaves.
 * Example: check_splits().
 */
static void
check_splits(void) {
    const uint8_t *vectors[] = { expected_der, expected_cer };
    const size_t sizes[] = { sizeof(expected_der), sizeof(expected_cer) };
    size_t vector_index;

    for(vector_index = 0; vector_index < 2; vector_index++) {
        size_t split;
        for(split = 0; split <= sizes[vector_index]; split++) {
            SetRec_t *decoded = NULL;
            asn_dec_rval_t (*decoder)(const asn_codec_ctx_t *,
                    const asn_TYPE_descriptor_t *, void **,
                    const void *, size_t) = vector_index ? cer_decode : ber_decode;
            asn_dec_rval_t first = decoder(NULL, &asn_DEF_SetRec,
                    (void **)&decoded, vectors[vector_index], split);
            assert(first.consumed <= split);
            if(split < sizes[vector_index]) assert(first.code == RC_WMORE);
            if(first.code == RC_WMORE) {
                size_t consumed = first.consumed;
                asn_dec_rval_t second = decoder(NULL, &asn_DEF_SetRec,
                        (void **)&decoded, vectors[vector_index] + consumed,
                        sizes[vector_index] - consumed);
                assert(second.code == RC_OK);
                assert(consumed + second.consumed == sizes[vector_index]);
            } else {
                assert(split == sizes[vector_index] && first.code == RC_OK);
                assert(first.consumed == sizes[vector_index]);
            }
            if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
        }
    }
}

/*
 * Purpose: verify canonical XER flattens groups and handles DEFAULT scope.
 * Original source: X.693 9.6 canonical root/extension ordering and DEFAULT.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; compares a populated group with an absent group.
 * Returns: no value.
 * Exceptions: assertions flag wrapper/default leakage or ordering errors.
 * Responsible party: asn1c maintainers.
 * History: added for group DEFAULT materialization regression.
 * Example: check_xer().
 */
static void
check_xer(void) {
    SetRec_t value;
    SetRec_t absent;
    BOOLEAN_t before;
    output_buffer_t output = { { 0 }, 0, 0 };
    output_buffer_t absent_output = { { 0 }, 0, 0 };
    asn_enc_rval_t result;
    const uint8_t *root;
    const uint8_t *root_value;
    const uint8_t *before_leaf;
    const uint8_t *default_leaf;
    const uint8_t *group_leaf;

    init_value(&value, &before);
    memset(&absent, 0, sizeof(absent));
    absent.selectedRoot.present = SetRec__selectedRoot_PR_nested;
    absent.selectedRoot.choice.nested.present =
        SetRec__selectedRoot__nested_PR_low;
    absent.selectedRoot.choice.nested.choice.low = 1;
    absent.rootValue = 2;
    result = xer_encode(&asn_DEF_SetRec, &value, XER_F_CANONICAL,
                        collect_bytes, &output);
    assert(result.encoded == (ssize_t)output.size);
    assert(find_bytes(output.bytes, output.size, "<ext1>", 6) == NULL);
    assert(find_bytes(output.bytes, output.size, "<ext2>", 6) == NULL);
    root = find_bytes(output.bytes, output.size, "<selectedRoot>", 14);
    root_value = find_bytes(output.bytes, output.size, "<rootValue>", 11);
    before_leaf = find_bytes(output.bytes, output.size, "<before>", 8);
    default_leaf = find_bytes(output.bytes, output.size, "<defaultFlag>", 13);
    group_leaf = find_bytes(output.bytes, output.size, "<first>2</first>", 16);
    assert(root && root_value && before_leaf && default_leaf && group_leaf);
    assert(root < root_value && root_value < before_leaf);
    assert(before_leaf < default_leaf && default_leaf < group_leaf);
    assert(find_bytes(output.bytes, output.size,
                      "<defaultFlag><true/></defaultFlag>", 34) != NULL);
    {
        size_t split;
        for(split = 0; split <= output.size; split++) {
            SetRec_t *decoded = NULL;
            asn_dec_rval_t first = xer_decode(NULL, &asn_DEF_SetRec,
                    (void **)&decoded, output.bytes, split);
            assert(first.consumed <= split);
            if(split < output.size) assert(first.code == RC_WMORE);
            if(first.code == RC_WMORE) {
                size_t consumed = first.consumed;
                asn_dec_rval_t second = xer_decode(NULL, &asn_DEF_SetRec,
                        (void **)&decoded, output.bytes + consumed,
                        output.size - consumed);
                assert(second.code == RC_OK);
                assert(consumed + second.consumed == output.size);
                assert(decoded->ext1 && decoded->ext1->defaultFlag);
                assert(*decoded->ext1->defaultFlag != 0);
            } else {
                assert(split == output.size && first.code == RC_OK);
                assert(first.consumed == output.size);
            }
            if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
        }
    }

    result = xer_encode(&asn_DEF_SetRec, &absent, XER_F_CANONICAL,
                        collect_bytes, &absent_output);
    assert(result.encoded == (ssize_t)absent_output.size);
    assert(find_bytes(absent_output.bytes, absent_output.size,
                      "defaultFlag", 11) == NULL);
    assert(find_bytes(absent_output.bytes, absent_output.size,
                      "<first>", 7) == NULL);
    free_groups(&value);
}

/*
 * Purpose: skip unknown nested XML without treating a hidden group leaf as set.
 * Original source: review of SET extension XER unknown-subtree handling.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; unknown nested markup precedes the real `first` leaf.
 * Returns: no value.
 * Exceptions: assertions detect leaked values or split-boundary state errors.
 * Responsible party: asn1c maintainers.
 * History: added after review found a possible unknown-subtree phase bug.
 * Example: check_xer_unknown_group_leaf().
 */
static void
check_xer_unknown_group_leaf(void) {
    static const char xml[] =
        "<SetRec><selectedRoot><nested><high><true/></high></nested>"
        "</selectedRoot><rootValue>1</rootValue><before><true/></before>"
        "<unknown><nested><first>99</first></nested></unknown>"
        "<first>2</first></SetRec>";
    size_t split;

    for(split = 0; split <= sizeof(xml) - 1; split++) {
        SetRec_t *decoded = NULL;
        asn_dec_rval_t first = xer_decode(NULL, &asn_DEF_SetRec,
                (void **)&decoded, xml, split);
        assert(first.consumed <= split);
        if(split < sizeof(xml) - 1) assert(first.code == RC_WMORE);
        if(first.code == RC_WMORE) {
            size_t consumed = first.consumed;
            asn_dec_rval_t second = xer_decode(NULL, &asn_DEF_SetRec,
                    (void **)&decoded, xml + consumed,
                    sizeof(xml) - 1 - consumed);
            assert(second.code == RC_OK);
            assert(consumed + second.consumed == sizeof(xml) - 1);
        } else {
            assert(split == sizeof(xml) - 1 && first.code == RC_OK);
        }
        assert(decoded && decoded->ext1 && decoded->ext1->first == 2);
        assert(decoded->ext1->optionalFlag == NULL);
        ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
    }
}

/*
 * Purpose: reject a child XER decoder that reports beyond its input boundary.
 * Original source: review of SET XER member-consumption validation.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: the fake decoder receives one ordinary root member's bounded bytes.
 * Returns: RC_OK with consumed=size+1 to simulate a faulty child callback.
 * Exceptions: none; the parent decoder must convert the invalid count to fail.
 * Responsible party: asn1c maintainers.
 * History: added after review found an unchecked consumed-count subtraction.
 * Example: check_xer_consumed_bound().
 */
static asn_dec_rval_t
overconsuming_xer_decoder(const asn_codec_ctx_t *codec_ctx,
                          const asn_TYPE_descriptor_t *td, void **value,
                          const char *member_name, const void *buffer,
                          size_t size) {
    asn_dec_rval_t result = { RC_OK, size + 1 };

    (void)codec_ctx;
    (void)td;
    (void)value;
    (void)member_name;
    (void)buffer;
    return result;
}

/*
 * Purpose: protect SET XER framing against a child decoder over-consumption.
 * Original source: malformed test descriptor for SET_rec_decode_xer.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; a private descriptor copy substitutes one callback.
 * Returns: no value.
 * Exceptions: assertions flag acceptance or over-consumption of malformed data.
 * Responsible party: asn1c maintainers.
 * History: added for the XER_ADVANCE consumed-bound regression.
 * Example: check_xer_consumed_bound().
 */
static void
check_xer_consumed_bound(void) {
    static const char xml[] =
        "<SetRec><selectedRoot><nested><low>1</low></nested></selectedRoot>"
        "<rootValue>1</rootValue></SetRec>";
    asn_TYPE_descriptor_t parent = asn_DEF_SetRec;
    asn_TYPE_descriptor_t child = *parent.elements[0].type;
    asn_TYPE_operation_t child_ops = *child.op;
    asn_TYPE_member_t *members = malloc(parent.elements_count *
                                        sizeof(*members));
    SetRec_t *decoded = NULL;
    asn_dec_rval_t result;

    assert(members != NULL);
    memcpy(members, parent.elements, parent.elements_count * sizeof(*members));
    child_ops.xer_decoder = overconsuming_xer_decoder;
    child.op = &child_ops;
    members[0].type = &child;
    parent.elements = members;
    result = xer_decode(NULL, &parent, (void **)&decoded, xml,
                        sizeof(xml) - 1);
    assert(result.code == RC_FAIL);
    assert(result.consumed <= sizeof(xml) - 1);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
    free(members);
}

/*
 * Purpose: reject invalid parent presence-map offsets before decoder writes.
 * Original source: review of malformed SET descriptor bounds in BER and XER.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; copied specifics set the parent offset to UINT_MAX.
 * Returns: no value.
 * Exceptions: assertions flag an accepted descriptor or consumed-size breach.
 * Responsible party: asn1c maintainers.
 * History: added for parent-level SET metadata validation coverage.
 * Example: check_decode_bad_presence_offset().
 */
static void
check_decode_bad_presence_offset(void) {
    static const char xml[] = "<SetRec><rootValue>1</rootValue></SetRec>";
    asn_TYPE_descriptor_t parent = asn_DEF_SetRec;
    asn_SET_specifics_t specifics =
        *(const asn_SET_specifics_t *)parent.specifics;
    SetRec_t *decoded = NULL;
    asn_dec_rval_t result;

    specifics.pres_offset = UINT_MAX;
    parent.specifics = &specifics;
    result = ber_decode(NULL, &parent, (void **)&decoded,
                        expected_der, sizeof(expected_der));
    assert(result.code == RC_FAIL);
    assert(result.consumed <= sizeof(expected_der));
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
    decoded = NULL;
    result = xer_decode(NULL, &parent, (void **)&decoded, xml, sizeof(xml) - 1);
    assert(result.code == RC_FAIL);
    assert(result.consumed <= sizeof(xml) - 1);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
}

/*
 * Purpose: assert that BER or XER rejects a malformed descriptor safely.
 * Original source: SET descriptor-offset regression checks.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: decoder/td select the codec and copied descriptor; data/size bound it.
 * Returns: no value.
 * Exceptions: assertions detect acceptance or consumption beyond the input.
 * Responsible party: asn1c maintainers.
 * History: added for inline-member storage-width validation.
 * Example: expect_bad_set_decode(ber_decode, &bad, expected_der, sizeof(...)).
 */
static void
expect_bad_set_decode(asn_dec_rval_t (*decoder)(const asn_codec_ctx_t *,
                             const asn_TYPE_descriptor_t *, void **,
                             const void *, size_t),
                     const asn_TYPE_descriptor_t *td,
                     const void *data, size_t size) {
    SetRec_t *decoded = NULL;
    asn_dec_rval_t result = decoder(NULL, td, (void **)&decoded, data, size);

    assert(result.code == RC_FAIL);
    assert(result.consumed <= size);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetRec, decoded);
}

/*
 * Purpose: reject inline member offsets that cannot hold their native values.
 * Original source: malformed SET descriptor storage-width regression checks.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; copied parent and group descriptors are corrupted.
 * Returns: no value.
 * Exceptions: assertions detect acceptance, over-consumption, or unsafe writes.
 * Responsible party: asn1c maintainers.
 * History: added for parent and synthetic-group inline field bounds.
 * Example: check_decode_bad_member_offsets().
 */
static void
check_decode_bad_member_offsets(void) {
    static const char xml[] =
        "<SetRec><selectedRoot><nested><high><true/></high></nested>"
        "</selectedRoot><rootValue>1</rootValue><before><true/></before>"
        "<first>2</first></SetRec>";
    asn_TYPE_descriptor_t parent = asn_DEF_SetRec;
    asn_SET_specifics_t parent_specs =
        *(const asn_SET_specifics_t *)parent.specifics;
    asn_TYPE_member_t parent_members[16];
    unsigned root_index = find_member(&parent, "rootValue");
    unsigned group_index = find_member(&parent, "ext1");
    unsigned child_index;

    assert(parent.elements_count <= 16);
    assert(root_index < parent.elements_count);
    assert(group_index < parent.elements_count);
    memcpy(parent_members, parent.elements,
           parent.elements_count * sizeof(*parent_members));
    parent.elements = parent_members;
    parent_members[root_index].memb_offset = parent_specs.struct_size - 1;
    expect_bad_set_decode(ber_decode, &parent, expected_der,
                          sizeof(expected_der));
    expect_bad_set_decode(xer_decode, &parent, xml, sizeof(xml) - 1);

    parent = asn_DEF_SetRec;
    memcpy(parent_members, parent.elements,
           parent.elements_count * sizeof(*parent_members));
    {
        asn_TYPE_descriptor_t group = *parent_members[group_index].type;
        asn_TYPE_member_t children[16];

        assert(group.elements_count <= 16);
        memcpy(children, group.elements, group.elements_count * sizeof(*children));
        child_index = find_member(&group, "first");
        assert(child_index < group.elements_count);
        group.elements = children;
        parent_members[group_index].type = &group;
        parent.elements = parent_members;
        children[child_index].memb_offset =
            ((const asn_SET_specifics_t *)group.specifics)->struct_size - 1;
        expect_bad_set_decode(ber_decode, &parent, expected_der,
                              sizeof(expected_der));
        expect_bad_set_decode(xer_decode, &parent, xml, sizeof(xml) - 1);
    }
}

/*
 * Purpose: exercise callback failure recovery for DER, CER, and XER encoders.
 * Original source: test 585 output-callback error-path regression.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; a populated valid value follows each failed callback.
 * Returns: no value.
 * Exceptions: assertions flag stale recursion/resource state after failure.
 * Responsible party: asn1c maintainers.
 * History: added for encoder cleanup and recovery coverage.
 * Example: check_callback_recovery().
 */
static void
check_callback_recovery(void) {
    SetRec_t value;
    BOOLEAN_t before;
    output_buffer_t failing = { { 0 }, 0, 1 };
    output_buffer_t succeeding = { { 0 }, 0, 0 };
    asn_enc_rval_t result;

    init_value(&value, &before);
    result = der_encode(&asn_DEF_SetRec, &value, collect_bytes, &failing);
    assert(result.encoded == -1);
    result = der_encode(&asn_DEF_SetRec, &value, collect_bytes, &succeeding);
    assert(result.encoded == (ssize_t)sizeof(expected_der));
    memset(&failing, 0, sizeof(failing));
    failing.fail = 1;
    result = cer_encode(NULL, &asn_DEF_SetRec, &value,
                        collect_bytes, &failing);
    assert(result.encoded == -1);
    memset(&succeeding, 0, sizeof(succeeding));
    result = cer_encode(NULL, &asn_DEF_SetRec, &value,
                        collect_bytes, &succeeding);
    assert(result.encoded == (ssize_t)sizeof(expected_cer));
    memset(&failing, 0, sizeof(failing));
    failing.fail = 1;
    result = xer_encode(&asn_DEF_SetRec, &value, XER_F_CANONICAL,
                        collect_bytes, &failing);
    assert(result.encoded == -1);
    memset(&succeeding, 0, sizeof(succeeding));
    result = xer_encode(&asn_DEF_SetRec, &value, XER_F_CANONICAL,
                        collect_bytes, &succeeding);
    assert(result.encoded == (ssize_t)succeeding.size);
    free_groups(&value);
}

/*
 * Purpose: find a generated SET member index by its descriptor name.
 * Original source: test 585 malformed-descriptor helpers.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: td is a generated descriptor; name is the expected member name.
 * Returns: matching index, or elements_count when no match exists.
 * Exceptions: none.
 * Responsible party: asn1c maintainers.
 * History: added to avoid hard-coding synthetic member positions.
 * Example: find_member(&asn_DEF_SetRec, "ext1").
 */
static unsigned
find_member(const asn_TYPE_descriptor_t *td, const char *name) {
    unsigned index;

    for(index = 0; index < td->elements_count; index++) {
        if(strcmp(td->elements[index].name, name) == 0) return index;
    }
    return td->elements_count;
}

/*
 * Purpose: assert that CER rejects a descriptor/value pair without crashing.
 * Original source: test 585 bounded malformed-descriptor probes.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: td/value are the candidate descriptor and matching value object.
 * Returns: no value.
 * Exceptions: assertion failure means malformed metadata was accepted.
 * Responsible party: asn1c maintainers.
 * History: added for descriptor validation coverage.
 * Example: expect_cer_rejected(&bad_parent, &value).
 */
static void
expect_cer_rejected(const asn_TYPE_descriptor_t *td, const void *value) {
    uint8_t output[128];
    asn_enc_rval_t result = cer_encode_to_buffer(NULL, td, value,
                                                 output, sizeof(output));
    assert(result.encoded == -1);
}

/*
 * Purpose: reject malformed SET/group tables and missing pointer-backed leaves.
 * Original source: CER SET descriptor and mandatory-mask security review.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; local descriptor copies leave generated metadata intact.
 * Returns: no value.
 * Exceptions: assertions detect acceptance or corruption; group memory is freed.
 * Responsible party: asn1c maintainers.
 * History: added for malformed-offset and missing-mandatory-value defenses.
 * Example: check_cer_malformed_descriptors().
 */
static void
check_cer_malformed_descriptors(void) {
    SetRec_t value;
    BOOLEAN_t before;
    asn_TYPE_descriptor_t parent = asn_DEF_SetRec;
    asn_TYPE_member_t parent_members[16];
    unsigned group_index = find_member(&parent, "ext1");
    unsigned child_index;
    unsigned mode;

    assert(parent.elements_count <= 16 && group_index < parent.elements_count);
    init_value(&value, &before);
    parent.elements = NULL;
    expect_cer_rejected(&parent, &value);

    parent = asn_DEF_SetRec;
    memcpy(parent_members, parent.elements,
           parent.elements_count * sizeof(*parent_members));
    for(mode = 0; mode < 4; mode++) {
        asn_TYPE_descriptor_t group = *parent_members[group_index].type;
        asn_TYPE_member_t children[16];
        asn_SET_specifics_t specifics =
            *(const asn_SET_specifics_t *)group.specifics;

        assert(group.elements_count <= 16);
        memcpy(children, group.elements, group.elements_count * sizeof(*children));
        child_index = find_member(&group, "first");
        assert(child_index < group.elements_count);
        parent.elements = parent_members;
        parent_members[group_index].type = &group;
        group.elements = children;
        if(mode == 0) {
            group.elements = NULL;
        } else if(mode == 1) {
            children[child_index].memb_offset = UINT_MAX;
        } else if(mode == 2) {
            children[child_index].flags |= ATF_EXTENSION_GROUP;
        } else {
            specifics.pres_offset = UINT_MAX;
            group.specifics = &specifics;
        }
        expect_cer_rejected(&parent, &value);
        parent_members[group_index].type = asn_DEF_SetRec.elements[
            group_index].type;
    }

    if(sizeof(long) == sizeof(void *)) {
        asn_TYPE_descriptor_t group = *parent_members[group_index].type;
        asn_TYPE_member_t children[16];
        memcpy(children, group.elements, group.elements_count * sizeof(*children));
        child_index = find_member(&group, "first");
        assert(child_index < group.elements_count);
        group.elements = children;
        children[child_index].flags |= ATF_POINTER;
        parent = asn_DEF_SetRec;
        memcpy(parent_members, parent.elements,
               parent.elements_count * sizeof(*parent_members));
        parent_members[group_index].type = &group;
        parent.elements = parent_members;
        value.ext1->first = 0;
        expect_cer_rejected(&parent, &value);
        value.ext1->first = 2;
    }
    free_groups(&value);
}

/*
 * Purpose: verify recursive SET XER stack checks in builds that enable them.
 * Original source: security review of recursive SET_decode_xer traversal.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters; a bounded XML document nests 128 Node values.
 * Returns: no value.
 * Exceptions: assertions flag missing depth enforcement or lost input bounds.
 * Responsible party: asn1c maintainers.
 * History: added after finding no stack check in the SET XER decoder.
 * Example: check_xer_stack_limit().
 */
static void
check_xer_stack_limit(void) {
    enum { nesting = 128 };
    char xml[8192];
    size_t used = 0;
    unsigned index;
    Node_t *decoded = NULL;
    asn_codec_ctx_t codec_ctx;
    asn_dec_rval_t result;

    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.max_stack_size = 1024;
    append_xml(xml, sizeof(xml), &used, "<Node>");
    for(index = 0; index < nesting; index++) {
        append_xml(xml, sizeof(xml), &used, "<value>1</value>");
        if(index + 1 < nesting) append_xml(xml, sizeof(xml), &used, "<next>");
    }
    for(index = 1; index < nesting; index++) {
        append_xml(xml, sizeof(xml), &used, "</next>");
    }
    append_xml(xml, sizeof(xml), &used, "</Node>");
    result = xer_decode(&codec_ctx, &asn_DEF_Node, (void **)&decoded,
                        xml, used);
#if defined(SET_TEST_STACK_CHECK_DISABLED)
    /* ASan builds disable the pointer-difference stack check by design. */
    assert(result.code == RC_OK);
    assert(result.consumed == used);
#else
    assert(result.code == RC_FAIL);
#endif
    assert(result.consumed <= used);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Node, decoded);
}

/*
 * Purpose: run the focused SET group regression checks.
 * Original source: test 585 canonical SET extension-group vectors.
 * Version/date: 1.0, 2026-10-22.
 * Inputs: no parameters.
 * Returns: zero when encoders, decoders, and split-boundary checks pass.
 * Exceptions: assertions abort on mismatch.
 * Responsible party: asn1c maintainers.
 * History: added with transparent SET extension-group support.
 * Example: check-assembly.sh invokes main().
 */
int
main(void) {
    check_binary_codecs();
    check_ber_malformed();
    check_splits();
    check_xer();
    check_xer_unknown_group_leaf();
    check_xer_consumed_bound();
    check_decode_bad_presence_offset();
    check_decode_bad_member_offsets();
    check_callback_recovery();
    check_cer_malformed_descriptors();
    check_xer_stack_limit();
    return 0;
}

#endif /* ENABLE_LIBFUZZER */
