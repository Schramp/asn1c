#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "AnyLengthList.h"
#include "Holder.h"
#include "List.h"
#include "Small.h"
#include "SmallExact.h"
#include "SmallSet.h"
#include <ber_decoder.h>
#include <constraints.h>

/**
 * Purpose: Decode a BER value and check whether its ASN.1 constraints pass.
 * Original source: Regression coverage for asn1c issue #570.
 * Version: 2026-10-11, collection SIZE constraint regression test.
 * Parameters:
 *   td - Descriptor of the PDU to decode and validate.
 *   encoded - BER bytes containing the PDU.
 *   encoded_size - Number of bytes available in encoded.
 *   expect_valid - Nonzero when constraint checking must succeed.
 * Returns: None; assertions fail if decoding or validation differs from expected.
 * Exceptions: None; test failures terminate through assert.
 * Author: asn1c maintainers.
 * History: Added on 2026-10-11 for issue #570.
 * Example: check_constraints(&asn_DEF_Small, empty_sequence, 2, 0).
 */
static void
check_constraints(const asn_TYPE_descriptor_t *td, const uint8_t *encoded,
                  size_t encoded_size, int expect_valid) {
    void *decoded = NULL;
    asn_dec_rval_t decode_result;
    char error_buffer[128];
    size_t error_size = sizeof(error_buffer);
    int constraint_result;

    /* Decode first to show that BER acceptance is separate from constraint
     * validation; malformed collection sizes remain valid BER values. */
    decode_result = ber_decode(NULL, td, &decoded, encoded, encoded_size);
    assert(decode_result.code == RC_OK);
    assert(decoded != NULL);

    constraint_result = asn_check_constraints(td, decoded, error_buffer,
                                              &error_size);
    assert((constraint_result == 0) == (expect_valid != 0));
    ASN_STRUCT_FREE(*td, decoded);
}

/**
 * Purpose: Write a BER length and return the number of encoded length bytes.
 * Original source: Regression test helper for asn1c issue #570.
 * Version: 2026-10-11, collection SIZE constraint regression test.
 * Parameters:
 *   output - Buffer receiving the BER length encoding.
 *   length - Content length to encode; this test supports values through 65535.
 * Returns: One or three bytes used for the BER length.
 * Exceptions: None; an unsupported test input fails through assert.
 * Author: asn1c maintainers.
 * History: Added on 2026-10-11 for issue #570.
 * Example: put_length(buffer, 320) writes the long-form encoding 0x82 0x01 0x40.
 */
static size_t
put_length(uint8_t *output, size_t length) {
    if(length < 128) {
        output[0] = (uint8_t)length;
        return 1;
    }

    assert(length <= 65535);
    output[0] = 0x82;
    output[1] = (uint8_t)(length >> 8);
    output[2] = (uint8_t)length;
    return 3;
}

/**
 * Purpose: Encode a BER collection of Info values for direct and nested tests.
 * Original source: Regression test helper for asn1c issue #570.
 * Version: 2026-10-11, collection SIZE constraint regression test.
 * Parameters:
 *   output - Buffer receiving the encoded SEQUENCE OF contents.
 *   count - Number of Info values to encode, from zero through 64.
 *   mode - INTEGER value written into each Info value.
 *   tag - Collection tag, either SEQUENCE (0x30) or IMPLICIT [0] (0xa0).
 * Returns: Number of BER bytes written to output.
 * Exceptions: None; unsupported test inputs fail through assert.
 * Author: asn1c maintainers.
 * History: Added on 2026-10-11 for issue #570.
 * Example: encode_info_list(bytes, 64, 1, 0x30) builds an oversized List.
 */
static size_t
encode_info_list(uint8_t *output, size_t count, uint8_t mode, uint8_t tag) {
    size_t content_size = count * 5;
    size_t length_size;
    size_t offset;
    size_t i;

    assert(count <= 64);
    output[0] = tag;
    length_size = put_length(output + 1, content_size);
    offset = 1 + length_size;

    /* Each Info is a three-byte SEQUENCE containing one two-byte [0] INTEGER. */
    for(i = 0; i < count; i++) {
        output[offset++] = 0x30;
        output[offset++] = 0x03;
        output[offset++] = 0x80;
        output[offset++] = 0x01;
        output[offset++] = mode;
    }

    return offset;
}

/**
 * Purpose: Wrap a BER List value in its Holder SEQUENCE and implicit [0] tag.
 * Original source: Regression test helper for asn1c issue #570.
 * Version: 2026-10-11, nested collection SIZE regression test.
 * Parameters:
 *   output - Buffer receiving the encoded Holder value.
 *   count - Number of List elements to encode, from zero through 64.
 *   mode - INTEGER value written into each Info value.
 * Returns: Number of BER bytes written to output.
 * Exceptions: None; unsupported test inputs fail through assert.
 * Author: asn1c maintainers.
 * History: Added on 2026-10-11 for issue #570.
 * Example: encode_holder(bytes, 64, 1) builds the reported nested failure.
 */
static size_t
encode_holder(uint8_t *output, size_t count, uint8_t mode) {
    uint8_t list[4 + 64 * 5];
    size_t list_size = encode_info_list(list, count, mode, 0xa0);
    size_t outer_length_size;

    output[0] = 0x30;
    outer_length_size = put_length(output + 1, list_size);
    memcpy(output + 1 + outer_length_size, list, list_size);
    return 1 + outer_length_size + list_size;
}

/**
 * Purpose: Check SIZE bounds on constrained SEQUENCE OF and SET OF values.
 * Original source: Regression coverage for asn1c issue #570.
 * Version: 2026-10-11, collection SIZE constraint regression test.
 * Parameters: None.
 * Returns: None; assertions verify both accepted and rejected collection sizes.
 * Exceptions: None; test failures terminate through assert.
 * Author: asn1c maintainers.
 * History: Added on 2026-10-11 for issue #570.
 * Example: Called by main() to check lower and upper SIZE bounds.
 */
static void
check_small_collections(void) {
    static const uint8_t small_empty[] = { 0x30, 0x00 };
    static const uint8_t small_one[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    static const uint8_t small_two[] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02
    };
    static const uint8_t small_three[] = {
        0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
        0x02, 0x01, 0x03
    };
    static const uint8_t set_empty[] = { 0x31, 0x00 };
    static const uint8_t set_one[] = { 0x31, 0x03, 0x02, 0x01, 0x01 };
    static const uint8_t set_two[] = {
        0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02
    };
    static const uint8_t set_three[] = {
        0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
        0x02, 0x01, 0x03
    };

    check_constraints(&asn_DEF_Small, small_empty, sizeof(small_empty), 0);
    check_constraints(&asn_DEF_Small, small_one, sizeof(small_one), 1);
    check_constraints(&asn_DEF_Small, small_two, sizeof(small_two), 1);
    check_constraints(&asn_DEF_Small, small_three, sizeof(small_three), 0);
    check_constraints(&asn_DEF_SmallExact, small_one, sizeof(small_one), 1);
    check_constraints(&asn_DEF_SmallExact, small_two, sizeof(small_two), 0);
    check_constraints(&asn_DEF_SmallSet, set_empty, sizeof(set_empty), 0);
    check_constraints(&asn_DEF_SmallSet, set_one, sizeof(set_one), 1);
    check_constraints(&asn_DEF_SmallSet, set_two, sizeof(set_two), 1);
    check_constraints(&asn_DEF_SmallSet, set_three, sizeof(set_three), 0);
}

/**
 * Purpose: Check collection bounds, element constraints, and nested validation.
 * Original source: Regression coverage for asn1c issue #570.
 * Version: 2026-10-11, collection SIZE constraint regression test.
 * Parameters: None.
 * Returns: Zero after all collection constraint assertions pass.
 * Exceptions: None; test failures terminate through assert.
 * Author: asn1c maintainers.
 * History: Added on 2026-10-11 for issue #570.
 * Example: The direct and Holder-contained List checks exercise 1..63 bounds.
 */
int
main(void) {
    uint8_t encoded[8 + 64 * 5];
    size_t encoded_size;

    check_small_collections();

    encoded_size = encode_info_list(encoded, 0, 1, 0x30);
    check_constraints(&asn_DEF_List, encoded, encoded_size, 0);
    encoded_size = encode_info_list(encoded, 1, 1, 0x30);
    check_constraints(&asn_DEF_List, encoded, encoded_size, 1);
    encoded_size = encode_info_list(encoded, 63, 1, 0x30);
    check_constraints(&asn_DEF_List, encoded, encoded_size, 1);
    encoded_size = encode_info_list(encoded, 64, 1, 0x30);
    check_constraints(&asn_DEF_List, encoded, encoded_size, 0);

    /* The custom collection checker must still validate element constraints. */
    encoded_size = encode_info_list(encoded, 1, 4, 0x30);
    check_constraints(&asn_DEF_List, encoded, encoded_size, 0);

    /* An effectively unbounded size must still run the element checker. */
    encoded_size = encode_info_list(encoded, 0, 1, 0x30);
    check_constraints(&asn_DEF_AnyLengthList, encoded, encoded_size, 1);
    encoded_size = encode_info_list(encoded, 1, 4, 0x30);
    check_constraints(&asn_DEF_AnyLengthList, encoded, encoded_size, 0);

    encoded_size = encode_holder(encoded, 63, 1);
    check_constraints(&asn_DEF_Holder, encoded, encoded_size, 1);
    encoded_size = encode_holder(encoded, 64, 1);
    check_constraints(&asn_DEF_Holder, encoded, encoded_size, 0);

    return 0;
}
