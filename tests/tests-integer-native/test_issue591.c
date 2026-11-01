/*
 * Regression coverage for DEFAULT INTEGER callbacks generated under each
 * -finteger-native-type mode. The same grammar selects both native scalars
 * and INTEGER_t, depending on the mode and the member's constraints.
 * Original source: GitHub issue #591 and the asn1c regression suite.
 * Version/date: 1.0, 2026-10-26.
 * Inputs: The generated MySequence descriptor and default callbacks.
 * Returns: Zero when every default has the right value and memory ownership.
 * Exceptions: None; failures return a nonzero process status.
 * Responsible party: asn1c maintainers.
 * History: Added to catch scalar callbacks emitted for INTEGER_t storage.
 * Example: Generated, compiled, and run by tests/tests-integer-native/run.sh.
 */
#include "MySequence.h"

#include <stdio.h>

/*
 * Purpose: Check one generated DEFAULT setter, comparator, and DER value.
 * Original source: GitHub issue #591 regression.
 * Version/date: 1.0, 2026-10-26.
 * Parameters: index selects a MySequence member; value is its one-byte
 *             signed default value.
 * Returns: Zero on success and nonzero on a missing or incorrect callback.
 * Exceptions: None; allocated values are released through their descriptor.
 * Responsible party: asn1c maintainers.
 * History: Added for INTEGER_t versus native scalar storage selection.
 * Example: check_default(0, 1) verifies the unconstrained member.
 */
static int
check_default(unsigned index, signed char value) {
    const asn_TYPE_member_t *member;
    unsigned char encoded[8];
    asn_enc_rval_t result;
    void *storage = 0;
    int failed = 0;

    /* Reject bad test indices before reading generated descriptor members. */
    if(index >= (unsigned)asn_DEF_MySequence.elements_count) return 1;
    member = &asn_DEF_MySequence.elements[index];
    if(!member->default_value_cmp || !member->default_value_set || !member->type) return 1;

    /* A missing value is distinct from any DEFAULT, including zero. */
    if(member->default_value_cmp(0) != -1) return 1;
    if(member->default_value_set(&storage) != 0 || !storage) {
        if(storage) ASN_STRUCT_FREE(*member->type, storage);
        return 1;
    }

    /* Compare the stored default and DER payload across storage modes. */
    if(member->default_value_cmp(storage) != 0) failed = 1;
    result = der_encode_to_buffer(member->type, storage, encoded, sizeof(encoded));
    if(result.encoded != 3 || encoded[1] != 1 || encoded[2] != (unsigned char)value)
        failed = 1;
    ASN_STRUCT_FREE(*member->type, storage);
    return failed;
}

/*
 * Purpose: Exercise native and arbitrary-precision generated defaults.
 * Original source: GitHub issue #591 regression.
 * Version/date: 1.0, 2026-10-26.
 * Parameters: None.
 * Returns: Zero when all callback checks pass; nonzero otherwise.
 * Exceptions: None.
 * Responsible party: asn1c maintainers.
 * History: Added for the issue #591 compile-time regression.
 * Example: Run the enclosing tests/tests-integer-native/run.sh script.
 */
int
main(void) {
    static const signed char expected[] = {1, 0, 7, -3};
    unsigned index;
    int failed = 0;

    /* Every numeric member must compile, set, compare, encode, and free. */
    for(index = 0; index < sizeof(expected) / sizeof(expected[0]); index++) {
        if(check_default(index, expected[index])) {
            fprintf(stderr, "issue #591: DEFAULT callback failed for member %u\n", index);
            failed = 1;
        }
    }
    return failed;
}
