/*
 * Purpose: Verify generated constraint checkers for types without applicable
 *          runtime value checks, including aliases of string types.
 * Original source: asn1c regression for issue reported on 2026-10-23.
 * Version/date: 1.0, 2026-10-23.
 * Inputs: Generated descriptors from NoApplicable.asn1.
 * Returns: The executable reports assertion failures through its exit status.
 * Errors: None at load time; checker failures are reported by main().
 * Responsible party: asn1c maintainers.
 * History: Added to cover the OCTET STRING self-forwarding regression.
 * Example: Built and run by check-no-applicable-constraints.sh.
 */
#include <T.h>
#include <B.h>
#include <Alias.h>
#include <constraints.h>

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Purpose: Reject a forwarded validation request so delegation is observable.
 * Original source: asn1c generated-code regression fixture.
 * Version/date: 1.0, 2026-10-23.
 * Parameters: td is the descriptor; sptr is the value; ctfailcb is the
 *             failure reporter; app_key is its caller-owned context.
 * Returns: Always -1 to represent a distinct failing base constraint.
 * Errors: None; all inputs are intentionally unused.
 * Responsible party: asn1c maintainers.
 * History: Added to confirm generated checkers preserve callback forwarding.
 * Example: Install it in a descriptor copy before calling T_constraint.
 */
static int
reject_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                  asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    (void)td;
    (void)sptr;
    (void)ctfailcb;
    (void)app_key;
    return -1;
}

/*
 * Purpose: Exercise generated checkers when a value constraint has no
 *          applicable runtime check, including aliases of string types.
 * Original source: asn1c regression for issue reported on 2026-10-23.
 * Version/date: 1.0, 2026-10-23.
 * Parameters: None; the test uses valid, fixed values for each fixture type.
 * Returns: EXIT_SUCCESS when all generated checkers accept their values.
 * Errors: Returns EXIT_FAILURE on an unexpected constraint failure. An alarm
 *         terminates the process if any checker recurses indefinitely.
 * Responsible party: asn1c maintainers.
 * History: Added to cover the OCTET STRING self-forwarding regression.
 * Example: Run through check-no-applicable-constraints.sh after generation.
 */
int
main(void) {
    uint8_t octets[] = {0x2a};
    T_t octet_value = {.buf = octets, .size = sizeof(octets)};
    B_t bit_value = {
        .buf = octets,
        .size = sizeof(octets),
        .bits_unused = 0
    };
    Alias_t alias_value = {.buf = octets, .size = sizeof(octets)};
    asn_TYPE_descriptor_t descriptor_copy = asn_DEF_T; /* state variable. */

    /* Bound execution so an erroneous self-forwarding callback fails quickly. */
    alarm(10);

    if(asn_check_constraints(&asn_DEF_T, &octet_value, NULL, NULL) != 0) {
        fputs("T OCTET STRING checker rejected a value\n", stderr);
        return EXIT_FAILURE;
    }
    if(asn_check_constraints(&asn_DEF_T, NULL, NULL, NULL) == 0) {
        fputs("T OCTET STRING checker accepted a missing value\n", stderr);
        return EXIT_FAILURE;
    }
    if(asn_check_constraints(&asn_DEF_B, &bit_value, NULL, NULL) != 0) {
        fputs("B BIT STRING checker rejected a value\n", stderr);
        return EXIT_FAILURE;
    }
    if(asn_check_constraints(&asn_DEF_B, NULL, NULL, NULL) == 0) {
        fputs("B BIT STRING checker accepted a missing value\n", stderr);
        return EXIT_FAILURE;
    }
    if(asn_check_constraints(&asn_DEF_Alias, &alias_value, NULL, NULL) != 0) {
        fputs("Alias checker rejected a value\n", stderr);
        return EXIT_FAILURE;
    }
    if(asn_check_constraints(&asn_DEF_Alias, NULL, NULL, NULL) == 0) {
        fputs("Alias checker accepted a missing value\n", stderr);
        return EXIT_FAILURE;
    }

    /* A generated checker accepts a missing base callback without calling it. */
    descriptor_copy.encoding_constraints.general_constraints = NULL;
    if(T_constraint(&descriptor_copy, &octet_value, NULL, NULL) != 0) {
        fputs("T checker rejected a missing base callback\n", stderr);
        return EXIT_FAILURE;
    }

    /* A distinct base callback must receive and propagate validation. */
    descriptor_copy.encoding_constraints.general_constraints = reject_constraint;
    if(T_constraint(&descriptor_copy, &octet_value, NULL, NULL) != -1) {
        fputs("T checker did not propagate a failing base callback\n", stderr);
        return EXIT_FAILURE;
    }

    alarm(0);
    return EXIT_SUCCESS;
}
