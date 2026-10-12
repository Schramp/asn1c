/*
 * Exercise compile-time CER output limits with an intentionally tiny cap.
 * Original source: New asn1c CER skeleton regression suite.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: NULL and BOOLEAN primitive values with fixed golden output sizes.
 * Returns: EXIT_SUCCESS only when the configured encoded-size cap is enforced.
 * Errors: Failed checks report to stderr; no C++ exceptions are used.
 * Responsible party: asn1c maintainers.
 * History: Added 2026-10-11 for compile-time resource-limit coverage.
 * Example: Run `make -C tests/tests-skeletons check-CER-limits`.
 */
#include <asn_application.h>
#include <cer_encoder.h>
#include <BOOLEAN.h>
#include <NULL.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Check one CER result's encoded size and expected errno value.
 * Original source: New asn1c CER resource-limit regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: result is the encoder return; expected/error are the required
 *   byte count and errno; label names the resource-limit case.
 * Returns: Zero for an exact match, otherwise -1 after writing stderr.
 * Errors: No exceptions; diagnostic output failures do not alter the result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: check_limit_result(encoded, -1, EOVERFLOW, "over output cap").
 */
static int
check_limit_result(asn_enc_rval_t result, ssize_t expected, int error,
                   const char *label) {
    if(result.encoded == expected && errno == error) return 0;
    fprintf(stderr, "%s: encoded=%ld errno=%d expected=%ld/%d\n", label,
            (long)result.encoded, errno, (long)expected, error);
    return -1;
}

/*
 * Prove the configured two-octet cap accepts NULL and rejects BOOLEAN.
 * Original source: New asn1c CER resource-limit regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; the output ceiling is provided by target CPPFLAGS.
 * Returns: EXIT_SUCCESS if the exact boundary and overflow results are correct.
 * Errors: No exceptions; failed assertions return EXIT_FAILURE after stderr.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: `./check-CER-limits` exercises ASN_CER_MAX_ENCODED_SIZE=2.
 */
int
main(void) {
    uint8_t output[4] = {0};
    NULL_t null_value = 0;
    BOOLEAN_t truth = 1;
    asn_enc_rval_t encoded;
    int failed = 0;

#if !defined(ASN_CER_MAX_ENCODED_SIZE) || ASN_CER_MAX_ENCODED_SIZE != 2
#error check-CER-limits must compile with a two-octet encoded-size ceiling
#endif
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_NULL, &null_value, output,
                                   sizeof(output));
    failed |= check_limit_result(encoded, 2, 0, "NULL at encoded-size ceiling");
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_BOOLEAN, &truth, output,
                                   sizeof(output));
    failed |= check_limit_result(encoded, -1, EOVERFLOW,
                                 "BOOLEAN above encoded-size ceiling");
    if(failed) return EXIT_FAILURE;
    puts("CER encoded-size limits passed");
    return EXIT_SUCCESS;
}
