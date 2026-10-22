/*
 * Purpose: verify OCTET STRING random filling respects PER and abstract rules.
 * Original source: Issue #582 random-fill security regression tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: built-in string descriptors and malformed custom PER metadata.
 * Returns: zero when every generated value and failure path meets expectations.
 * Exceptions: checks report failures and return a non-zero process status.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: make check-OCTET_STRING-rfill-guard.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <NumericString.h>
#include <OCTET_STRING.h>
#include <PrintableString.h>
#include <VisibleString.h>
#include <asn_random_fill.h>
#include <constraints.h>

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static unsigned failures; /* state variable: accumulated failed test checks. */

/*
 * Record one independent test assertion.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: condition is expected truth; label names the failed behavior.
 * Returns: zero for success or -1 after recording a failure.
 * Errors: None; failure increments the test-local counter.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: check(result.code == ARFILL_OK, "valid string is generated").
 */
static int
check(int condition, const char *label) {
    if(condition) return 0;
    fprintf(stderr, "FAIL: %s\n", label);
    failures++;
    return -1;
}

/*
 * Reject one character to exercise candidate validation and bounded retries.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td is the candidate type; ptr is an OCTET STRING value; callback
 *         and key are unused diagnostic parameters.
 * Returns: zero unless the candidate contains 'x' or has malformed storage.
 * Errors: None; malformed values are rejected by return value.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: use as general_constraints for a temporary VisibleString descriptor.
 */
static int
reject_x_constraint(const asn_TYPE_descriptor_t *td, const void *ptr,
                    asn_app_constraint_failed_f *callback, void *key) {
    const OCTET_STRING_t *value = (const OCTET_STRING_t *)ptr;
    size_t index;

    (void)td;
    (void)callback;
    (void)key;
    if(!value || (value->size && !value->buf)) return -1;
    for(index = 0; index < value->size; index++) {
        if(value->buf[index] == 'x') return -1;
    }
    return 0;
}

/*
 * Reject every candidate to verify bounded failure preserves the old value.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: all callback arguments are unused.
 * Returns: always -1, indicating that no candidate satisfies this constraint.
 * Errors: None; rejection is reported through the return value.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: use for a descriptor that exhausts the random-fill retry budget.
 */
static int
reject_all_constraint(const asn_TYPE_descriptor_t *td, const void *ptr,
                      asn_app_constraint_failed_f *callback, void *key) {
    (void)td;
    (void)ptr;
    (void)callback;
    (void)key;
    return -1;
}

/*
 * Check one generated value with both the ASN.1 checker and its character set.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td identifies NumericString or PrintableString; value is generated.
 * Returns: zero if valid, including an empty value, otherwise -1.
 * Errors: Invalid alphabet characters and failed constraints are reported.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: check_builtin_string(&asn_DEF_NumericString, value).
 */
static int
check_builtin_string(const asn_TYPE_descriptor_t *td,
                     const OCTET_STRING_t *value) {
    size_t index;
    int failed = 0;

    failed |= check(value && (!value->size || value->buf),
                    "generated string storage matches its size");
    if(!value || !value->buf) return -1;
    failed |= check(asn_check_constraints(td, value, NULL, NULL) == 0,
                    "generated value satisfies its ASN.1 constraints");
    for(index = 0; index < value->size; index++) {
        uint8_t ch = value->buf[index];

        if(td == &asn_DEF_NumericString) {
            failed |= check(ch == ' ' || (ch >= '0' && ch <= '9'),
                            "NumericString uses space or an ASCII digit");
        } else {
            failed |= check(ch >= 0x20 && ch <= 0x7e,
                            "PrintableString uses printable ASCII");
        }
    }
    return failed ? -1 : 0;
}

/*
 * Generate repeated built-in values and validate every character.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td is the built-in string descriptor to sample.
 * Returns: zero when all generated values are valid and at least one is nonempty.
 * Errors: Failed fills, malformed storage, or invalid characters are reported.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: check_builtin_generation(&asn_DEF_PrintableString).
 */
static int
check_builtin_generation(const asn_TYPE_descriptor_t *td) {
    void *value = NULL;
    int generated_nonempty = 0;
    int iteration;
    int failed = 0;

    for(iteration = 0; iteration < 32; iteration++) {
        asn_random_fill_result_t result =
            OCTET_STRING_random_fill(td, &value, NULL, 16);
        OCTET_STRING_t *string_value = (OCTET_STRING_t *)value;

        failed |= check(result.code == ARFILL_OK,
                        "built-in string generation succeeds");
        if(result.code != ARFILL_OK) break;
        if(string_value && string_value->size) generated_nonempty = 1;
        failed |= check_builtin_string(td, string_value);
    }
    failed |= check(generated_nonempty, "random samples include a character");
    if(value) ASN_STRUCT_FREE(*td, value);
    return failed ? -1 : 0;
}

/*
 * Check generated sizes against one custom PER length constraint.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td/constraints select metadata; hint is approximate; min/max bound
 *         the required generated size; label names the expected behavior.
 * Returns: zero when every generated value stays within the requested bounds.
 * Errors: Failed generation or a size outside [min_size, max_size] is reported.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: check_size_range(&asn_DEF_OCTET_STRING, &member, 1, 4, 4, label).
 */
static int
check_size_range(const asn_TYPE_descriptor_t *td,
                 const asn_encoding_constraints_t *constraints,
                 size_t hint, size_t min_size, size_t max_size,
                 const char *label) {
    void *value = NULL;
    int iteration;
    int failed = 0;

    for(iteration = 0; iteration < 8; iteration++) {
        asn_random_fill_result_t result =
            OCTET_STRING_random_fill(td, &value, constraints, hint);
        const OCTET_STRING_t *string_value =
            (const OCTET_STRING_t *)value;

        failed |= check(result.code == ARFILL_OK, label);
        if(result.code != ARFILL_OK) break;
        failed |= check(string_value
                        && string_value->size >= min_size
                        && string_value->size <= max_size,
                        "generated size respects PER metadata");
    }
    if(value) ASN_STRUCT_FREE(*td, value);
    return failed ? -1 : 0;
}

/*
 * Verify semi-constrained character metadata uses its lower bound only.
 * Original source: Issue #582 standalone random-fill regression test.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td is a one-byte OCTET STRING type; constraints supplies a lower
 *         bound whose unused upper-bound field is zero.
 * Returns: zero when each generated byte respects the lower bound.
 * Errors: Failed fills or a byte below the lower bound are reported.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: check_value_lower_bound(&asn_DEF_OCTET_STRING, &member, 128).
 */
static int
check_value_lower_bound(const asn_TYPE_descriptor_t *td,
                        const asn_encoding_constraints_t *constraints,
                        uint8_t lower_bound) {
    void *value = NULL;
    int iteration;
    int failed = 0;

    for(iteration = 0; iteration < 16; iteration++) {
        asn_random_fill_result_t result =
            OCTET_STRING_random_fill(td, &value, constraints, 8);
        const OCTET_STRING_t *string_value =
            (const OCTET_STRING_t *)value;
        size_t index;

        failed |= check(result.code == ARFILL_OK,
                        "semi-constrained character generation succeeds");
        if(result.code != ARFILL_OK) break;
        for(index = 0; string_value && index < string_value->size; index++) {
            failed |= check(string_value->buf[index] >= lower_bound,
                            "semi-constrained character uses its lower bound");
        }
    }
    if(value) ASN_STRUCT_FREE(*td, value);
    return failed ? -1 : 0;
}
#endif

/*
 * Exercise PER maps, member constraints, empty values, and failure atomicity.
 * Original source: Issue #582 standalone OCTET STRING random-fill regression.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: none; metadata and candidate values are local test fixtures.
 * Returns: zero when checks pass, 77 when PER support is disabled, or one on
 *          failed checks.
 * Errors: Each unexpected status, character, or storage mutation is recorded.
 * Responsible party: asn1c maintainers. History: added for issue #582.
 * Example: make check-OCTET_STRING-rfill-guard.
 */
int
main(void) {
#if defined(ASN_DISABLE_UPER_SUPPORT) && defined(ASN_DISABLE_APER_SUPPORT)
    return 77;
#else
    asn_TYPE_descriptor_t reject_descriptor = asn_DEF_VisibleString;
    asn_TYPE_descriptor_t fixed_size_descriptor = asn_DEF_OCTET_STRING;
    asn_per_constraints_t fixed_size_per = {
        { APC_UNCONSTRAINED, 0, 0, 0, 0 },
        { APC_CONSTRAINED, 0, 0, 4, 4 }, NULL, NULL
    };
    asn_per_constraints_t empty_size_per = {
        { APC_UNCONSTRAINED, 0, 0, 0, 0 },
        { APC_CONSTRAINED, 0, 0, 0, 0 }, NULL, NULL
    };
    asn_per_constraints_t semi_size_per = {
        { APC_UNCONSTRAINED, 0, 0, 0, 0 },
        { APC_SEMI_CONSTRAINED, 0, 0, 3, 0 }, NULL, NULL
    };
    asn_per_constraints_t semi_value_per = {
        { APC_SEMI_CONSTRAINED, 0, 0, 128, 0 },
        { APC_UNCONSTRAINED, 0, 0, 0, 0 }, NULL, NULL
    };
    asn_per_constraints_t invalid_semi_value_per = {
        { APC_SEMI_CONSTRAINED, 0, 0, -1, 0 },
        { APC_UNCONSTRAINED, 0, 0, 0, 0 }, NULL, NULL
    };
    asn_per_constraints_t invalid_value_per = {
        { APC_CONSTRAINED, 8, 8, -1, 10 },
        { APC_UNCONSTRAINED, 0, 0, 0, 0 }, NULL, NULL
    };
    asn_per_constraints_t reversed_value_per = {
        { APC_CONSTRAINED, 8, 8, 10, 9 },
        { APC_UNCONSTRAINED, 0, 0, 0, 0 }, NULL, NULL
    };
    asn_per_constraints_t invalid_size_per = {
        { APC_UNCONSTRAINED, 0, 0, 0, 0 },
        { APC_CONSTRAINED, 0, 0, -1, 4 }, NULL, NULL
    };
    asn_per_constraints_t reversed_size_per = {
        { APC_UNCONSTRAINED, 0, 0, 0, 0 },
        { APC_CONSTRAINED, 0, 0, 5, 4 }, NULL, NULL
    };
    asn_encoding_constraints_t fixed_size_constraints = { 0 };
    asn_encoding_constraints_t empty_size_constraints = { 0 };
    asn_encoding_constraints_t semi_size_constraints = { 0 };
    asn_encoding_constraints_t semi_value_constraints = { 0 };
    asn_encoding_constraints_t invalid_semi_value_constraints = { 0 };
    asn_encoding_constraints_t invalid_value_constraints = { 0 };
    asn_encoding_constraints_t reversed_value_constraints = { 0 };
    asn_encoding_constraints_t invalid_size_constraints = { 0 };
    asn_encoding_constraints_t reversed_size_constraints = { 0 };
    OCTET_STRING_t existing = { 0 };
    uint8_t *original_buffer = existing.buf;
    void *value = NULL;
    asn_random_fill_result_t result;

    /* Keep randomized alphabet coverage reproducible on either PRNG backend. */
#ifdef HAVE_RANDOM
    srandom(582);
#else
    srand(582);
#endif

    reject_descriptor.encoding_constraints.general_constraints =
        reject_all_constraint;
    fixed_size_constraints = fixed_size_descriptor.encoding_constraints;
    fixed_size_constraints.per_constraints = &fixed_size_per;
    empty_size_constraints = fixed_size_descriptor.encoding_constraints;
    empty_size_constraints.per_constraints = &empty_size_per;
    semi_size_constraints = fixed_size_descriptor.encoding_constraints;
    semi_size_constraints.per_constraints = &semi_size_per;
    semi_value_constraints = fixed_size_descriptor.encoding_constraints;
    semi_value_constraints.per_constraints = &semi_value_per;
    invalid_semi_value_constraints = fixed_size_descriptor.encoding_constraints;
    invalid_semi_value_constraints.per_constraints = &invalid_semi_value_per;
    invalid_value_constraints = fixed_size_descriptor.encoding_constraints;
    invalid_value_constraints.per_constraints = &invalid_value_per;
    reversed_value_constraints = fixed_size_descriptor.encoding_constraints;
    reversed_value_constraints.per_constraints = &reversed_value_per;
    invalid_size_constraints = fixed_size_descriptor.encoding_constraints;
    invalid_size_constraints.per_constraints = &invalid_size_per;
    reversed_size_constraints = fixed_size_descriptor.encoding_constraints;
    reversed_size_constraints.per_constraints = &reversed_size_per;

    check_builtin_generation(&asn_DEF_NumericString);
    check_builtin_generation(&asn_DEF_PrintableString);

    value = NULL;
    {
        asn_encoding_constraints_t member_except = { 0 };

        member_except.general_constraints = reject_x_constraint;
        result = OCTET_STRING_random_fill(&asn_DEF_VisibleString, &value,
                                          &member_except, 8);
    }
    check(result.code == ARFILL_OK, "EXCEPT candidate generation succeeds");
    if(value) {
        OCTET_STRING_t *string_value = (OCTET_STRING_t *)value;
        size_t index;

        for(index = 0; index < string_value->size; index++) {
            check(string_value->buf[index] != 'x',
                  "EXCEPT candidate excludes the forbidden character");
        }
        ASN_STRUCT_FREE(asn_DEF_VisibleString, value);
    }

    value = NULL;
    result = OCTET_STRING_random_fill(&asn_DEF_OCTET_STRING, &value, NULL, 0);
    check(result.code == ARFILL_SKIPPED && value == NULL,
          "zero budget skips generation when no value exists");

    value = NULL;
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &fixed_size_constraints, 1);
    check(result.code == ARFILL_OK,
          "fixed SIZE(4) is generated despite an approximate hint of one");
    check(value && ((OCTET_STRING_t *)value)->size == 4,
          "fixed SIZE(4) retains its required length");
    if(value) ASN_STRUCT_FREE(fixed_size_descriptor, value);
    check_size_range(&fixed_size_descriptor, &semi_size_constraints,
                     8, 3, 8,
                     "semi-constrained SIZE generation succeeds");
    check_value_lower_bound(&fixed_size_descriptor, &semi_value_constraints,
                            128);

    value = NULL;
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &empty_size_constraints, 1);
    check(result.code == ARFILL_OK && value
          && ((OCTET_STRING_t *)value)->size == 0,
          "fixed SIZE(0) produces an empty value");
    if(value) ASN_STRUCT_FREE(fixed_size_descriptor, value);

    check(OCTET_STRING_fromBuf(&existing, "keep", 4) == 0,
          "existing value setup succeeds");
    original_buffer = existing.buf;
    value = &existing;
    result = OCTET_STRING_random_fill(&reject_descriptor, &value, NULL, 8);
    check(result.code == ARFILL_FAILED, "bounded rejected candidates fail");
    check(value == &existing && existing.buf == original_buffer
          && existing.size == 4 && memcmp(existing.buf, "keep", 4) == 0,
          "failed generation preserves the prior value and storage");
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &existing);

    value = NULL;
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &invalid_value_constraints, 8);
    check(result.code == ARFILL_FAILED && value == NULL,
          "negative PER character bounds are rejected without assertion");
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &reversed_value_constraints, 8);
    check(result.code == ARFILL_FAILED && value == NULL,
          "reversed PER character bounds are rejected without assertion");
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &invalid_semi_value_constraints, 8);
    check(result.code == ARFILL_FAILED && value == NULL,
          "negative semi-constrained character lower bound is rejected");
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &invalid_size_constraints, 8);
    check(result.code == ARFILL_FAILED && value == NULL,
          "negative PER size bounds are rejected without assertion");
    result = OCTET_STRING_random_fill(&fixed_size_descriptor, &value,
                                      &reversed_size_constraints, 8);
    check(result.code == ARFILL_FAILED && value == NULL,
          "reversed PER size bounds are rejected without assertion");
    result = OCTET_STRING_random_fill(&asn_DEF_OCTET_STRING, &value, NULL,
                                      SIZE_MAX);
    check(result.code == ARFILL_FAILED && value == NULL,
          "oversized generation budgets are rejected safely");
    result = OCTET_STRING_random_fill(NULL, &value, NULL, 1);
    check(result.code == ARFILL_FAILED, "null type descriptors are rejected");
    result = OCTET_STRING_random_fill(&asn_DEF_OCTET_STRING, NULL, NULL, 1);
    check(result.code == ARFILL_FAILED, "null output pointers are rejected");

    if(failures) fprintf(stderr, "%u random-fill checks failed\n", failures);
    return failures ? 1 : 0;
#endif
}
