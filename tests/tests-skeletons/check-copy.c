#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <OCTET_STRING.h>
#include <BIT_STRING.h>

/*
 * Call libc memcmp after enforcing its non-NULL argument precondition.
 *
 * Purpose: Make zero-length NULL comparisons fail deterministically in tests.
 * Original source: Test-only wrapper around the C standard library function.
 * Version: 2026-10-21.
 * Parameters: lhs and rhs are compared byte arrays; size is their byte count.
 * Returns: The result returned by libc memcmp.
 * Errors: An assertion fails when either pointer is NULL, including at size 0.
 * Responsible party: asn1c maintainers.
 * History: Added to detect C 7.24.1p2 violations without sanitizer support.
 * Example: check_copy_memcmp_nonnull(a, b, 0) still requires non-NULL pointers.
 */
static int
check_copy_memcmp_nonnull(const void *lhs, const void *rhs, size_t size) {
    assert(lhs != NULL && rhs != NULL);
    return memcmp(lhs, rhs, size);
}

/*
 * Call libc memcpy after enforcing its non-NULL argument precondition.
 *
 * Purpose: Make zero-length NULL copies fail deterministically in tests.
 * Original source: Test-only wrapper around the C standard library function.
 * Version: 2026-10-21.
 * Parameters: dst is the destination; src is the source; size is bytes copied.
 * Returns: The destination pointer returned by libc memcpy.
 * Errors: An assertion fails when either pointer is NULL, including at size 0.
 * Responsible party: asn1c maintainers.
 * History: Added to detect C 7.24.1p2 violations without sanitizer support.
 * Example: check_copy_memcpy_nonnull(a, b, 0) still requires non-NULL pointers.
 */
static void *
check_copy_memcpy_nonnull(void *dst, const void *src, size_t size) {
    assert(dst != NULL && src != NULL);
    return memcpy(dst, src, size);
}

/* Redirect only the OCTET and BIT skeleton implementations under test. */
#define memcmp check_copy_memcmp_nonnull
#define memcpy check_copy_memcpy_nonnull
#include <OCTET_STRING.c>
#include <BIT_STRING.c>
#undef memcpy
#undef memcmp

#include <INTEGER.c>
#include <BOOLEAN.c>
#include <NULL.c>
#include <REAL.c>

#define check(td, a, b) test(__LINE__, td, a, b)

/*
 * Copy a value through the public ASN.1 copy API.
 *
 * Purpose: Convert the API's zero-success convention to a test failure flag.
 * Original source: asn1c skeleton copy test.
 * Version: 2026-10-21.
 * Parameters: td is the type descriptor; a and b are destination and source.
 * Returns: 0 on successful copy, or 1 when copying fails.
 * Errors: Does not throw; reports copy failure through its return value.
 * Responsible party: asn1c maintainers.
 * History: Existing shared helper used by all copy checks.
 * Example: copy(&asn_DEF_BIT_STRING, &dst, &src) returns zero on success.
 */
static int
copy(asn_TYPE_descriptor_t *td, void **a, const void *b) {
    return asn_copy(td, a, b) != 0;
}

/*
 * Compare two values using their descriptor's comparison operation.
 *
 * Purpose: Convert equality into a zero-success test flag.
 * Original source: asn1c skeleton copy test.
 * Version: 2026-10-21.
 * Parameters: td is the type descriptor; a and b are values to compare.
 * Returns: 0 when values compare equal, or 1 otherwise.
 * Errors: Does not throw; reports inequality through its return value.
 * Responsible party: asn1c maintainers.
 * History: Existing shared helper used by all copy checks.
 * Example: compare(&asn_DEF_BIT_STRING, &a, &b) returns zero when equal.
 */
static int
compare(asn_TYPE_descriptor_t *td, void *a, void *b) {
    return td->op->compare_struct(td, a, b) != 0;
}

/*
 * Copy, compare, and release a pair of test values.
 *
 * Purpose: Verify a type's copy result and clean up both supplied values.
 * Original source: asn1c skeleton copy test.
 * Version: 2026-10-21.
 * Parameters: lineno identifies the assertion site; td is the type descriptor;
 *             a points to the destination pointer; b is the source value.
 * Returns: 0 after successful checks and cleanup.
 * Errors: Assertions terminate the test when copy or comparison fails.
 * Responsible party: asn1c maintainers.
 * History: Existing shared helper used by all copy checks.
 * Example: check() copies a value, confirms equality, then frees both values.
 */
static int
test(int lineno, asn_TYPE_descriptor_t *td, void **a, void *b) {
    int rv;

    rv = copy(td, a, b);
    if(rv) {
        fprintf(stderr, "%03d: copy() failed\n", lineno);
        assert(rv == 0);
    }
    rv = compare(td, *a, b);
    if(rv) {
        fprintf(stderr, "%03d: compare() failed\n", lineno);
        assert(rv == 0);
    }

    ASN_STRUCT_FREE(*td, *a);
    ASN_STRUCT_FREE_CONTENTS_ONLY(*td, b);

    return 0;
}

/*
 * Check null-backed and allocated empty OCTET STRING values.
 *
 * Purpose: Exercise both empty comparison orders and copy a null-backed source.
 * Original source: Test-only regression helper for OCTET STRING operations.
 * Version: 2026-10-21.
 * Parameters: None.
 * Returns: None.
 * Errors: Assertions terminate the test if comparison or copying fails.
 * Responsible party: asn1c maintainers.
 * History: Added to ensure wrappers detect the OCTET STRING empty-buffer path.
 * Example: An allocated empty value compares equal to a null-backed empty one.
 */
static void
check_octet_empty_values(void) {
    OCTET_STRING_t null_empty = { 0 };
    OCTET_STRING_t allocated_empty = { 0 };
    OCTET_STRING_t *copy = NULL;

    assert(OCTET_STRING_fromBuf(&allocated_empty, "", 0) == 0);
    assert(allocated_empty.buf != NULL && allocated_empty.size == 0);
    assert(OCTET_STRING_compare(&asn_DEF_OCTET_STRING,
                               &null_empty, &allocated_empty) == 0);
    assert(OCTET_STRING_compare(&asn_DEF_OCTET_STRING,
                               &allocated_empty, &null_empty) == 0);
    assert(OCTET_STRING_copy(&asn_DEF_OCTET_STRING,
                             (void **)&copy, &null_empty) == 0);
    assert(copy != NULL && copy->buf != NULL && copy->size == 0);

    FREEMEM(copy->buf);
    FREEMEM(copy);
    FREEMEM(allocated_empty.buf);
}

/*
 * Run copy and comparison checks for the built-in ASN.1 skeleton types.
 *
 * Purpose: Verify type copy operations and empty OCTET/BIT STRING edge cases.
 * Original source: asn1c skeleton copy test, extended for empty string values.
 * Version: 2026-10-21.
 * Parameters: ac and av are ignored command-line arguments.
 * Returns: 0 when all assertions pass.
 * Errors: Assertions terminate the test on a failed expectation.
 * Responsible party: asn1c maintainers.
 * History: Added empty OCTET and BIT STRING copy and comparison checks.
 * Example: Running check-copy verifies that empty values copy successfully.
 */
int
main(int ac, char **av) {
    (void)ac;
	(void)av;

    check_octet_empty_values();

    /* OCTET STRING */
    {
        OCTET_STRING_t b = { 0 };
        OCTET_STRING_fromBuf(&b, "Hello", 5);
        OCTET_STRING_t* a = NULL;
        check(&asn_DEF_OCTET_STRING, (void**)&a, &b);
    }

    /* INTEGER */
    {
        INTEGER_t b = { 0 };
        asn_ulong2INTEGER(&b, 123);
        INTEGER_t* a = NULL;
        check(&asn_DEF_INTEGER, (void**)&a, &b);
    }
    {
        INTEGER_t b = { 0 };
        INTEGER_t* a = NULL;
        check(&asn_DEF_INTEGER, (void**)&a, &b);
    }

    /* BIT STRING */
    {
        BIT_STRING_t b = { 0 };
        b.buf = MALLOC(2);
        b.size = 2;
        b.buf[0] = 0x80;
        b.buf[1] = 0x02;
        b.bits_unused = 1;
        BIT_STRING_t* a = NULL;
        check(&asn_DEF_BIT_STRING, (void**)&a, &b);
    }
    /* Copying and comparing an empty buffer must not pass NULL to mem* calls. */
    {
        BIT_STRING_t b = { 0 };
        BIT_STRING_t* a = NULL;
        check(&asn_DEF_BIT_STRING, (void**)&a, &b);
    }
    /* Absent values precede valid empty values; malformed values follow them. */
    {
        BIT_STRING_t empty = { 0 };
        BIT_STRING_t missing_buffer = { 0 };
        BIT_STRING_t invalid_padding = { 0 };
        BIT_STRING_t invalid_padding_tie = { 0 };
        uint8_t bit_byte = 0x80;
        BIT_STRING_t trailing_zeroes = { 0 };
        BIT_STRING_t one_significant_bit = { 0 };

        missing_buffer.size = 1;
        invalid_padding.bits_unused = 1;
        invalid_padding_tie.bits_unused = 8;
        invalid_padding_tie.size = 1;
        trailing_zeroes.buf = &bit_byte;
        trailing_zeroes.size = 1;
        one_significant_bit.buf = &bit_byte;
        one_significant_bit.size = 1;
        one_significant_bit.bits_unused = 7;
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, NULL, NULL) == 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, NULL, &empty) < 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, &empty, NULL) > 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, &empty,
                                  &missing_buffer) < 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, NULL,
                                  &missing_buffer) < 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, &invalid_padding,
                                  &missing_buffer) < 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, &missing_buffer,
                                  &invalid_padding_tie) == 0);
        assert(BIT_STRING_compare(&asn_DEF_BIT_STRING, &trailing_zeroes,
                                  &one_significant_bit) == 0);
    }
    /* Invalid source storage and metadata leave an existing destination intact. */
    {
        BIT_STRING_t destination = { 0 };
        BIT_STRING_t invalid_source = { 0 };
        BIT_STRING_t overflow_source = { 0 };
        BIT_STRING_t* destination_pointer = &destination;
        uint8_t* original_buffer = MALLOC(1);

        assert(original_buffer != NULL);
        original_buffer[0] = 0xA5;
        destination.buf = original_buffer;
        destination.size = 1;
        invalid_source.size = 1;
        assert(BIT_STRING_copy(&asn_DEF_BIT_STRING,
                               (void**)&destination_pointer,
                               &invalid_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer && destination.buf[0] == 0xA5);

        overflow_source.buf = (uint8_t*)&overflow_source;
        overflow_source.size = (size_t)-1;
        assert(BIT_STRING_copy(&asn_DEF_BIT_STRING,
                               (void**)&destination_pointer,
                               &overflow_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer && destination.buf[0] == 0xA5);

        invalid_source.buf = original_buffer;
        invalid_source.bits_unused = -1;
        assert(BIT_STRING_copy(&asn_DEF_BIT_STRING,
                               (void**)&destination_pointer,
                               &invalid_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer && destination.buf[0] == 0xA5);

        invalid_source.bits_unused = 8;
        assert(BIT_STRING_copy(&asn_DEF_BIT_STRING,
                               (void**)&destination_pointer,
                               &invalid_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer && destination.buf[0] == 0xA5);

        invalid_source.size = 0;
        invalid_source.buf = NULL;
        invalid_source.bits_unused = 1;
        assert(BIT_STRING_copy(&asn_DEF_BIT_STRING,
                               (void**)&destination_pointer,
                               &invalid_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer && destination.buf[0] == 0xA5);
        FREEMEM(original_buffer);
    }
    /* Copy rejects descriptor metadata that cannot hold a BIT_STRING_t. */
    {
        asn_TYPE_descriptor_t short_descriptor = asn_DEF_BIT_STRING;
        asn_OCTET_STRING_specifics_t short_specs = asn_SPC_BIT_STRING_specs;
        BIT_STRING_t empty_source = { 0 };
        BIT_STRING_t destination = { 0 };
        BIT_STRING_t* destination_pointer = &destination;
        uint8_t* original_buffer = MALLOC(1);

        assert(original_buffer != NULL);
        destination.buf = original_buffer;
        destination.size = 1;
        short_specs.struct_size = sizeof(BIT_STRING_t) - 1;
        short_descriptor.specifics = &short_specs;
        assert(BIT_STRING_copy(&short_descriptor,
                               (void**)&destination_pointer,
                               &empty_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer);

        short_specs.struct_size = sizeof(BIT_STRING_t);
        short_specs.subvariant = ASN_OSUBV_STR;
        assert(BIT_STRING_copy(&short_descriptor,
                               (void**)&destination_pointer,
                               &empty_source) == -1);
        assert(destination_pointer == &destination);
        assert(destination.buf == original_buffer);
        FREEMEM(original_buffer);
    }

    /* BOOLEAN */
    {
        BOOLEAN_t b = { 0 };
        b = 1;
        BIT_STRING_t* a = NULL;
        check(&asn_DEF_BOOLEAN, (void**)&a, &b);
    }

    /* NULL */
    {
        NULL_t b = { 0 };
        NULL_t* a = NULL;
        check(&asn_DEF_NULL, (void**)&a, &b);
    }

    /* REAL */
    {
        REAL_t b = { 0 };
        asn_double2REAL(&b, 123.456);
        REAL_t* a = NULL;
        check(&asn_DEF_REAL, (void**)&a, &b);
    }

	return 0;
}

