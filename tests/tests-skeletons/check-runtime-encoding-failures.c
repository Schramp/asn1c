/*
 * Check callback and nested encoder failures in UniversalString JER, SET OF
 * canonical XER, and CHOICE JER.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: Small generated-style values and deterministic callback failures.
 * Returns: EXIT_SUCCESS if failure reporting, output, and depth checks pass.
 * Errors: Failed checks are reported to stderr; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: `make -C tests/tests-skeletons check-runtime-encoding-failures`.
 */
#include <asn_internal.h>
#include <asn_application.h>
#include <UniversalString.h>
#include <NativeInteger.h>
#include <constr_CHOICE.h>
#include <constr_SET_OF.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Fixed-size callback capture also supports deterministic failure injection. */
typedef struct output_capture_s {
    char bytes[256]; /* Captured output from the encoder. */
    size_t length; /* state variable: number of bytes currently captured. */
    size_t calls; /* state variable: number of callback invocations. */
    size_t fail_at; /* state variable: callback index to reject, or zero. */
} output_capture_t;

/* Generated-style SET OF storage contains pointers to native INTEGER values. */
typedef struct test_set_s {
    struct {
        long **array; /* Pointer to each native INTEGER value. */
        int count; /* state variable: initialized list element count. */
        int size; /* Allocated pointer-array capacity. */
        void (*free)(long *); /* Element destructor, unused by this test. */
    } list; /* SET OF collection layout. */
    asn_struct_ctx_t _asn_ctx; /* Decoder context required by SET OF metadata. */
} test_set_t;

/* CHOICE stores the active alternative index and its inline native value. */
typedef struct test_choice_s {
    unsigned present; /* 1-based active member index. */
    long value; /* Inline value passed to the child encoder. */
} test_choice_t;

/* Track only allocations made by the locally included SET OF XER source. */
typedef struct set_allocator_s {
    void *pointers[32]; /* Live allocations owned by the encoder. */
    size_t live_count; /* state variable: number of tracked allocations. */
    int accounting_error; /* state variable: ownership-table inconsistency. */
} set_allocator_t;

/* state variable: records temporary SET OF buffers and the encodings array. */
static set_allocator_t set_allocator = {{0}, 0, 0};

/* Child encoder state lets one fixture exercise both success and failure. */
static int child_encoder_fails; /* state variable: force the child to fail. */

static void *tracked_malloc(size_t size);
static void *tracked_realloc(void *old_pointer, size_t size);
static void tracked_free(void *pointer);
static int require(int condition, const char *label);

/* Override the included SET OF encoder's allocations for deterministic checks. */
#undef MALLOC
#undef REALLOC
#undef FREEMEM
#define MALLOC(size) tracked_malloc(size)
#define REALLOC(pointer, size) tracked_realloc(pointer, size)
#define FREEMEM(pointer) tracked_free(pointer)
#include "../../skeletons/constr_SET_OF_xer.c"

/* Collect bytes unless this callback invocation is the selected injected fault.
 * Purpose: Capture bounded encoder output for the regression checks.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: data/size identify a chunk; key points to output_capture_t.
 * Returns: Zero on capture, or -1 on injected failure or invalid capacity.
 * Errors: No exceptions; errors are reported through the callback result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: Return capture_callback("A", 1, &capture) to save one byte.
 */
static int
capture_callback(const void *data, size_t size, void *key) {
    output_capture_t *capture = (output_capture_t *)key;

    capture->calls++;
    if(capture->fail_at && capture->calls == capture->fail_at) return -1;
    if(size > sizeof(capture->bytes) - capture->length) return -1;
    memcpy(capture->bytes + capture->length, data, size);
    capture->length += size;
    return 0;
}

/* Register an allocation while preserving ordinary malloc failure behavior.
 * Purpose: Track buffers owned by the included SET OF XER implementation.
 * Original source: New runtime encoder allocation-failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: pointer is the freshly allocated buffer to register.
 * Returns: The pointer on success, or NULL if allocation/tracking fails.
 * Errors: A full tracking table frees the new pointer and marks an error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: return track_allocation(malloc(size)) from tracked_malloc().
 */
static void *
track_allocation(void *pointer) {
    if(!pointer) return NULL;
    if(set_allocator.live_count >=
       sizeof(set_allocator.pointers) / sizeof(set_allocator.pointers[0])) {
        set_allocator.accounting_error = 1;
        free(pointer);
        return NULL;
    }
    set_allocator.pointers[set_allocator.live_count++] = pointer;
    return pointer;
}

/* Replace the tracked address after realloc succeeds.
 * Purpose: Keep allocation ownership accurate when temporary buffers grow.
 * Original source: New runtime encoder allocation-failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: old_pointer is tracked or NULL; size is the requested byte count.
 * Returns: The resized buffer, or NULL while retaining old ownership.
 * Errors: Unknown pointers mark accounting_error and are not reallocated.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: tracked_realloc(NULL, 8) allocates and tracks eight bytes.
 */
static void *
tracked_realloc(void *old_pointer, size_t size) {
    size_t index;
    void *new_pointer;

    if(!old_pointer) return track_allocation(malloc(size));
    for(index = 0; index < set_allocator.live_count; index++) {
        if(set_allocator.pointers[index] == old_pointer) break;
    }
    if(index == set_allocator.live_count) {
        set_allocator.accounting_error = 1;
        return NULL;
    }
    new_pointer = realloc(old_pointer, size);
    if(new_pointer) set_allocator.pointers[index] = new_pointer;
    return new_pointer;
}

/* Release a tracked allocation and remove it from the ownership table.
 * Purpose: Detect leaks and duplicate frees in SET OF encoder cleanup paths.
 * Original source: New runtime encoder allocation-failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: pointer is the buffer to release; NULL is accepted.
 * Returns: No value; the allocation is freed when it is tracked.
 * Errors: Unknown non-NULL pointers mark accounting_error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: tracked_free(pointer) removes one live encoder allocation.
 */
static void
tracked_free(void *pointer) {
    size_t index;

    if(!pointer) return;
    for(index = 0; index < set_allocator.live_count; index++) {
        if(set_allocator.pointers[index] == pointer) break;
    }
    if(index == set_allocator.live_count) {
        set_allocator.accounting_error = 1;
        return;
    }
    set_allocator.pointers[index] =
        set_allocator.pointers[--set_allocator.live_count];
    free(pointer);
}

/* Allocate through malloc, then record the encoder's new workspace block.
 * Purpose: Implement the included source's MALLOC hook.
 * Original source: New runtime encoder allocation-failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: size is the requested allocation size.
 * Returns: Tracked storage or NULL on allocation/tracking failure.
 * Errors: Failure is propagated as NULL to the encoder.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: tracked_malloc(16) returns one tracked workspace block.
 */
static void *
tracked_malloc(size_t size) {
    return track_allocation(malloc(size));
}

/* Ensure one test path released every allocation made by the SET OF encoder.
 * Purpose: Assert allocator accounting is clean between isolated encode calls.
 * Original source: New runtime encoder allocation-failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: label identifies the success or failure path being checked.
 * Returns: Zero when no allocations remain, otherwise one.
 * Errors: A nonempty table or allocator mismatch is reported through require.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: require_set_allocator_clean("canonical callback failure").
 */
static int
require_set_allocator_clean(const char *label) {
    return require(set_allocator.live_count == 0
                   && !set_allocator.accounting_error, label);
}

/* Return a child encoder error or emit a single native INTEGER token.
 * Purpose: Inject a nested JER child failure while preserving its descriptor.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: td/sptr identify the child; cb/app_key receive the successful token.
 * Returns: One encoded byte, or an error naming this child and its value.
 * Errors: Callback errors return the same child error descriptor.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: Set child_encoder_fails before invoking CHOICE_encode_jer.
 */
static asn_enc_rval_t
test_child_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      const void *sptr, int ilevel,
                      enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t result = {0, 0, 0};
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(child_encoder_fails || cb("7", 1, app_key) < 0) {
        result.encoded = -1;
        result.failed_type = td;
        result.structure_ptr = sptr;
        return result;
    }
    result.encoded = 1;
    return result;
}

/* Test-only operation table routes JER through the injectable child encoder. */
static asn_TYPE_operation_t test_child_operations = {
    .jer_encoder = test_child_encode_jer, /* Injected child JER implementation. */
};

/* The child descriptor names the error that CHOICE must pass through. */
static asn_TYPE_descriptor_t asn_DEF_TestChild = {
    .name = "TestChild", /* Diagnostic type name. */
    .xml_tag = "TestChild", /* Display name for encoders. */
    .op = &test_child_operations, /* JER operation table. */
};

/* One member maps the inline long value to the test child descriptor. */
static asn_TYPE_member_t test_choice_members[] = {
    {
        .flags = 0, /* Member storage is inline. */
        .memb_offset = offsetof(test_choice_t, value), /* Inline field offset. */
        .type = &asn_DEF_TestChild, /* Child descriptor under test. */
        .name = "value", /* JSON object member name. */
    },
};

/* CHOICE specifics identify the active member and generated-style layout. */
static asn_CHOICE_specifics_t test_choice_specifics = {
    .struct_size = sizeof(test_choice_t), /* Value layout size. */
    .ctx_offset = 0, /* No decoder context is needed. */
    .pres_offset = offsetof(test_choice_t, present), /* Active-member field. */
    .pres_size = sizeof(((test_choice_t *)0)->present), /* Presence width. */
    .ext_start = -1, /* The fixture has no extension members. */
};

/* Descriptor binds the one-member test value to the CHOICE encoder. */
static asn_TYPE_descriptor_t asn_DEF_TestChoice = {
    .name = "TestChoice", /* Diagnostic type name. */
    .xml_tag = "TestChoice", /* Display name for encoders. */
    .op = &asn_OP_CHOICE, /* Runtime CHOICE operation table. */
    .elements = test_choice_members, /* The single child member. */
    .elements_count = 1, /* Number of child alternatives. */
    .specifics = &test_choice_specifics, /* Generated-style layout metadata. */
};

/* SET OF's element descriptor uses the native signed INTEGER encoder. */
static asn_TYPE_member_t test_set_members[] = {
    {
        .flags = 0, /* List entries point directly to their native values. */
        .type = &asn_DEF_NativeInteger, /* Native signed INTEGER descriptor. */
        .name = "value", /* XER member tag. */
    },
};

/* SET OF metadata carries its generated storage size and context offset. */
static asn_SET_OF_specifics_t test_set_specifics = {
    .struct_size = sizeof(test_set_t), /* Collection value size. */
    .ctx_offset = offsetof(test_set_t, _asn_ctx), /* Decoder context location. */
    .as_XMLValueList = 0, /* Encode as ordinary SET OF elements. */
};

/* Descriptor connects the generated-style list with canonical XER. */
static asn_TYPE_descriptor_t asn_DEF_TestSet = {
    .name = "TestSet", /* Diagnostic type name. */
    .xml_tag = "TestSet", /* Display name for encoders. */
    .op = &asn_OP_SET_OF, /* Runtime SET OF operation table. */
    .elements = test_set_members, /* One native INTEGER member descriptor. */
    .elements_count = 1, /* One element type. */
    .specifics = &test_set_specifics, /* Generated-style layout metadata. */
};

/* Record an assertion failure while allowing later independent checks to run.
 * Purpose: Report one false condition in the focused test executable.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: condition is expected true; label identifies the expectation.
 * Returns: Zero when true, or one after reporting a false condition.
 * Errors: None; a false condition is printed to stderr.
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: failed |= require(result.encoded < 0, "encoding fails").
 */
static int
require(int condition, const char *label) {
    if(condition) return 0;
    fprintf(stderr, "runtime encoder failure check failed: %s\n", label);
    return 1;
}

/* Compare the captured callback bytes with a fixed expected encoding.
 * Purpose: Check exact success output without depending on a trailing NUL.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: capture contains output; expected is its NUL-terminated spelling.
 * Returns: Zero for exact equality, or one after reporting a failed check.
 * Errors: None; mismatches are reported through require().
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: require_output(&capture, "\\\"A\\\"") checks a quoted A.
 */
static int
require_output(const output_capture_t *capture, const char *expected) {
    size_t expected_length = strlen(expected);
    int exact = capture->length == expected_length
        && memcmp(capture->bytes, expected, expected_length) == 0;
    return require(exact, "success output matches expected bytes");
}

/* Check success and each callback failure point in UniversalString JER.
 * Purpose: Verify dump and outer punctuation callbacks cannot report success.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: None; the value is one big-endian UCS-4 character.
 * Returns: Number of failed expectations.
 * Errors: No exceptions; check failures are counted for main().
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: universal_string_checks() checks a valid "A" and three faults.
 */
static int
universal_string_checks(void) {
    uint8_t character[] = {0, 0, 0, 'A'};
    UniversalString_t value = {character, sizeof(character), {0}};
    output_capture_t capture = {{0}, 0, 0, 0};
    asn_enc_rval_t result;
    int failed = 0;
    size_t fail_at;

    result = UniversalString_encode_jer(&asn_DEF_UniversalString, NULL,
                                        &value, 0, JER_F,
                                        capture_callback, &capture);
    failed |= require(result.encoded == 3, "UniversalString JER succeeds");
    failed |= require_output(&capture, "\"A\"");

    /* Reject punctuation and dump output in turn to cover both error sources. */
    for(fail_at = 1; fail_at <= 3; fail_at++) {
        capture = (output_capture_t){{0}, 0, 0, fail_at};
        result = UniversalString_encode_jer(&asn_DEF_UniversalString, NULL,
                                            &value, 0, JER_F,
                                            capture_callback, &capture);
        failed |= require(result.encoded == -1,
                          "UniversalString callback failure is reported");
        failed |= require(result.failed_type == &asn_DEF_UniversalString,
                          "UniversalString error names its type");
    }
    return failed;
}

/* Check sorted output and cleanup/depth recovery after canonical XER callback
 * failure. Purpose: Exercise the final callback that drains sorted buffers.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: None; two native INTEGER values are encoded as one SET OF.
 * Returns: Number of failed expectations.
 * Errors: No exceptions; check failures are counted for main().
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: set_of_checks() expects canonical values in lexical order.
 */
static int
set_of_checks(void) {
    long first = 2;
    long second = 1;
    long *values[] = {&first, &second};
    test_set_t value = {{values, 2, 2, NULL}, {0}};
    output_capture_t capture = {{0}, 0, 0, 0};
    asn_enc_rval_t result;
    int failed = 0;
    int saved_depth = xer_encoding_depth;

    result = SET_OF_encode_xer(&asn_DEF_TestSet, &value, 0,
                               XER_F_CANONICAL, capture_callback, &capture);
    failed |= require(result.encoded >= 0, "canonical SET OF succeeds");
    failed |= require_output(&capture,
                             "<value>1</value><value>2</value>");
    failed |= require_set_allocator_clean(
        "successful canonical encoding releases all temporary buffers");
    failed |= require(xer_encoding_depth == saved_depth,
                      "successful SET OF restores XER depth");

    capture = (output_capture_t){{0}, 0, 0, 1};
    result = SET_OF_encode_xer(&asn_DEF_TestSet, &value, 0,
                               XER_F_CANONICAL, capture_callback, &capture);
    failed |= require(result.encoded == -1,
                      "final canonical XER callback failure is reported");
    failed |= require(result.failed_type == &asn_DEF_TestSet,
                      "canonical XER error names the SET OF");
    failed |= require_set_allocator_clean(
        "failed final callback releases all buffers and the encodings array");
    failed |= require(xer_encoding_depth == saved_depth,
                      "failed SET OF restores XER depth exactly once");
    return failed;
}

/* Check the child error survives and CHOICE restores its recursion depth.
 * Purpose: Cover the direct return path for a failed JER member encoder.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: None; a one-member generated-style CHOICE selects its child.
 * Returns: Number of failed expectations.
 * Errors: No exceptions; check failures are counted for main().
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: choice_checks() checks both nested failure and successful output.
 */
static int
choice_checks(void) {
    test_choice_t value = {1, 7};
    output_capture_t capture = {{0}, 0, 0, 0};
    asn_enc_rval_t result;
    int failed = 0;
    int saved_depth = jer_encoding_depth;

    child_encoder_fails = 1;
    result = CHOICE_encode_jer(&asn_DEF_TestChoice, NULL, &value, 0,
                               JER_F_MINIFIED, capture_callback, &capture);
    failed |= require(result.encoded == -1, "failed CHOICE child is reported");
    failed |= require(result.failed_type == &asn_DEF_TestChild,
                      "CHOICE preserves child error descriptor");
    failed |= require(result.structure_ptr == &value.value,
                      "CHOICE preserves child error structure");
    failed |= require(jer_encoding_depth == saved_depth,
                      "failed CHOICE restores JER depth");

    child_encoder_fails = 0;
    capture = (output_capture_t){{0}, 0, 0, 0};
    result = CHOICE_encode_jer(&asn_DEF_TestChoice, NULL, &value, 0,
                               JER_F_MINIFIED, capture_callback, &capture);
    failed |= require(result.encoded >= 0, "successful CHOICE child is encoded");
    failed |= require_output(&capture, "{\"value\":7}");
    failed |= require(jer_encoding_depth == saved_depth,
                      "successful CHOICE restores JER depth");
    return failed;
}

/* Run each independent failure-family check and return a process status.
 * Purpose: Execute the focused runtime encoder regressions.
 * Original source: New runtime encoder failure regression test.
 * Version/date: 1.0, 2026-10-24.
 * Inputs: No command-line arguments are used.
 * Returns: EXIT_SUCCESS when all checks pass, otherwise EXIT_FAILURE.
 * Errors: Failed expectations are printed by require().
 * Responsible party: asn1c maintainers. History: Added 2026-10-24.
 * Example: Run the test binary directly to execute all injected failures.
 */
int
main(void) {
    int failed = 0;

    failed |= universal_string_checks();
    failed |= set_of_checks();
    failed |= choice_checks();
    return failed ? 1 : 0;
}
