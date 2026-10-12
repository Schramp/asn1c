/*
 * Test CER allocation cleanup and independent work/scratch ceilings.
 * Original source: New asn1c CER resource regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: A nested SEQUENCE/SET OF value and build-specific resource ceilings.
 * Returns: EXIT_SUCCESS when fault cleanup and selected limits behave exactly.
 * Errors: Failed assertions report to stderr; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: `make -C tests/tests-skeletons check-CER-resources`.
 */
#include <asn_internal.h>
#include <asn_application.h>
#include <cer_encoder.h>
#include <BOOLEAN.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <constr_SET_OF.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocator bookkeeping lets each injected CER failure prove complete cleanup. */
typedef struct cer_resource_allocator_s {
    void *pointers[256]; /* state variable: live CER allocations under test. */
    size_t live_count; /* state variable: number of tracked live allocations. */
    size_t calls; /* state variable: allocation and reallocation attempts. */
    size_t fail_at; /* state variable: selected failing allocation attempt. */
    int accounting_error; /* state variable: allocator tracking inconsistency. */
} cer_resource_allocator_t;

/* state variable: records only allocations made by the included CER source. */
static cer_resource_allocator_t cer_resource_allocator = {{0}, 0, 0, 0, 0};

/* Generated-style SET OF storage points to native signed INTEGER values. */
typedef struct cer_resource_set_s {
    struct {
        long **array; /* Pointers to each present list element. */
        int count; /* state variable: initialized element count. */
        int size; /* Allocated pointer-array capacity. */
        void (*free)(long *); /* Element destructor, unused for stack values. */
    } list; /* Collection layout expected by SET OF operations. */
    asn_struct_ctx_t _asn_ctx; /* Decoder context field used by metadata. */
} cer_resource_set_t;

/* Nested parent value keeps a constructed member live while SET OF sorts. */
typedef struct cer_resource_sequence_s {
    cer_resource_set_t numbers; /* Inline SET OF member. */
    BOOLEAN_t enabled; /* Required trailing BOOLEAN member. */
} cer_resource_sequence_t;

#if !defined(ASN_CER_TEST_WORK_LIMIT) && \
    !defined(ASN_CER_TEST_SCRATCH_LIMIT)
/* SET OF descriptor has one native INTEGER element type. */
static asn_TYPE_member_t cer_resource_set_members[] = {
    {
        .flags = 0, /* List entries point directly to their values. */
        .optional = 0, /* Every counted element must be present. */
        .memb_offset = 0, /* SET OF uses its list array, not a C struct field. */
        .tag_mode = 0, /* Native INTEGER retains its universal tag. */
        .type = &asn_DEF_NativeInteger, /* Element value descriptor. */
        .name = "element", /* Diagnostic ASN.1 component name. */
    },
};

/* SET OF specifics provide the C layout and decoder-context offset. */
static asn_SET_OF_specifics_t cer_resource_set_specifics = {
    .struct_size = sizeof(cer_resource_set_t), /* Collection value size. */
    .ctx_offset = offsetof(cer_resource_set_t, _asn_ctx), /* Context location. */
    .as_XMLValueList = 0, /* The value is an ASN.1 SET OF. */
};

/* The canonical collection receives universal constructed tag 17. */
static const ber_tlv_tag_t cer_resource_set_tags[] = {
    ASN_TAG_CLASS_UNIVERSAL | (17u << 2), /* SET OF tag. */
};

/* This descriptor forces member bytes to remain live for canonical sorting. */
static asn_TYPE_descriptor_t asn_DEF_CER_ResourceSet = {
    .name = "CER-ResourceSet", /* Diagnostic type name. */
    .xml_tag = "CER-ResourceSet", /* Stable display tag. */
    .op = &asn_OP_SET_OF, /* SET OF operation table. */
    .tags = cer_resource_set_tags, /* Effective constructed tag. */
    .tags_count = 1, /* One effective tag. */
    .all_tags = cer_resource_set_tags, /* Complete effective tag chain. */
    .all_tags_count = 1, /* One tag in the complete chain. */
    .elements = cer_resource_set_members, /* Element descriptor table. */
    .elements_count = 1, /* One element type. */
    .specifics = &cer_resource_set_specifics, /* Generated-style layout. */
};

/* Parent SEQUENCE emits the nested SET OF before its required BOOLEAN. */
static asn_TYPE_member_t cer_resource_sequence_members[] = {
    {
        .flags = 0, /* SET OF storage is inline. */
        .optional = 0, /* The collection member is required. */
        .memb_offset = offsetof(cer_resource_sequence_t, numbers),
        .tag_mode = 0, /* The SET OF universal tag is retained. */
        .type = &asn_DEF_CER_ResourceSet, /* Nested collection descriptor. */
        .name = "numbers", /* Diagnostic ASN.1 member name. */
    },
    {
        .flags = 0, /* BOOLEAN storage is inline. */
        .optional = 0, /* The BOOLEAN member is required. */
        .memb_offset = offsetof(cer_resource_sequence_t, enabled),
        .tag_mode = 0, /* The BOOLEAN universal tag is retained. */
        .type = &asn_DEF_BOOLEAN, /* Required BOOLEAN descriptor. */
        .name = "enabled", /* Diagnostic ASN.1 member name. */
    },
};

/* SEQUENCE specifics bound both inline offsets against the containing value. */
static asn_SEQUENCE_specifics_t cer_resource_sequence_specifics = {
    .struct_size = sizeof(cer_resource_sequence_t), /* Parent value size. */
    .ctx_offset = 0, /* No decoder context is needed by this fixture. */
    .tag2el = NULL, /* CER encoding does not use the BER lookup table. */
    .tag2el_count = 0, /* No BER lookup entries. */
    .oms = NULL, /* No PER optional map is needed. */
    .roms_count = 0, /* No root optional members. */
    .aoms_count = 0, /* No extension optional members. */
    .first_extension = -1, /* The fixture is not extensible. */
};

/* Parent descriptor emits a CER indefinite-length SEQUENCE. */
static const ber_tlv_tag_t cer_resource_sequence_tags[] = {
    ASN_TAG_CLASS_UNIVERSAL | (16u << 2), /* SEQUENCE tag. */
};

/* Root type descriptor traverses the nested SET OF during each test call. */
static asn_TYPE_descriptor_t asn_DEF_CER_ResourceSequence = {
    .name = "CER-ResourceSequence", /* Diagnostic type name. */
    .xml_tag = "CER-ResourceSequence", /* Stable display tag. */
    .op = &asn_OP_SEQUENCE, /* SEQUENCE operation table. */
    .tags = cer_resource_sequence_tags, /* Effective constructed tag. */
    .tags_count = 1, /* One effective tag. */
    .all_tags = cer_resource_sequence_tags, /* Complete effective tag chain. */
    .all_tags_count = 1, /* One tag in the complete chain. */
    .elements = cer_resource_sequence_members, /* Ordered component table. */
    .elements_count = 2, /* SET OF and BOOLEAN components. */
    .specifics = &cer_resource_sequence_specifics, /* Generated-style layout. */
};
#endif

/* Override allocation only in the locally included CER implementation unit. */
void *cer_resource_malloc(size_t size);
void *cer_resource_realloc(void *old_pointer, size_t size);
void cer_resource_free(void *pointer);

#undef MALLOC
#undef REALLOC
#undef FREEMEM
#define MALLOC(size) cer_resource_malloc(size)
#define REALLOC(oldptr, size) cer_resource_realloc(oldptr, size)
#define FREEMEM(ptr) cer_resource_free(ptr)
#include "../../skeletons/cer_encoder.c"

/*
 * Add a successful allocation to the fault-test ownership table.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: pointer is a newly allocated CER workspace block.
 * Returns: Zero after tracking the block, or -1 if the table is full.
 * Errors: Frees pointer and marks accounting_error if tracking capacity is hit.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: return cer_resource_track(malloc(size)) ? NULL : pointer.
 */
static int
cer_resource_track(void *pointer) {
    if(cer_resource_allocator.live_count >=
       sizeof(cer_resource_allocator.pointers) /
           sizeof(cer_resource_allocator.pointers[0])) {
        cer_resource_allocator.accounting_error = 1;
        free(pointer);
        return -1;
    }
    cer_resource_allocator.pointers[cer_resource_allocator.live_count++] =
        pointer;
    return 0;
}

/*
 * Remove one block from the test allocator's live-allocation table.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: pointer is the live CER allocation being released or resized.
 * Returns: Zero when pointer was tracked, otherwise -1 and a sticky error.
 * Errors: Marks accounting_error when the pointer is absent; no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: if(cer_resource_untrack(pointer)) fail_the_allocator_test();
 */
static int
cer_resource_untrack(void *pointer) {
    size_t index;

    for(index = 0; index < cer_resource_allocator.live_count; index++) {
        if(cer_resource_allocator.pointers[index] == pointer) {
            cer_resource_allocator.live_count--;
            cer_resource_allocator.pointers[index] =
                cer_resource_allocator.pointers[cer_resource_allocator.live_count];
            return 0;
        }
    }
    cer_resource_allocator.accounting_error = 1;
    return -1;
}

/*
 * Implement the CER source's MALLOC hook with deterministic failure injection.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: size is the requested allocation size.
 * Returns: A tracked allocation, or NULL on injected/system/tracking failure.
 * Errors: No errno contract; all failures are observed through the CER API.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: CER calls MALLOC(size), which expands to this function.
 */
void *
cer_resource_malloc(size_t size) {
    void *pointer;

    cer_resource_allocator.calls++;
    if(cer_resource_allocator.calls == cer_resource_allocator.fail_at) {
        return NULL;
    }
    pointer = malloc(size);
    if(pointer && cer_resource_track(pointer)) return NULL;
    return pointer;
}

/*
 * Implement the CER source's REALLOC hook and retain ownership on failure.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: old_pointer is NULL or a tracked block; size is its new size.
 * Returns: A tracked replacement block, or NULL with old_pointer still live.
 * Errors: No errno contract; injected failures follow realloc semantics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: grown = REALLOC(old_block, capacity) in the included CER source.
 */
void *
cer_resource_realloc(void *old_pointer, size_t size) {
    void *new_pointer;
    int tracked_old = old_pointer != NULL;

    cer_resource_allocator.calls++;
    if(cer_resource_allocator.calls == cer_resource_allocator.fail_at) {
        return NULL;
    }
    if(tracked_old && cer_resource_untrack(old_pointer)) return NULL;
    new_pointer = realloc(old_pointer, size);
    if(!new_pointer) {
        if(tracked_old) cer_resource_track(old_pointer);
        return NULL;
    }
    if(cer_resource_track(new_pointer)) return NULL;
    return new_pointer;
}

/*
 * Implement CER's FREEMEM hook and record mismatched ownership attempts.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: pointer is NULL or a CER block previously returned by a hook.
 * Returns: No value; live allocation state is updated before the system free.
 * Errors: Marks accounting_error when a non-NULL block was not tracked.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: FREEMEM(block) expands to cer_resource_free(block).
 */
void
cer_resource_free(void *pointer) {
    if(!pointer) return;
    cer_resource_untrack(pointer);
    free(pointer);
}

/*
 * Reset fault-injection counters for one independent encoder invocation.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: fail_at is the one-based allocation attempt to reject, or zero.
 * Returns: No value; frees stale blocks and records a leak before resetting.
 * Errors: A previous live block makes accounting_error sticky for this run.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_resource_begin(2) fails the second CER allocation attempt.
 */
static void
cer_resource_begin(size_t fail_at) {
    size_t index;
    int prior_leak = cer_resource_allocator.live_count != 0;

    for(index = 0; index < cer_resource_allocator.live_count; index++) {
        free(cer_resource_allocator.pointers[index]);
    }
    memset(&cer_resource_allocator, 0, sizeof(cer_resource_allocator));
    cer_resource_allocator.fail_at = fail_at;
    cer_resource_allocator.accounting_error = prior_leak;
}

/*
 * Report one resource-test assertion failure with its short diagnostic label.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: condition is the expected result; label describes the check.
 * Returns: Zero when condition is true, otherwise -1 after writing stderr.
 * Errors: No exceptions; diagnostic output errors do not change the result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: failed |= cer_resource_require(live == 0, "cleanup").
 */
static int
cer_resource_require(int condition, const char *label) {
    if(condition) return 0;
    fprintf(stderr, "CER resource test failed: %s\n", label);
    return -1;
}

#if !defined(ASN_CER_TEST_WORK_LIMIT) && \
    !defined(ASN_CER_TEST_SCRATCH_LIMIT)
/*
 * Encode the nested fixture with one injected allocation failure.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: fail_at selects an allocation attempt; completed receives success.
 * Returns: Zero when error/success, output atomicity, cleanup, and input checks pass.
 * Errors: Reports any mismatch through cer_resource_require(); no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_resource_run_failure(1, &completed) rejects the first allocation.
 */
static int
cer_resource_run_failure(size_t fail_at, int *completed) {
    static const uint8_t expected[] = {
        0x30, 0x80, 0x31, 0x80, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80,
        0x02, 0x02, 0xff, 0x7f, 0x00, 0x00, 0x01, 0x01, 0xff, 0x00, 0x00
    };
    uint8_t output[128];
    long values[] = {128, -129, 1};
    long *entries[] = {&values[0], &values[1], &values[2]};
    cer_resource_sequence_t sequence;
    asn_enc_rval_t encoded;
    size_t index;
    int failed = 0;

    cer_resource_begin(fail_at);
    memset(&sequence, 0, sizeof(sequence));
    sequence.numbers.list.array = entries;
    sequence.numbers.list.count = 3;
    sequence.numbers.list.size = 3;
    sequence.enabled = 1;
    memset(output, 0xa5, sizeof(output));
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_CER_ResourceSequence,
                                   &sequence, output, sizeof(output));
    if(encoded.encoded == -1) {
        failed |= cer_resource_require(errno == ENOMEM,
                                       "injected failure reports ENOMEM");
        for(index = 0; index < sizeof(output); index++) {
            if(output[index] != 0xa5) break;
        }
        failed |= cer_resource_require(index == sizeof(output),
                                       "failed direct output preserves sentinel");
    } else {
        failed |= cer_resource_require(
            encoded.encoded == (ssize_t)sizeof(expected) &&
            memcmp(output, expected, sizeof(expected)) == 0,
            "allocation sweep eventually produces the independent CER vector");
        failed |= cer_resource_require(cer_resource_allocator.calls < fail_at,
                                       "success occurs after the last CER allocation");
        *completed = 1;
    }
    failed |= cer_resource_require(cer_resource_allocator.live_count == 0,
                                   "all CER allocations are released");
    failed |= cer_resource_require(!cer_resource_allocator.accounting_error,
                                   "allocation tracker remains consistent");
    failed |= cer_resource_require(values[0] == 128 && values[1] == -129 &&
                                   values[2] == 1 && entries[0] == &values[0] &&
                                   entries[1] == &values[1] &&
                                   entries[2] == &values[2] &&
                                   sequence.numbers.list.count == 3 &&
                                   sequence.numbers.list.size == 3,
                                   "encoding preserves caller-owned input storage");
    return failed;
}

/*
 * Sweep every CER-owned allocation point until encoding completes.
 * Original source: New asn1c CER allocation-failure fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; the encoder allocation index is advanced by this test.
 * Returns: Zero when every injected failure cleans up and one later call succeeds.
 * Errors: Returns -1 on any unexpected encoder, cleanup, or input result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: selected by the default `check-CER-resources` build mode.
 */
static int
cer_resource_check_allocation_failures(void) {
    size_t fail_at;
    int completed = 0;
    int failed = 0;

    for(fail_at = 1; fail_at <= 128 && !completed; fail_at++) {
        failed |= cer_resource_run_failure(fail_at, &completed);
    }
    failed |= cer_resource_require(completed,
                                   "allocation sweep reaches successful encoding");
    return failed;
}
#endif

#if defined(ASN_CER_TEST_WORK_LIMIT)
/*
 * Prove a zero work budget rejects a small value before allocating output.
 * Original source: New asn1c CER resource-limit regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; target CPPFLAGS set work cap zero and other caps ample.
 * Returns: Zero when CER returns EOVERFLOW without changing the caller buffer.
 * Errors: A failed condition is reported as -1; no exceptions are used.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: selected by `check-CER-work` with ASN_CER_MAX_WORK_ITEMS=0.
 */
static int
cer_resource_check_work_limit(void) {
    NULL_t value = 0;
    uint8_t output[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    asn_enc_rval_t encoded;

    cer_resource_begin(0);
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_NULL, &value, output,
                                   sizeof(output));
    return cer_resource_require(encoded.encoded == -1 && errno == EOVERFLOW &&
                                output[0] == 0xa5 &&
                                cer_resource_allocator.calls == 0 &&
                                cer_resource_allocator.live_count == 0,
                                "zero work budget rejects a fitting NULL TLV");
}
#endif

#if defined(ASN_CER_TEST_SCRATCH_LIMIT)
/*
 * Prove a small scratch budget rejects a fitting value before allocation.
 * Original source: New asn1c CER resource-limit regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; target CPPFLAGS set scratch cap 63 and other caps ample.
 * Returns: Zero when CER returns EOVERFLOW without changing the caller buffer.
 * Errors: A failed condition is reported as -1; no exceptions are used.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: selected by `check-CER-scratch` with a 63-byte scratch cap.
 */
static int
cer_resource_check_scratch_limit(void) {
    NULL_t value = 0;
    uint8_t output[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    asn_enc_rval_t encoded;

    cer_resource_begin(0);
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_NULL, &value, output,
                                   sizeof(output));
    return cer_resource_require(encoded.encoded == -1 && errno == EOVERFLOW &&
                                output[0] == 0xa5 &&
                                cer_resource_allocator.calls == 0 &&
                                cer_resource_allocator.live_count == 0,
                                "undersized scratch budget rejects fitting NULL TLV");
}
#endif

/*
 * Run the resource test selected by this target's compile-time limits.
 * Original source: New asn1c CER resource regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; the target CPPFLAGS select allocation, work, or scratch mode.
 * Returns: EXIT_SUCCESS when the selected resource assertion passes.
 * Errors: EXIT_FAILURE when the selected mode detects an unexpected result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: `./check-CER-work` runs the work-ceiling variant.
 */
int
main(void) {
    int failed;

#if defined(ASN_CER_TEST_WORK_LIMIT)
    failed = cer_resource_check_work_limit();
#elif defined(ASN_CER_TEST_SCRATCH_LIMIT)
    failed = cer_resource_check_scratch_limit();
#else
    failed = cer_resource_check_allocation_failures();
#endif
    if(failed) return EXIT_FAILURE;
    puts("CER resource tests passed");
    return EXIT_SUCCESS;
}
