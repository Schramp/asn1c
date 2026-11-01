/*
 * Purpose: exercise generated XER TEXT BIT STRING encoders and decoders.
 * Original source: ASN.1 XER TEXT BIT STRING encoding-control regression.
 * Version/date: 1.0, 2026-10-24.
 * Parameters: none.
 * Returns: zero when all generated-code behavior matches the expectations.
 * Errors: failed assertions terminate the test with a nonzero status.
 * Responsible party: asn1c maintainers.
 * History: added empty-name and named-bit callback/error coverage.
 * Example: run from check-xer-text-bitstring.sh after code generation.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "Empty.h"
#include "Named.h"
#include "xer_decoder.h"
#include "xer_encoder.h"

/* Collect callback output for checking the named-bit wire representation. */
typedef struct output_buffer_s {
    char *data; /* state variable: accumulated callback bytes, NUL-terminated */
    size_t size; /* state variable: number of accumulated callback bytes */
    int calls; /* state variable: number of callback invocations */
} output_buffer_t;

/*
 * Purpose: append one encoder callback chunk to a test output buffer.
 * Original source: local XER TEXT BIT STRING regression test.
 * Version/date: 1.0, 2026-10-24.
 * Parameters: data is the chunk; size is its byte count; key is output_buffer_t.
 * Returns: zero on success, negative on allocation failure.
 * Errors: allocation failure is reported to the encoder callback caller.
 * Responsible party: asn1c maintainers.
 * History: initial regression-test implementation.
 * Example: passed as the consume_bytes callback to a generated encoder.
 */
static int
collect_output(const void *data, size_t size, void *key) {
    output_buffer_t *output = (output_buffer_t *)key;
    char *resized;

    /* Preserve the existing output if allocation fails. */
    resized = (char *)realloc(output->data, output->size + size + 1);
    if(!resized) return -1;
    output->data = resized;
    memcpy(output->data + output->size, data, size);
    output->size += size;
    output->data[output->size] = '\0';
    output->calls++;
    return 0;
}

/*
 * Purpose: fail the first callback to check generated callback error handling.
 * Original source: local XER TEXT BIT STRING regression test.
 * Version/date: 1.0, 2026-10-24.
 * Parameters: data and size are intentionally ignored; key counts invocations.
 * Returns: always negative, as required to make ASN__CALLBACK fail.
 * Errors: none.
 * Responsible party: asn1c maintainers.
 * History: initial regression-test implementation.
 * Example: passed to Named's generated encoder to reach cb_failed.
 */
static int
fail_output(const void *data, size_t size, void *key) {
    int *calls = (int *)key;

    (void)data;
    (void)size;
    (*calls)++;
    return -1;
}

/*
 * Purpose: verify empty-name output, named-bit mapping, and malformed input.
 * Original source: local XER TEXT BIT STRING regression test.
 * Version/date: 1.0, 2026-10-24.
 * Parameters: none.
 * Returns: zero after assertions pass.
 * Errors: failed assertions terminate the test with a nonzero status.
 * Responsible party: asn1c maintainers.
 * History: initial regression-test implementation.
 * Example: invoked by check-xer-text-bitstring.sh.
 */
int
main(void) {
    uint8_t empty_storage = 0;
    Empty_t empty = {&empty_storage, 0, 0, 0};
    uint8_t named_storage = 0xc0;
    Named_t named = {&named_storage, 1, 6, 0};
    output_buffer_t output = {0, 0, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t decoded_result;
    Empty_t *empty_decoded = 0;
    Named_t *named_decoded = 0;
    int failed_callback_calls = 0;

    /* Empty named-bit sets encode no bytes and never call the callback. */
    encoded = asn_DEF_Empty.op->xer_encoder(&asn_DEF_Empty, &empty, 0,
                                             XER_F_BASIC, collect_output,
                                             &output);
    assert(encoded.encoded == 0);
    assert(output.calls == 0);
    assert(output.data == 0);

    /* Named bits retain their names, separator, and callback error path. */
    encoded = asn_DEF_Named.op->xer_encoder(&asn_DEF_Named, &named, 0,
                                             XER_F_BASIC, collect_output,
                                             &output);
    assert(encoded.encoded >= 0);
    assert(output.data);
    assert(strcmp(output.data, "alpha beta") == 0);
    assert(output.calls == 3);
    encoded = asn_DEF_Named.op->xer_encoder(&asn_DEF_Named, &named, 0,
                                             XER_F_BASIC, fail_output,
                                             &failed_callback_calls);
    assert(encoded.encoded < 0);
    assert(encoded.failed_type == &asn_DEF_Named);
    assert(failed_callback_calls == 1);

    /* The empty-name decoder rejects any token because none can be named. */
    decoded_result = xer_decode(0, &asn_DEF_Empty, (void **)&empty_decoded,
                                "<Empty>alpha</Empty>", sizeof("<Empty>alpha</Empty>") - 1);
    assert(decoded_result.code != RC_OK);
    if(empty_decoded) ASN_STRUCT_FREE(asn_DEF_Empty, empty_decoded);

    /* Named-bit decoder rejects unknown tokens without writing to the value. */
    decoded_result = xer_decode(0, &asn_DEF_Named, (void **)&named_decoded,
                                "<Named>unknown</Named>",
                                sizeof("<Named>unknown</Named>") - 1);
    assert(decoded_result.code != RC_OK);
    if(named_decoded) ASN_STRUCT_FREE(asn_DEF_Named, named_decoded);

    free(output.data);
    return 0;
}
