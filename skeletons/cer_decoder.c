/*
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cer_decoder.h>
#include <errno.h>

#if !defined(ASN_DISABLE_BER_SUPPORT) && !defined(ASN_DISABLE_CER_SUPPORT)

#include <ber_decoder.h>
#include <cer_encoder.h>

/*
 * Comparison state for checking a CER re-encoding against consumed input.
 * Original source: New asn1c strict CER decoder.
 * Version/date: 1.0, 2026-10-11.
 * Fields: expected/expected_size describe the consumed input bytes; offset
 *   counts re-encoded bytes compared so far; mismatch records a difference.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: initialized by cer_decode() and passed to cer_compare_cb().
 */
typedef struct cer_compare_state_s {
    const uint8_t *expected;
    size_t expected_size;
    size_t offset;
    int mismatch;
} cer_compare_state_t;

/*
 * Compare one chunk of CER output with the next bytes of the original input.
 * Original source: New asn1c strict CER decoder callback.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: buffer/size are encoder output; key is cer_compare_state_t.
 * Returns: 0 when the chunk matches, -1 on overrun or byte mismatch.
 * Errors: Sets state->mismatch; cer_encode() then reports EIO, which
 *   cer_decode() translates to EBADF. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_encode(ctx, td, value, cer_compare_cb, &state).
 */
static int
cer_compare_cb(const void *buffer, size_t size, void *key) {
    cer_compare_state_t *state = (cer_compare_state_t *)key;

    if(size > state->expected_size - state->offset
       || (size != 0
           && memcmp(state->expected + state->offset, buffer, size) != 0)) {
        state->mismatch = 1;
        return -1;
    }
    state->offset += size;
    return 0;
}

/*
 * Release a structure produced by a failed or incomplete strict decode.
 * Original source: New asn1c strict CER decoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td describes the type; struct_ptr points at the structure
 *   pointer; allocated_here is nonzero when cer_decode() allocated it.
 * Returns: No value. Caller-owned storage is reset, never freed.
 * Errors: None; NULL structures are ignored. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_release(td, sptr, 1) frees and sets *sptr to NULL.
 */
static void
cer_release(const asn_TYPE_descriptor_t *td, void **struct_ptr,
            int allocated_here) {
    if(*struct_ptr == NULL) return;
    if(allocated_here) {
        td->op->free_struct(td, *struct_ptr, ASFM_FREE_EVERYTHING);
        *struct_ptr = NULL;
    } else {
        td->op->free_struct(td, *struct_ptr, ASFM_FREE_UNDERLYING_AND_RESET);
    }
}

/*
 * Decode a value strictly according to the Canonical Encoding Rules.
 * Original source: New asn1c strict CER decoder; see cer_decoder.h.
 * Version/date: 1.0, 2026-10-11.
 * Parameters/Returns/Errors: As documented in cer_decoder.h.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_decode(0, &asn_DEF_NULL, (void **)&v, "\x05\x00", 2).
 */
asn_dec_rval_t
cer_decode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *td, void **struct_ptr,
           const void *buffer, size_t size) {
    asn_dec_rval_t rval = {RC_FAIL, 0};
    asn_dec_rval_t failed = {RC_FAIL, 0};
    asn_enc_rval_t er;
    cer_compare_state_t state;
    int allocated_here;

    if(!td || !td->op || !td->op->free_struct || !struct_ptr
       || (!buffer && size != 0)) {
        errno = EINVAL;
        return failed;
    }
    allocated_here = (*struct_ptr == NULL);

    rval = ber_decode(opt_codec_ctx, td, struct_ptr, buffer, size);
    if(rval.code != RC_OK) {
        cer_release(td, struct_ptr, allocated_here);
        rval.consumed = 0;
        return rval;
    }

    state.expected = (const uint8_t *)buffer;
    state.expected_size = rval.consumed;
    state.offset = 0;
    state.mismatch = 0;

    er = cer_encode(opt_codec_ctx, td, *struct_ptr, cer_compare_cb, &state);
    if(er.encoded < 0 || state.mismatch
       || (size_t)er.encoded != rval.consumed
       || state.offset != rval.consumed) {
        int saved_errno = (er.encoded < 0 && !state.mismatch) ? errno : EBADF;
        ASN_DEBUG("Rejecting non-canonical CER encoding of %s"
                  " (re-encoded %ld bytes, consumed %ld)",
                  td->name, (long)er.encoded, (long)rval.consumed);
        cer_release(td, struct_ptr, allocated_here);
        errno = saved_errno;
        return failed;
    }

    return rval;
}

#else /* BER or CER support disabled */

/*
 * Report that strict CER decoding was compiled out.
 * Original source: Disabled-codec stub for the asn1c strict CER decoder.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: Ignored; signature matches the enabled implementation.
 * Returns: RC_FAIL with zero bytes consumed.
 * Errors: Sets errno to ENOENT. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: Builds with ASN_DISABLE_CER_SUPPORT reach this stub.
 */
asn_dec_rval_t
cer_decode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *td, void **struct_ptr,
           const void *buffer, size_t size) {
    asn_dec_rval_t failed = {RC_FAIL, 0};
    (void)opt_codec_ctx;
    (void)td;
    (void)struct_ptr;
    (void)buffer;
    (void)size;
    errno = ENOENT;
    return failed;
}

#endif /* !ASN_DISABLE_BER_SUPPORT && !ASN_DISABLE_CER_SUPPORT */
