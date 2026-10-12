/*
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef ASN_CER_ENCODER_H
#define ASN_CER_ENCODER_H

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encode one value using the descriptor-driven Canonical Encoding Rules.
 * Original source: New asn1c CER encoder, based on X.690 (2015) sections 9-11.
 * Version/date: 1.0, 2026-10-11.
 * Parameters:
 *   opt_codec_ctx: Optional stack limit context, matching other codecs.
 *   type_descriptor: Descriptor for the root ASN.1 type.
 *   struct_ptr: Root value to encode.
 *   consume_bytes_cb: Destination callback; negative return stops encoding.
 *   app_key: Opaque value passed to the callback.
 * Limits: Compile-time defaults are 64 MiB encoded output
 *   (ASN_CER_MAX_ENCODED_SIZE), 128 MiB aggregate live scratch allocations
 *   (ASN_CER_MAX_SCRATCH_SIZE), 1,000,000 descriptor elements
 *   (ASN_CER_MAX_ELEMENTS), and 4,000,000 descriptor/value visits
 *   (ASN_CER_MAX_WORK_ITEMS). Define any macro before compiling this source
 *   to override that ceiling. Live scratch accounting includes growth overlap
 *   and conservative DER-adapter reserves (16 bytes for native INTEGER or
 *   ENUMERATED, 64 for native REAL, and 128 for GeneralizedTime). Recursion is
 *   capped by ASN_STACK_OVERFLOW_LIMIT (default 30). Each descriptor's tag
 *   chain is capped by the same limit; an EXPLICIT member tag adds one layer,
 *   while an IMPLICIT member tag replaces the outer layer. A stack-local copy
 *   of opt_codec_ctx applies its optional
 *   max_stack_size byte limit, defaulting to ASN__DEFAULT_STACK_MAX when NULL.
 * Returns: Encoded byte count, or -1 with errno and failure descriptor set.
 * Errors: EINVAL for bad arguments, ENOENT for unsupported type, EBADF for an
 *   invalid value, EOVERFLOW for configured bounds, ENOMEM for allocation, and
 *   EIO for callback failure. C has no exceptions.
 * Responsible party: asn1c maintainers.
 * History: Added 2026-10-11.
 * Example: cer_encode(NULL, &asn_DEF_BOOLEAN, &value, write_bytes, key).
 */
asn_enc_rval_t cer_encode(
    const asn_codec_ctx_t *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr,
    asn_app_consume_bytes_f *consume_bytes_cb,
    void *app_key);

/*
 * Encode one CER value into a caller-supplied buffer.
 * Original source: New asn1c CER encoder, based on X.690 (2015) sections 9-11.
 * Version/date: 1.0, 2026-10-11.
 * Parameters:
 *   opt_codec_ctx: Optional stack limit context, matching other codecs.
 *   type_descriptor: Descriptor for the root ASN.1 type.
 *   struct_ptr: Root value to encode.
 *   buffer: Destination buffer; may be NULL only when buffer_size is zero.
 *   buffer_size: Available output bytes; it must hold the complete encoding.
 *   Resource limits are identical to cer_encode().
 * Returns: Encoded byte count, or -1 with errno and failure descriptor.
 * Errors: EINVAL for bad arguments, ENOSPC for a short buffer, and other
 *   errors matching cer_encode(). The buffer is not modified on short space.
 * Responsible party: asn1c maintainers.
 * History: Added 2026-10-11.
 * Example: cer_encode_to_buffer(NULL, &asn_DEF_NULL, &value, bytes, sizeof(bytes)).
 */
asn_enc_rval_t cer_encode_to_buffer(
    const asn_codec_ctx_t *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr,
    void *buffer,
    size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* ASN_CER_ENCODER_H */
