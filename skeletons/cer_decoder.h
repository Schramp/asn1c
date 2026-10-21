/*
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef ASN_CER_DECODER_H
#define ASN_CER_DECODER_H

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode one value and accept it only if it is the canonical CER encoding.
 * Original source: New asn1c strict CER decoder, based on X.690 (2015)
 *   sections 8, 9 and 11; validation reuses ber_decode() and cer_encode().
 * Version/date: 1.0, 2026-10-11.
 * Parameters:
 *   opt_codec_ctx: Optional stack limit context, passed to both the BER
 *     decoder and the CER re-encoder.
 *   type_descriptor: Descriptor for the root ASN.1 type.
 *   struct_ptr: Pointer to the target structure pointer. When *struct_ptr is
 *     NULL a new structure is allocated; otherwise the caller's structure is
 *     filled in place.
 *   buffer, size: Complete input. Bytes after the first value are ignored
 *     and not counted in the returned consumption, exactly as in ber_decode().
 * Validation: The first value is decoded with ber_decode(), re-encoded with
 *   cer_encode(), and accepted only when the re-encoding is byte-identical to
 *   the consumed input. Consequently every CER rule enforced by the encoder
 *   is enforced on input: 0xFF for TRUE, minimal INTEGER and tag octets,
 *   definite length for primitives, indefinite length for constructed
 *   values, primitive strings of at most 1000 octets and 1000-octet
 *   fragments above that, canonical SET and SET OF ordering, omitted
 *   DEFAULT values, zero unused BIT STRING bits, and canonical time and REAL
 *   forms. Values the encoder cannot reproduce are rejected: unknown
 *   extension additions (EBADF) and ANY or other types without CER encoder
 *   support (ENOENT).
 * Limits: All cer_encode() limits apply to the re-encoding, including
 *   ASN_CER_MAX_ENCODED_SIZE (default 64 MiB) and ASN_CER_MAX_SCRATCH_SIZE.
 *   Peak memory is the decoded structure plus the encoder scratch buffers.
 * Restartability: Unlike ber_decode(), this decoder is not restartable.
 *   On RC_WMORE the partial structure is released (freed when allocated by
 *   this call, otherwise reset), *struct_ptr is restored, and consumed is 0;
 *   the caller should retry with the same input extended by more bytes.
 * Returns: RC_OK with consumed bytes on success; RC_WMORE as described
 *   above; RC_FAIL with consumed 0 on any failure. On RC_FAIL the decoded
 *   structure is released in the same way as for RC_WMORE.
 * Errors: EINVAL for bad arguments; EBADF for noncanonical or unreproducible
 *   input; ENOENT for unsupported types or when CER support is disabled;
 *   EOVERFLOW/ENOMEM from encoder limits. BER structural errors leave errno
 *   as set by ber_decode(). C has no exceptions.
 * Responsible party: asn1c maintainers.
 * History: Added 2026-10-11 as the strict ATS_CER decoder.
 * Example:
 *   BOOLEAN_t *v = 0;
 *   asn_dec_rval_t rv = cer_decode(0, &asn_DEF_BOOLEAN, (void **)&v,
 *                                  "\x01\x01\xff", 3);
 *   (rv.code == RC_OK; "\x01\x01\x01" would fail with errno EBADF)
 */
asn_dec_rval_t cer_decode(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *type_descriptor,
                          void **struct_ptr, const void *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* ASN_CER_DECODER_H */
