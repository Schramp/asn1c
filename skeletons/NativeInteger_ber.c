/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeInteger.h>
#include <INTEGER.h>

/*
 * Decode a native INTEGER and validate explicit wrapper EOCs before storage.
 * Original source: Existing asn1c NativeInteger BER decoder with CER support.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds decoding; td provides INTEGER metadata;
 *             nint_ptr is the target; buf_ptr/size bound bytes; tag_mode
 *             selects implicit, ordinary, or explicit tagging.
 * Returns: RC_OK with consumed bytes, RC_WMORE for truncation, or RC_FAIL.
 * Errors: Allocation, integer overflow, invalid tags, and bad EOCs fail.
 * Responsible party: asn1c maintainers. History: Added primitive EOC checking.
 * Example: decodes an explicitly tagged native count ending in EOC.
 */
asn_dec_rval_t
NativeInteger_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **nint_ptr,
                         const void *buf_ptr, size_t size, int tag_mode) {
    const asn_INTEGER_specifics_t *specs;
    void *native;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;
    size_t eoc_size;

    if(!td || !nint_ptr || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }
    specs = (const asn_INTEGER_specifics_t *)td->specifics;
    if(specs && ((specs->field_width
                  && specs->field_width != 1 && specs->field_width != 2
                  && specs->field_width != 4 && specs->field_width != 8)
                 || (specs->field_unsigned != 0
                     && specs->field_unsigned != 1))) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    ASN_DEBUG("Decoding %s as INTEGER (tm=%d)",
              td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_primitive_tags(opt_codec_ctx, td, &buf_ptr, &size,
                                    tag_mode, &length, &eoc_size);
    if(rval.code != RC_OK)
        return rval;

    native = *nint_ptr;
    if(native == NULL) {
        native = (*nint_ptr = CALLOC(1, NativeInteger_field_width(specs)));
        if(native == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

    /*
     * Make sure we have this length.
     */
    /*
     * ASN.1 encoded INTEGER: buf_ptr, length
     * Fill the native, at the same time checking for overflow.
     * If overflow occurred, return with RC_FAIL.
     */
    {
        INTEGER_t tmp;
        union {
            const void *constbuf;
            void *nonconstbuf;
        } unconst_buf;

        unconst_buf.constbuf = buf_ptr;
        tmp.buf = (uint8_t *)unconst_buf.nonconstbuf;
        tmp.size = length;

        if(NativeInteger_store_from_INTEGER(native, specs, &tmp)) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    rval.code = RC_OK;
    rval.consumed += length + eoc_size;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s",
              (long)rval.consumed, (long)length, td->name);

    return rval;
}

/*
 * Encode a native integer through the standard INTEGER DER encoder.
 * Original source: Existing asn1c NativeInteger DER adapter.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: sd supplies native INTEGER layout; ptr points to the value;
 *             tag_mode/tag control tags; cb/app_key receive encoded bytes.
 * Returns: DER encoding result, or failure if native conversion fails.
 * Errors: Invalid native layout/value, allocation, tag, and callback failures.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: encodes a native count as a minimally signed INTEGER.
 */
asn_enc_rval_t
NativeInteger_encode_der(const asn_TYPE_descriptor_t *sd, const void *ptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_TYPE_descriptor_t *td = sd;  /* for ASN__ENCODE_FAILED */
    const void *sptr = ptr;                /* for ASN__ENCODE_FAILED */
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)sd->specifics;
    asn_enc_rval_t erval = {0,0,0};
    INTEGER_t tmp;

    /* Materialize the native member (any width) as a canonical INTEGER. */
    if(NativeInteger_to_INTEGER(ptr, specs, &tmp)) {
        ASN__ENCODE_FAILED;
    }

    erval = INTEGER_encode_der(sd, &tmp, tag_mode, tag, cb, app_key);
    if(erval.structure_ptr == &tmp) {
        erval.structure_ptr = ptr;
    }
    if(tmp.buf) FREEMEM(tmp.buf);
    return erval;
}
