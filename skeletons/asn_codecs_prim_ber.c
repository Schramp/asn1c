/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <asn_codecs_prim.h>

/*
 * Decode an always-primitive value after validating its tag/EOC boundaries.
 * Original source: Existing asn1c BER primitive decoder with CER wrapper support.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds decoding; td describes the value; sptr is
 *             the target pointer; buf_ptr/size bound input; tag_mode controls
 *             implicit, ordinary, or explicit tag validation.
 * Returns: RC_OK with consumed bytes, RC_WMORE for truncation, or RC_FAIL.
 * Errors: Allocation, invalid length, malformed tags, or malformed EOCs fail.
 * Responsible party: asn1c maintainers. History: Added primitive EOC checking.
 * Example: decodes an explicit OBJECT IDENTIFIER with its wrapper EOC.
 */
asn_dec_rval_t
ber_decode_primitive(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, void **sptr,
                     const void *buf_ptr, size_t size, int tag_mode) {
    ASN__PRIMITIVE_TYPE_t *st;
    asn_dec_rval_t rval;
    ber_tlv_len_t length = 0;  /* =0 to avoid [incorrect] warning. */
    size_t eoc_size;

    if(!td || !sptr || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    ASN_DEBUG("Decoding %s as plain primitive (tm=%d)",
              td->name, tag_mode);

    /*
     * Check tags and extract value length.
     */
    rval = ber_check_primitive_tags(opt_codec_ctx, td, &buf_ptr, &size,
                                    tag_mode, &length, &eoc_size);
    if(rval.code != RC_OK)
        return rval;

    st = (ASN__PRIMITIVE_TYPE_t *)*sptr;
    if(st == NULL) {
        st = (ASN__PRIMITIVE_TYPE_t *)CALLOC(1, sizeof(*st));
        if(st == NULL) ASN__DECODE_FAILED;
        *sptr = (void *)st;
    }

    ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

    /*
     * Make sure we have this length.
     */
    st->size = (int)length;
    /* The following better be optimized away. */
    if(sizeof(st->size) != sizeof(length)
            && (ber_tlv_len_t)st->size != length) {
        st->size = 0;
        ASN__DECODE_FAILED;
    }

    st->buf = (uint8_t *)MALLOC(length + 1);
    if(!st->buf) {
        st->size = 0;
        ASN__DECODE_FAILED;
    }

    memcpy(st->buf, buf_ptr, length);
    st->buf[length] = '\0';  /* Just in case */

    rval.code = RC_OK;
    rval.consumed += length + eoc_size;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s",
              (long)rval.consumed,
              (long)length, td->name);

    return rval;
}

/*
 * Encode an always-primitive value using DER.
 * Original source: Existing asn1c primitive DER encoder.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td describes the primitive; sptr contains its buffer/size;
 *             tag_mode/tag control tagging; cb/app_key receive output bytes.
 * Returns: Encoded byte count, or -1 with failure details set.
 * Errors: Invalid source storage, tag generation, and callback failures fail.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: encodes primitive OID contents with their descriptor tag.
 */
asn_enc_rval_t
der_encode_primitive(const asn_TYPE_descriptor_t *td, const void *sptr,
                     int tag_mode, ber_tlv_tag_t tag,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t erval = {0,0,0};
    const ASN__PRIMITIVE_TYPE_t *st = (const ASN__PRIMITIVE_TYPE_t *)sptr;

    ASN_DEBUG("%s %s as a primitive type (tm=%d)",
              cb?"Encoding":"Estimating", td->name, tag_mode);

    erval.encoded = der_write_tags(td, st->size, tag_mode, 0, tag,
                                   cb, app_key);
    ASN_DEBUG("%s wrote tags %d", td->name, (int)erval.encoded);
    if(erval.encoded == -1) {
        erval.failed_type = td;
        erval.structure_ptr = sptr;
        return erval;
    }

    if(cb && st->buf) {
        if(cb(st->buf, st->size, app_key) < 0) {
            erval.encoded = -1;
            erval.failed_type = td;
            erval.structure_ptr = sptr;
            return erval;
        }
    } else {
        assert(st->buf || st->size == 0);
    }

    erval.encoded += st->size;
    ASN__ENCODED_OK(erval);
}
