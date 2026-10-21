/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BOOLEAN.h>

/*
 * Decode a BOOLEAN value and account for explicit indefinite wrappers.
 * Original source: Existing asn1c BER BOOLEAN decoder with CER wrapper support.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds decoding; td describes tags; bool_value is
 *             the target pointer; buf_ptr/size bound input; tag_mode selects
 *             implicit, ordinary, or explicit tag handling.
 * Returns: RC_OK with consumed bytes, RC_WMORE for truncation, or RC_FAIL.
 * Errors: Allocation/tag/value/EOC failures return RC_FAIL without overread.
 * Responsible party: asn1c maintainers. History: Added EOC suffix validation.
 * Example: decodes `[5] EXPLICIT BOOLEAN` followed by one EOC pair.
 */
asn_dec_rval_t
BOOLEAN_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **bool_value,
                   const void *buf_ptr, size_t size, int tag_mode) {
    BOOLEAN_t *st;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;
    ber_tlv_len_t lidx;
    size_t eoc_size;

    if(!td || !bool_value || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    ASN_DEBUG("Decoding %s as BOOLEAN (tm=%d)",
            td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_primitive_tags(opt_codec_ctx, td, &buf_ptr, &size,
                                    tag_mode, &length, &eoc_size);
    if(rval.code != RC_OK)
        return rval;

    st = (BOOLEAN_t *)*bool_value;
    if(st == NULL) {
        st = (BOOLEAN_t *)(*bool_value = CALLOC(1, sizeof(*st)));
        if(st == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("Boolean length is %d bytes", (int)length);

    /*
     * Compute boolean value.
     */
    for(*st = 0, lidx = 0;
        (lidx < length) && *st == 0; lidx++) {
        /*
         * Very simple approach: read bytes until the end or
         * value is already TRUE.
         * BOOLEAN is not supposed to contain meaningful data anyway.
         */
        *st |= ((const uint8_t *)buf_ptr)[lidx];
    }

    rval.code = RC_OK;
    rval.consumed += length + eoc_size;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s, value=%d",
        (long)rval.consumed, (long)length,
        td->name, *st);

    return rval;
}

/*
 * Encode a BOOLEAN value using DER canonical contents.
 * Original source: Existing asn1c BOOLEAN DER encoder.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td describes BOOLEAN; sptr points to its value; tag_mode/tag
 *             control tagging; cb/app_key receive encoded bytes.
 * Returns: Encoded byte count, or -1 with failed_type/structure_ptr set.
 * Errors: Tag generation or a negative callback result fails encoding.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: emits `01 01 ff` for TRUE with the universal tag.
 */
asn_enc_rval_t
BOOLEAN_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int tag_mode, ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb,
                   void *app_key) {
    asn_enc_rval_t erval = {0,0,0};
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;

    erval.encoded = der_write_tags(td, 1, tag_mode, 0, tag, cb, app_key);
    if(erval.encoded == -1) {
        erval.failed_type = td;
        erval.structure_ptr = sptr;
        return erval;
    }

    if(cb) {
        uint8_t bool_value;

        bool_value = *st ? 0xff : 0; /* 0xff mandated by DER */

        if(cb(&bool_value, 1, app_key) < 0) {
            erval.encoded = -1;
            erval.failed_type = td;
            erval.structure_ptr = sptr;
            return erval;
        }
    }

    erval.encoded += 1;

    ASN__ENCODED_OK(erval);
}
