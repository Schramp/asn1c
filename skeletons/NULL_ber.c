/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NULL.h>

/*
 * Decode NULL and validate explicit wrapper EOCs before reporting success.
 * Original source: Existing asn1c BER NULL decoder with CER wrapper support.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds tag checking; td describes NULL;
 *             bool_value is the target pointer; buf_ptr/size bound input;
 *             tag_mode selects implicit, ordinary, or explicit tags.
 * Returns: RC_OK with consumed bytes, RC_WMORE for incomplete input, or RC_FAIL.
 * Errors: Allocation, invalid content length, bad tags, and malformed EOCs fail.
 * Responsible party: asn1c maintainers. History: Added primitive EOC checking.
 * Example: decodes `[5] EXPLICIT NULL` ending with an EOC pair.
 */
asn_dec_rval_t
NULL_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **bool_value,
                const void *buf_ptr, size_t size, int tag_mode) {
    asn_dec_rval_t rval;
    ber_tlv_len_t length;
    size_t eoc_size;

    if(!td || !bool_value || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    ASN_DEBUG("Decoding %s as NULL (tm=%d)", td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_primitive_tags(opt_codec_ctx, td, &buf_ptr, &size,
                                    tag_mode, &length, &eoc_size);
    if(rval.code != RC_OK) {
        return rval;
    }

    // X.690-201508, #8.8.2, length shall be zero.
    if(length != 0) {
        ASN_DEBUG("Decoding %s as NULL failed: too much data", td->name);
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    if(!*bool_value) {
        *bool_value = CALLOC(1, sizeof(NULL_t));
        if(!*bool_value) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    rval.consumed += eoc_size;
    return rval;
}

/*
 * Encode a NULL value using DER.
 * Original source: Existing asn1c NULL DER encoder.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td describes NULL; ptr identifies the source structure;
 *             tag_mode/tag control tagging; cb/app_key receive output bytes.
 * Returns: Encoded byte count, or -1 when tag generation fails.
 * Errors: Tag-generation and callback failures are reported in the result.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: emits `05 00` for the universal NULL tag.
 */
asn_enc_rval_t
NULL_encode_der(const asn_TYPE_descriptor_t *td, const void *ptr, int tag_mode,
                ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t erval = {0,0,0};

    erval.encoded = der_write_tags(td, 0, tag_mode, 0, tag, cb, app_key);
    if(erval.encoded == -1) {
        erval.failed_type = td;
        erval.structure_ptr = ptr;
    }

    ASN__ENCODED_OK(erval);
}
