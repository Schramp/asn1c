/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeReal.h>
#include <REAL.h>

/*
 * Decode a native REAL after validating any explicit wrapper EOCs.
 * Original source: Existing asn1c NativeReal BER decoder with CER support.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds tag checking; td describes the REAL;
 *             sptr is the native target; buf_ptr/size bound input; tag_mode
 *             selects implicit, ordinary, or explicit tag handling.
 * Returns: RC_OK with consumed bytes, RC_WMORE for incomplete input, or RC_FAIL.
 * Errors: Invalid REAL content, malformed wrappers, and allocation failures.
 * Responsible party: asn1c maintainers. History: Added primitive EOC checking.
 * Example: decodes a REAL inside an indefinite explicit wrapper.
 */
asn_dec_rval_t
NativeReal_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td, void **sptr,
                      const void *buf_ptr, size_t size, int tag_mode) {
    asn_dec_rval_t rval;
    ber_tlv_len_t length;
    size_t eoc_size;

    if(!td || !sptr || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }
    ASN_DEBUG("Decoding %s as REAL (tm=%d)", td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_primitive_tags(opt_codec_ctx, td, &buf_ptr, &size,
                                    tag_mode, &length, &eoc_size);
    if(rval.code != RC_OK) return rval;
    ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

    /*
     * Make sure we have this length.
     */
    /*
     * ASN.1 encoded REAL: buf_ptr, length
     * Fill the Dbl, at the same time checking for overflow.
     * If overflow occurred, return with RC_FAIL.
     */
    {
        uint8_t scratch[24]; /* Longer than %.16f in decimal */
        REAL_t tmp;
        double d;
        int ret;

        if((size_t)length < sizeof(scratch)) {
            tmp.buf = scratch;
            tmp.size = length;
        } else {
            /* This rarely happens: impractically long value */
            tmp.buf = CALLOC(1, length + 1);
            tmp.size = length;
            if(!tmp.buf) {
                rval.code = RC_FAIL;
                rval.consumed = 0;
                return rval;
            }
        }

        memcpy(tmp.buf, buf_ptr, length);
        tmp.buf[length] = '\0';

        ret = asn_REAL2double(&tmp, &d);
        if(tmp.buf != scratch) FREEMEM(tmp.buf);
        if(ret) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }

        if(NativeReal__set(td, sptr, d) < 0)
            ASN__DECODE_FAILED;
    }

    rval.code = RC_OK;
    rval.consumed += length + eoc_size;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s", (long)rval.consumed,
              (long)length, td->name);

    return rval;
}

/*
 * Encode a native REAL through the standard REAL DER encoder.
 * Original source: Existing asn1c NativeReal DER adapter.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td supplies native REAL layout; sptr points to its value;
 *             tag_mode/tag control tags; cb/app_key receive encoded bytes.
 * Returns: DER encoding result, or failure when conversion/allocation fails.
 * Errors: Invalid native layout/value, REAL conversion, tags, or callback fail.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: emits canonical binary REAL contents for a native double.
 */
asn_enc_rval_t
NativeReal_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int tag_mode, ber_tlv_tag_t tag,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    double d = NativeReal__get_double(td, sptr);
    asn_enc_rval_t erval = {0,0,0};
    REAL_t tmp;

    /* Prepare a temporary clean structure */
    memset(&tmp, 0, sizeof(tmp));

    if(asn_double2REAL(&tmp, d))
        ASN__ENCODE_FAILED;

    /* Encode a fake REAL */
    erval = der_encode_primitive(td, &tmp, tag_mode, tag, cb, app_key);
    if(erval.encoded == -1) {
        assert(erval.structure_ptr == &tmp);
        erval.structure_ptr = sptr;
    }

    /* Free possibly allocated members of the temporary structure */
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);

    return erval;
}
