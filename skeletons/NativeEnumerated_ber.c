/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <INTEGER.h>
#include <NativeEnumerated.h>

/*
 * Decode NativeEnumerated and validate explicit wrapper EOCs before mapping.
 * Original source: Existing asn1c NativeEnumerated BER decoder with CER support.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds decoding; td provides enum metadata;
 *             nint_ptr is the target; buf_ptr/size bound bytes; tag_mode
 *             selects implicit, ordinary, or explicit tagging.
 * Returns: RC_OK with consumed bytes, RC_WMORE for truncation, or RC_FAIL.
 * Errors: Allocation, integer conversion, invalid tags, and bad EOCs fail.
 * Responsible party: asn1c maintainers. History: Added primitive EOC checking.
 * Example: decodes a named enumerated value inside an explicit wrapper.
 */
asn_dec_rval_t
NativeEnumerated_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **nint_ptr,
                         const void *buf_ptr, size_t size, int tag_mode) {
    const asn_INTEGER_specifics_t *specs;
    long *native;
    const asn_INTEGER_enum_map_t *el;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;
    size_t eoc_size;

    if(!td || !nint_ptr || !td->specifics || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }
    specs = (const asn_INTEGER_specifics_t *)td->specifics;

    ASN_DEBUG("Decoding %s as NativeEnumerated (tm=%d)",
              td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_primitive_tags(opt_codec_ctx, td, &buf_ptr, &size,
                                    tag_mode, &length, &eoc_size);
    if(rval.code != RC_OK)
        return rval;

    native = (long *)*nint_ptr;
    if(native == NULL) {
        native = (long *)(*nint_ptr = CALLOC(1, sizeof(*native)));
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
     * ASN.1 encoded NativeEnumerated: buf_ptr, length
     * Fill the native, at the same time checking for overflow.
     * If overflow occurred, return with RC_FAIL.
     */
    {
        INTEGER_t tmp;
        union {
            const void *constbuf;
            void *nonconstbuf;
        } unconst_buf;
        long l;

        unconst_buf.constbuf = buf_ptr;
        tmp.buf = (uint8_t *)unconst_buf.nonconstbuf;
        tmp.size = length;

        if((specs&&specs->field_unsigned)
            ? asn_INTEGER2ulong(&tmp, (unsigned long *)&l) /* sic */
            : asn_INTEGER2long(&tmp, &l)) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }

        el = INTEGER_map_value2enum(specs, l);
        if(!el) {
            ASN_DEBUG("No element corresponds to the value %ld", l);
            ASN__DECODE_FAILED;
        }

        *native = el->nat_value;
    }

    rval.code = RC_OK;
    rval.consumed += length + eoc_size;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s (%ld)",
              (long)rval.consumed, (long)length, td->name, (long)*native);

    return rval;
}

/*
 * Encode a native enumerated value through the INTEGER DER encoder.
 * Original source: Existing asn1c NativeEnumerated DER adapter.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td supplies enum metadata; sptr points to its value; tag_mode/tag
 *             control tags; cb/app_key receive encoded bytes.
 * Returns: DER encoding result, or failure when the value is unmapped.
 * Errors: Unknown enum values, invalid tags, and callback failures are reported.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: emits the mapped integer contents for a named enumeration value.
 */
asn_enc_rval_t
NativeEnumerated_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    unsigned long native = *(const unsigned long *)sptr; /* Disable sign ext. */


    asn_enc_rval_t erval = {0,0,0};
    INTEGER_t tmp;
    const asn_INTEGER_enum_map_t *el;

    el = INTEGER_map_value2enum(specs, native);
    if(!el) {
        ASN_DEBUG(
            "No elemenet corresponds to the value %ld", native);
        ASN__ENCODE_FAILED;
    }

#ifdef WORDS_BIGENDIAN  /* Opportunistic optimization */

    tmp.buf = (uint8_t *)&native;
    tmp.size = sizeof(native);

#else  /* Works even if WORDS_BIGENDIAN is not set where should've been */
    uint8_t buf[sizeof(native)];
    uint8_t *p;

    /* Prepare a fake INTEGER */
    for(p = buf + sizeof(buf) - 1; p >= buf; p--, native >>= 8)
        *p = (uint8_t)native;

    tmp.buf = buf;
    tmp.size = sizeof(buf);
#endif  /* WORDS_BIGENDIAN */

    /* Encode fake INTEGER */
    erval = INTEGER_encode_der(td, &tmp, tag_mode, tag, cb, app_key);
    if(erval.structure_ptr == &tmp) {
        erval.structure_ptr = sptr;
    }
    return erval;
}

