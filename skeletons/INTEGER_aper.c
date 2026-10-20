/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <INTEGER.h>

/*
 * Purpose: calculate the number of bits needed to encode a bounded positive
 *          integer whose values run from zero through v - 1.
 * Original source: added for X.691 section 13.2.6 APER INTEGER support.
 * Version: 2026-07-06.
 * Parameters: v - positive upper bound (exclusive) for the encoded value.
 * Returns: the smallest unsigned bit count with 2^bits >= v.
 * Errors: none; callers must provide a non-zero value and a representable
 *         size_t bound.
 * Responsible party: asn1c maintainers.
 * History: retained while the APER constrained INTEGER length determinant
 *          was corrected to use its constrained bit field.
 * Example: aper_log2_ceil_size(5) returns 3.
 */
static unsigned
aper_log2_ceil_size(size_t v) {
    unsigned bits = 0;
    size_t power = 1;

    while(power < v) {
        power <<= 1;
        bits++;
    }

    return bits;
}

/*
 * Purpose: normalize the content octets of a SEMI-CONSTRAINED whole
 *          number for the PER length-determinant encoding.
 * Original source: added because X.691 11.7 requires the offset
 *          (n - lb) to be encoded as a non-negative-binary-integer,
 *          while asn1c stores the value in the minimal signed
 *          two's-complement form.
 * Version: 2026-10-17.
 * Parameters: buf,end - the whole octet buffer of the INTEGER value.
 * Returns: pointer to the first payload octet, skipping the leading
 *          sign octet that a non-negative value carries in signed
 *          two's-complement storage. A negative value in minimal
 *          storage never starts with 0x00, so it passes through
 *          unchanged.
 * Errors: none.
 * Responsible party: asn1c maintainers.
 * Example: {0x00,0xfd,0xe8} yields a pointer at 0xfd.
 *
 * This MUST NOT be used for unconstrained whole numbers: X.691 11.8
 * requires the 2's-complement-binary-integer representation there, so
 * a leading 0x00 sign octet is significant and must be kept.
 */
static const uint8_t *
aper_integer_min_contents(const uint8_t *buf, const uint8_t *end) {
    while(end - buf > 1 && buf[0] == 0x00) {
        buf++;
    }
    return buf;
}

asn_dec_rval_t
INTEGER_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_per_constraints_t *constraints, void **sptr, asn_per_data_t *pd) {
    const asn_INTEGER_specifics_t *specs = (const asn_INTEGER_specifics_t *)td->specifics;
    asn_dec_rval_t rval = { RC_OK, 0 };
    INTEGER_t *st = (INTEGER_t *)*sptr;
    const asn_per_constraint_t *ct;
    asn_per_constraint_t ct_ext_copy;  /* Local copy for extension case */
    int repeat;
    int inext = 0;  /* Track if value is in extension part (outside constraint range) */

    (void)opt_codec_ctx;

    if(!st) {
        st = (INTEGER_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;

    if(ct && ct->flags & APC_EXTENSIBLE) {
        inext = per_get_few_bits(pd, 1);
        if(inext < 0) ASN__DECODE_STARVED;
        if(inext) {
            /*
             * Value encoded in extension root's extension container.
             *
             * If the original constraint was semi-constrained (only lower_bound
             * present), treat the extension value as semi-constrained too:
             * preserve lower_bound while allowing unconstrained length (range_bits=-1).
             *
             * If the original constraint was fully constrained or unconstrained,
             * extension values MUST be treated as fully unconstrained here.
             */
            if(ct->flags & APC_SEMI_CONSTRAINED) {
                ct_ext_copy = *ct;
                ct_ext_copy.flags = APC_SEMI_CONSTRAINED;
                ct_ext_copy.range_bits = -1;
                ct_ext_copy.effective_bits = -1;
                ct = &ct_ext_copy;
            } else {
                /* keep previous behavior for other cases */
                ct = 0;
            }
        }
    }

    FREEMEM(st->buf);
    st->buf = 0;
    st->size = 0;
    if(ct) {
        if(ct->flags & APC_SEMI_CONSTRAINED) {
            st->buf = (uint8_t *)CALLOC(1, 2);
            if(!st->buf) ASN__DECODE_FAILED;
            st->size = 1;
        } else if(ct->flags & APC_CONSTRAINED && ct->range_bits >= 0) {
            size_t size = (ct->range_bits + 7) >> 3;
            st->buf = (uint8_t *)MALLOC(1 + size + 1);
            if(!st->buf) ASN__DECODE_FAILED;
            st->size = size;
        }
    }

    /* X.691, #12.2.2 */
    if(ct && ct->flags != APC_UNCONSTRAINED) {
        /* #10.5.6 */
        ASN_DEBUG("Integer with range %d bits", ct->range_bits);
        if(ct->range_bits >= 0) {
            if (ct->range_bits > 16) {
                /*
                 * X.691 13.2.6: constrained whole number with range > 65536.
                 * The offset length is encoded as a constrained length
                 * determinant (len - 1), then the value octets are aligned.
                 */
                size_t max_range_bytes = ((size_t)ct->range_bits + 7) >> 3;
                unsigned length_bits = aper_log2_ceil_size(max_range_bytes);
                int len_minus_one;
                ssize_t len;
                uintmax_t offset = 0;
                intmax_t value;

                /*
                 * The offset accumulator is uintmax_t, so reject constraint
                 * metadata wider than the value representation it can hold.
                 */
                if((size_t)ct->range_bits > 8 * sizeof(offset))
                    ASN__DECODE_FAILED;

                len_minus_one = per_get_few_bits(pd, length_bits);
                if(len_minus_one < 0) ASN__DECODE_STARVED;
                len = (ssize_t)len_minus_one + 1;
                /*
                 * The constrained determinant is rounded to a power-of-two
                 * bit field. Reject unused determinant values before aligning
                 * or reading any payload octets.
                 */
                if(len <= 0 || (size_t)len > max_range_bytes
                   || (size_t)len > sizeof(offset))
                    ASN__DECODE_FAILED;
                ASN_DEBUG("Constrained INTEGER>16 decode: range_bits=%d max_bytes=%" ASN_PRI_SIZE
                          " len_bits=%u len=%" ASN_PRI_SSIZE,
                          ct->range_bits, max_range_bytes, length_bits, len);

                if(aper_get_align(pd) < 0) ASN__DECODE_FAILED;

                while(len-- > 0) {
                    int buf = per_get_few_bits(pd, 8);
                    if(buf < 0) ASN__DECODE_STARVED;
                    if(offset > (UINTMAX_MAX >> 8)) ASN__DECODE_FAILED;
                    offset = (offset << 8) | (unsigned)buf;
                }

                if(specs && specs->field_unsigned) {
                    uintmax_t uvalue;
                    if(ct->upper_bound < 0
                       || per_umax_range_unrebase(offset, ct->lower_bound,
                                                  &uvalue)
                       || uvalue > (uintmax_t)ct->upper_bound
                       || asn_umax2INTEGER(st, uvalue))
                        ASN__DECODE_FAILED;
                    ASN_DEBUG("Got unsigned offset %"ASN_PRIuMAX" + low %"ASN_PRIdMAX"",
                              offset, ct->lower_bound);
                } else {
                    if(per_imax_range_unrebase(offset, ct->lower_bound,
                                               ct->upper_bound, &value)
                       || asn_imax2INTEGER(st, value))
                        ASN__DECODE_FAILED;
                    ASN_DEBUG("Got value %"ASN_PRIdMAX" + low %"ASN_PRIdMAX"",
                              value, ct->lower_bound);
                }
            } else {
                uintmax_t offset;
                intmax_t raw_offset;
                if (ct->range_bits < 8) {
                    raw_offset = per_get_few_bits(pd, ct->range_bits);
                    if(raw_offset < 0) ASN__DECODE_STARVED;
                } else if (ct->range_bits == 8) {
                    if (aper_get_align(pd) < 0)
                        ASN__DECODE_FAILED;
                    raw_offset = per_get_few_bits(pd, ct->range_bits);
                    if(raw_offset < 0) ASN__DECODE_STARVED;
                } else {
                    if (aper_get_align(pd) < 0)
                        ASN__DECODE_FAILED;
                    raw_offset = per_get_few_bits(pd, 16);
                    if(raw_offset < 0) ASN__DECODE_STARVED;
                }
                offset = (uintmax_t)raw_offset;
                if(specs && specs->field_unsigned) {
                    uintmax_t value;
                    if(ct->upper_bound < 0
                       || per_umax_range_unrebase(offset, ct->lower_bound,
                                                  &value)
                       || value > (uintmax_t)ct->upper_bound
                       || asn_umax2INTEGER(st, value))
                        ASN__DECODE_FAILED;
                } else {
                    intmax_t value;
                    if(per_imax_range_unrebase(offset, ct->lower_bound,
                                               ct->upper_bound, &value)
                       || asn_imax2INTEGER(st, value))
                        ASN__DECODE_FAILED;
                }
            }
            return rval;
        }
        /* Semi-constrained (range_bits < 0): fall through to unconstrained decoding */
    } else {
        ASN_DEBUG("Decoding unconstrained integer %s", td->name);
    }

    /* X.691, #12.2.3, #12.2.4 */
    size_t bytes_received = 0;  /* Actual content bytes decoded from stream */
    do {
        ssize_t len;
        void *p;
        int ret;

        /* Get the PER length */
        len = aper_get_length(pd, -1, -1, -1, &repeat);
        if(len < 0) ASN__DECODE_STARVED;

        p = REALLOC(st->buf, st->size + len + 1);
        if(!p) ASN__DECODE_FAILED;
        st->buf = (uint8_t *)p;

        ret = per_get_many_bits(pd, &st->buf[st->size], 0, 8 * len);
        if(ret < 0) ASN__DECODE_STARVED;
        st->size += len;
        bytes_received += (size_t)len;
    } while(repeat);
    st->buf[st->size] = 0;  /* JIC */

    /* INTEGER must have at least one content octet (X.691 §12.2.3) */
    if(bytes_received == 0) {
        ASN__DECODE_FAILED;
    }

    /* #12.2.3: restore the semi-constrained value from its offset. */
    if(ct && (ct->flags & APC_SEMI_CONSTRAINED)) {
        uintmax_t offset;
        if(asn_INTEGER2umax(st, &offset))
            ASN__DECODE_FAILED;
        if(specs && specs->field_unsigned) {
            uintmax_t value;
            if(per_umax_range_unrebase(offset, ct->lower_bound, &value)
               || asn_umax2INTEGER(st, value))
                ASN__DECODE_FAILED;
        } else {
            intmax_t value;
            if(per_imax_range_unrebase(offset, ct->lower_bound, INTMAX_MAX,
                                       &value)
               || asn_imax2INTEGER(st, value))
                ASN__DECODE_FAILED;
        }
    }

    return rval;
}

asn_enc_rval_t
INTEGER_encode_aper(const asn_TYPE_descriptor_t *td,
                    const asn_per_constraints_t *constraints,
                    const void *sptr, asn_per_outp_t *po) {
    const asn_INTEGER_specifics_t *specs = (const asn_INTEGER_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0,0,0};
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    const uint8_t *buf;
    const uint8_t *end;
    const asn_per_constraint_t *ct;
    asn_per_constraint_t ct_ext_copy;  /* Local copy for extension case */
    intmax_t value = 0;

    if(!st || st->size == 0) ASN__ENCODE_FAILED;

    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;

    er.encoded = 0;

    if(ct) {
        int inext = 0;
        if(specs && specs->field_unsigned) {
            uintmax_t uval;
            if(asn_INTEGER2umax(st, &uval))
                ASN__ENCODE_FAILED;
            /* Check proper range */
            if(ct->flags & APC_SEMI_CONSTRAINED) {
                if(uval < (uintmax_t)ct->lower_bound)
                    inext = 1;
            } else if(ct->range_bits >= 0) {
                if(uval < (uintmax_t)ct->lower_bound
                        || uval > (uintmax_t)ct->upper_bound)
                    inext = 1;
            }
            ASN_DEBUG("Value %"ASN_PRIdMAX" (%02x/%"ASN_PRI_SIZE") lb %"ASN_PRIdMAX" ub %"ASN_PRIdMAX" %s",
                      uval, st->buf[0], st->size,
                      (intmax_t)ct->lower_bound,
                      (intmax_t)ct->upper_bound,
                      inext ? "ext" : "fix");
            value = uval;
        } else {
            if(asn_INTEGER2imax(st, &value)) ASN__ENCODE_FAILED;
            /* Check proper range */
            if(ct->flags & APC_SEMI_CONSTRAINED) {
                if(value < ct->lower_bound)
                    inext = 1;
            } else if(ct->range_bits >= 0) {
                if(value < ct->lower_bound
                        || value > ct->upper_bound)
                    inext = 1;
            }
            ASN_DEBUG("Value %"ASN_PRIdMAX" (%02x/%"ASN_PRI_SIZE") lb %"ASN_PRIdMAX" ub %"ASN_PRIdMAX" %s",
                      value, st->buf[0], st->size,
                      (intmax_t)ct->lower_bound,
                      (intmax_t)ct->upper_bound,
                      inext ? "ext" : "fix");
        }
        if(ct->flags & APC_EXTENSIBLE) {
            if(per_put_few_bits(po, inext, 1))
                ASN__ENCODE_FAILED;
            if(inext) {
                if(ct->flags & APC_SEMI_CONSTRAINED) {
                    ct_ext_copy = *ct;
                    ct_ext_copy.flags = APC_SEMI_CONSTRAINED;
                    ct_ext_copy.range_bits = -1;
                    ct_ext_copy.effective_bits = -1;
                    ct = &ct_ext_copy;
                } else {
                    ct = 0;
                }
            }
        } else if(inext) {
            ASN__ENCODE_FAILED;
        }
    }

    /* X.691, #12.2.2 */
    if(ct && ct->range_bits >= 0) {
        uintmax_t v;

        /* #10.5.6: encode the checked non-negative offset. */
        if(specs && specs->field_unsigned) {
            uintmax_t uvalue;
            if(asn_INTEGER2umax(st, &uvalue)
               || ct->upper_bound < 0
               || per_umax_range_rebase(uvalue, ct->lower_bound, &v)
               || v > (uintmax_t)ct->upper_bound - (uintmax_t)ct->lower_bound)
                ASN__ENCODE_FAILED;
            ASN_DEBUG("Encoding unsigned integer offset %"ASN_PRIuMAX" with range %d bits",
                      v, ct->range_bits);
        } else if(per_imax_range_rebase(value, ct->lower_bound,
                                        ct->upper_bound, &v)) {
            ASN__ENCODE_FAILED;
        } else {
            ASN_DEBUG("Encoding integer offset %"ASN_PRIuMAX" with range %d bits",
                      v, ct->range_bits);
        }

        /* #12 <= 8 -> alignment ? */
        int range = ct->upper_bound - ct->lower_bound + 1;
        if (ct->range_bits < 8 || (ct->range_bits == 8 && range < 256)) {
            if(per_put_few_bits(po, 0x00 | v, ct->range_bits))
                ASN__ENCODE_FAILED;
        } else if (ct->range_bits == 8) {
            if(aper_put_align(po) < 0)
                ASN__ENCODE_FAILED;
            if(per_put_few_bits(po, 0x00 | v, ct->range_bits))
                ASN__ENCODE_FAILED;
        } else if (ct->range_bits <= 16) {
            /* Consume the bytes to align on octet */
            if(aper_put_align(po) < 0)
                ASN__ENCODE_FAILED;
            if(per_put_few_bits(po, 0x0000 | v, 16))
                ASN__ENCODE_FAILED;
        } else {
            /* X.691 13.2.6: constrained whole number with range > 65536. */
            size_t max_range_bytes = ((size_t)ct->range_bits + 7) >> 3;
            unsigned length_bits = aper_log2_ceil_size(max_range_bytes);
            size_t num_bytes = 0;
            uint8_t buf[sizeof(v)];
            uintmax_t tmp = v;

            do {
                num_bytes++;
                tmp >>= 8;
            } while(tmp);

            if(num_bytes > max_range_bytes || num_bytes > sizeof(buf))
                ASN__ENCODE_FAILED;
            ASN_DEBUG("Constrained INTEGER>16 encode: range_bits=%d max_bytes=%" ASN_PRI_SIZE
                      " len_bits=%u len=%" ASN_PRI_SIZE " offset=%" ASN_PRIuMAX,
                      ct->range_bits, max_range_bytes, length_bits, num_bytes, v);

            tmp = v;
            {
                size_t i;
                for(i = 0; i < num_bytes; i++) {
                    buf[num_bytes - i - 1] = (uint8_t)(tmp & 0xff);
                    tmp >>= 8;
                }
            }

            if(per_put_few_bits(po, num_bytes - 1, length_bits))
                ASN__ENCODE_FAILED;
            if(aper_put_align(po) < 0)
                ASN__ENCODE_FAILED;
            if(per_put_many_bits(po, buf, 8 * num_bytes))
                ASN__ENCODE_FAILED;
        }
        ASN__ENCODED_OK(er);
    }

    /*
     * Semi-constrained whole number (X.691 11.7). A zero lower bound is
     * still semi-constrained, so test the constraint flags rather than
     * the numeric value of lower_bound, which would be false for 0.
     */
    if(ct && (ct->lower_bound || (ct->flags & APC_SEMI_CONSTRAINED))) {
        ASN_DEBUG("Adjust lower bound to %"ASN_PRIdMAX"", (intmax_t)ct->lower_bound);
        /*
         * Encode semi-constrained integer by subtracting lower bound.
         * Per X.691 11.7, the value is encoded as (value - lower_bound),
         * which is always non-negative.
         */
        INTEGER_t adjusted_int;
        memset(&adjusted_int, 0, sizeof(adjusted_int));

        if(specs && specs->field_unsigned) {
            uintmax_t uval;
            if(asn_INTEGER2umax(st, &uval)
               || per_umax_range_rebase(uval, ct->lower_bound, &uval)
               || asn_umax2INTEGER(&adjusted_int, uval)) {
                ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted_int);
                ASN__ENCODE_FAILED;
            }
        } else {
            intmax_t sval;
            uintmax_t offset;
            if(asn_INTEGER2imax(st, &sval)
               || per_imax_range_rebase(sval, ct->lower_bound, INTMAX_MAX,
                                        &offset)
               || asn_umax2INTEGER(&adjusted_int, offset)) {
                ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted_int);
                ASN__ENCODE_FAILED;
            }
        }

        /*
         * Encode the adjusted value using unconstrained encoding.
         * X.691 11.7: the semi-constrained offset (n - lb) is a
         * non-negative-binary-integer, so drop the sign octet that the
         * signed two's-complement storage would carry.
         */
        buf = aper_integer_min_contents(adjusted_int.buf,
                                        adjusted_int.buf + adjusted_int.size);
        end = adjusted_int.buf + adjusted_int.size;
        while(buf < end) {
            int need_eom = 0;
            ssize_t mayEncode = aper_put_length(po, -1, -1, end - buf, &need_eom);
            if(mayEncode < 0) {
                ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted_int);
                ASN__ENCODE_FAILED;
            }
            if(per_put_many_bits(po, buf, 8 * mayEncode)) {
                ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted_int);
                ASN__ENCODE_FAILED;
            }
            buf += mayEncode;
            if(need_eom && (aper_put_length(po, -1, -1, 0, NULL) < 0)) {
                ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted_int);
                ASN__ENCODE_FAILED;
            }
        }

        ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted_int);
        ASN__ENCODED_OK(er);
    }

    /*
     * X.691 11.8: an unconstrained whole number is encoded as a
     * 2's-complement-binary-integer in the minimum number of octets,
     * i.e. its leading sign octet (if any) is significant and must be
     * kept. Semi-constrained whole numbers (including those whose
     * lower bound is zero) never reach this point; they are handled as
     * non-negative offsets above.
     */
    for(buf = st->buf, end = st->buf + st->size; buf < end;) {
        int need_eom = 0;
        ssize_t mayEncode = aper_put_length(po, -1, -1, end - buf, &need_eom);
        if(mayEncode < 0)
            ASN__ENCODE_FAILED;
        if(per_put_many_bits(po, buf, 8 * mayEncode))
            ASN__ENCODE_FAILED;
        buf += mayEncode;
        if(need_eom && (aper_put_length(po, -1, -1, 0, NULL) < 0))
            ASN__ENCODE_FAILED;
    }

    ASN__ENCODED_OK(er);
}
