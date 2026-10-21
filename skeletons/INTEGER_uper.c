/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <INTEGER.h>

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
 * History: retained while constrained arithmetic was split into checked helpers.
 * Example: {0x00,0xfd,0xe8} yields a pointer at 0xfd.
 *
 * This MUST NOT be used for unconstrained whole numbers: X.691 11.8
 * requires the 2's-complement-binary-integer representation there, so
 * a leading 0x00 sign octet is significant and must be kept.
 */
static const uint8_t *
uper_integer_min_contents(const uint8_t *buf, const uint8_t *end) {
    while(end - buf > 1 && buf[0] == 0x00) {
        buf++;
    }
    return buf;
}

/*
 * Purpose: prepare the INTEGER buffer for a PER offset or signed value.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, owned INTEGER; ct, optional effective constraints.
 * Returns: 0 on success; -1 on allocation failure or unsupported width.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_prepare(st, ct).
 */
static int
uper_integer_prepare(INTEGER_t *st, const asn_per_constraint_t *ct) {
    /* Clear old storage before choosing signed or non-negative offset storage. */
    FREEMEM(st->buf);
    st->buf = 0;
    st->size = 0;
    if(!ct) return 0;
    if(ct->flags & APC_SEMI_CONSTRAINED) {
        st->buf = (uint8_t *)CALLOC(1, 2);
        if(!st->buf) return -1;
        st->size = 1; /* Positive sign octet for the unsigned wire offset. */
    } else if(ct->flags & APC_CONSTRAINED) {
        size_t size;
        if(ct->range_bits < 0 || (size_t)ct->range_bits > 8 * sizeof(uintmax_t))
            return -1;
        size = ((size_t)ct->range_bits + 7) >> 3;
        st->buf = (uint8_t *)MALLOC(size + 2);
        if(!st->buf) return -1;
        st->size = size;
    }
    return 0;
}

/*
 * Purpose: read a UPER constrained offset with an explicit width bound.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: ct, constraints; pd, input state; offset, decoded output.
 * Returns: RC_OK, RC_WMORE for truncation, or RC_FAIL for invalid metadata.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_get_offset(ct, pd, &offset).
 */
static enum asn_dec_rval_code_e
uper_integer_get_offset(const asn_per_constraint_t *ct, asn_per_data_t *pd,
                        uintmax_t *offset) {
    /* The constrained accumulator cannot represent metadata wider than itself. */
    if(ct->range_bits < 0 || (size_t)ct->range_bits > 8 * sizeof(*offset))
        return RC_FAIL;
    *offset = 0;
    if(uper_get_constrained_whole_number(pd, offset, ct->range_bits)) return RC_WMORE;
    return RC_OK;
}

/*
 * Purpose: restore a constrained offset using the descriptor's signedness.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, result; ct, constraints; specs, optional storage metadata; pd, input.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; never adds an unchecked offset.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_get_constrained(st, ct, specs, pd).
 */
static enum asn_dec_rval_code_e
uper_integer_get_constrained(INTEGER_t *st, const asn_per_constraint_t *ct,
                               const asn_INTEGER_specifics_t *specs, asn_per_data_t *pd) {
    uintmax_t offset;
    enum asn_dec_rval_code_e code = uper_integer_get_offset(ct, pd, &offset);
    if(code != RC_OK) return code;

    /* Native unsigned bounds occupy signed metadata slots as bit patterns. */
    if(specs && specs->field_unsigned) {
        uintmax_t value;
        if(per_unsigned_range_unrebase(offset, (uintmax_t)ct->lower_bound,
                                       (uintmax_t)ct->upper_bound, &value)
           || asn_umax2INTEGER(st, value)) return RC_FAIL;
    } else {
        intmax_t value;
        if(per_imax_range_unrebase(offset, ct->lower_bound, ct->upper_bound, &value)
           || asn_imax2INTEGER(st, value)) return RC_FAIL;
    }
    return RC_OK;
}

/*
 * Purpose: collect fragmented INTEGER contents with checked buffer growth.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, owned result buffer; pd, input bit state.
 * Returns: RC_OK, RC_WMORE for truncation, or RC_FAIL for empty/oversized data.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_get_contents(st, pd).
 */
static enum asn_dec_rval_code_e
uper_integer_get_contents(INTEGER_t *st, asn_per_data_t *pd) {
    size_t initial_size = st->size;
    int repeat; /* Fragment-continuation state variable. */

    /* Append only lengths whose allocation and bit counts are representable. */
    do {
        ssize_t len = uper_get_length(pd, -1, 0, &repeat);
        void *p;
        if(len < 0) return RC_WMORE;
        if(st->size == SIZE_MAX || (size_t)len > SIZE_MAX - st->size - 1
           || (size_t)len > (size_t)INT_MAX / 8) return RC_FAIL;
        p = REALLOC(st->buf, st->size + (size_t)len + 1);
        if(!p) return RC_FAIL;
        st->buf = (uint8_t *)p;
        if(per_get_many_bits(pd, st->buf + st->size, 0, 8 * len) < 0) return RC_WMORE;
        st->size += (size_t)len;
    } while(repeat);

    /* A preallocated positive sign octet is not a received content octet. */
    st->buf[st->size] = 0;
    return st->size > initial_size ? RC_OK : RC_FAIL;
}

/*
 * Purpose: restore a nonzero semi-constrained lower bound with checked arithmetic.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, offset/result; ct, optional constraints; specs, optional signedness.
 * Returns: 0 on success; -1 on conversion, arithmetic or allocation failure.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_restore_semi(st, ct, specs).
 */
static int
uper_integer_restore_semi(INTEGER_t *st, const asn_per_constraint_t *ct,
                            const asn_INTEGER_specifics_t *specs) {
    uintmax_t offset;

    /* A zero bound needs no arithmetic: preserve arbitrary-precision storage.
     * NativeInteger_store_from_INTEGER() enforces native widths afterward. */
    if(!ct || !(ct->flags & APC_SEMI_CONSTRAINED) || ct->lower_bound == 0) return 0;
    if(asn_INTEGER2umax(st, &offset)) return -1;
    if(specs && specs->field_unsigned) {
        uintmax_t value;
        if(per_umax_range_unrebase(offset, ct->lower_bound, &value)) return -1;
        return asn_umax2INTEGER(st, value);
    } else {
        intmax_t value;
        if(per_imax_range_unrebase(offset, ct->lower_bound, INTMAX_MAX, &value)) return -1;
        return asn_imax2INTEGER(st, value);
    }
}

/*
 * Purpose: validate minimal unconstrained UPER signed INTEGER contents.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: ctx, optional canonical policy; ct, effective constraints; st, contents.
 * Returns: 0 if accepted; -1 for non-minimal content in strict canonical mode.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_check_canonical(ctx, ct, st).
 */
static int
uper_integer_check_canonical(const asn_codec_ctx_t *ctx, const asn_per_constraint_t *ct,
                             const INTEGER_t *st) {
    int redundant;

    /* Semi-constrained contents use unsigned offsets, not signed minimality. */
    if(!ctx || !ctx->uper_canonical || ct || st->size <= 1) return 0;
    redundant = (st->buf[0] == 0 && (st->buf[1] & 0x80) == 0)
                || (st->buf[0] == 0xff && (st->buf[1] & 0x80) != 0);
    if(redundant && !ctx->uper_canonical_lenient) return -1;
    return 0;
}

/*
 * Purpose: decode a PER INTEGER while separating bit I/O from checked range arithmetic.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: opt_codec_ctx, policy; td, type; constraints, optional override;
 * sptr, owned result pointer; pd, input bit state.
 * Returns: ASN.1 decoder status; failure for missing arguments or invalid data.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: INTEGER_decode_uper(ctx, td, constraints, &value, pd).
 */
asn_dec_rval_t
INTEGER_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td,
                     const asn_per_constraints_t *constraints, void **sptr,
                     asn_per_data_t *pd) {
    const asn_INTEGER_specifics_t *specs;
    const asn_per_constraint_t *ct;
    INTEGER_t *st;
    asn_dec_rval_t rval = {RC_OK, 0};
    /* Validate API pointers before dereferencing the descriptor or output. */
    if(!td || !sptr || !pd) ASN__DECODE_FAILED;
    specs = (const asn_INTEGER_specifics_t *)td->specifics;
    st = (INTEGER_t *)*sptr;
    if(!st) {
        st = (INTEGER_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }
    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;
    if(ct && (ct->flags & APC_EXTENSIBLE)) {
        int inext = per_get_few_bits(pd, 1);
        if(inext < 0) ASN__DECODE_STARVED;
        if(inext) ct = 0;
    }
    /* Constrained offsets are bounded before restoring the stored INTEGER. */
    if(uper_integer_prepare(st, ct)) ASN__DECODE_FAILED;
    if(ct && ct->flags != APC_UNCONSTRAINED && ct->range_bits >= 0) {
        rval.code = uper_integer_get_constrained(st, ct, specs, pd);
        return rval;
    }

    /* Unconstrained contents retain their sign; semi-constrained offsets do not. */
    rval.code = uper_integer_get_contents(st, pd);
    if(rval.code != RC_OK) return rval;
    if(uper_integer_check_canonical(opt_codec_ctx, ct, st)) ASN__DECODE_FAILED;
    if(uper_integer_restore_semi(st, ct, specs)) ASN__DECODE_FAILED;
    return rval;
}

/*
 * Purpose: test root bounds before emitting a PER extension marker.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, integer; ct, root constraints; specs, optional storage signedness.
 * Returns: -1 for conversion failure; 0 in root; 1 outside root.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_in_extension(st, ct, specs).
 */
static int
uper_integer_in_extension(const INTEGER_t *st, const asn_per_constraint_t *ct,
                            const asn_INTEGER_specifics_t *specs) {
    /* Check each representation before deciding whether extension encoding is needed. */
    if(specs && specs->field_unsigned) {
        uintmax_t value;
        if(asn_INTEGER2umax(st, &value)) return -1;
        if(ct->flags & APC_SEMI_CONSTRAINED) return value < (uintmax_t)ct->lower_bound;
        if(ct->range_bits >= 0)
            return value < (uintmax_t)ct->lower_bound || value > (uintmax_t)ct->upper_bound;
    } else {
        intmax_t value;
        if(asn_INTEGER2imax(st, &value)) return -1;
        if(ct->flags & APC_SEMI_CONSTRAINED) return value < ct->lower_bound;
        if(ct->range_bits >= 0) return value < ct->lower_bound || value > ct->upper_bound;
    }
    return 0;
}

/*
 * Purpose: validate the root value and emit its extension marker.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, integer; ct, effective constraints; specs, signedness; po, output;
 * copy, APER extension copy storage (APER only).
 * Returns: 0 on success; -1 for invalid values or failed output.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_encode_extension(st, &ct, specs, po).
 */
static int
uper_integer_encode_extension(const INTEGER_t *st, const asn_per_constraint_t **ct,
                                const asn_INTEGER_specifics_t *specs,
                                asn_per_outp_t *po) {
    int inext;
    if(!*ct) return 0;
    inext = uper_integer_in_extension(st, *ct, specs);
    if(inext < 0) return -1;

    /* Keep the existing flavor-specific extension policy; reject nonextensible values. */
    if((*ct)->flags & APC_EXTENSIBLE) {
        if(per_put_few_bits(po, inext, 1)) return -1;
        if(inext) {
            *ct = 0;
        }
    } else if(inext) {
        return -1;
    }
    return 0;
}

/*
 * Purpose: rebase a constrained value with fully signed or fully unsigned bounds.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, integer; ct, constraints; specs, signedness; po, output bit state.
 * Returns: 0 on success; -1 for conversion, range or output errors.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_put_constrained(st, ct, specs, po).
 */
static int
uper_integer_put_constrained(const INTEGER_t *st, const asn_per_constraint_t *ct,
                               const asn_INTEGER_specifics_t *specs, asn_per_outp_t *po) {
    uintmax_t offset;
    /* Each helper validates bounds before performing a possibly full-width subtraction. */
    if(specs && specs->field_unsigned) {
        uintmax_t value;
        if(asn_INTEGER2umax(st, &value)
           || per_unsigned_range_rebase(value, (uintmax_t)ct->lower_bound,
                                         (uintmax_t)ct->upper_bound, &offset)) return -1;
    } else {
        intmax_t value;
        if(asn_INTEGER2imax(st, &value)
           || per_imax_range_rebase(value, ct->lower_bound, ct->upper_bound, &offset)) return -1;
    }
    if(ct->range_bits < 0 || (size_t)ct->range_bits > 8 * sizeof(offset)) return -1;
    return uper_put_constrained_whole_number_u(po, offset, ct->range_bits);
}

/*
 * Purpose: write INTEGER content fragments and their length determinants.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: buf/end, nonempty validated content range; po, output bit state.
 * Returns: 0 on success; -1 on invalid fragment length or failed output.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_put_contents(st->buf, st->buf + st->size, po).
 */
static int
uper_integer_put_contents(const uint8_t *buf, const uint8_t *end, asn_per_outp_t *po) {
    /* The same framing carries signed unconstrained values and unsigned offsets. */
    while(buf < end) {
        int need_eom = 0; /* End-of-fragments state variable. */
        ssize_t len = uper_put_length(po, end - buf, &need_eom);
        if(len <= 0 || len > end - buf) return -1;
        if(per_put_many_bits(po, buf, 8 * len)) return -1;
        buf += len;
        if(need_eom && (uper_put_length(po, 0, 0) != 0)) return -1;
    }
    return 0;
}

/*
 * Purpose: encode a semi-constrained value as its non-negative offset.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, value; ct, lower bound; specs, optional signedness; po, output.
 * Returns: 0 on success; -1 for range, conversion, allocation or output failure.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: uper_integer_put_semi(st, ct, specs, po).
 */
static int
uper_integer_put_semi(const INTEGER_t *st, const asn_per_constraint_t *ct,
                        const asn_INTEGER_specifics_t *specs, asn_per_outp_t *po) {
    INTEGER_t adjusted = {0};
    uintmax_t offset;
    const uint8_t *buf;
    int ret;

    /* Convert to a checked non-negative offset before allocating its representation. */
    if(specs && specs->field_unsigned) {
        uintmax_t value;
        if(asn_INTEGER2umax(st, &value)
           || per_umax_range_rebase(value, ct->lower_bound, &offset)) return -1;
    } else {
        intmax_t value;
        if(asn_INTEGER2imax(st, &value)
           || per_imax_range_rebase(value, ct->lower_bound, INTMAX_MAX, &offset)) return -1;
    }
    if(asn_umax2INTEGER(&adjusted, offset)) return -1;

    /* X.691 11.7 omits signed storage's positive sign octet only for this offset. */
    buf = uper_integer_min_contents(adjusted.buf, adjusted.buf + adjusted.size);
    ret = uper_integer_put_contents(buf, adjusted.buf + adjusted.size, po);
    ASN_STRUCT_RESET(asn_DEF_INTEGER, &adjusted);
    return ret;
}

/*
 * Purpose: encode a PER INTEGER through independently checked framing steps.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: td, descriptor; constraints, optional override; sptr, value; po, output.
 * Returns: ASN.1 encoder status, with failed type/value on errors.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: INTEGER_encode_uper(td, constraints, &value, po).
 */
asn_enc_rval_t
INTEGER_encode_uper(const asn_TYPE_descriptor_t *td,
                     const asn_per_constraints_t *constraints,
                     const void *sptr, asn_per_outp_t *po) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    const asn_INTEGER_specifics_t *specs;
    const asn_per_constraint_t *ct;
    asn_enc_rval_t er = {0, 0, 0};
    /* Reject missing buffers before conversion or pointer-range formation. */
    if(!td || !po || !st || !st->buf || st->size == 0 || st->size > PTRDIFF_MAX) ASN__ENCODE_FAILED;
    specs = (const asn_INTEGER_specifics_t *)td->specifics;
    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;
    if(uper_integer_encode_extension(st, &ct, specs, po)) ASN__ENCODE_FAILED;

    /* Keep each representation's arithmetic and bit framing in a bounded helper. */
    if(ct && ct->range_bits >= 0) {
        if(uper_integer_put_constrained(st, ct, specs, po)) ASN__ENCODE_FAILED;
    } else if(ct && (ct->lower_bound || (ct->flags & APC_SEMI_CONSTRAINED))) {
        if(uper_integer_put_semi(st, ct, specs, po)) ASN__ENCODE_FAILED;
    } else {
        /* X.691 11.8 keeps signed unconstrained INTEGER sign octets. */
        if(uper_integer_put_contents(st->buf, st->buf + st->size, po)) ASN__ENCODE_FAILED;
    }
    ASN__ENCODED_OK(er);
}
