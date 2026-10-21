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
 * History: retained while constrained arithmetic was split into checked helpers.
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

/*
 * Purpose: prepare the INTEGER buffer for a PER offset or signed value.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, owned INTEGER; ct, optional effective constraints.
 * Returns: 0 on success; -1 on allocation failure or unsupported width.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_prepare(st, ct).
 */
static int
aper_integer_prepare(INTEGER_t *st, const asn_per_constraint_t *ct) {
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
 * Purpose: read a wide APER constrained offset and validate its length.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: ct, constraints; pd, input state; offset, output accumulator.
 * Returns: RC_OK, RC_WMORE for truncation, or RC_FAIL for invalid length.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_get_wide(ct, pd, &offset).
 */
static enum asn_dec_rval_code_e
aper_integer_get_wide(const asn_per_constraint_t *ct, asn_per_data_t *pd,
                      uintmax_t *offset) {
    size_t max_bytes = ((size_t)ct->range_bits + 7) >> 3;
    unsigned length_bits = aper_log2_ceil_size(max_bytes);
    int len_minus_one = per_get_few_bits(pd, length_bits);
    size_t len;

    /* Reject rounded-up determinant values before aligning or reading payload. */
    if(len_minus_one < 0) return RC_WMORE;
    len = (size_t)len_minus_one + 1;
    if(len > max_bytes || len > sizeof(*offset)) return RC_FAIL;
    if(aper_get_align(pd) < 0) return RC_FAIL;

    /* A width-validated determinant bounds the unsigned accumulator. */
    *offset = 0;
    while(len > 0) {
        int octet = per_get_few_bits(pd, 8);
        if(octet < 0) return RC_WMORE;
        if(*offset > (UINTMAX_MAX >> 8)) return RC_FAIL;
        *offset = (*offset << 8) | (unsigned)octet;
        len--;
    }
    return RC_OK;
}

/*
 * Purpose: read the APER constrained offset without signed arithmetic.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: ct, constraints; pd, input state; offset, decoded output.
 * Returns: RC_OK, RC_WMORE for truncation, or RC_FAIL for invalid metadata.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_get_offset(ct, pd, &offset).
 */
static enum asn_dec_rval_code_e
aper_integer_get_offset(const asn_per_constraint_t *ct, asn_per_data_t *pd,
                        uintmax_t *offset) {
    int raw;
    int bits = ct->range_bits;

    /* Metadata may be hand-written: bound it before shifts or allocation. */
    if(bits < 0 || (size_t)bits > 8 * sizeof(*offset)) return RC_FAIL;
    if(bits > 16) return aper_integer_get_wide(ct, pd, offset);
    if(bits >= 8 && aper_get_align(pd) < 0) return RC_FAIL;
    if(bits > 8) bits = 16;
    raw = per_get_few_bits(pd, bits);
    if(raw < 0) return RC_WMORE;
    *offset = (uintmax_t)raw;
    return RC_OK;
}

/*
 * Purpose: restore a constrained offset using the descriptor's signedness.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, result; ct, constraints; specs, optional storage metadata; pd, input.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; never adds an unchecked offset.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_get_constrained(st, ct, specs, pd).
 */
static enum asn_dec_rval_code_e
aper_integer_get_constrained(INTEGER_t *st, const asn_per_constraint_t *ct,
                               const asn_INTEGER_specifics_t *specs, asn_per_data_t *pd) {
    uintmax_t offset;
    enum asn_dec_rval_code_e code = aper_integer_get_offset(ct, pd, &offset);
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
 * Example: aper_integer_get_contents(st, pd).
 */
static enum asn_dec_rval_code_e
aper_integer_get_contents(INTEGER_t *st, asn_per_data_t *pd) {
    size_t initial_size = st->size;
    int repeat; /* Fragment-continuation state variable. */

    /* Append only lengths whose allocation and bit counts are representable. */
    do {
        ssize_t len = aper_get_length(pd, -1, -1, -1, &repeat);
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
 * Example: aper_integer_restore_semi(st, ct, specs).
 */
static int
aper_integer_restore_semi(INTEGER_t *st, const asn_per_constraint_t *ct,
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
 * Purpose: select the existing APER extension-region constraint policy.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: ct, root constraints; copy, extension copy storage; pd, input state.
 * Returns: effective constraints through ct; RC_WMORE if extension bit is absent.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_decode_extension(&ct, &copy, pd).
 */
static enum asn_dec_rval_code_e
aper_integer_decode_extension(const asn_per_constraint_t **ct,
                              asn_per_constraint_t *copy, asn_per_data_t *pd) {
    int inext;
    if(!*ct || !((*ct)->flags & APC_EXTENSIBLE)) return RC_OK;
    inext = per_get_few_bits(pd, 1);
    if(inext < 0) return RC_WMORE;
    if(inext) {
        /* Preserve the codec's existing semi-constrained extension convention. */
        if((*ct)->flags & APC_SEMI_CONSTRAINED) {
            *copy = **ct;
            copy->flags = APC_SEMI_CONSTRAINED;
            copy->range_bits = -1;
            copy->effective_bits = -1;
            *ct = copy;
        } else {
            *ct = 0;
        }
    }
    return RC_OK;
}

/*
 * Purpose: decode a PER INTEGER while separating bit I/O from checked range arithmetic.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: opt_codec_ctx, policy; td, type; constraints, optional override;
 * sptr, owned result pointer; pd, input bit state.
 * Returns: ASN.1 decoder status; failure for missing arguments or invalid data.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: INTEGER_decode_aper(ctx, td, constraints, &value, pd).
 */
asn_dec_rval_t
INTEGER_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td,
                     const asn_per_constraints_t *constraints, void **sptr,
                     asn_per_data_t *pd) {
    const asn_INTEGER_specifics_t *specs;
    const asn_per_constraint_t *ct;
    INTEGER_t *st;
    asn_dec_rval_t rval = {RC_OK, 0};
    asn_per_constraint_t extension_copy; /* Effective-constraint state variable. */
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
    rval.code = aper_integer_decode_extension(&ct, &extension_copy, pd);
    if(rval.code != RC_OK) return rval;
    /* Constrained offsets are bounded before restoring the stored INTEGER. */
    if(aper_integer_prepare(st, ct)) ASN__DECODE_FAILED;
    if(ct && ct->flags != APC_UNCONSTRAINED && ct->range_bits >= 0) {
        rval.code = aper_integer_get_constrained(st, ct, specs, pd);
        return rval;
    }

    /* Unconstrained contents retain their sign; semi-constrained offsets do not. */
    rval.code = aper_integer_get_contents(st, pd);
    if(rval.code != RC_OK) return rval;
    (void)opt_codec_ctx;
    if(aper_integer_restore_semi(st, ct, specs)) ASN__DECODE_FAILED;
    return rval;
}

/*
 * Purpose: test root bounds before emitting a PER extension marker.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, integer; ct, root constraints; specs, optional storage signedness.
 * Returns: -1 for conversion failure; 0 in root; 1 outside root.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_in_extension(st, ct, specs).
 */
static int
aper_integer_in_extension(const INTEGER_t *st, const asn_per_constraint_t *ct,
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
 * Example: aper_integer_encode_extension(st, &ct, specs, po, &copy).
 */
static int
aper_integer_encode_extension(const INTEGER_t *st, const asn_per_constraint_t **ct,
                                const asn_INTEGER_specifics_t *specs,
                                asn_per_outp_t *po, asn_per_constraint_t *copy) {
    int inext;
    if(!*ct) return 0;
    inext = aper_integer_in_extension(st, *ct, specs);
    if(inext < 0) return -1;

    /* Keep the existing flavor-specific extension policy; reject nonextensible values. */
    if((*ct)->flags & APC_EXTENSIBLE) {
        if(per_put_few_bits(po, inext, 1)) return -1;
        if(inext) {
            if((*ct)->flags & APC_SEMI_CONSTRAINED) {
                *copy = **ct;
                copy->flags = APC_SEMI_CONSTRAINED;
                copy->range_bits = -1;
                copy->effective_bits = -1;
                *ct = copy;
            } else {
                *ct = 0;
            }
        }
    } else if(inext) {
        return -1;
    }
    return 0;
}

/*
 * Purpose: write the bounded length and octets of a wide APER offset.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: po, output state; bits, constraint width; value, checked offset.
 * Returns: 0 on success; -1 for invalid width/length or output failure.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_put_wide(po, 64, offset).
 */
static int
aper_integer_put_wide(asn_per_outp_t *po, int bits, uintmax_t value) {
    size_t max_bytes = ((size_t)bits + 7) >> 3;
    unsigned length_bits = aper_log2_ceil_size(max_bytes);
    uint8_t buf[sizeof(value)];
    uintmax_t remaining = value; /* Octet-emission state variable. */
    size_t bytes = 0;
    size_t i;

    /* Use the minimal non-negative octet representation, retaining zero's octet. */
    do {
        bytes++;
        remaining >>= 8;
    } while(remaining);
    if(bytes > max_bytes || bytes > sizeof(buf)) return -1;
    for(i = 0; i < bytes; i++) {
        buf[bytes - i - 1] = (uint8_t)(value & 0xff);
        value >>= 8;
    }

    /* Length is constrained, followed by octet alignment and offset payload. */
    if(per_put_few_bits(po, bytes - 1, length_bits)) return -1;
    if(aper_put_align(po) < 0) return -1;
    return per_put_many_bits(po, buf, 8 * bytes);
}

/*
 * Purpose: write a checked APER offset with the required alignment.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: po, output; bits, constraint width; offset, value; span, maximum offset.
 * Returns: 0 on success; -1 for invalid width or output failure.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_put_offset(po, 8, offset, 255).
 */
static int
aper_integer_put_offset(asn_per_outp_t *po, int bits, uintmax_t offset, uintmax_t span) {
    /* Checking width also makes the offset-fit shift defined at zero/full widths. */
    if(bits < 0 || (size_t)bits > 8 * sizeof(offset)) return -1;
    if((size_t)bits < 8 * sizeof(offset) && (offset >> bits) != 0) return -1;
    if(bits > 16) return aper_integer_put_wide(po, bits, offset);

    /* Never form span + 1: full-width signed and unsigned ranges overflow it. */
    if(bits < 8 || (bits == 8 && span < 255)) return per_put_few_bits(po, offset, bits);
    if(aper_put_align(po) < 0) return -1;
    if(bits > 8) bits = 16;
    return per_put_few_bits(po, offset, bits);
}

/*
 * Purpose: rebase a constrained value with fully signed or fully unsigned bounds.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: st, integer; ct, constraints; specs, signedness; po, output bit state.
 * Returns: 0 on success; -1 for conversion, range or output errors.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_put_constrained(st, ct, specs, po).
 */
static int
aper_integer_put_constrained(const INTEGER_t *st, const asn_per_constraint_t *ct,
                               const asn_INTEGER_specifics_t *specs, asn_per_outp_t *po) {
    uintmax_t offset;
    uintmax_t span;
    /* Each helper validates bounds before performing a possibly full-width subtraction. */
    if(specs && specs->field_unsigned) {
        uintmax_t value;
        if(asn_INTEGER2umax(st, &value)
           || per_unsigned_range_rebase(value, (uintmax_t)ct->lower_bound,
                                         (uintmax_t)ct->upper_bound, &offset)) return -1;
        span = (uintmax_t)ct->upper_bound - (uintmax_t)ct->lower_bound;
    } else {
        intmax_t value;
        if(asn_INTEGER2imax(st, &value)
           || per_imax_range_rebase(value, ct->lower_bound, ct->upper_bound, &offset)) return -1;
        if(per_imax_range_rebase(ct->upper_bound, ct->lower_bound, ct->upper_bound, &span)) return -1;
    }
    return aper_integer_put_offset(po, ct->range_bits, offset, span);
}

/*
 * Purpose: write INTEGER content fragments and their length determinants.
 * Original source: asn1c INTEGER PER codec, extracted during security fixes.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: buf/end, nonempty validated content range; po, output bit state.
 * Returns: 0 on success; -1 on invalid fragment length or failed output.
 * Exceptions: none. History: separates validation, arithmetic and bit I/O.
 * Example: aper_integer_put_contents(st->buf, st->buf + st->size, po).
 */
static int
aper_integer_put_contents(const uint8_t *buf, const uint8_t *end, asn_per_outp_t *po) {
    /* The same framing carries signed unconstrained values and unsigned offsets. */
    while(buf < end) {
        int need_eom = 0; /* End-of-fragments state variable. */
        ssize_t len = aper_put_length(po, -1, -1, end - buf, &need_eom);
        if(len <= 0 || len > end - buf) return -1;
        if(per_put_many_bits(po, buf, 8 * len)) return -1;
        buf += len;
        if(need_eom && (aper_put_length(po, -1, -1, 0, 0) < 0)) return -1;
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
 * Example: aper_integer_put_semi(st, ct, specs, po).
 */
static int
aper_integer_put_semi(const INTEGER_t *st, const asn_per_constraint_t *ct,
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
    buf = aper_integer_min_contents(adjusted.buf, adjusted.buf + adjusted.size);
    ret = aper_integer_put_contents(buf, adjusted.buf + adjusted.size, po);
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
 * Example: INTEGER_encode_aper(td, constraints, &value, po).
 */
asn_enc_rval_t
INTEGER_encode_aper(const asn_TYPE_descriptor_t *td,
                     const asn_per_constraints_t *constraints,
                     const void *sptr, asn_per_outp_t *po) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    const asn_INTEGER_specifics_t *specs;
    const asn_per_constraint_t *ct;
    asn_enc_rval_t er = {0, 0, 0};
    asn_per_constraint_t extension_copy; /* Effective-constraint state variable. */
    /* Reject missing buffers before conversion or pointer-range formation. */
    if(!td || !po || !st || !st->buf || st->size == 0 || st->size > PTRDIFF_MAX) ASN__ENCODE_FAILED;
    specs = (const asn_INTEGER_specifics_t *)td->specifics;
    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;
    if(aper_integer_encode_extension(st, &ct, specs, po, &extension_copy)) ASN__ENCODE_FAILED;

    /* Keep each representation's arithmetic and bit framing in a bounded helper. */
    if(ct && ct->range_bits >= 0) {
        if(aper_integer_put_constrained(st, ct, specs, po)) ASN__ENCODE_FAILED;
    } else if(ct && (ct->lower_bound || (ct->flags & APC_SEMI_CONSTRAINED))) {
        if(aper_integer_put_semi(st, ct, specs, po)) ASN__ENCODE_FAILED;
    } else {
        /* X.691 11.8 keeps signed unconstrained INTEGER sign octets. */
        if(aper_integer_put_contents(st->buf, st->buf + st->size, po)) ASN__ENCODE_FAILED;
    }
    ASN__ENCODED_OK(er);
}
