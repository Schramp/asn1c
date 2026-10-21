/*
 * Copyright (c) 2005-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_system.h>
#include <asn_internal.h>
#include <per_support.h>

/*
 * Purpose: obtain an offset within a fully unsigned constrained range.
 * Source: asn1c security review of legacy signed PER metadata.
 * Version: 2026-10-20; responsible party: asn1c maintainers.
 * Inputs: value, the native unsigned value; lb/ub, unsigned inclusive bounds;
 * output, receives value - lb. Returns: 0 on success, -1 on invalid arguments
 * or range violations. Exceptions: none; output is unchanged on failure.
 * History: added to support bounds above INTMAX_MAX without signed arithmetic.
 * Example: per_unsigned_range_rebase(UINTMAX_MAX, 0, UINTMAX_MAX, &offset).
 */
int
per_unsigned_range_rebase(uintmax_t value, uintmax_t lb, uintmax_t ub,
                          uintmax_t *output) {
    /* Validate before subtracting so malformed metadata cannot wrap. */
    if(!output || lb > ub || value < lb || value > ub) return -1;
    *output = value - lb;
    return 0;
}

/*
 * Purpose: restore an unsigned value from a constrained PER offset.
 * Source: asn1c security review of legacy signed PER metadata.
 * Version: 2026-10-20; responsible party: asn1c maintainers.
 * Inputs: offset, non-negative wire value; lb/ub, unsigned inclusive bounds;
 * output, receives lb + offset. Returns: 0 on success, -1 on invalid arguments
 * or range violations. Exceptions: none; output is unchanged on failure.
 * History: added with unsigned constrained-range regression coverage.
 * Example: per_unsigned_range_unrebase(UINTMAX_MAX, 0, UINTMAX_MAX, &value).
 */
int
per_unsigned_range_unrebase(uintmax_t offset, uintmax_t lb, uintmax_t ub,
                            uintmax_t *output) {
    /* The offset bound guarantees the subsequent addition cannot overflow. */
    if(!output || lb > ub || offset > ub - lb) return -1;
    *output = lb + offset;
    return 0;
}

/*
 * Range rebasing helpers shared by the UPER and APER codecs.
 * See the comment in per_support.h for why they must live in this file.
 */

/*
 * Purpose: compute the inclusive signed bounds' maximum unsigned offset.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: lb/ub, signed bounds; range_r, checked maximum offset.
 * Returns: 0 on success; -1 for null output or reversed bounds.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per__imax_range(INTMAX_MIN, INTMAX_MAX, &span).
 */
static int
per__imax_range(intmax_t lb, intmax_t ub, uintmax_t *range_r) {
    uintmax_t bounds_range;

    if(!range_r || lb > ub) return -1;

    if((ub < 0) == (lb < 0)) {
        /* The difference of same-sign bounds is representable. */
        bounds_range = (uintmax_t)(ub - lb);
    } else if(lb < 0) {
        /* Compute ub - lb without ever negating INTMAX_MIN. */
        bounds_range = (uintmax_t)ub
                      + ((uintmax_t)(-(lb + 1)) + 1);
    } else {
        return -1;
    }

    *range_r = bounds_range;
    return 0;
}

/*
 * Purpose: subtract a signed lower bound without signed overflow.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: v, signed value; lb/ub, inclusive bounds; output, offset.
 * Returns: 0 on success; -1 for invalid arguments or range violations.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per_imax_range_rebase(0, INTMAX_MIN, INTMAX_MAX, &offset).
 */
int
per_imax_range_rebase(intmax_t v, intmax_t lb, intmax_t ub, uintmax_t *output) {
    uintmax_t range;

    if(!output || v < lb || v > ub
       || per__imax_range(lb, ub, &range) < 0) {
        return -1;
    }

    /* Return v - lb while avoiding signed overflow at cross-sign bounds. */
    if((v < 0) == (lb < 0)) {
        *output = (uintmax_t)(v - lb);
    } else if(v < 0) {
        uintmax_t v_magnitude = (uintmax_t)(-(v + 1)) + 1;
        uintmax_t lb_magnitude = (uintmax_t)(-(lb + 1)) + 1;
        if(v_magnitude > lb_magnitude) return -1;
        *output = lb_magnitude - v_magnitude;
    } else {
        uintmax_t lb_magnitude = (uintmax_t)(-(lb + 1)) + 1;
        if(lb_magnitude > UINTMAX_MAX - (uintmax_t)v) return -1;
        *output = lb_magnitude + (uintmax_t)v;
    }

    return *output <= range ? 0 : -1;
}

/*
 * Purpose: rebase a long while checking the unsigned long output width.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: v, long value; lb/ub, signed bounds; output, checked offset.
 * Returns: 0 on success; -1 for invalid range, output or narrowing.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per_long_range_rebase(0, -1, 1, &offset).
 */
int
per_long_range_rebase(long v, intmax_t lb, intmax_t ub, unsigned long *output) {
    uintmax_t tmp;
    int rc;

    if(!output) return -1;
    rc = per_imax_range_rebase((intmax_t)v, lb, ub, &tmp);
    if(rc == 0 && tmp <= (uintmax_t)ULONG_MAX) *output = (unsigned long)tmp;
    else if(rc == 0) rc = -1;
    return rc;
}

/*
 * Purpose: rebase an unsigned value using a signed semi-constrained lower bound.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: v, unsigned value; lb, signed lower bound; output, offset.
 * Returns: 0 on success; -1 for null output, underflow or overflow.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per_umax_range_rebase(0, -1, &offset).
 */
int
per_umax_range_rebase(uintmax_t v, intmax_t lb, uintmax_t *output) {
    if(!output) return -1;

    if(lb < 0) {
        /* v - lb == v + |lb|; do not negate INTMAX_MIN. */
        uintmax_t magnitude = (uintmax_t)(-(lb + 1)) + 1;
        if(v > UINTMAX_MAX - magnitude) return -1;
        *output = v + magnitude;
    } else {
        if(v < (uintmax_t)lb) return -1;
        *output = v - (uintmax_t)lb;
    }
    return 0;
}

/*
 * Purpose: restore a signed value without overflowing at cross-sign bounds.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: inp, offset; lb/ub, inclusive signed bounds; outp, result.
 * Returns: 0 on success; -1 for invalid output, range or offset.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per_imax_range_unrebase(0, INTMAX_MIN, INTMAX_MAX, &value).
 */
int
per_imax_range_unrebase(uintmax_t inp, intmax_t lb, intmax_t ub, intmax_t *outp) {
    uintmax_t range;

    if(!outp || per__imax_range(lb, ub, &range) != 0 || inp > range)
        return -1;

    if(lb >= 0) {
        /* lb and the offset have the same non-negative representation. */
        if(inp > (uintmax_t)INTMAX_MAX - (uintmax_t)lb)
            return -1;
        *outp = lb + (intmax_t)inp;
    } else if(ub < 0) {
        /* Both bounds are negative, so the mathematical sum is safe. */
        *outp = lb + (intmax_t)inp;
    } else {
        /* Cross-sign range: split the offset at zero. */
        uintmax_t neg_lb = (uintmax_t)(-(lb + 1)) + 1;
        if(inp < neg_lb) {
            uintmax_t magnitude = neg_lb - inp;
            if(magnitude == (uintmax_t)INTMAX_MAX + 1) {
                *outp = INTMAX_MIN;
            } else {
                if(magnitude > (uintmax_t)INTMAX_MAX) return -1;
                *outp = -(intmax_t)magnitude;
            }
        } else {
            uintmax_t positive = inp - neg_lb;
            if(positive > (uintmax_t)INTMAX_MAX) return -1;
            *outp = (intmax_t)positive;
        }
    }

    return *outp >= lb && *outp <= ub ? 0 : -1;
}

/*
 * Purpose: restore a long and reject results outside the native long width.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: inp, offset; lb/ub, signed bounds; outp, checked long result.
 * Returns: 0 on success; -1 for invalid arguments or narrowing.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per_long_range_unrebase(0, -1, 1, &value).
 */
int
per_long_range_unrebase(unsigned long inp, intmax_t lb, intmax_t ub, long *outp) {
    intmax_t tmp;
    int rc;

    if(!outp) return -1;
    rc = per_imax_range_unrebase((uintmax_t)inp, lb, ub, &tmp);
    if(rc == 0 && (tmp < LONG_MIN || tmp > LONG_MAX)) rc = -1;
    if(rc == 0) *outp = (long)tmp;
    return rc;
}

/*
 * Purpose: restore an unsigned value using a signed semi-constrained lower bound.
 * Original source: asn1c PER range support, formerly in uper_support.c.
 * Version: 2026-10-20. Responsible party: asn1c maintainers.
 * Inputs: inp, offset; lb, signed lower bound; outp, unsigned result.
 * Returns: 0 on success; -1 for null output, negative result or overflow.
 * Exceptions: none. History: retained with shared unsigned-range hardening.
 * Example: per_umax_range_unrebase(1, -1, &value).
 */
int
per_umax_range_unrebase(uintmax_t inp, intmax_t lb, uintmax_t *outp) {
    if(!outp) return -1;

    if(lb < 0) {
        /* v == inp + lb; reject offsets whose result would be negative. */
        uintmax_t magnitude = (uintmax_t)(-(lb + 1)) + 1;
        if(inp < magnitude) return -1;
        *outp = inp - magnitude;
    } else {
        if(inp > UINTMAX_MAX - (uintmax_t)lb) return -1;
        *outp = inp + (uintmax_t)lb;
    }
    return 0;
}
