/*
 * Copyright (c) 2005-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_system.h>
#include <asn_internal.h>
#include <per_support.h>

/*
 * Range rebasing helpers shared by the UPER and APER codecs.
 * See the comment in per_support.h for why they must live in this file.
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
