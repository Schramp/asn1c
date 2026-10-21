/*
 * Copyright (c) 2005-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_PER_SUPPORT_H_
#define	_PER_SUPPORT_H_

#include <asn_system.h>		/* Platform-specific types */
#include <asn_bit_data.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pre-computed PER constraints.
 */
typedef struct asn_per_constraint_s {
	enum asn_per_constraint_flags {
		APC_UNCONSTRAINED	= 0x0,	/* No PER visible constraints */
		APC_SEMI_CONSTRAINED	= 0x1,	/* Constrained at "lb" */
		APC_CONSTRAINED		= 0x2,	/* Fully constrained */
		APC_EXTENSIBLE		= 0x4	/* May have extension */
	} flags;
	int  range_bits;		/* Full number of bits in the range */
	int  effective_bits;		/* Effective bits */
	intmax_t lower_bound;		/* "lb" value */
	intmax_t upper_bound;		/* "ub" value */
} asn_per_constraint_t;
typedef struct asn_per_constraints_s {
	asn_per_constraint_t value;
	asn_per_constraint_t size;
	int (*value2code)(unsigned int value);
	int (*code2value)(unsigned int code);
} asn_per_constraints_t;

/* Temporary compatibility layer. Will get removed. */
typedef struct asn_bit_data_s asn_per_data_t;
#define per_get_few_bits(data, bits)   asn_get_few_bits(data, bits)
#define per_get_undo(data, bits)   asn_get_undo(data, bits)
#define per_get_many_bits(data, dst, align, bits) \
    asn_get_many_bits(data, dst, align, bits)

/* Temporary compatibility layer. Will get removed. */
typedef struct asn_bit_outp_s asn_per_outp_t;
#define per_put_few_bits(out, bits, obits) asn_put_few_bits(out, bits, obits)
#define per_put_many_bits(out, src, nbits) asn_put_many_bits(out, src, nbits)
#define per_put_aligned_flush(out) asn_put_aligned_flush(out)

#define ASN_UPER_NSNNWN_MAX 65535L

/*
 * Rebase the given value as an offset into the range specified by the
 * lower bound (lb) and upper bound (ub), and the inverse operation.
 *
 * These helpers are common to both Unaligned (UPER) and Aligned (APER)
 * PER codecs. They MUST live here (per_support.[ch]) rather than in
 * uper_support.[ch] or aper_support.[ch], because per_support.[ch] is
 * the only support module emitted for BOTH the CODEC-UPER and CODEC-APER
 * skeleton sections. Placing them in a codec-specific module breaks
 * builds where only one PER flavor is generated (asn1c -no-gen-UPER or
 * asn1c -no-gen-APER).
 *
 * RETURN VALUES:
 *  -1: Conversion failed due to range problems.
 *   0: Conversion was successful.
 */
int per_long_range_rebase(long, intmax_t lb, intmax_t ub, unsigned long *output);
int per_imax_range_rebase(intmax_t v, intmax_t lb, intmax_t ub, uintmax_t *output);
/* Checked offset arithmetic for an unsigned value and a signed lower bound. */
int per_umax_range_rebase(uintmax_t v, intmax_t lb, uintmax_t *output);
/* The inverse operation: restores a non-negative value from an offset. */
int per_long_range_unrebase(unsigned long inp, intmax_t lb, intmax_t ub, long *outp);
int per_imax_range_unrebase(uintmax_t inp, intmax_t lb, intmax_t ub, intmax_t *outp);
int per_umax_range_unrebase(uintmax_t inp, intmax_t lb, uintmax_t *outp);

/*
 * Fully unsigned constrained ranges. Unlike the semi-constrained helpers
 * above, BOTH bounds are unsigned. Generated native unsigned descriptors
 * store their bit patterns in signed metadata slots; callers must cast
 * those slots to uintmax_t before calling. Return 0 on success, -1 for
 * missing output, reversed bounds, or an out-of-range value/offset.
 */
int per_unsigned_range_rebase(uintmax_t value, uintmax_t lb, uintmax_t ub,
                              uintmax_t *output);
int per_unsigned_range_unrebase(uintmax_t offset, uintmax_t lb, uintmax_t ub,
                                uintmax_t *output);

#ifdef __cplusplus
}
#endif

#endif	/* _PER_SUPPORT_H_ */
