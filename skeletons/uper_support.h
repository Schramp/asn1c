/*
 * Copyright (c) 2005-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_UPER_SUPPORT_H_
#define	_UPER_SUPPORT_H_

#include <asn_system.h>		/* Platform-specific types */
#include <per_support.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * X.691 (08/2015) #11.9 "General rules for encoding a length determinant"
 * Get the length "n" from the Unaligned PER stream.
 */
ssize_t uper_get_length(asn_per_data_t *pd, int effective_bound_bits,
                        size_t lower_bound, int *repeat);

/*
 * Get the normally small length "n".
 */
ssize_t uper_get_nslength(asn_per_data_t *pd);

/*
 * Get the normally small non-negative whole number.
 */
ssize_t uper_get_nsnnwn(asn_per_data_t *pd);

/* X.691-2008/11, #11.5.6 */
int uper_get_constrained_whole_number(asn_per_data_t *pd, uintmax_t *v, int nbits);

/*
 * NOTE: per_{long,imax,umax}_range_{rebase,unrebase}() are shared by the
 * UPER and APER codecs and are therefore declared in <per_support.h>
 * (included above) and defined in per_support.c, which is shipped with
 * both the CODEC-UPER and CODEC-APER skeleton sections.
 */

/* X.691-2008/11, #11.5 */
int uper_put_constrained_whole_number_u(asn_per_outp_t *po, uintmax_t v, int nbits);

/*
 * X.691 (08/2015) #11.9 "General rules for encoding a length determinant"
 * Put the length "whole_length" to the Unaligned PER stream.
 * If (opt_need_eom) is given, it will be set to 1 if final 0-length is needed.
 * In that case, invoke uper_put_length(po, 0, 0) after encoding the last block.
 * This function returns the number of units which may be flushed
 * in the next units saving iteration.
 */
ssize_t uper_put_length(asn_per_outp_t *po, size_t whole_length,
                        int *opt_need_eom);

/*
 * Put the normally small length "n" to the Unaligned PER stream.
 * Returns 0 or -1.
 */
int uper_put_nslength(asn_per_outp_t *po, size_t length);

/*
 * Put the normally small non-negative whole number.
 */
int uper_put_nsnnwn(asn_per_outp_t *po, int n);

#ifdef __cplusplus
}
#endif

#endif	/* _UPER_SUPPORT_H_ */
