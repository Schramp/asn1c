/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_BER_DECODER_H_
#define	_BER_DECODER_H_

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum explicit-tag or constructed-string nesting layers parsed here. */
#define BER_EXPLICIT_TAG_DEPTH_LIMIT 30

struct asn_TYPE_descriptor_s;	/* Forward declaration */
struct asn_codec_ctx_s;		/* Forward declaration */

/*
 * The BER decoder of any type.
 * This function may be invoked directly from the application.
 * Decodes BER, DER and CER data (DER and CER are different subsets of BER).
 *
 * NOTE: Use the der_encode() function (der_encoder.h) to produce encoding
 * which is compliant with ber_decode().
 */
asn_dec_rval_t ber_decode(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of that buffer */
);

/*
 * Type of generic function which decodes the byte stream into the structure.
 */
typedef asn_dec_rval_t(ber_type_decoder_f)(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr,
    const void *buf_ptr, size_t size, int tag_mode);

/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Check that all tags correspond to the type definition (as given in head).
 * On return, last_length would contain either a non-negative length of the
 * value part of the last TLV, or the negative number of expected
 * "end of content" sequences. The number may only be negative if the
 * head->last_tag_form is non-zero.
 */
asn_dec_rval_t ber_check_tags(
    const struct asn_codec_ctx_s *opt_codec_ctx, /* codec options */
    const struct asn_TYPE_descriptor_s *type_descriptor,
    asn_struct_ctx_t *opt_ctx, /* saved decoding context */
    const void *ptr, size_t size,
    int tag_mode,      /* {-1,0,1}: IMPLICIT, no, EXPLICIT */
    int last_tag_form, /* {-1,0:1}: any, primitive, constr */
    ber_tlv_len_t *last_length, int *opt_tlv_form /* optional tag form */
);

/*
 * Check tags while also reporting end-of-contents wrappers separately.
 * Original source: BER decoder support, based on X.690 8.1.3 and 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: Same as ber_check_tags; opt_eoc_count receives wrapper count.
 * Returns: Decoding status; last_length is the innermost value length.
 * Errors: RC_WMORE for incomplete headers; RC_FAIL for invalid chains or
 *         explicit descriptor depth above BER_EXPLICIT_TAG_DEPTH_LIMIT.
 * Responsible party: asn1c maintainers. History: Added for mixed CER lengths.
 * Example: explicit indefinite wrapper around a definite primitive value.
 */
asn_dec_rval_t ber_check_tags_ex(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    asn_struct_ctx_t *opt_ctx, const void *ptr, size_t size, int tag_mode,
    int last_tag_form, ber_tlv_len_t *last_length, int *opt_eoc_count,
    int *opt_tlv_form
);

/*
 * Validate EOC octets following a definite primitive value.
 * Original source: BER decoder support, based on X.690 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ptr/size bound input; length is value size; eoc_count is count.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; opt_eoc_size gets validated suffix size.
 * Errors: RC_WMORE for truncation; RC_FAIL for malformed EOC or bad arguments.
 * Responsible party: asn1c maintainers. History: Added for explicit CER wrappers.
 * Example: validates the two zero octets ending an indefinite wrapper.
 */
enum asn_dec_rval_code_e ber_check_eoc_suffix(
    const void *ptr, size_t size, ber_tlv_len_t length, int eoc_count,
    size_t *opt_eoc_size
);

/*
 * Check primitive tags and ensure its value and wrapper EOCs are available.
 * Original source: BER decoder support, based on X.690 8.1.3/8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ptr/size are advanced to value; length/eoc_size are outputs.
 * Returns: Header-byte consumption and decode status.
 * Errors: RC_WMORE for partial value/EOC; RC_FAIL for malformed tags/EOCs.
 * Responsible party: asn1c maintainers. History: Added for explicit CER wrappers.
 * Example: shared by INTEGER, BOOLEAN, NULL, and REAL primitive decoders.
 */
asn_dec_rval_t ber_check_primitive_tags(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, const void **ptr,
    size_t *size, int tag_mode, ber_tlv_len_t *length, size_t *eoc_size
);

#ifdef __cplusplus
}
#endif

#endif	/* _BER_DECODER_H_ */
