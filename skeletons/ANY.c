/*
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ANY.h>
#include <limits.h>
#include <stdint.h>

asn_OCTET_STRING_specifics_t asn_SPC_ANY_specs = {
    sizeof(ANY_t),
    offsetof(ANY_t, _asn_ctx),
    ASN_OSUBV_ANY
};
asn_TYPE_operation_t asn_OP_ANY = {
    .kind = ASN_KIND_PRIMITIVE,
    OCTET_STRING_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    ANY_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    ANY_compare,
    ANY_copy,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    OCTET_STRING_decode_ber,
    OCTET_STRING_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    OCTET_STRING_decode_xer_hex,
    ANY_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    OCTET_STRING_decode_jer_hex,
    ANY_encode_jer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    OCTET_STRING_decode_oer,
    OCTET_STRING_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    ANY_decode_uper,
    ANY_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    ANY_decode_aper,
    ANY_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
    0,  /* Random fill is not defined for ANY type */
    0,  /* Use generic outmost tag fetcher */
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    OCTET_STRING_decode_cbor,    /* Reuse OCTET STRING decoder (raw DER bytes) */
    OCTET_STRING_encode_cbor,    /* Reuse OCTET STRING encoder (raw DER bytes) */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};

#if !defined(ASN_DISABLE_PRINT_SUPPORT)
/*
 * Purpose: Print ANY octets without interpreting its int size as a size_t.
 * Original source: Adapter to the asn1c OCTET STRING hexadecimal printer.
 * Version: 2026-10-22.
 * Parameters: td identifies ANY; sptr is the nullable value; ilevel controls
 *             indentation; cb consumes printed bytes using app_key as context.
 * Returns: 0 on success or -1 for invalid values, missing callbacks, or I/O errors.
 * Errors: Negative sizes and missing nonempty storage are rejected before access.
 * Responsible party: asn1c maintainers.
 * History: Issue #586 uses ANY for opaque values; normalize its layout for printing.
 * Example: A one-octet value 0x80 prints as "80", independent of structure padding.
 */
int
ANY_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
           asn_app_consume_bytes_f *cb, void *app_key) {
    const ANY_t *value = (const ANY_t *)sptr;
    OCTET_STRING_t view;

    if(!td || !cb) return -1;
    if(!value) return OCTET_STRING_print(td, NULL, ilevel, cb, app_key);
    if(value->size < 0 || (value->size > 0 && !value->buf)) return -1;
    if(value->size == 0) return 0;

    /* Only the temporary view uses the OCTET STRING layout; payload stays borrowed. */
    memset(&view, 0, sizeof(view));
    view.buf = value->buf;
    view.size = (size_t)value->size;
    return OCTET_STRING_print(&asn_DEF_OCTET_STRING, &view, ilevel, cb, app_key);
}
#endif /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
asn_TYPE_descriptor_t asn_DEF_ANY = {
    "ANY",
    "ANY",
    &asn_OP_ANY,
    0, 0, 0, 0,
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
        asn_generic_no_constraint
    },  /* No constraints */
    0, 0,  /* No members */
    &asn_SPC_ANY_specs,
};

/*
 * Purpose: Compare two ANY payloads without treating a negative int size as huge.
 * Original source: OCTET_STRING_compare adapted for the public ANY_t layout.
 * Version: 2026-10-22.
 * Parameters: td is the ANY descriptor; aptr and bptr are nullable ANY values.
 * Returns: Negative, zero, or positive according to payload ordering.
 * Errors: Malformed sizes or missing positive-size buffers sort after valid data.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586's ANY-backed opaque open-type choice arm.
 * Example: Equal opaque payloads compare as zero even when their buffers differ.
 */
int
ANY_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
            const void *bptr) {
    const ANY_t *a = (const ANY_t *)aptr;
    const ANY_t *b = (const ANY_t *)bptr;
    int a_invalid;
    int b_invalid;
    size_t common_size;
    int result;

    (void)td;
    if(!a) return b ? -1 : 0;
    if(!b) return 1;

    a_invalid = a->size < 0 || (a->size > 0 && !a->buf);
    b_invalid = b->size < 0 || (b->size > 0 && !b->buf);
    if(a_invalid || b_invalid) {
        if(a_invalid != b_invalid) return a_invalid ? 1 : -1;
        if(a->size < b->size) return -1;
        if(a->size > b->size) return 1;
        return 0;
    }

    common_size = (size_t)(a->size < b->size ? a->size : b->size);
    result = common_size ? memcmp(a->buf, b->buf, common_size) : 0;
    if(result) return result < 0 ? -1 : 1;
    if(a->size < b->size) return -1;
    if(a->size > b->size) return 1;
    return 0;
}

/*
 * Purpose: Deep-copy an ANY payload using ANY_t's signed-int size field.
 * Original source: OCTET_STRING_copy adapted for the public ANY_t layout.
 * Version: 2026-10-22.
 * Parameters: td describes ANY storage; aptr receives the copy; bptr is source.
 * Returns: 0 on success, -1 for malformed values or allocation failure.
 * Errors: Negative sizes, missing positive-size buffers, and invalid storage
 *         descriptors fail without replacing the destination contents.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for opaque APER fallback lifecycle support in issue #586.
 * Example: Copying an empty ANY produces an independently owned empty buffer.
 */
int
ANY_copy(const asn_TYPE_descriptor_t *td, void **aptr, const void *bptr) {
    const asn_OCTET_STRING_specifics_t *specs;
    const ANY_t *source = (const ANY_t *)bptr;
    ANY_t *destination;
    uint8_t *new_buffer = NULL;
    size_t size;

    if(!td || !aptr) return -1;
    specs = td->specifics
                ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                : &asn_SPC_ANY_specs;
    if(specs->struct_size < sizeof(ANY_t)
       || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset) {
        return -1;
    }
    destination = (ANY_t *)*aptr;

    if(!source) {
        if(destination) OCTET_STRING_free(td, destination, ASFM_FREE_EVERYTHING);
        *aptr = NULL;
        return 0;
    }
    if(source->size < 0 || (source->size > 0 && !source->buf)) return -1;
    if(destination == source) return 0;

    size = (size_t)source->size;
    if(size == SIZE_MAX) return -1;
    new_buffer = (uint8_t *)MALLOC(size + 1);
    if(!new_buffer) return -1;
    if(size) memcpy(new_buffer, source->buf, size);
    new_buffer[size] = 0;

    if(!destination) {
        destination = (ANY_t *)CALLOC(1, specs->struct_size);
        if(!destination) {
            FREEMEM(new_buffer);
            return -1;
        }
    }

    FREEMEM(destination->buf);
    destination->buf = new_buffer;
    destination->size = source->size;
    *aptr = destination;
    return 0;
}
