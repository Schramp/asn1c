/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <OPEN_TYPE.h>
#include <aper_opentype.h>
#include <string.h>   /* strncmp() — used to identify NULL-typed extension
                       * fields without introducing a hard link
                       * dependency on NULL.o */

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

/*
 * Purpose: Decode present sequence extension members from their open types.
 * Original source: Existing SEQUENCE_decode_aper extension-member loop.
 * Version: 2026-10-22.
 * Parameters: ctx, td, st, pd, and specs describe the sequence; epmd is its
 *             extension bitmap cursor.
 * Returns: RC_OK or the error result from a member's open-type decoder.
 * Errors: Truncated or malformed member payloads return their decode status.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted while routing IOC open types through runtime fallback.
 * Example: Called after decoding the extension presence bitmap.
 */
static asn_dec_rval_t
SEQUENCE_decode_extension_members(const asn_codec_ctx_t *ctx,
                                  const asn_TYPE_descriptor_t *td, void *st,
                                  asn_per_data_t *pd,
                                  const asn_SEQUENCE_specifics_t *specs,
                                  asn_per_data_t *epmd) {
    asn_dec_rval_t rv = {RC_OK, 0};
    size_t edx;

    for(edx = specs->first_extension; edx < td->elements_count; edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        void *memb_ptr;
        void **memb_ptr2;
        int present;

        if(!IN_EXTENSION_GROUP(specs, edx)) continue;
        if(elm->flags & ATF_POINTER) {
            memb_ptr2 = (void **)((char *)st + elm->memb_offset);
        } else {
            memb_ptr = (char *)st + elm->memb_offset;
            memb_ptr2 = &memb_ptr;
        }
        present = per_get_few_bits(epmd, 1);
        if(present <= 0) {
            if(present < 0) break;
            continue;
        }
        rv = aper_open_type_get(ctx, elm->type,
                                elm->encoding_constraints.per_constraints,
                                memb_ptr2, pd);
        if(rv.code == RC_WMORE) return rv;
        if(rv.code != RC_OK && elm->type->name
           && strncmp(elm->type->name, "NULL", 4) == 0) {
            /*
             * A NULL-typed extension is a schema placeholder that preserves
             * extension-bitmap numbering. Its decoder consumes no inner bits,
             * so valid non-empty payloads fail the open-type padding check.
             * aper_open_type_get has already consumed the complete envelope,
             * making it safe to accept the placeholder and continue decoding.
             * Keep this exception limited to NULL so other schema mismatches
             * remain errors.
             */
            ASN_DEBUG("Skipping payload for NULL-placeholder extension %s in %s",
                      elm->name, td->name);
            if(elm->flags & ATF_POINTER) {
                /* The NULL decoder may allocate before its padding check fails. */
                ASN_STRUCT_FREE(*elm->type, *memb_ptr2);
                *memb_ptr2 = NULL;
            }
            rv.code = RC_OK;
            rv.consumed = 0;
        } else if(rv.code != RC_OK) {
            return rv;
        }
    }
    return rv;
}

/*
 * Purpose: Skip the first present extension beyond this schema's known range.
 * Original source: Existing SEQUENCE_decode_aper overflow-extension loop.
 * Version: 2026-10-22.
 * Parameters: ctx is the codec context; pd is the input; epmd is the remaining
 *             extension-bitmap cursor.
 * Returns: 0 after consuming the first set overflow bit, or -1 on truncation.
 * Errors: Incomplete or invalid open-type data returns -1.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted while reducing SEQUENCE decoder complexity.
 * Example: Called after known extension members are decoded.
 */
static int
SEQUENCE_skip_extension_overflow(const asn_codec_ctx_t *ctx,
                                 asn_per_data_t *pd, asn_per_data_t *epmd) {
    for(;;) {
        int present = per_get_few_bits(epmd, 1);
        if(present < 0) return 0;
        if(present == 0) continue;
        if(aper_open_type_skip(ctx, pd)) return -1;
        break;
    }
    return 0;
}

/*
 * Purpose: Fill absent extension members that declare DEFAULT values.
 * Original source: Existing SEQUENCE_decode_aper extension-default loop.
 * Version: 2026-10-22.
 * Parameters: td, st, and specs describe the decoded sequence.
 * Returns: 0 when defaults are set, or -1 when a setter fails.
 * Errors: A default setter failure returns -1.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted while reducing SEQUENCE decoder complexity.
 * Example: Called after all extension additions have been processed.
 */
static int
SEQUENCE_fill_extension_defaults(const asn_TYPE_descriptor_t *td, void *st,
                                 const asn_SEQUENCE_specifics_t *specs) {
    size_t edx;

    for(edx = specs->roms_count; edx < specs->roms_count + specs->aoms_count;
        edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        void **memb_ptr2;

        if(!elm->default_value_set || !(elm->flags & ATF_POINTER)) continue;
        memb_ptr2 = (void **)((char *)st + elm->memb_offset);
        if(!*memb_ptr2 && elm->default_value_set(memb_ptr2)) return -1;
    }
    return 0;
}

/*
 * Purpose: Decode APER extension additions and fill absent extension defaults.
 * Original source: Existing SEQUENCE_decode_aper extension phase, extracted.
 * Version: 2026-10-22.
 * Parameters: ctx is the codec context; td, st, pd, and specs describe the
 *             sequence; extpresent says whether an extension bitmap follows.
 * Returns: RC_OK when extensions decode, otherwise the APER error result.
 * Errors: Truncated maps and malformed open types return RC_WMORE or RC_FAIL.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted while routing IOC open types through runtime fallback.
 * Example: Called after root members have decoded in SEQUENCE_decode_aper.
 */
static asn_dec_rval_t
SEQUENCE_decode_extensions_aper(const asn_codec_ctx_t *ctx,
                                const asn_TYPE_descriptor_t *td, void *st,
                                asn_per_data_t *pd,
                                const asn_SEQUENCE_specifics_t *specs,
                                int extpresent) {
    asn_dec_rval_t rv = {RC_OK, 0};

    if(extpresent) {
        ssize_t bmlength = aper_get_nslength(pd);
        uint8_t *epres;
        asn_per_data_t epmd;

        if(bmlength < 0) ASN__DECODE_STARVED;
        ASN_DEBUG("Extensions %" ASN_PRI_SSIZE " present in %s", bmlength, td->name);
        epres = (uint8_t *)MALLOC((bmlength + 15) >> 3);
        if(!epres) ASN__DECODE_STARVED;
        if(per_get_many_bits(pd, epres, 0, bmlength)) {
            FREEMEM(epres);
            ASN__DECODE_STARVED;
        }

        /* The bitmap selects extension members and aligns their open types. */
        memset(&epmd, 0, sizeof(epmd));
        epmd.buffer = epres;
        epmd.nbits = bmlength;
        ASN_DEBUG("Read in extensions bitmap for %s of %zd bits (%x..)",
                  td->name, bmlength, *epres);
        if(aper_get_align(pd) < 0) {
            FREEMEM(epres);
            ASN__DECODE_STARVED;
        }
        rv = SEQUENCE_decode_extension_members(ctx, td, st, pd, specs, &epmd);
        if(rv.code != RC_OK) {
            FREEMEM(epres);
            return rv;
        }
        if(SEQUENCE_skip_extension_overflow(ctx, pd, &epmd)) {
            FREEMEM(epres);
            ASN__DECODE_STARVED;
        }
        FREEMEM(epres);
    }
    if(SEQUENCE_fill_extension_defaults(td, st, specs)) ASN__DECODE_FAILED;
    return rv;
}

/*
 * Purpose: Validate the descriptor and cursor needed by the APER SEQUENCE decoder.
 * Original source: asn1c APER SEQUENCE decoder input checks for issue #586.
 * Version: 2026-10-22.
 * Parameters: td is the sequence descriptor; sptr is the destination address;
 *             pd is the APER input cursor.
 * Returns: Nonzero for valid decoder metadata, zero for missing metadata.
 * Errors: None; this helper never dereferences a missing descriptor.
 * Responsible party: asn1c maintainers.
 * History: Added while bounding the root decoder's unit complexity.
 * Example: Reject a NULL descriptor before reading its specifics.
 */
static int
SEQUENCE_aper_has_descriptor(const asn_TYPE_descriptor_t *td, void **sptr,
                             const asn_per_data_t *pd) {
    return td && td->specifics && sptr && pd
           && (td->elements_count == 0 || td->elements);
}

/*
 * Purpose: Resolve one root member's OPTIONAL/DEFAULT presence bit.
 * Original source: Existing SEQUENCE_decode_aper optional-member handling.
 * Version: 2026-10-22.
 * Parameters: elm is the member descriptor; bitmap is the optional-bit cursor;
 *             member is the destination for an absent member's DEFAULT value.
 * Returns: 1 for present, 0 for absent, -1 for truncation or DEFAULT failure.
 * Errors: Reports truncated presence maps and failed default setters.
 * Responsible party: asn1c maintainers.
 * History: Extracted while adding opaque open-type retention for issue #586.
 * Example: An absent optional open type leaves its pointer NULL.
 */
static int
SEQUENCE_aper_root_member_present(const asn_TYPE_member_t *elm,
                                  asn_per_data_t *bitmap, void **member) {
    int present;

    if(!elm->optional) return 1;
    present = per_get_few_bits(bitmap, 1);
    if(present != 0) return present > 0 ? 1 : -1;

    /* Defaults are materialized only for an absent optional root member. */
    if(elm->default_value_set && elm->default_value_set(member)) return -1;
    return 0;
}

/*
 * Purpose: Decode one APER SEQUENCE, including root and extension members.
 * Original source: Existing asn1c SEQUENCE APER decoder.
 * Version: 2026-10-22.
 * Parameters: ctx is the codec context; td and constraints describe the type;
 *             sptr is the destination pointer and pd is the input bit stream.
 * Returns: RC_OK when the sequence decodes, otherwise RC_WMORE or RC_FAIL.
 * Errors: Invalid member descriptors, truncated input, or allocation failure.
 * Responsible party: asn1c runtime maintainers.
 * History: Open types now dispatch through OPEN_TYPE_aper_get (issue #586).
 * Example: Used by the public APER decoder for generated SEQUENCE types.
 */
asn_dec_rval_t
SEQUENCE_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td,
                     const asn_per_constraints_t *constraints, void **sptr, asn_per_data_t *pd) {
    const asn_SEQUENCE_specifics_t *specs;
    void *st; /* Target structure. */
    int extpresent;    /* state variable: extension additions are present */
    uint8_t *opres;    /* state variable: presence of optional root members */
    asn_per_data_t opmd; /* state variable: optional-member bitmap cursor */
    asn_dec_rval_t rv;
    size_t edx;

    (void)constraints;

    /* Validate public decoder arguments before accessing sequence metadata. */
    if(!SEQUENCE_aper_has_descriptor(td, sptr, pd)) ASN__DECODE_FAILED;
    specs = (const asn_SEQUENCE_specifics_t *)td->specifics;
    st = *sptr;

    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
        ASN__DECODE_FAILED;

    if(!st) {
        st = *sptr = CALLOC(1, specs->struct_size);
        if(!st) ASN__DECODE_FAILED;
    }

    ASN_DEBUG("Decoding %s as SEQUENCE (APER)", td->name);

    /* Handle extensions */
    if(specs->first_extension < 0) {
        extpresent = 0;
    } else {
        extpresent = per_get_few_bits(pd, 1);
        if(extpresent < 0) ASN__DECODE_STARVED;
    }

    /* Prepare a place and read-in the presence bitmap */
    memset(&opmd, 0, sizeof(opmd));
    if(specs->roms_count) {
        opres = (uint8_t *)MALLOC(((specs->roms_count + 7) >> 3) + 1);
        if(!opres) ASN__DECODE_FAILED;
        /* Get the presence map */
        if(per_get_many_bits(pd, opres, 0, specs->roms_count)) {
            FREEMEM(opres);
            ASN__DECODE_STARVED;
        }
        opmd.buffer = opres;
        opmd.nbits = specs->roms_count;
        ASN_DEBUG("Read in presence bitmap for %s of %d bits (%x..)",
                  td->name, specs->roms_count, *opres);
    } else {
        opres = 0;
    }

    /*
     * Get the sequence ROOT elements.
     */
    for(edx = 0; edx < td->elements_count; edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        void *memb_ptr;    /* Pointer to the member */
        void **memb_ptr2;  /* Pointer to that pointer */
        int present; /* state variable: root member presence after defaults */


        if(IN_EXTENSION_GROUP(specs, edx))
            continue;

        /* Fetch the pointer to this member */
        if(elm->flags & ATF_POINTER) {
            memb_ptr2 = (void **)((char *)st + elm->memb_offset);
        } else {
            memb_ptr = (char *)st + elm->memb_offset;
            memb_ptr2 = &memb_ptr;
        }

        /* Resolve absent/default roots before dispatching any open-type decoder. */
        present = SEQUENCE_aper_root_member_present(elm, &opmd, memb_ptr2);
        if(present < 0) {
            FREEMEM(opres);
            ASN__DECODE_FAILED;
        }
        if(!present) continue;

        /* Fetch the member from the stream */
        ASN_DEBUG("Decoding member \"%s\" in %s", elm->name, td->name);

        if(elm->flags & ATF_OPEN_TYPE) {
            rv = OPEN_TYPE_aper_get(opt_codec_ctx, td, st, elm, pd);
            if(rv.code != RC_OK) {
                ASN_DEBUG("Failed decode %s in %s",
                          elm->name, td->name);
                FREEMEM(opres);
                return rv;
            }
        } else {
            rv = elm->type->op->aper_decoder(opt_codec_ctx, elm->type,
                                             elm->encoding_constraints.per_constraints,
                                             memb_ptr2, pd);
            if(rv.code != RC_OK) {
                ASN_DEBUG("Failed decode %s in %s",
                          elm->name, td->name);
                FREEMEM(opres);
                return rv;
            }
        }
    }

    /* Root members are complete; decode the bitmap-driven extensions. */
    FREEMEM(opres);
    return SEQUENCE_decode_extensions_aper(opt_codec_ctx, td, st,
                                            pd, specs, extpresent);
}

static int
SEQUENCE_handle_extensions_aper(const asn_TYPE_descriptor_t *td,
                                const void *sptr,
                                asn_per_outp_t *po1, asn_per_outp_t *po2) {
    const asn_SEQUENCE_specifics_t *specs
        = (const asn_SEQUENCE_specifics_t *)td->specifics;
    int exts_present = 0;
    int exts_count = 0;
    size_t edx;

    if(specs->first_extension < 0) {
        return 0;
    }

    /* Find out which extensions are present */
    for(edx = specs->first_extension; edx < td->elements_count; edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;           /* Pointer to the member */
        const void * const *memb_ptr2;  /* Pointer to that pointer */
        int present;

        if(!IN_EXTENSION_GROUP(specs, edx)) {
            ASN_DEBUG("%s (@%zu) is not extension", elm->type->name, edx);
            continue;
        }

        /* Fetch the pointer to this member */
        if(elm->flags & ATF_POINTER) {
            memb_ptr2 = (const void * const *)((const char *)sptr + elm->memb_offset);
            present = (*memb_ptr2 != 0);
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
            memb_ptr2 = &memb_ptr;
            present = 1;
        }

        ASN_DEBUG("checking %s (@%zu) present => %d",
                  elm->type->name, edx, present);
        exts_count++;
        exts_present += present;

        /* Encode as presence marker */
        if(po1 && per_put_few_bits(po1, present, 1))
            return -1;
        /* Encode as open type field */
        if(po2 && present && aper_open_type_put(elm->type,
                                                elm->encoding_constraints.per_constraints,
                                                *memb_ptr2, po2))
            return -1;

    }

    return exts_present ? exts_count : 0;
}

asn_enc_rval_t
SEQUENCE_encode_aper(const asn_TYPE_descriptor_t *td,
                     const asn_per_constraints_t *constraints,
                     const void *sptr, asn_per_outp_t *po) {
    const asn_SEQUENCE_specifics_t *specs
        = (const asn_SEQUENCE_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0,0,0};
    int n_extensions;
    size_t edx;
    size_t i;

    (void)constraints;

    if(!sptr)
        ASN__ENCODE_FAILED;

    /* Check recursion depth to prevent stack overflow */
    APER_ENCODER_RECURSION_DEPTH_INC();

    er.encoded = 0;

    ASN_DEBUG("Encoding %s as SEQUENCE (APER)", td->name);

    /*
     * X.691#18.1 Whether structure is extensible
     * and whether to encode extensions
     */
    if(specs->first_extension < 0) {
        n_extensions = 0; /* There are no extensions to encode */
    } else {
        n_extensions = SEQUENCE_handle_extensions_aper(td, sptr, 0, 0);
        if(n_extensions < 0) {
            APER_ENCODER_RECURSION_DEPTH_DEC();
            ASN__ENCODE_FAILED;
        }
        if(per_put_few_bits(po, n_extensions ? 1 : 0, 1)) {
            APER_ENCODER_RECURSION_DEPTH_DEC();
            ASN__ENCODE_FAILED;
        }
    }

    /* Encode a presence bitmap */
    for(i = 0; i < specs->roms_count; i++) {
        asn_TYPE_member_t *elm;
        const void *memb_ptr;           /* Pointer to the member */
        const void * const *memb_ptr2;  /* Pointer to that pointer */
        int present;

        edx = specs->oms[i];
        elm = &td->elements[edx];

        /* Fetch the pointer to this member */
        if(elm->flags & ATF_POINTER) {
            memb_ptr2 = (const void * const *)((const char *)sptr + elm->memb_offset);
            present = (*memb_ptr2 != 0);
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
            memb_ptr2 = &memb_ptr;
            present = 1;
        }

        /* Eliminate default values */
        if(present && elm->default_value_cmp
                && elm->default_value_cmp(*memb_ptr2) == 0)
            present = 0;

        ASN_DEBUG("Element %s %s %s->%s is %s",
                  elm->flags & ATF_POINTER ? "ptr" : "inline",
                  elm->default_value_cmp ? "def" : "wtv",
                  td->name, elm->name, present ? "present" : "absent");
        if(per_put_few_bits(po, present, 1)) {
            APER_ENCODER_RECURSION_DEPTH_DEC();
            ASN__ENCODE_FAILED;
        }
    }

    /*
     * Encode the sequence ROOT elements.
     */
    ASN_DEBUG("first_extension = %d, elements = %d", specs->first_extension,
              td->elements_count);
    for(edx = 0;
        edx < ((specs->first_extension < 0) ? td->elements_count
                                            : (size_t)specs->first_extension);
        edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;           /* Pointer to the member */
        const void * const *memb_ptr2;  /* Pointer to that pointer */

        if(IN_EXTENSION_GROUP(specs, edx))
            continue;

        ASN_DEBUG("About to encode %s", elm->type->name);

        /* Fetch the pointer to this member */
        if(elm->flags & ATF_POINTER) {
            memb_ptr2 = (const void * const *)((const char *)sptr + elm->memb_offset);
            if(!*memb_ptr2) {
                ASN_DEBUG("Element %s %zu not present",
                          elm->name, edx);
                if(elm->optional)
                    continue;
                /* Mandatory element is missing */
                APER_ENCODER_RECURSION_DEPTH_DEC();
                ASN__ENCODE_FAILED;
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
            memb_ptr2 = &memb_ptr;
        }

        /* Eliminate default values */
        if(elm->default_value_cmp && elm->default_value_cmp(*memb_ptr2) == 0)
            continue;

        ASN_DEBUG("Encoding %s->%s", td->name, elm->name);
        if(elm->flags & ATF_OPEN_TYPE) {
            er = OPEN_TYPE_aper_put(td, sptr, elm, po);
        } else {
            er = elm->type->op->aper_encoder(elm->type,
                                             elm->encoding_constraints.per_constraints,
                                             *memb_ptr2, po);
        }
        if(er.encoded == -1) {
            APER_ENCODER_RECURSION_DEPTH_DEC();
            return er;
        }
    }

    /* No extensions to encode */
    if(!n_extensions) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODED_OK(er);
    }

    ASN_DEBUG("Length of %d bit-map", n_extensions);
    /* #18.8. Write down the presence bit-map length. */
    if(aper_put_nslength(po, n_extensions)) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }

    ASN_DEBUG("Bit-map of %d elements", n_extensions);
    /* #18.7. Encoding the extensions presence bit-map. */
    /* TODO: act upon NOTE in #18.7 for canonical PER */
    if(SEQUENCE_handle_extensions_aper(td, sptr, po, 0) != n_extensions) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }

    ASN_DEBUG("Writing %d extensions", n_extensions);
    /* #18.9. Encode extensions as open type fields. */
    if(SEQUENCE_handle_extensions_aper(td, sptr, 0, po) != n_extensions) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }

    APER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODED_OK(er);
}
