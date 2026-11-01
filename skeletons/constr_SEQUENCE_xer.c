/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <OPEN_TYPE.h>
#include <limits.h>

/*
 * Purpose: match an XML tag to a direct child of a synthetic extension group.
 * Original source: XER handling for ASN.1 extension addition groups.
 * Version/date: 2026-10-21.
 * Inputs: td is the candidate group descriptor; ptr/tag_size identify the
 *         current XML token; first limits the search to unprocessed members.
 * Returns: 1 if a direct child tag matches, otherwise 0.
 * Exceptions: none; invalid descriptors, sizes, and missing names do not match.
 * Responsible party: asn1c maintainers.
 * History: added for issue #583; group children are encoded without a wrapper.
 * Example: use the result to dispatch <field> to its containing group.
 */
static int
SEQUENCE_xer_group_has_child_tag(const asn_TYPE_descriptor_t *td,
                                 const void *ptr, ssize_t tag_size,
                                 size_t first) {
    const asn_SEQUENCE_specifics_t *specs;
    size_t i;

    if(!td || !td->specifics || !td->elements || !ptr || tag_size <= 0
       || tag_size > INT_MAX)
        return 0;
    specs = (const asn_SEQUENCE_specifics_t *)td->specifics;
    if(!specs->extension_group)
        return 0;

    for(i = first; i < td->elements_count; i++) {
        xer_check_tag_e tcv;
        const char *name = td->elements[i].name;

        if(!name)
            continue;
        tcv = xer_check_tag(ptr, (int)tag_size, name);
        if(tcv == XCT_OPENING || tcv == XCT_BOTH)
            return 1;
    }

    return 0;
}

/*
 * Purpose: determine whether every unprocessed group member is optional.
 * Original source: XER handling for ASN.1 extension addition groups.
 * Version/date: 2026-10-21.
 * Inputs: td is the group descriptor; first is the first unprocessed member.
 * Returns: 1 when the remainder is optional or empty; 0 for invalid metadata
 *          or if any remaining member is mandatory.
 * Exceptions: none; invalid descriptors are treated as having mandatory data.
 * Responsible party: asn1c maintainers.
 * History: added for issue #583 to distinguish an absent optional group tail
 *          from a missing mandatory group component.
 * Example: return success at the next parent tag after all mandatory children.
 */
static int
SEQUENCE_xer_group_tail_optional(const asn_TYPE_descriptor_t *td,
                                 size_t first) {
    size_t i;

    if(!td || !td->elements || first > td->elements_count)
        return 0;
    for(i = first; i < td->elements_count; i++) {
        if(!td->elements[i].optional)
            return 0;
    }
    return 1;
}

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

#undef XER_ADVANCE
#define XER_ADVANCE(num_bytes)            \
    do {                                  \
        size_t num = (num_bytes);         \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        consumed_myself += num;           \
    } while(0)

/*
 * Purpose: decode a SEQUENCE's XER contents, including flat extension groups.
 * Original source: asn1c's XER SEQUENCE decoder.
 * Version/date: 2026-10-21.
 * Inputs: opt_codec_ctx controls recursion; td describes the sequence;
 *         struct_ptr receives/retains the decoded object; opt_mname is the
 *         member's expected XML tag; ptr/size contain the available XML data.
 * Returns: RC_OK for a complete value, RC_WMORE for incomplete data, or
 *          RC_FAIL for invalid XML or missing mandatory data.
 * Exceptions: allocation failures return RC_FAIL; nested decoder failures
 *             propagate, while the caller retains any partial object to free.
 * Responsible party: asn1c maintainers.
 * History: the extension-group path was added for issue #583.
 * Example: decode a SEQUENCE whose extension group members appear as siblings.
 */
asn_dec_rval_t
SEQUENCE_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td, void **struct_ptr,
                    const char *opt_mname, const void *ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SEQUENCE_specifics_t *specs
        = (const asn_SEQUENCE_specifics_t *)td->specifics;
    asn_TYPE_member_t *elements = td->elements;
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder state variable. */

    asn_dec_rval_t rval;          /* Return value from a decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    size_t edx;                   /* Element index */

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) RETURN(RC_FAIL);
    }

    /*
     * Restore parsing context.
     */
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

    /* Check recursion depth to prevent stack overflow */
    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
        RETURN(RC_FAIL);


    /*
     * Phases of XER/XML processing:
     * Phase 0: Check that the opening tag matches our expectations.
     * Phase 1: Processing body and reacting on closing tag.
     * Phase 2: Processing inner type.
     * Phase 3: Skipping unknown extensions.
     * Phase 4: PHASED OUT
     */
    for(edx = ctx->step; ctx->phase <= 3;) {
        pxer_chunk_type_e ch_type;  /* XER chunk type */
        ssize_t ch_size;            /* Chunk size */
        xer_check_tag_e tcv;        /* Tag check value */
        asn_TYPE_member_t *elm;

        /*
         * Go inside the inner member of a sequence.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval;
            void *memb_ptr_dontuse;  /* Pointer to the member */
            void **memb_ptr2;        /* Pointer to that pointer */

            elm = &td->elements[edx];

            if(elm->flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st + elm->memb_offset);
            } else {
                memb_ptr_dontuse = (char *)st + elm->memb_offset;
                memb_ptr2 = &memb_ptr_dontuse;  /* Only use of memb_ptr_dontuse */
            }

            if(elm->flags & ATF_OPEN_TYPE) {
                tmprval = OPEN_TYPE_xer_get(opt_codec_ctx, td, st, elm, ptr, size);
                /* Debug: Check if CHOICE present field was set (only in CHOICE wrapper mode) */
                if(tmprval.code == RC_OK && elm->type->elements_count > 0) {
	                void *choice_ptr = (elm->flags & ATF_POINTER) 
		                ? *(void**)((char*)st + elm->memb_offset)
		                : (void*)((char*)st + elm->memb_offset);
	                if(choice_ptr) {
		                unsigned int *present __attribute__((unused)) = (unsigned int*)choice_ptr;
		                ASN_DEBUG("OPEN_TYPE decoded: present=%u", *present);
	                }
                }
            } else {
                /* Invoke the inner type decoder, m.b. multiple times */
                tmprval = elm->type->op->xer_decoder(opt_codec_ctx,
                                                     elm->type, memb_ptr2, elm->name,
                                                     ptr, size);
            }
            XER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 1;  /* Back to body processing */
            ctx->step = ++edx;
            ASN_DEBUG("XER/SEQUENCE phase => %d, step => %d",
                ctx->phase, ctx->step);
            /* Fall through */
        }

        /*
         * Get the next part of the XML stream.
         */
        ch_size = xer_next_token(&ctx->context, ptr, size,
            &ch_type);
        if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
            switch(ch_type) {
            case PXER_WMORE:
                RETURN(RC_WMORE);
            case PXER_COMMENT:  /* Got XML comment */
            case PXER_TEXT:  /* Ignore free-standing text */
                XER_ADVANCE(ch_size);  /* Skip silently */
                continue;
            case PXER_TAG:
                break;  /* Check the rest down there */
            }
        }

        tcv = xer_check_tag(ptr, ch_size, xml_tag);
        ASN_DEBUG("XER/SEQUENCE: tcv = %d, ph=%d [%s]",
                  tcv, ctx->phase, xml_tag);

        /* A synthetic group has no opening wrapper: its first child starts it. */
        if(specs->extension_group && ctx->phase == 0) {
            if(!SEQUENCE_xer_group_has_child_tag(td, ptr, ch_size, edx)) {
                if(SEQUENCE_xer_group_tail_optional(td, edx)) {
                    ctx->phase = 4;
                    RETURN(RC_OK);
                }
                RETURN(RC_FAIL);
            }
            ctx->phase = 1;
            tcv = XCT_UNKNOWN_OP;
        } else if(specs->extension_group && ctx->phase == 1
                  && !SEQUENCE_xer_group_has_child_tag(td, ptr, ch_size,
                                                       edx)) {
            /* Leave the next parent's tag untouched after an optional tail. */
            if(SEQUENCE_xer_group_tail_optional(td, edx)) {
                ctx->phase = 4;
                RETURN(RC_OK);
            }
            RETURN(RC_FAIL);
        }

        /* Skip the extensions section */
        if(ctx->phase == 3) {
            switch(xer_skip_unknown(tcv, &ctx->left)) {
            case -1:
                ctx->phase = 4;
                RETURN(RC_FAIL);
            case 0:
                XER_ADVANCE(ch_size);
                continue;
            case 1:
                XER_ADVANCE(ch_size);
                ctx->phase = 1;
                continue;
            case 2:
                ctx->phase = 1;
                break;
            }
        }

        switch(tcv) {
        case XCT_CLOSING:
            if(ctx->phase == 0) break;
            ctx->phase = 0;
            /* Fall through */
        case XCT_BOTH:
            if(ctx->phase == 0) {
                if(edx >= td->elements_count ||
                   /* Explicit OPTIONAL specs reaches the end */
                   (edx + elements[edx].optional == td->elements_count) ||
                   /* All extensions are optional */
                   IN_EXTENSION_GROUP(specs, edx)) {
                    XER_ADVANCE(ch_size);
                    ctx->phase = 4;  /* Phase out */
                    RETURN(RC_OK);
                } else {
                    ASN_DEBUG("Premature end of XER SEQUENCE");
                    RETURN(RC_FAIL);
                }
            }
            /* Fall through */
        case XCT_OPENING:
            if(ctx->phase == 0) {
                XER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }
            /* Fall through */
        case XCT_UNKNOWN_OP:
        case XCT_UNKNOWN_BO:

            ASN_DEBUG("XER/SEQUENCE: tcv=%d, ph=%d, edx=%" ASN_PRI_SIZE "",
                      tcv, ctx->phase, edx);
            
            /* In phase 0, check if this is the generic <SEQUENCE> tag */
            if(ctx->phase == 0) {
                xer_check_tag_e seq_tcv = xer_check_tag(ptr, ch_size, "SEQUENCE");
                if(seq_tcv == XCT_OPENING || seq_tcv == XCT_BOTH) {
                    ASN_DEBUG("XER/SEQUENCE: Accepting generic <SEQUENCE> tag in phase 0");
                    XER_ADVANCE(ch_size);
                    ctx->phase = 1;  /* Processing body phase */
                    continue;
                }
                break;  /* Really unexpected */
            }
            
            if(ctx->phase != 1) {
                break;  /* Really unexpected */
            }

            if(edx < td->elements_count) {
                /*
                 * Search which member corresponds to this tag.
                 */
                size_t n;
                size_t edx_end = edx + elements[edx].optional + 1;
                if(edx_end > td->elements_count)
                    edx_end = td->elements_count;
                for(n = edx; n < edx_end; n++) {
                    elm = &td->elements[n];
                    if(elm->flags & ATF_EXTENSION_GROUP) {
                        tcv = SEQUENCE_xer_group_has_child_tag(
                            elm->type, ptr, ch_size, 0)
                            ? XCT_OPENING : XCT_UNKNOWN_OP;
                    } else {
                        tcv = xer_check_tag(ptr, ch_size, elm->name);
                    }
                    
                    ASN_DEBUG("XER/SEQUENCE: Checking member n=%zu, name='%s', tcv=%d, tag='%.*s'",
                              n, elm->name ? elm->name : "(null)", tcv, 
                              (int)(ch_size < 50 ? ch_size : 50), (const char*)ptr);
                        
                    switch(tcv) {
                    case XCT_BOTH:
#if XER_EMPTY_OPTIONALS_ENABLED
                        /*
                         * Empty tag detected (e.g., <field/>).
                         * If this field is OPTIONAL, treat it as absent.
                         */
                        if(elm->optional) {
                            ASN_DEBUG("XER/SEQUENCE: Empty optional field '%s', treating as absent",
                                      elm->name ? elm->name : "(null)");
                            XER_ADVANCE(ch_size);
                            ctx->step = edx = n + 1;
                            break;  /* Exit inner loop to get next token */
                        }
#endif
                        /* Fall through for non-optional or when feature disabled */
                    case XCT_OPENING:
#if XER_EMPTY_OPTIONALS_ENABLED
                        /*
                         * Check if this is an empty optional field with separate
                         * opening/closing tags (e.g., <field></field>).
                         */
                        if(elm->optional) {
                            const char *peek_ptr = (const char *)ptr + ch_size;
                            size_t peek_size = size - ch_size;
                            int peek_ctx = 0;
                            pxer_chunk_type_e peek_type;
                            ssize_t peek_ch_size;
                            ssize_t closing_tag_size = 0;
                            
                            /* Skip whitespace and comments to find next token */
                            while(peek_size > 0) {
                                peek_ch_size = xer_next_token(&peek_ctx, peek_ptr, peek_size, &peek_type);
                                if(peek_ch_size <= 0) break;
                                
                                if(peek_type == PXER_COMMENT || peek_type == PXER_TEXT) {
                                    /* Skip whitespace/comments */
                                    size_t ws_span = xer_whitespace_span(peek_ptr, peek_ch_size);
                                    if(ws_span == (size_t)peek_ch_size) {
                                        /* Pure whitespace, skip it */
                                        peek_ptr += peek_ch_size;
                                        peek_size -= peek_ch_size;
                                        peek_ctx = 0;
                                        continue;
                                    } else if(peek_type == PXER_COMMENT) {
                                        /* Comment, skip it */
                                        peek_ptr += peek_ch_size;
                                        peek_size -= peek_ch_size;
                                        peek_ctx = 0;
                                        continue;
                                    }
                                }
                                
                                /* Found a non-whitespace token */
                                if(peek_type == PXER_TAG) {
                                    xer_check_tag_e peek_tcv = xer_check_tag(peek_ptr, peek_ch_size, elm->name);
                                    if(peek_tcv == XCT_CLOSING) {
                                        /* This is an empty optional field! */
                                        ASN_DEBUG("XER/SEQUENCE: Empty optional field '%s' "
                                                  "(separate tags), treating as absent",
                                                  elm->name ? elm->name : "(null)");
                                        /* Capture closing tag size before using it */
                                        closing_tag_size = peek_ch_size;
                                        /* Skip both opening and closing tags */
                                        XER_ADVANCE((peek_ptr - (const char *)ptr) + closing_tag_size);
                                        ctx->step = edx = n + 1;
                                        break;  /* Exit inner loop to get next token */
                                    }
                                }
                                break;  /* Not an empty tag, proceed normally */
                            }
                            
                            /* If we found and handled an empty optional, skip normal processing */
                            if(closing_tag_size > 0) {
                                break;  /* Exit switch to skip normal member processing */
                            }
                        }
#endif
                        /*
                         * Process this member.
                         */
                        ctx->step = edx = n;
                        ctx->phase = 2;
                        break;
                    case XCT_UNKNOWN_OP:
                    case XCT_UNKNOWN_BO:
                        continue;
                    default:
                        n = edx_end;
                        break;  /* Phase out */
                    }
                    break;
                }
                if(n != edx_end)
                    continue;
            } else {
                ASN_DEBUG("Out of defined members: %" ASN_PRI_SIZE "/%u",
                          edx, td->elements_count);
            }

            /* It is expected extension */
            if(IN_EXTENSION_GROUP(specs,
                edx + (edx < td->elements_count
                    ? elements[edx].optional : 0))) {
                ASN_DEBUG("Got anticipated extension at %" ASN_PRI_SIZE "",
                          edx);
                /*
                 * Check for (XCT_BOTH or XCT_UNKNOWN_BO)
                 * By using a mask. Only record a pure
                 * <opening> tags.
                 */
                if(tcv & XCT_CLOSING) {
                    /* Found </extension> without body */
                } else {
                    ctx->left = 1;
                    ctx->phase = 3;  /* Skip ...'s */
                }
                XER_ADVANCE(ch_size);
                continue;
            }

            /* Check if this is a type wrapper tag (e.g., <Reset> when opt_mname="value") */
            if(ctx->phase == 1 && td->xml_tag && opt_mname && 
               strcmp(td->xml_tag, opt_mname) != 0) {
                tcv = xer_check_tag(ptr, ch_size, td->xml_tag);
                if(tcv == XCT_OPENING || tcv == XCT_BOTH) {
                    ASN_DEBUG("XER/SEQUENCE: Skipping type wrapper tag <%s>", td->xml_tag);
                    XER_ADVANCE(ch_size);
                    /* Stay in phase 1 to process the actual content */
                    continue;
                }
            }
            
            /* Fall through */
        case XCT_UNKNOWN_CL:
            /* Check if this is a type wrapper closing tag (e.g., </Reset> when opt_mname="value") */
            if(ctx->phase == 1 && td->xml_tag && opt_mname && 
               strcmp(td->xml_tag, opt_mname) != 0) {
                xer_check_tag_e wrapper_tcv = xer_check_tag(ptr, ch_size, td->xml_tag);
                if(wrapper_tcv == XCT_CLOSING) {
                    ASN_DEBUG("XER/SEQUENCE: Closing type wrapper tag </%s>", td->xml_tag);
                    XER_ADVANCE(ch_size);
                    /* Stay in phase 1, expecting the element closing tag */
                    continue;
                }
            }
            
            /* Check if this is the closing generic </SEQUENCE> tag */
            if(ctx->phase == 1) {
                xer_check_tag_e seq_tcv = xer_check_tag(ptr, ch_size, "SEQUENCE");
                if(seq_tcv == XCT_CLOSING) {
                    ASN_DEBUG("XER/SEQUENCE: Accepting generic </SEQUENCE> tag in phase 1");
                    /* Check if we're done with all mandatory elements */
                    if(edx >= td->elements_count ||
                       (edx + elements[edx].optional == td->elements_count) ||
                       IN_EXTENSION_GROUP(specs, edx)) {
                        XER_ADVANCE(ch_size);
                        ctx->phase = 0;  /* Reset for next use */
                        /* Check if there's an outer element tag to consume */
                        if(opt_mname && td->xml_tag && strcmp(opt_mname, td->xml_tag) != 0) {
                            /* Element name differs from type name, so expect outer </opt_mname> tag.
                             * Continue looping to consume it in the next iteration. */
                            ASN_DEBUG("XER/SEQUENCE: Expecting outer closing tag </%s>", opt_mname);
                            continue;
                        } else {
                            /* This was the only wrapper, we're done */
                            ctx->phase = 4;
                            RETURN(RC_OK);
                        }
                    } else {
                        ASN_DEBUG("Missing mandatory elements after </SEQUENCE>");
                        break;  /* Missing mandatory elements */
                    }
                }
            }

            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected XML tag in SEQUENCE [%c%c%c%c%c%c]",
                  size>0?((const char *)ptr)[0]:'.',
                  size>1?((const char *)ptr)[1]:'.',
                  size>2?((const char *)ptr)[2]:'.',
                  size>3?((const char *)ptr)[3]:'.',
                  size>4?((const char *)ptr)[4]:'.',
                  size>5?((const char *)ptr)[5]:'.');
        break;
    }

    ctx->phase = 4;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}

/*
 * Purpose: serialize one SEQUENCE member, flattening synthetic group wrappers.
 * Original source: XER member-emission logic from asn1c's SEQUENCE encoder.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td/sptr identify the parent; elm/member identify the field; edx and
 *         previous_bytes set indentation; ilevel/flags/cb/app_key set XER mode.
 * Returns: Encoded byte count, or the failing child/member descriptor.
 * Errors: Callback and child encoder failures propagate in the result.
 * Responsible party: asn1c maintainers. History: extracted to bound complexity.
 * Example: emit a group's child tags at the current parent indentation.
 */
static asn_enc_rval_t
SEQUENCE_xer_encode_member(const asn_TYPE_descriptor_t *td, const void *sptr,
                           asn_TYPE_member_t *elm, const void *member,
                           size_t edx, ssize_t previous_bytes, int ilevel,
                           enum xer_encoder_flags_e flags,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_SEQUENCE_specifics_t *specs =
        (const asn_SEQUENCE_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0, 0, 0};
    asn_enc_rval_t child;
    const char *mname = elm->name;
    size_t mlen = strlen(mname);

    /* A synthetic group is represented by its child elements in XER. */
    if(elm->flags & ATF_EXTENSION_GROUP)
        return elm->type->op->xer_encoder(elm->type, member, ilevel, flags,
                                          cb, app_key);

    /* Separate wrapped members with indentation in the selected XER form. */
    if(!(flags & XER_F_CANONICAL)) {
        if((edx == 0 || previous_bytes == 0)
           && !(specs && specs->extension_group)) {
            ASN__TEXT_INDENT(1, ilevel);
        } else {
            int tmp_i;
            for(tmp_i = 0; tmp_i < ilevel; tmp_i++)
                ASN__CALLBACK("    ", 4);
        }
    }
    ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

    /* Encode the member value, including open types, inside its XML element. */
    if(elm->flags & ATF_OPEN_TYPE) {
        child = OPEN_TYPE_xer_put(td, sptr, elm, ilevel + 1, flags, cb, app_key);
    } else {
        child = elm->type->op->xer_encoder(elm->type, member, ilevel + 1,
                                           flags, cb, app_key);
    }
    if(child.encoded < 0) return child;
    er.encoded += child.encoded;

    /* Match pretty-mode child indentation and canonical wrapper spelling. */
    if(!(flags & XER_F_CANONICAL)) {
        if(child.encoded > 0
           && (ASN__IS_STRUCTURED_TYPE(elm) || (elm->flags & ATF_OPEN_TYPE)))
            ASN__TEXT_INDENT(0, ilevel);
        ASN__CALLBACK3("</", 2, mname, mlen, ">\n", 2);
    } else {
        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }
    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Purpose: encode SEQUENCE contents as XER, flattening extension groups.
 * Original source: asn1c's XER SEQUENCE encoder.
 * Version/date: 2026-10-24.
 * Inputs: td describes the sequence; sptr is its value; ilevel controls
 *         indentation; flags selects canonical form; cb/app_key collect bytes.
 * Returns: encoded byte count, or an error result if a child fails.
 * Exceptions: callback and child encoder errors propagate as encoding failure.
 * Responsible party: asn1c maintainers.
 * History: the extension-group path was added for issue #583. Removed the
 *          unreachable callback-failure label after callback work moved to
 *          SEQUENCE_xer_encode_member on 2026-10-24.
 * Example: encode group members as sibling tags inside the parent sequence.
 */
asn_enc_rval_t
SEQUENCE_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int ilevel, enum xer_encoder_flags_e flags,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};
    asn_TYPE_descriptor_t *tmp_def_val_td = 0;
    void *tmp_def_val = 0;
    size_t edx;

    if(!sptr) ASN__ENCODE_FAILED;

    /* Check recursion depth to prevent stack overflow */
    XER_ENCODER_RECURSION_DEPTH_INC();

    er.encoded = 0;

    for(edx = 0; edx < td->elements_count; edx++) {
        asn_enc_rval_t tmper;
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                assert(tmp_def_val == 0);
                if(elm->default_value_set) {
                    if(elm->default_value_set(&tmp_def_val)) {
                        XER_ENCODER_RECURSION_DEPTH_DEC();
                        ASN__ENCODE_FAILED;
                    } else {
                        memb_ptr = tmp_def_val;
                        tmp_def_val_td = elm->type;
                    }
                } else if(elm->optional) {
                    continue;
                } else {
                    /* Mandatory element is missing */
                    XER_ENCODER_RECURSION_DEPTH_DEC();
                    ASN__ENCODE_FAILED;
                }
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        tmper = SEQUENCE_xer_encode_member(td, sptr, elm, memb_ptr, edx,
                                            er.encoded, ilevel, flags, cb,
                                            app_key);
        if(tmp_def_val) {
            ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
            tmp_def_val = 0;
        }
        if(tmper.encoded == -1) {
            XER_ENCODER_RECURSION_DEPTH_DEC();
            return tmper;
        }
        er.encoded += tmper.encoded;
    }

    XER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODED_OK(er);
}
