/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>
#include <OPEN_TYPE.h>

/*
 * Number of bytes left for this structure.
 * (ctx->left) indicates the number of bytes _transferred_ for the structure.
 * (size) contains the number of bytes in the buffer passed.
 */
#define LEFT ((size<(size_t)ctx->left)?size:(size_t)ctx->left)

/*
 * If the subprocessor function returns with an indication that it wants
 * more data, it may well be a fatal decoding problem, because the
 * size is constrained by the <TLV>'s L, even if the buffer size allows
 * reading more data.
 * For example, consider the buffer containing the following TLVs:
 * <T:5><L:1><V> <T:6>...
 * The TLV length clearly indicates that one byte is expected in V, but
 * if the V processor returns with "want more data" even if the buffer
 * contains way more data than the V processor have seen.
 */
#define SIZE_VIOLATION (ctx->left >= 0 && (size_t)ctx->left <= size)

/*
 * This macro "eats" the part of the buffer which is definitely "consumed",
 * i.e. was correctly converted into local representation or rightfully skipped.
 */
#undef ADVANCE
#define ADVANCE(num_bytes)                \
    do {                                  \
        size_t num = num_bytes;           \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        if(ctx->left >= 0)                \
            ctx->left -= num;             \
        consumed_myself += num;           \
    } while(0)

/*
 * Switch to the next phase of parsing.
 */
#undef NEXT_PHASE
#define NEXT_PHASE(ctx)  \
    do {                 \
        ctx->phase++;    \
        ctx->step = 0;   \
    } while(0)
#undef PHASE_OUT
#define PHASE_OUT(ctx)    \
    do {                  \
        ctx->phase = 10;  \
    } while(0)

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

/*
 * X.680 25.6 and 52.7: the first unknown extension addition must not carry
 * a tag of the trailing OPTIONAL/DEFAULT run of the root components.
 */
static int
_tag_in_trailing_optionals(const asn_SEQUENCE_specifics_t *specs,
                           const asn_TYPE_member_t *elements,
                           ber_tlv_tag_t tlv_tag) {
    size_t i = (size_t)specs->first_extension;

    while(i > 0 && elements[i - 1].optional) {
        const asn_TYPE_member_t *m = &elements[--i];
        if(m->flags & (ATF_ANY_TYPE | ATF_OPEN_TYPE)) continue;
        if(m->tag != (ber_tlv_tag_t)-1) {
            if(BER_TAGS_EQUAL(tlv_tag, m->tag)) return 1;
        } else if(m->type->op->ber_decoder == CHOICE_decode_ber
                  && m->type->specifics) {
            const asn_CHOICE_specifics_t *cs =
                (const asn_CHOICE_specifics_t *)m->type->specifics;
            unsigned k;
            for(k = 0; k < cs->tag2el_count; k++)
                if(BER_TAGS_EQUAL(tlv_tag, cs->tag2el[k].el_tag)) return 1;
        }
    }
    return 0;
}

/*
 * Tags are canonically sorted in the tag2element map.
 */
static int
_t2e_cmp(const void *ap, const void *bp) {
    const asn_TYPE_tag2member_t *a = (const asn_TYPE_tag2member_t *)ap;
    const asn_TYPE_tag2member_t *b = (const asn_TYPE_tag2member_t *)bp;

    int a_class = BER_TAG_CLASS(a->el_tag);
    int b_class = BER_TAG_CLASS(b->el_tag);

    if(a_class == b_class) {
        ber_tlv_tag_t a_value = BER_TAG_VALUE(a->el_tag);
        ber_tlv_tag_t b_value = BER_TAG_VALUE(b->el_tag);

        if(a_value == b_value) {
            if(a->el_no > b->el_no)
                return 1;
            /*
             * Important: we do not check
             * for a->el_no <= b->el_no!
             */
            return 0;
        } else if(a_value < b_value)
            return -1;
        else
            return 1;
    } else if(a_class < b_class) {
        return -1;
    } else {
        return 1;
    }
}

/*
 * Purpose: test whether a BER tag belongs to one transparent group member.
 * Source: Extension-group child tag metadata emitted by asn1c.
 * Version: 2026-10-21.
 * Parameters: member is a parent descriptor entry; tag is the input BER tag.
 * Returns: nonzero when a child accepts tag, zero otherwise.
 * Errors: none; all reads follow compiler-generated descriptor bounds.
 * Author: asn1c maintainers.
 * History: Added to route flat SEQUENCE extension tags to group storage.
 * Example: [2] INTEGER matches an extension group containing a [2] child.
 */
static int
_sequence_group_has_tag(const asn_TYPE_member_t *member, ber_tlv_tag_t tag) {
	const asn_TYPE_descriptor_t *group_type = member->type;
	const asn_SEQUENCE_specifics_t *group_specs;
	unsigned i;

	if(!(member->flags & ATF_EXTENSION_GROUP) || !group_type->specifics)
		return 0;
	group_specs = (const asn_SEQUENCE_specifics_t *)group_type->specifics;
	if(!group_specs->extension_group) return 0;
	for(i = 0; i < group_type->elements_count; i++) {
		const asn_TYPE_member_t *child = &group_type->elements[i];
		if(child->flags & (ATF_ANY_TYPE | ATF_OPEN_TYPE)) return 1;
		if(child->tag != (ber_tlv_tag_t)-1
		&& BER_TAGS_EQUAL(tag, child->tag)) return 1;
		if(child->tag == (ber_tlv_tag_t)-1
		&& child->type->op->ber_decoder == CHOICE_decode_ber
		&& child->type->specifics) {
			const asn_CHOICE_specifics_t *choice_specs =
				(const asn_CHOICE_specifics_t *)child->type->specifics;
			unsigned j;
			for(j = 0; j < choice_specs->tag2el_count; j++) {
				if(BER_TAGS_EQUAL(tag, choice_specs->tag2el[j].el_tag))
					return 1;
			}
		}
	}
	return 0;
}

static int
_sequence_group_match_child(const asn_TYPE_descriptor_t *td, size_t first,
		ber_tlv_tag_t tag, size_t *matched);

/*
 * Purpose: determine whether all remaining group components may be absent.
 * Source: Generated ASN.1 optional-member run lengths.
 * Version: 2026-10-21.
 * Parameters: td is the group descriptor; first is the next member index.
 * Returns: nonzero if every component from first through the group end is
 *          optional, zero otherwise.
 * Errors: none; first is checked against the descriptor element count.
 * Author: asn1c maintainers.
 * History: Added for transparent BER group boundary detection.
 * Example: a remaining OPTIONAL tail may end before the parent's next field.
 */
static int
_sequence_group_optional_tail(const asn_TYPE_descriptor_t *td, size_t first) {
	const asn_TYPE_member_t *elements = td->elements;
	return first < td->elements_count
		&& elements[first].optional >= td->elements_count - first;
}

/*
 * Purpose: locate a group child by its leading BER tag or classify a boundary.
 * Source: X.690 TLV tags and the generated extension-group member table.
 * Version: 2026-10-21.
 * Parameters: td is the group descriptor; first is the next child index;
 *             ptr and available describe current bytes; left is the definite
 *             parent remainder or -1 for an indefinite parent; matched gets
 *             the selected child index on a match.
 * Returns: 1 for a match, 0 for a valid optional tail boundary, -1 for invalid
 *          mandatory content, or -2 when more bytes are required.
 * Errors: malformed tags and missing mandatory children return -1.
 * Author: asn1c maintainers.
 * History: Added to keep the body decoder's state machine bounded.
 * Example: an unmatched following parent field ends an all-optional group.
 */
static int
_sequence_group_probe(const asn_TYPE_descriptor_t *td, size_t first,
		const void *ptr, size_t available, ssize_t left, size_t *matched) {
	ber_tlv_tag_t tag;
	ssize_t tag_len;
	int optional_tail = _sequence_group_optional_tail(td, first);

	if(left == 0) return optional_tail ? 0 : -1;
	tag_len = ber_fetch_tag(ptr, available, &tag);
	if(tag_len == 0) return optional_tail && left == 0 ? 0 : -2;
	if(tag_len < 0) return -1;
	if(left < 0 && available >= 2
	&& ((const uint8_t *)ptr)[0] == 0
	&& ((const uint8_t *)ptr)[1] == 0)
		return optional_tail ? 0 : -1;
	if(left < 0 && available == 1 && ((const uint8_t *)ptr)[0] == 0)
		return -2;
	if(_sequence_group_match_child(td, first, tag, matched)) return 1;
	return optional_tail ? 0 : -1;
}

/*
 * Purpose: invoke one selected member decoder in transparent group storage.
 * Source: The standard SEQUENCE BER member dispatch convention.
 * Version: 2026-10-21.
 * Parameters: codec_ctx is the decoder context; td and st describe group;
 *             member is the selected child; ptr and available are input bytes.
 * Returns: the child decoder result, or RC_FAIL for an invalid descriptor.
 * Errors: allocation and child decode failures are returned to the caller.
 * Author: asn1c maintainers.
 * History: Extracted from the group body decoder to bound complexity.
 * Example: an OPTIONAL pointer child is allocated by its normal decoder.
 */
static asn_dec_rval_t
_sequence_group_decode_child(const asn_codec_ctx_t *codec_ctx,
		const asn_TYPE_descriptor_t *td, void *st,
		const asn_TYPE_member_t *member, const void *ptr, size_t available) {
	void *member_ptr;
	void **member_ptr2;
	if(member->flags & ATF_POINTER) {
		member_ptr2 = (void **)((char *)st + member->memb_offset);
	} else {
		member_ptr = (char *)st + member->memb_offset;
		member_ptr2 = &member_ptr;
	}
	if(member->flags & ATF_OPEN_TYPE)
		return OPEN_TYPE_ber_get(codec_ctx, td, st, member, ptr, available);
	return member->type->op->ber_decoder(codec_ctx, member->type,
			member_ptr2, ptr, available, member->tag_mode);
}

/*
 * Purpose: match the next group child using its BER tag and optional window.
 * Source: Generated descriptor tags and CHOICE tag maps.
 * Version: 2026-10-21.
 * Parameters: td is the group descriptor; first is next child; tag is input;
 *             matched receives the selected child index.
 * Returns: nonzero when a child in the permitted window accepts tag.
 * Errors: none; descriptor bounds are checked before reading child entries.
 * Author: asn1c maintainers.
 * History: Added for flat-wire SEQUENCE group dispatch.
 * Example: a CHOICE child matches any tag in its generated tag map.
 */
static int
_sequence_group_match_child(const asn_TYPE_descriptor_t *td, size_t first,
		ber_tlv_tag_t tag, size_t *matched) {
	const asn_TYPE_member_t *elements = td->elements;
	size_t end;
	size_t i;
	if(first >= td->elements_count) return 0;
	if(elements[first].optional >= td->elements_count - first - 1)
		end = td->elements_count;
	else
		end = first + elements[first].optional + 1;
	for(i = first; i < end; i++) {
		const asn_TYPE_member_t *member = &elements[i];
		if(member->flags & (ATF_ANY_TYPE | ATF_OPEN_TYPE)) {
			*matched = i;
			return 1;
		}
		if(member->tag != (ber_tlv_tag_t)-1
		&& BER_TAGS_EQUAL(tag, member->tag)) {
			*matched = i;
			return 1;
		}
		if(member->tag == (ber_tlv_tag_t)-1
		&& member->type->op->ber_decoder == CHOICE_decode_ber
		&& member->type->specifics) {
			const asn_CHOICE_specifics_t *cs =
				(const asn_CHOICE_specifics_t *)member->type->specifics;
			unsigned j;
			for(j = 0; j < cs->tag2el_count; j++) {
				if(BER_TAGS_EQUAL(tag, cs->tag2el[j].el_tag)) {
					*matched = i;
					return 1;
				}
			}
		}
	}
	return 0;
}

/*
 * Purpose: decode the flat BER body of one SEQUENCE extension addition group.
 * Source: X.690 component TLV handling with the generated group member table.
 * Version: 2026-10-21.
 * Parameters: codec_ctx is the active decoder context; td and struct_ptr name
 *             group descriptor/storage; ptr and size are available input;
 *             parent_left bounds a definite parent SEQUENCE frame.
 * Returns: RC_OK when the group body is complete, RC_WMORE for more input,
 *          or RC_FAIL for malformed/truncated mandatory group content.
 * Errors: allocation or child decoder failures return RC_FAIL.
 * Author: asn1c maintainers.
 * History: Added to decode group leaves without an artificial SEQUENCE TLV.
 * Example: consecutive [2] and [3] child TLVs populate one group pointer.
 */
static asn_dec_rval_t
_sequence_decode_group_ber(const asn_codec_ctx_t *codec_ctx,
		const asn_TYPE_descriptor_t *td, void **struct_ptr,
		const void *ptr, size_t size, ssize_t parent_left) {
	const asn_SEQUENCE_specifics_t *specs =
		(const asn_SEQUENCE_specifics_t *)td->specifics;
	const asn_TYPE_member_t *elements = td->elements;
	void *st = *struct_ptr;
	asn_struct_ctx_t *ctx;
	size_t consumed = 0;
	asn_dec_rval_t rval = {RC_FAIL, 0};

#define GROUP_RETURN(_group_code) do { rval.code = (_group_code); \
		rval.consumed = consumed; return rval; } while(0)
#define GROUP_LEFT() ((ctx->left >= 0 && (size_t)ctx->left < size) \
		? (size_t)ctx->left : size)
#define GROUP_ADVANCE(nbytes) do { size_t n_ = (nbytes); \
		ptr = (const char *)ptr + n_; size -= n_; consumed += n_; \
		if(ctx->left >= 0) ctx->left -= (ber_tlv_len_t)n_; } while(0)

	if(!specs->extension_group || td->elements_count == 0)
		GROUP_RETURN(RC_FAIL);
	if(st == 0) {
		st = *struct_ptr = CALLOC(1, specs->struct_size);
		if(st == 0) GROUP_RETURN(RC_FAIL);
	}
	ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
	if(ASN__STACK_OVERFLOW_CHECK(codec_ctx)) GROUP_RETURN(RC_FAIL);
	if(ctx->phase == 0) {
		ctx->left = parent_left;
		ctx->phase = 1;
	}
	if(ctx->phase != 1) GROUP_RETURN(RC_FAIL);

	while(((size_t)ctx->step >> 1) < td->elements_count) {
		size_t first = (size_t)ctx->step >> 1;
		size_t selected;
		int resume_child = (ctx->step & 1) != 0; /* state variable */
		size_t available = GROUP_LEFT();
		const asn_TYPE_member_t *member;
		int probe;

		if(resume_child && ctx->left == 0) GROUP_RETURN(RC_FAIL);
		if(resume_child) {
			selected = first;
		} else {
			probe = _sequence_group_probe(td, first, ptr, available,
					ctx->left, &selected);
			if(probe == 0) GROUP_RETURN(RC_OK);
			if(probe == -2) GROUP_RETURN(RC_WMORE);
			if(probe < 0) GROUP_RETURN(RC_FAIL);
		}
		member = &elements[selected];
		ctx->step = (unsigned)(2 * selected + 1);
		rval = _sequence_group_decode_child(codec_ctx, td, st, member,
				ptr, available);
		if(rval.consumed > available)
			GROUP_RETURN(RC_FAIL);
		if(rval.code == RC_WMORE) {
			GROUP_ADVANCE(rval.consumed);
			if(ctx->left == 0) GROUP_RETURN(RC_FAIL);
			GROUP_RETURN(RC_WMORE);
		}
		if(rval.code != RC_OK || rval.consumed == 0)
			GROUP_RETURN(RC_FAIL);
		GROUP_ADVANCE(rval.consumed);
		ctx->step = (unsigned)(2 * selected + 2);
	}
	ctx->phase = 10;
	GROUP_RETURN(RC_OK);

#undef GROUP_ADVANCE
#undef GROUP_LEFT
#undef GROUP_RETURN
}

/*
 * The decoder of the SEQUENCE type.
 */
asn_dec_rval_t
SEQUENCE_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td, void **struct_ptr,
                    const void *ptr, size_t size, int tag_mode) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SEQUENCE_specifics_t *specs = (const asn_SEQUENCE_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elements = td->elements;

    /*
     * Parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    ber_tlv_tag_t tlv_tag;  /* T from TLV */
    asn_dec_rval_t rval;    /* Return code from subparsers */

    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    size_t edx;  /* SEQUENCE element's index */

    ASN_DEBUG("Decoding %s as SEQUENCE", td->name);

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) {
            RETURN(RC_FAIL);
        }
    }

    /*
     * Restore parsing context.
     */
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

	/*
     * Check recursion depth to prevent stack overflow from circular references,
     * using ctx->step 
	 */
    ASN__DECODER_RECURSION_DEPTH_CHECK(opt_codec_ctx);

    /*
     * Start to parse where left previously
     */
    switch(ctx->phase) {
    case 0:
        /*
         * PHASE 0.
         * Check that the set of tags associated with given structure
         * perfectly fits our expectations.
         */

        rval = ber_check_tags(opt_codec_ctx, td, ctx, ptr, size,
                              tag_mode, 1, &ctx->left, 0);
        if(rval.code != RC_OK) {
            ASN_DEBUG("%s tagging check failed: %d",
                      td->name, rval.code);
            return rval;
        }

        if(ctx->left >= 0)
            ctx->left += rval.consumed;  /* ?Subtracted below! */
        ADVANCE(rval.consumed);

        NEXT_PHASE(ctx);

        ASN_DEBUG("Structure consumes %ld bytes, buffer %ld",
                  (long)ctx->left, (long)size);

        /* Fall through */
    case 1:
        /*
         * PHASE 1.
         * From the place where we've left it previously,
         * try to decode the next member from the list of
         * this structure's elements.
         * (ctx->step) stores the member being processed
         * between invocations and the microphase {0,1} of parsing
         * that member:
         *     step = (<member_number> * 2 + <microphase>).
         */
        for(edx = ((size_t)ctx->step >> 1); edx < td->elements_count;
                edx++, ctx->step = (ctx->step & ~1) + 2) {
            void *memb_ptr;      /* Pointer to the member */
            void **memb_ptr2;    /* Pointer to that pointer */
            ssize_t tag_len;     /* Length of TLV's T */
            size_t opt_edx_end;  /* Next non-optional element */
            size_t opt_edx_end_full;
            size_t n;
            int use_bsearch;

            if(ctx->step & 1)
                goto microphase2;

            /*
             * MICROPHASE 1: Synchronize decoding.
             */
            ASN_DEBUG("In %s SEQUENCE left %d, edx=%" ASN_PRI_SIZE " flags=%d"
                      " opt=%d ec=%d",
                      td->name, (int)ctx->left, edx,
                      elements[edx].flags, elements[edx].optional,
                      td->elements_count);

            if(ctx->left == 0 /* No more stuff is expected */
               && !((ctx->step & 1)
                    && (elements[edx].flags & ATF_EXTENSION_GROUP))
               && (
                      /* Explicit OPTIONAL specification reaches the end */
                      (edx + elements[edx].optional == td->elements_count) ||
                      /* All extensions are optional */
                      IN_EXTENSION_GROUP(specs, edx))) {
                ASN_DEBUG("End of SEQUENCE %s", td->name);
                /*
                 * Found the legitimate end of the structure.
                 */
                PHASE_OUT(ctx);
                RETURN(RC_OK);
            }

            /*
             * Fetch the T from TLV.
             */
            tag_len = ber_fetch_tag(ptr, LEFT, &tlv_tag);
            ASN_DEBUG("Current tag in %s SEQUENCE for element %" ASN_PRI_SIZE " "
                      "(%s) is %s encoded in %d bytes, of frame %ld",
                      td->name, edx, elements[edx].name,
                      ber_tlv_tag_string(tlv_tag), (int)tag_len, (long)LEFT);
            switch(tag_len) {
            case 0: if(!SIZE_VIOLATION) RETURN(RC_WMORE);
                /* Fall through */
            case -1: RETURN(RC_FAIL);
            }

            if(ctx->left < 0 && ((const uint8_t *)ptr)[0] == 0) {
                if(LEFT < 2) {
                    if(SIZE_VIOLATION) {
                        RETURN(RC_FAIL);
                    } else {
                        RETURN(RC_WMORE);
                    }
                } else if(((const uint8_t *)ptr)[1] == 0) {
                    if((elements[edx].flags & ATF_EXTENSION_GROUP)
					&& edx + elements[edx].optional ==
						td->elements_count) {
						PHASE_OUT(ctx);
						RETURN(RC_OK);
					}
                    ASN_DEBUG("edx = %" ASN_PRI_SIZE ", opt = %d, ec=%d", edx,
                              elements[edx].optional, td->elements_count);
                    if((edx + elements[edx].optional == td->elements_count)
                       || IN_EXTENSION_GROUP(specs, edx)) {
                        /*
                         * Yeah, baby! Found the terminator
                         * of the indefinite length structure.
                         */
                        /*
                         * Proceed to the canonical
                         * finalization function.
                         * No advancing is necessary.
                         */
                        goto phase3;
                    }
                }
            }

            /*
             * Find the next available type with this tag.
             */
            use_bsearch = 0;
            opt_edx_end_full = edx + elements[edx].optional + 1;
            if(opt_edx_end_full > td->elements_count)
                opt_edx_end_full = td->elements_count;
            opt_edx_end = opt_edx_end_full;
            if(opt_edx_end - edx > 8) {
                /* Limit the scope of linear search... */
                opt_edx_end = edx + 8;
                use_bsearch = 1;
                /* ... and resort to bsearch() */
            }
            for(n = edx; n < opt_edx_end; n++) {
                if((elements[n].flags & ATF_EXTENSION_GROUP)
				&& _sequence_group_has_tag(&elements[n], tlv_tag)) {
					edx = n;
					ctx->step = 1 + 2 * edx;
					goto microphase2;
				} else if(!(elements[n].flags & ATF_EXTENSION_GROUP)
				&& BER_TAGS_EQUAL(tlv_tag, elements[n].tag)) {
                    /*
                     * Found element corresponding to the tag
                     * being looked at.
                     * Reposition over the right element.
                     */
                    edx = n;
                    ctx->step = 1 + 2 * edx;  /* Remember! */
                    goto microphase2;
                } else if(elements[n].flags & ATF_ANY_TYPE) {
                    /*
                     * This is the ANY type, which may bear
                     * any flag whatsoever.
                     */
                    edx = n;
                    ctx->step = 1 + 2 * edx;  /* Remember! */
                    goto microphase2;
                } else if(elements[n].flags & ATF_OPEN_TYPE) {
                    /*
                     * This is the OPEN TYPE, which may bear
                     * any tag whatsoever.
                     */
                    edx = n;
                    ctx->step = 1 + 2 * edx;  /* Remember! */
                    goto microphase2;
                } else if(elements[n].tag == (ber_tlv_tag_t)-1) {
                    use_bsearch = 1;
                    break;
                }
            }
            if(use_bsearch) {
				/* A group leaf maps to its wrapper, not the nested descriptor. */
				for(n = edx; n < opt_edx_end_full; n++) {
					if(_sequence_group_has_tag(&elements[n], tlv_tag)) {
						edx = n;
						ctx->step = 1 + 2 * edx;
						goto microphase2;
					}
				}
                /*
                 * Resort to a binary search over
                 * sorted array of tags.
                 */
                const asn_TYPE_tag2member_t *t2m;
                asn_TYPE_tag2member_t key = {0, 0, 0, 0};
                key.el_tag = tlv_tag;
                key.el_no = edx;
                t2m = (const asn_TYPE_tag2member_t *)bsearch(&key,
                       specs->tag2el, specs->tag2el_count,
                       sizeof(specs->tag2el[0]), _t2e_cmp);
                if(t2m) {
                    const asn_TYPE_tag2member_t *best = 0;
                    const asn_TYPE_tag2member_t *t2m_f, *t2m_l;
                    size_t edx_max = edx + elements[edx].optional;
                    /*
                     * Rewind to the first element with that tag,
                     * `cause bsearch() does not guarantee order.
                     */
                    t2m_f = t2m + t2m->toff_first;
                    t2m_l = t2m + t2m->toff_last;
                    for(t2m = t2m_f; t2m <= t2m_l; t2m++) {
                        if(t2m->el_no > edx_max) break;
                        if(t2m->el_no < edx) continue;
                        if(t2m->el_no >= td->elements_count) continue;
                        if((elements[t2m->el_no].flags
							& ATF_EXTENSION_GROUP)
						&& !_sequence_group_has_tag(
								&elements[t2m->el_no], tlv_tag))
							continue;
                        best = t2m;
                    }
                    if(best) {
                        edx = best->el_no;
                        ctx->step = 1 + 2 * edx;
                        goto microphase2;
                    }
                }
                n = opt_edx_end;
            }
            if(n == opt_edx_end) {
                /*
                 * If tag is unknown, it may be either
                 * an unknown (thus, incorrect) tag,
                 * or an extension (...),
                 * or an end of the indefinite-length structure.
                 */
                if(!IN_EXTENSION_GROUP(specs,
                    edx + elements[edx].optional)) {
                    ASN_DEBUG("Unexpected tag %s (at %" ASN_PRI_SIZE ")",
                              ber_tlv_tag_string(tlv_tag), edx);
                    ASN_DEBUG("Expected tag %s (%s)%s",
                              ber_tlv_tag_string(elements[edx].tag),
                              elements[edx].name,
                              elements[edx].optional ?" or alternatives":"");
                    RETURN(RC_FAIL);
                } else {
                    /* Skip this tag */
                    ssize_t skip;
                    edx += elements[edx].optional;

                    if(!ctx->context
                       && edx == (size_t)specs->first_extension
                       && _tag_in_trailing_optionals(specs, elements,
                                                     tlv_tag)) {
                        ASN_DEBUG("Tag %s repeats a component before the "
                                  "extension marker in %s",
                                  ber_tlv_tag_string(tlv_tag), td->name);
                        RETURN(RC_FAIL);
                    }
                    ctx->context = 1;  /* First extension addition seen */

                    ASN_DEBUG("Skipping unexpected %s (at %" ASN_PRI_SIZE ")",
                              ber_tlv_tag_string(tlv_tag), edx);
                    skip = ber_skip_length(opt_codec_ctx,
                                           BER_TLV_CONSTRUCTED(ptr),
                                           (const char *)ptr + tag_len,
                                           LEFT - tag_len);
                    ASN_DEBUG("Skip length %d in %s",
                              (int)skip, td->name);
                    switch(skip) {
                    case 0: if(!SIZE_VIOLATION) RETURN(RC_WMORE);
                        /* Fall through */
                    case -1: RETURN(RC_FAIL);
                    }

                    ADVANCE(skip + tag_len);
                    ctx->step -= 2;
                    edx--;
                    continue;  /* Try again with the next tag */
                }
            }

            /*
             * MICROPHASE 2: Invoke the member-specific decoder.
             */
            ctx->step |= 1;  /* Confirm entering next microphase */
        microphase2:
            ASN_DEBUG("Inside SEQUENCE %s MF2", td->name);

            /*
             * Compute the position of the member inside a structure,
             * and also a type of containment (it may be contained
             * as pointer or using inline inclusion).
             */
            if(elements[edx].flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st + elements[edx].memb_offset);
            } else {
                /*
                 * A pointer to a pointer
                 * holding the start of the structure
                 */
                memb_ptr = (char *)st + elements[edx].memb_offset;
                memb_ptr2 = &memb_ptr;
            }
            /*
             * Invoke the member fetch routine according to member's type
             */
            if(elements[edx].flags & ATF_OPEN_TYPE) {
                rval = OPEN_TYPE_ber_get(opt_codec_ctx, td, st, &elements[edx], ptr, LEFT);
			} else if(elements[edx].flags & ATF_EXTENSION_GROUP) {
				rval = _sequence_decode_group_ber(opt_codec_ctx,
						elements[edx].type, memb_ptr2, ptr, LEFT,
						ctx->left);
            } else {
	            rval = elements[edx].type->op->ber_decoder(opt_codec_ctx, elements[edx].type,
	                                                       memb_ptr2, ptr, LEFT,
	                                                       elements[edx].tag_mode);
            }
            
            ASN_DEBUG("In %s SEQUENCE decoded %" ASN_PRI_SIZE " %s of %d "
                      "in %d bytes rval.code %d, size=%d",
                      td->name, edx, elements[edx].type->name,
                      (int)LEFT, (int)rval.consumed, rval.code, (int)size);
            switch(rval.code) {
            case RC_OK:
                break;
            case RC_WMORE: /* More data expected */
                if(!SIZE_VIOLATION) {
                    ADVANCE(rval.consumed);
                    RETURN(RC_WMORE);
                }
                ASN_DEBUG("Size violation (c->l=%ld <= s=%ld)",
                          (long)ctx->left, (long)size);
                /* Fall through */
            case RC_FAIL: /* Fatal error */
                RETURN(RC_FAIL);
        } /* switch(rval) */

        ADVANCE(rval.consumed);
    }  /* for(all structure members) */

    phase3:
        ctx->phase = 3;
        /* Fall through */
    case 3:  /* 00 and other tags expected */
    case 4:  /* only 00's expected */

        ASN_DEBUG("SEQUENCE %s Leftover: %ld, size = %ld",
                  td->name, (long)ctx->left, (long)size);

        /*
         * Skip everything until the end of the SEQUENCE.
         */
        while(ctx->left) {
            ssize_t tl, ll;

            tl = ber_fetch_tag(ptr, LEFT, &tlv_tag);
            switch(tl) {
            case 0: if(!SIZE_VIOLATION) RETURN(RC_WMORE);
                /* Fall through */
            case -1: RETURN(RC_FAIL);
            }

            /*
             * If expected <0><0>...
             */
            if(ctx->left < 0 && ((const uint8_t *)ptr)[0] == 0) {
                if(LEFT < 2) {
                    if(SIZE_VIOLATION)
                        RETURN(RC_FAIL);
                    else
                        RETURN(RC_WMORE);
                } else if(((const uint8_t *)ptr)[1] == 0) {
                    /*
                     * Correctly finished with <0><0>.
                     */
                    ADVANCE(2);
                    ctx->left++;
                    ctx->phase = 4;
                    continue;
                }
            }

            if(!IN_EXTENSION_GROUP(specs, td->elements_count)
            || ctx->phase == 4) {
                ASN_DEBUG("Unexpected continuation "
                          "of a non-extensible type "
                          "%s (SEQUENCE): %s",
                          td->name,
                          ber_tlv_tag_string(tlv_tag));
                RETURN(RC_FAIL);
            }

            if(!ctx->context && specs->first_extension >= 0
               && _tag_in_trailing_optionals(specs, elements, tlv_tag)) {
                ASN_DEBUG("Tag %s repeats a component before the "
                          "extension marker in %s",
                          ber_tlv_tag_string(tlv_tag), td->name);
                RETURN(RC_FAIL);
            }
            ctx->context = 1;  /* First extension addition seen */

            ll = ber_skip_length(opt_codec_ctx,
                                 BER_TLV_CONSTRUCTED(ptr),
                                 (const char *)ptr + tl, LEFT - tl);
            switch(ll) {
            case 0: if(!SIZE_VIOLATION) RETURN(RC_WMORE);
                /* Fall through */
            case -1: RETURN(RC_FAIL);
            }

            ADVANCE(tl + ll);
        }

        PHASE_OUT(ctx);
    }

    RETURN(RC_OK);
}


/*
 * The DER encoder of the SEQUENCE type.
 */
/*
 * Purpose: emit the constructed wrapper unless this descriptor is a flat group.
 * Source: X.690 DER tag emission for SEQUENCE values.
 * Version: 2026-10-21.
 * Parameters: td describes the SEQUENCE; remaining arguments are forwarded to
 *             der_write_tags when an ordinary SEQUENCE wrapper is required.
 * Returns: emitted tag byte count, zero for a transparent extension group,
 *          or -1 on encoding failure.
 * Errors: reports a tag encoder failure as -1.
 * Author: asn1c maintainers.
 * History: Added to encode extension-group contents without a wrapper TLV.
 * Example: a marked group contributes only its child TLVs to its parent.
 */
static ssize_t
_sequence_der_write_tags(const asn_TYPE_descriptor_t *td,
		size_t computed_size, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	const asn_SEQUENCE_specifics_t *specs =
		(const asn_SEQUENCE_specifics_t *)td->specifics;
	if(specs && specs->extension_group) return 0;
	return der_write_tags(td, computed_size, tag_mode, 1, tag, cb, app_key);
}

/*
 * Purpose: add an encoded length only when the signed DER result can hold it.
 * Source: DER encoder length accounting for constructed values.
 * Version: 2026-10-21.
 * Parameters: sum is the current size; amount is a child or tag byte count.
 * Returns: zero on success, -1 for negative input or project size overflow.
 * Errors: reports values above RSSIZE_MAX as an encoding failure.
 * Author: asn1c maintainers.
 * History: added for checked extension-group and sequence size accumulation.
 * Example: _sequence_der_add_size(&total, child_result.encoded);
 */
static int
_sequence_der_add_size(size_t *sum, ssize_t amount) {
	if(*sum > (size_t)RSSIZE_MAX || amount < 0
	|| (size_t)amount > (size_t)RSSIZE_MAX - *sum)
		return -1;
	*sum += (size_t)amount;
	return 0;
}

/*
 * Purpose: resolve one SEQUENCE member and decide whether DER should encode it.
 * Source: Existing SEQUENCE pointer/default handling, shared by both DER passes.
 * Version: 2026-10-21.
 * Parameters: sptr is the value; elm and index select a member;
 *             value receives its inline or pointed-to storage address.
 * Returns: 1 when present, 0 when optional/defaulted, or -1 when mandatory data
 *          is missing.
 * Errors: none; caller reports an absent mandatory member as encode failure.
 * Author: asn1c maintainers.
 * History: extracted to bound DER encoder complexity and unify both passes.
 * Example: sizing and emission both skip the same absent/defaulted member.
 */
static int
_sequence_der_resolve_member(const void *sptr, const asn_TYPE_member_t *elm,
		size_t index,
		const void **value) {
	const void *member_value;

	if(elm->flags & ATF_POINTER) {
		const void *const *member_pointer =
			(const void *const *)((const char *)sptr + elm->memb_offset);
		member_value = *member_pointer;
		if(!member_value) {
			ASN_DEBUG("Element %s %" ASN_PRI_SIZE " not present",
				  elm->name, index);
			return elm->optional ? 0 : -1;
		}
	} else {
		member_value = (const char *)sptr + elm->memb_offset;
	}
	if(elm->default_value_cmp && elm->default_value_cmp(member_value) == 0)
		return 0;
	*value = member_value;
	return 1;
}

/*
 * Purpose: encode a SEQUENCE, flattening only synthetic extension-group bodies.
 * Source: X.690 DER SEQUENCE encoding with extension-group metadata.
 * Version: 2026-10-21.
 * Parameters: td is the descriptor; sptr is the value; tag_mode and tag select
 *             the outer tag; cb and app_key receive encoded bytes.
 * Returns: encoded byte count or -1 on failure.
 * Errors: propagates child errors and rejects missing mandatory fields or size
 *         overflow; recursion depth is restored on every post-increment exit.
 * Author: asn1c maintainers.
 * History: added transparent group bodies while preserving DER tag behavior.
 * Example: der_encode_to_buffer(&asn_DEF_Rec, &value, out, sizeof(out)).
 */
asn_enc_rval_t
SEQUENCE_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int tag_mode, ber_tlv_tag_t tag,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    size_t computed_size = 0;
    size_t total_size;
    asn_enc_rval_t erval = {0,0,0};
    ssize_t ret;
    size_t edx;

    ASN_DEBUG("%s %s as SEQUENCE",
              cb?"Encoding":"Estimating", td->name);

    if(!sptr) ASN__ENCODE_FAILED;

    /* Check encoding recursion depth to prevent stack overflow */
    ASN__ENCODER_RECURSION_DEPTH_INC();

    /*
     * Gather the length of the underlying members sequence.
     */
    for(edx = 0; edx < td->elements_count; edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *member_value = NULL;
        int member_state = _sequence_der_resolve_member(sptr, elm, edx,
										  &member_value);

		if(member_state < 0) {
			ASN__ENCODER_RECURSION_DEPTH_DEC();
			ASN__ENCODE_FAILED;
		}
		if(member_state == 0) continue;

        if(elm->flags & ATF_OPEN_TYPE) {
            erval = OPEN_TYPE_ber_put(td, sptr, elm,
                                      elm->tag_mode, elm->tag,
                                      0, 0); /* NULL callback for size estimation */
		} else {
			    erval = elm->type->op->der_encoder(elm->type, member_value,
	                                           elm->tag_mode, elm->tag,
	                                           0, 0);  /* NULL callback for size estimation */
        }

        if(erval.encoded < 0) {
            ASN__ENCODER_RECURSION_DEPTH_DEC();
            return erval;
        }
        if(_sequence_der_add_size(&computed_size, erval.encoded)) {
            ASN__ENCODER_RECURSION_DEPTH_DEC();
            ASN__ENCODE_FAILED;
        }
        ASN_DEBUG("Member %" ASN_PRI_SIZE " %s estimated %ld bytes",
                  edx, elm->name, (long)erval.encoded);
    }

    /*
     * Encode the TLV for the sequence itself.
     */
    ret = _sequence_der_write_tags(td, computed_size, tag_mode, tag,
			cb, app_key);
    ASN_DEBUG("Wrote tags: %ld (+%ld)", (long)ret, (long)computed_size);
    if(ret < 0) {
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }
    total_size = computed_size;
    if(_sequence_der_add_size(&total_size, ret)) {
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }
    erval.encoded = total_size;

    if(!cb) {
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODED_OK(erval);
    }

    /*
     * Encode all members.
     */
    for(edx = 0; edx < td->elements_count; edx++) {
        asn_TYPE_member_t *elm = &td->elements[edx];
        asn_enc_rval_t tmperval = {0,0,0};
        const void *member_value = NULL;
        int member_state = _sequence_der_resolve_member(sptr, elm, edx,
										  &member_value);

		if(member_state < 0) {
			ASN__ENCODER_RECURSION_DEPTH_DEC();
			ASN__ENCODE_FAILED;
		}
		if(member_state == 0) continue;

        if(elm->flags & ATF_OPEN_TYPE) {
            tmperval = OPEN_TYPE_ber_put(td, sptr, elm,
                                         elm->tag_mode, elm->tag, cb, app_key);
        } else {
            tmperval = elm->type->op->der_encoder(elm->type, member_value,
                                                  elm->tag_mode, elm->tag, cb, app_key);
        }

       
        if(tmperval.encoded < 0) {
            ASN__ENCODER_RECURSION_DEPTH_DEC();
            return tmperval;
        }

        if(computed_size < (size_t)tmperval.encoded) {
	        /* This should never happen if estimation and encoding are consistent */
	        ASN_DEBUG("Size mismatch: computed_size=%zu < tmperval.encoded=%zd for element %s",
	                  computed_size, tmperval.encoded, elm->name);
	        ASN__ENCODER_RECURSION_DEPTH_DEC();
	        ASN__ENCODE_FAILED;
        }
        
        computed_size -= tmperval.encoded;
        ASN_DEBUG("Member %" ASN_PRI_SIZE " %s of SEQUENCE %s encoded in %ld bytes",
                  edx, elm->name, td->name, (long)tmperval.encoded);
    }

    if(computed_size != 0) {
        /*
         * Encoded size is not equal to the computed size.
         */
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }

    ASN__ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODED_OK(erval);
}
