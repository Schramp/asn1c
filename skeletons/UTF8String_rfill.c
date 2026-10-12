/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <UTF8String.h>

/*
 * Select a valid UTF-8 sequence biased toward code point boundaries.
 * Original source: Existing asn1c random-fill helper.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: b receives bytes; size is the available maximum sequence width.
 * Returns: The number of bytes written, or zero when size is zero.
 * Errors: No allocation or exceptions; the caller supplies at least four bytes.
 * Responsible party: asn1c maintainers. History: Documented for CER closure.
 * Example: UTF8String__random_char(buffer, 4) returns a valid 1-4 byte sequence.
 */
static size_t
UTF8String__random_char(uint8_t *b, size_t size) {
    /* Struct describing one known-valid sample sequence and its byte width. */
    static const struct rnd_value {
        const char *value; /* Sample UTF-8 bytes, including embedded NUL if any. */
        size_t size; /* Number of bytes to copy from value. */
    } values[] = {{"\0", 1},
                  {"\x01", 1},
                  {"\x7f", 1},
                  {"\xc2\xa2", 2},
                  {"\xe2\x82\xac", 3},
                  {"\xf0\x90\x8d\x88", 4},
                  {"\xf4\x8f\xbf\xbf", 4}};

    const struct rnd_value *v;
    size_t max_idx = 0;

    switch(size) {
    case 0:
        return 0;
    case 1:
        max_idx = 2;
        break;
    case 2:
        max_idx = 3;
        break;
    default:
    case 4:
        max_idx = sizeof(values) / sizeof(values[0]) - 1;
        break;
    }

    v = &values[asn_random_between(0, max_idx)];
    memcpy(b, v->value, v->size);
    return v->size;
}

/*
 * Encode one Unicode scalar value into a UTF-8 byte sequence.
 * Original source: Existing asn1c random-fill helper.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: b receives output bytes; code is a candidate Unicode code point.
 * Returns: Number of UTF-8 bytes written; invalid scalar values use U+FFFD.
 * Errors: No allocation or exceptions; b must have four writable bytes.
 * Responsible party: asn1c maintainers. History: Documented for CER closure.
 * Example: UTF8String__encode_codepoint(buffer, 0x20ac) writes three bytes.
 */
static size_t
UTF8String__encode_codepoint(uint8_t *b, uint32_t code) {
    if(code <= 0x7f) {
        b[0] = code;
        return 1;
    } else if(code <= 0x7ff) {
        b[0] = 0xc0 | (code >> 6);
        b[1] = 0x80 | (code & 0x3f);
        return 2;
    } else if(code >= 0xd800 && code <= 0xdfff) {
        /* Surrogate code points are not valid Unicode scalar values. */
        return UTF8String__encode_codepoint(b, 0xfffd);
    } else if(code <= 0xffff) {
        b[0] = 0xe0 | (code >> 12);
        b[1] = 0x80 | ((code >> 6) & 0x3f);
        b[2] = 0x80 | (code & 0x3f);
        return 3;
    } else if(code <= 0x10ffff) {
        b[0] = 0xf0 | (code >> 18);
        b[1] = 0x80 | ((code >> 12) & 0x3f);
        b[2] = 0x80 | ((code >> 6) & 0x3f);
        b[3] = 0x80 | (code & 0x3f);
        return 4;
    } else {
        return UTF8String__encode_codepoint(b, 0x10ffff);
    }
}

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
/*
 * Select caller-provided PER constraints or the descriptor's constraints.
 * Original source: Existing asn1c random-fill helper.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td supplies defaults; constraints optionally override them.
 * Returns: Selected PER constraints or NULL when neither source has any.
 * Errors: No allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Guarded for CER-only builds.
 * Example: used by UTF8String_random_fill() when a PER codec is enabled.
 */
static const asn_per_constraints_t *
UTF8String__per_constraints(const asn_TYPE_descriptor_t *td,
                            const asn_encoding_constraints_t *constraints) {
    if(constraints && constraints->per_constraints)
        return constraints->per_constraints;
    if(td->encoding_constraints.per_constraints)
        return td->encoding_constraints.per_constraints;
    return 0;
}
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */

/*
 * State used to choose code points under optional PER alphabet constraints.
 */
typedef struct UTF8String_rfill_config_s {
    uint32_t value_lb; /* state variable: lowest permitted code point. */
    uint32_t value_ub; /* state variable: highest permitted code point. */
    int has_value_constraint; /* state variable: whether bounds are active. */
    int force_single_octets; /* state variable: whether generated chars stay ASCII. */
} UTF8String_rfill_config_t;

/*
 * Derive code-point and byte-width choices from active PER constraints.
 * Original source: Existing asn1c random-fill policy, refactored 2026-10-11.
 * Parameters: td/constraints supply PER bounds; config receives generation state.
 * Returns: No value; config is initialized even when PER support is disabled.
 * Errors: None; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Split to bound complexity.
 * Example: called once before generating randomized UTF-8 content.
 */
static void
UTF8String__configure_rfill(const asn_TYPE_descriptor_t *td,
                            const asn_encoding_constraints_t *constraints,
                            UTF8String_rfill_config_t *config) {
    config->value_lb = 0;
    config->value_ub = 0x7f;
    config->has_value_constraint = 0;
    config->force_single_octets = 0;
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
    {
        const asn_per_constraints_t *pc =
            UTF8String__per_constraints(td, constraints);
        if(pc) {
            if((pc->value.flags & APC_CONSTRAINED) &&
               pc->value.lower_bound >= 0 &&
               pc->value.lower_bound <= pc->value.upper_bound &&
               pc->value.lower_bound <= 0x10ffff) {
                config->value_lb = (uint32_t)pc->value.lower_bound;
                config->value_ub = pc->value.upper_bound > 0x10ffff
                    ? 0x10ffff : (uint32_t)pc->value.upper_bound;
                config->has_value_constraint = 1;
            }
            if(pc->size.flags & APC_CONSTRAINED) {
                config->force_single_octets = 1;
            }
        }
    }
#else
    (void)td;
    (void)constraints;
#endif
    if(config->has_value_constraint && config->force_single_octets) {
        if(config->value_lb > 0x7f) {
            config->force_single_octets = 0;
        } else if(config->value_ub > 0x7f) {
            config->value_ub = 0x7f;
        }
    }
}

/*
 * Fill a preallocated buffer with valid randomized UTF-8 characters.
 * Original source: Existing asn1c random-fill loop, refactored 2026-10-11.
 * Parameters: buf has four bytes per character plus a terminator; count selects
 *   the character count; config contains optional code-point bounds.
 * Returns: The address of the generated NUL terminator.
 * Errors: No allocation or exceptions; caller allocates a sufficiently large buf.
 * Responsible party: asn1c maintainers. History: Split to bound complexity.
 * Example: called after CALLOC(4, count + 1).
 */
static uint8_t *
UTF8String__generate_rfill(uint8_t *buf, size_t count,
                           const UTF8String_rfill_config_t *config) {
    uint8_t *b = buf; /* state variable: next output byte. */
    uint8_t *bend = &buf[4 * count]; /* state variable: maximum output boundary. */
    size_t idx; /* state variable: number of characters produced. */

    for(idx = 0; idx < count; idx++) {
        if(config->has_value_constraint) {
            uint32_t code = (uint32_t)asn_random_between(config->value_lb,
                                                          config->value_ub);
            b += UTF8String__encode_codepoint(b, code);
        } else if(config->force_single_octets) {
            b += UTF8String__random_char(b, 1);
        } else {
            b += UTF8String__random_char(b, (size_t)(bend - b));
        }
    }
    *b = 0;
    return b;
}

/*
 * Install generated bytes into existing or newly allocated UTF8String storage.
 * Original source: Existing asn1c random-fill ownership path.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: sptr is the value slot; buf is owned generated storage; end marks
 *   the terminator; count is the generated character count.
 * Returns: 0 after transfer, -1 if a value structure cannot be allocated.
 * Errors: Allocation failure returns -1 and frees buf; no exceptions.
 * Responsible party: asn1c maintainers. History: Split to bound complexity.
 * Example: called after UTF8String__generate_rfill().
 */
static int
UTF8String__install_rfill(void **sptr, uint8_t *buf, uint8_t *end,
                          size_t count) {
    UTF8String_t *st;

    if(*sptr) {
        st = *sptr;
        FREEMEM(st->buf);
    } else {
        st = (UTF8String_t *)CALLOC(1, sizeof(*st));
        if(!st) {
            FREEMEM(buf);
            return -1;
        }
        *sptr = st;
    }
    st->buf = buf;
    st->size = (size_t)(end - buf);
    assert(UTF8String_length(st) == (ssize_t)count);
    return 0;
}

/*
 * Create a randomized UTF-8 value satisfying available PER alphabet bounds.
 * Original source: Existing asn1c random-fill implementation.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td describes UTF8String; sptr receives/reuses its value;
 *   constraints supplies optional bounds; max_length limits generated bytes.
 * Returns: ARFILL_OK, ARFILL_FAILED, or ARFILL_SKIPPED with character count.
 * Errors: Allocation failure returns ARFILL_FAILED; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Guarded for CER-only builds.
 * Example: called by the random-fill API with asn_DEF_UTF8String.
 */
asn_random_fill_result_t
UTF8String_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                       const asn_encoding_constraints_t *constraints,
                       size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    uint8_t *buf;
    uint8_t *end;
    size_t rnd_len;
    UTF8String_rfill_config_t config;

    if(max_length == 0 && !*sptr) return result_skipped;
    UTF8String__configure_rfill(td, constraints, &config);

    rnd_len = OCTET_STRING_random_length_constrained(td, constraints,
                                                     max_length / 4);

    buf = CALLOC(4, rnd_len + 1);
    if(!buf) return result_failed;
    end = UTF8String__generate_rfill(buf, rnd_len, &config);
    if(UTF8String__install_rfill(sptr, buf, end, rnd_len)) return result_failed;

    return result_ok;
}
