/*
 * Compare generated Rust UPER vectors with a separately generated C project.
 *
 * Original source: new asn1c test fixture. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: initial Rust compiler slice.
 * Example: compile with CParity generated sources and run the resulting binary.
 */
#include <asn_application.h>
#include <NULL.h>
#include <BOOLEAN.h>
#include <uper_decoder.h>
#include <uper_encoder.h>
#include <asn_internal.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <Count.h>
#include <Empty.h>
#include <Flag.h>
#include <Singleton.h>

/* Compare a decoded C scalar with the semantic value expected by the fixture. */
typedef int (*value_matches_f)(const void *decoded, long expected);

/**
 * Save complete bytes produced by the generated C encoder for Rust to read.
 *
 * Parameters: `directory` is the temporary vector directory; `filename` is a
 * fixed fixture name; `bytes` and `octets` are the actual C output.
 * Returns zero on a complete write and one on path or I/O failure.
 * Errors: reports path, open, write, and close failures to stderr.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: added for live C-to-Rust decoding.
 * Example: write the C BOOLEAN encoding to `bool_true.bin`.
 */
static int
write_vector(const char *directory, const char *filename,
             const unsigned char *bytes, size_t octets) {
    char path[1024];
    int path_length;
    FILE *stream;

    path_length = snprintf(path, sizeof(path), "%s/%s", directory, filename);
    if(path_length < 0 || (size_t)path_length >= sizeof(path)) {
        fprintf(stderr, "vector output path is too long\n");
        return 1;
    }
    stream = fopen(path, "wb");
    if(!stream) {
        perror(path);
        return 1;
    }
    if(fwrite(bytes, 1, octets, stream) != octets) {
        fprintf(stderr, "could not write vector %s\n", path);
        fclose(stream);
        return 1;
    }
    if(fclose(stream) != 0) {
        perror(path);
        return 1;
    }
    return 0;
}

/**
 * Encode one value and compare complete bytes plus the meaningful UPER bit count.
 *
 * Parameters: `td` is its descriptor; `value` is its C value;
 * `expected` and `octets` are the complete golden vector; `bits` is its
 * meaningful length; `name` identifies failures; `directory` and `filename`
 * select where the actual C encoder output is saved for Rust to decode.
 * Returns zero on equality and one on mismatch.
 * Errors: reports encoder, comparison, and file-write failures; does not throw.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: initial Rust UPER slice and C-to-Rust
 * wire exchange. Example: compare `Flag` TRUE against `{ 0x80 }` and one bit.
 */
static int
check_encoding(const asn_TYPE_descriptor_t *td, const void *value,
               const unsigned char *expected, size_t octets, size_t bits,
               const char *name, const char *directory, const char *filename) {
    unsigned char bit_buffer[16] = {0};
    void *complete = 0;
    ssize_t complete_octets;
    asn_enc_rval_t er;

    /* Ask both C APIs: one reports meaningful bits, the other emits full bytes. */
    er = uper_encode_to_buffer(td, 0, value, bit_buffer, sizeof(bit_buffer));
    complete_octets = uper_encode_to_new_buffer(td, 0, value, &complete);
    if(er.encoded < 0 || (size_t)er.encoded != bits) {
        fprintf(stderr, "%s encoded %ld bits, expected %lu\n", name,
                (long)er.encoded, (unsigned long)bits);
        if(complete) FREEMEM(complete);
        return 1;
    }

    if(complete_octets < 0 || (size_t)complete_octets != octets || !complete
       || memcmp(complete, expected, octets) != 0) {
        fprintf(stderr, "%s encoded bytes differ from the fixed vector\n", name);
        if(complete) FREEMEM(complete);
        return 1;
    }
    if(write_vector(directory, filename, (const unsigned char *)complete, octets)) {
        FREEMEM(complete);
        return 1;
    }
    FREEMEM(complete);
    return 0;
}

/**
 * Decode one complete vector and compare its semantic value.
 *
 * Parameters: `td` is the generated descriptor; `encoded` and `octets` are
 * the vector; `matches` checks its generated C value; `expected` is the value;
 * `name` identifies failures.
 * Returns zero on successful decode and semantic equality, otherwise one.
 * Errors: reports decode or comparison errors; frees any partial decode.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: initial Rust UPER slice.
 * Example: decode Count bytes `0x50` and require value zero.
 */
static int
check_decoding(const asn_TYPE_descriptor_t *td, const unsigned char *encoded,
               size_t octets, value_matches_f matches, long expected,
               const char *name) {
    void *decoded = 0;
    asn_dec_rval_t rv;
    int failed;

    /* The complete decoder consumes the rounded complete-value byte prefix. */
    rv = uper_decode_complete(0, td, &decoded, encoded, octets);
    failed = rv.code != RC_OK || !decoded || !matches(decoded, expected);
    if(failed) {
        fprintf(stderr, "%s failed complete-vector decode or value comparison\n",
                name);
    }
    if(decoded) ASN_STRUCT_FREE(*td, decoded);
    return failed;
}

/**
 * Require a malformed or truncated complete vector to fail decoding.
 *
 * Parameters: `td` is the generated descriptor; `encoded` and `octets` are
 * the rejected vector; `name` identifies failures.
 * Returns zero when decoding rejects the input, otherwise one.
 * Errors: reports accidental acceptance and frees any allocated value.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: initial hostile-input fixture.
 * Example: reject the spare fifth-bit code for Count.
 */
static int
check_rejected(const asn_TYPE_descriptor_t *td, const unsigned char *encoded,
               size_t octets, const char *name) {
    void *decoded = 0;
    asn_dec_rval_t rv;

    /* Even a partial C decode must be released after the expected rejection. */
    rv = uper_decode_complete(0, td, &decoded, encoded, octets);
    if(rv.code == RC_OK) {
        fprintf(stderr, "%s unexpectedly accepted malformed input\n", name);
        if(decoded) ASN_STRUCT_FREE(*td, decoded);
        return 1;
    }
    if(decoded) ASN_STRUCT_FREE(*td, decoded);
    return 0;
}

/**
 * Compare a decoded BOOLEAN value with its expected truth value.
 *
 * Parameters: `decoded` points to generated `BOOLEAN_t`; `expected` is zero
 * for FALSE or nonzero for TRUE.
 * Returns nonzero when the semantic values agree.
 * Errors: returns zero for a null decoded pointer; does not throw.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: initial Rust UPER slice.
 * Example: compare a decoded value with expected TRUE (`1`).
 */
static int
matches_boolean(const void *decoded, long expected) {
    const BOOLEAN_t *value = (const BOOLEAN_t *)decoded;
    return value && (!!*value == !!expected);
}

/**
 * Compare decoded NULL storage with the sole ASN.1 NULL value.
 *
 * Parameters: `decoded` points to generated `NULL_t`; `expected` is ignored.
 * Returns nonzero for a non-null decoded pointer.
 * Errors: returns zero for a null pointer; does not throw.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: initial Rust UPER slice.
 * Example: accept a successfully decoded C NULL value.
 */
static int
matches_null(const void *decoded, long expected) {
    (void)expected;
    return decoded != 0;
}

/**
 * Compare a decoded bounded native INTEGER with its expected signed value.
 *
 * Parameters: `decoded` points to generated `long`; `expected` is the
 * expected signed `long` value.
 * Returns nonzero when the value equals `expected`.
 * Errors: returns zero for a null pointer or value mismatch.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: initial Rust UPER slice.
 * Example: compare decoded `Count` with `-1L`.
 */
static int
matches_integer(const void *decoded, long expected) {
    const long *value = (const long *)decoded;
    return value && *value == expected;
}

/**
 * Read one actual Rust encoding and ask the generated C decoder to accept it.
 *
 * Parameters: `directory` and `filename` locate the Rust-produced vector;
 * `td` is the generated C descriptor; `matches` checks the decoded value;
 * `expected` is its semantic value; `name` identifies failures.
 * Returns zero on valid decoding and semantic equality, otherwise one.
 * Errors: reports file errors and decoder mismatches; partial C values are freed.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: added for live Rust-to-C decoding.
 * Example: read `count_minus_one.bin` and require C value `-1`.
 */
static int
check_rust_file(const char *directory, const char *filename,
                const asn_TYPE_descriptor_t *td, value_matches_f matches,
                long expected, const char *name) {
    unsigned char bytes[16];
    char path[1024];
    int path_length;
    size_t octets;
    int extra;
    FILE *stream;

    path_length = snprintf(path, sizeof(path), "%s/%s", directory, filename);
    if(path_length < 0 || (size_t)path_length >= sizeof(path)) {
        fprintf(stderr, "Rust vector path is too long\n");
        return 1;
    }
    stream = fopen(path, "rb");
    if(!stream) {
        perror(path);
        return 1;
    }
    octets = fread(bytes, 1, sizeof(bytes), stream);
    extra = fgetc(stream);
    {
        int read_error = ferror(stream);
        int close_error = fclose(stream);
        if(read_error || close_error || extra != EOF) {
            fprintf(stderr, "invalid Rust vector file %s\n", path);
            return 1;
        }
    }
    if(octets == 0) {
        fprintf(stderr, "empty Rust vector file %s\n", path);
        return 1;
    }
    return check_decoding(td, bytes, octets, matches, expected, name);
}

/**
 * Cross-decode each named Rust-produced vector with its generated C descriptor.
 *
 * Parameters: `directory` contains Rust encoder output files. Returns zero if
 * every vector decodes to the expected C semantic value, otherwise one.
 * Errors: delegates file and decode diagnostics to `check_rust_file`.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: added for live Rust-to-C decoding.
 * Example: `check_rust_vectors("/tmp/rust-vectors")` checks all first-slice types.
 */
static int
check_rust_vectors(const char *directory) {
    int failed = 0;
    failed |= check_rust_file(directory, "bool_true.bin", &asn_DEF_Flag,
                              matches_boolean, 1, "Rust BOOLEAN TRUE");
    failed |= check_rust_file(directory, "bool_false.bin", &asn_DEF_Flag,
                              matches_boolean, 0, "Rust BOOLEAN FALSE");
    failed |= check_rust_file(directory, "null.bin", &asn_DEF_Empty,
                              matches_null, 0, "Rust NULL");
    failed |= check_rust_file(directory, "count_min.bin", &asn_DEF_Count,
                              matches_integer, -10, "Rust Count -10");
    failed |= check_rust_file(directory, "count_minus_one.bin", &asn_DEF_Count,
                              matches_integer, -1, "Rust Count -1");
    failed |= check_rust_file(directory, "count_zero.bin", &asn_DEF_Count,
                              matches_integer, 0, "Rust Count 0");
    failed |= check_rust_file(directory, "count_max.bin", &asn_DEF_Count,
                              matches_integer, 10, "Rust Count 10");
    failed |= check_rust_file(directory, "singleton.bin", &asn_DEF_Singleton,
                              matches_integer, 5, "Rust Singleton 5");
    if(!failed) puts("PASS: generated Rust vectors decoded by C");
    return failed;
}

/**
 * Run C encode/decode parity for the supported nonextensible primitive cases.
 *
 * Parameters: the normal mode accepts one C-to-Rust vector directory; decode
 * mode accepts `--decode-dir` and a Rust vector directory. Returns zero on
 * success and one if an encoding, cross-decode, or invalid-input check fails.
 * Errors: helpers print the failing vector; no exception is raised.
 * Source/version/date: new asn1c fixture, 0.1.0, 2026-10-11.
 * Author: asn1c maintainers. History: first generated Rust UPER integration.
 * Example: encode vectors into the argument directory, then run with
 * `--decode-dir <path>` to consume Rust-generated vectors.
 */
int
main(int argc, char **argv) {
    static const unsigned char true_bits[] = {0x80};
    static const unsigned char false_bits[] = {0x00};
    static const unsigned char null_complete[] = {0x00};
    static const unsigned char count_min[] = {0x00};
    static const unsigned char count_minus_one[] = {0x48};
    static const unsigned char count_zero[] = {0x50};
    static const unsigned char count_max[] = {0xa0};
    static const unsigned char singleton[] = {0x00};
    static const unsigned char count_spare[] = {0xa8};
    BOOLEAN_t true_value = 1;
    BOOLEAN_t false_value = 0;
    NULL_t empty_value = 0;
    Count_t count_value = -10L;
    Singleton_t singleton_value = 5L;
    int failed = 0;
    const char *vector_directory;

    if(argc == 3 && strcmp(argv[1], "--decode-dir") == 0) {
        return check_rust_vectors(argv[2]);
    }
    if(argc != 2) {
        fprintf(stderr, "usage: %s <C-vector-dir> | --decode-dir <Rust-vector-dir>\n",
                argv[0]);
        return 2;
    }
    vector_directory = argv[1];

    /* Encode C values and compare them with independent fixed vectors. */
    failed |= check_encoding(&asn_DEF_Flag, &true_value, true_bits, 1, 1,
                             "BOOLEAN TRUE", vector_directory, "bool_true.bin");
    failed |= check_encoding(&asn_DEF_Flag, &false_value, false_bits, 1, 1,
                             "BOOLEAN FALSE", vector_directory, "bool_false.bin");
    failed |= check_encoding(&asn_DEF_Empty, &empty_value, null_complete, 1, 0,
                             "NULL", vector_directory, "null.bin");

    /* The generated bounded INTEGER wrappers use native C `long` storage. */
    failed |= check_encoding(&asn_DEF_Count, &count_value, count_min, 1, 5,
                             "Count -10", vector_directory, "count_min.bin");
    count_value = -1L;
    failed |= check_encoding(&asn_DEF_Count, &count_value, count_minus_one, 1, 5,
                             "Count -1", vector_directory, "count_minus_one.bin");
    count_value = 0L;
    failed |= check_encoding(&asn_DEF_Count, &count_value, count_zero, 1, 5,
                             "Count 0", vector_directory, "count_zero.bin");
    count_value = 10L;
    failed |= check_encoding(&asn_DEF_Count, &count_value, count_max, 1, 5,
                             "Count 10", vector_directory, "count_max.bin");
    failed |= check_encoding(&asn_DEF_Singleton, &singleton_value, singleton, 1, 0,
                             "Singleton 5", vector_directory, "singleton.bin");

    /* Cross-decode the same complete vectors through the C implementation. */
    failed |= check_decoding(&asn_DEF_Flag, true_bits, 1, matches_boolean, 1,
                             "BOOLEAN TRUE");
    failed |= check_decoding(&asn_DEF_Flag, false_bits, 1, matches_boolean, 0,
                             "BOOLEAN FALSE");
    failed |= check_decoding(&asn_DEF_Empty, null_complete, 1, matches_null, 0,
                             "NULL");
    failed |= check_decoding(&asn_DEF_Count, count_min, 1, matches_integer, -10,
                             "Count -10");
    failed |= check_decoding(&asn_DEF_Count, count_minus_one, 1, matches_integer, -1,
                             "Count -1");
    failed |= check_decoding(&asn_DEF_Count, count_zero, 1, matches_integer, 0,
                             "Count 0");
    failed |= check_decoding(&asn_DEF_Count, count_max, 1, matches_integer, 10,
                             "Count 10");
    failed |= check_decoding(&asn_DEF_Singleton, singleton, 1, matches_integer, 5,
                             "Singleton 5");

    /* Exercise one truncated input and one invalid constrained code in C. */
    failed |= check_rejected(&asn_DEF_Count, count_spare, 1, "Count spare code");
    failed |= check_rejected(&asn_DEF_Count, count_zero, 0, "Count truncation");
    failed |= check_rejected(&asn_DEF_Empty, count_spare, 1, "NULL filler");

    if(!failed) puts("PASS: generated C UPER comparison fixture");
    return failed ? 1 : 0;
}
