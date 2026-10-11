//! Generated-crate conformance and hostile-input tests for the first Rust slice.
//!
//! These integration tests use independent UPER bit vectors, live API round
//! trips, explicit resource limits, and bounded deterministic mutations.

use asn1c_generated::first_slice::{
    Count, Decoded, Empty, Error as AsnError, Flag, Limits as AsnLimits, Ok as AsnOk,
    Result as AsnResult, Singleton, Wide,
};
use asn1c_runtime::{Error, Limits, Resource};
use std::path::Path;

/// Check the bytes and meaningful bit count returned by a generated encoder.
///
/// # Parameters
/// `actual` is the generated encoding, `bytes` is the independent golden byte
/// slice, `bit_len` is the golden meaningful-bit count, and `case` names it.
///
/// # Returns
/// No value; any difference panics and fails the calling integration test.
///
/// # Errors and panics
/// Panics on a byte or bit-count mismatch. The generated encoder is expected
/// to return a typed error before this helper is called when it cannot encode.
///
/// # Source, history, and example
/// Original source: new asn1c generated-Rust integration test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// with the primitive UPER slice. Example: `check_encoding(&encoded, &[0x80], 1, "TRUE")`.
fn check_encoding(actual: &asn1c_runtime::Encoded, bytes: &[u8], bit_len: usize, case: &str) {
    assert_eq!(actual.bytes, bytes, "{case} bytes");
    assert_eq!(actual.bit_len, bit_len, "{case} meaningful bits");
}

/// Save generated Rust bytes for a separately compiled C decoder.
///
/// # Parameters
/// `filename` is a fixed interop-vector name; `bytes` are the generated output.
///
/// # Returns
/// No value. Writes the vector under `ASN1C_RUST_VECTORS` for the harness.
///
/// # Errors and panics
/// Panics if the harness omitted its output directory or the vector cannot be
/// written. Those conditions indicate an invalid test environment.
///
/// # Source, history, and example
/// Original source: new asn1c generated-Rust interoperability test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// bidirectional C/Rust wire exchange. Example: `write_rust_vector("null.bin", &[0])`.
fn write_rust_vector(filename: &str, bytes: &[u8]) {
    let directory =
        std::env::var_os("ASN1C_RUST_VECTORS").expect("harness must configure ASN1C_RUST_VECTORS");
    let path = Path::new(&directory).join(filename);
    std::fs::write(&path, bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}

/// Read a complete vector emitted by the separate generated C encoder.
///
/// # Parameters
/// `filename` is a fixed vector name under the directory in `ASN1C_C_VECTORS`.
///
/// # Returns
/// The exact complete encoding emitted by the C fixture.
///
/// # Errors and panics
/// Panics if the harness omitted its directory or the file cannot be read.
///
/// # Source, history, and example
/// Original source: new asn1c generated-Rust interoperability test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// bidirectional C/Rust wire exchange. Example: `read_c_vector("bool_true.bin")`.
fn read_c_vector(filename: &str) -> Vec<u8> {
    let directory =
        std::env::var_os("ASN1C_C_VECTORS").expect("harness must configure ASN1C_C_VECTORS");
    let path = Path::new(&directory).join(filename);
    std::fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Check BOOLEAN values against fixed UPER vectors and prefix consumption.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Flag` encode/decode.
///
/// # Errors and panics
/// Panics if encoding, decoding, semantic values, or consumption differs.
///
/// # Source, history, and example
/// Original source: generated type contract plus X.691 UPER BOOLEAN bit order.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: TRUE is `0x80` in one bit.
#[test]
fn boolean_golden_vectors_and_prefix() {
    let limits = Limits::default();
    for (value, octet, filename) in [
        (false, 0x00, "bool_false.bin"),
        (true, 0x80, "bool_true.bin"),
    ] {
        let encoded = Flag::new(value).encode_uper(&limits).unwrap();
        check_encoding(&encoded, &[octet], 1, "BOOLEAN");
        write_rust_vector(filename, &encoded.bytes);

        let decoded = Flag::decode_uper(&[octet, 0x5a], &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bits, 1);
        assert_eq!(decoded.consumed_bytes, 1);
    }
}

/// Check zero-width NULL complete encoding and malformed filler handling.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated unit type `Empty`.
///
/// # Errors and panics
/// Panics if complete-value bytes, consumption, or malformed-input rejection
/// differs from the runtime contract.
///
/// # Source, history, and example
/// Original source: generated type contract and `uper_decode_complete` behavior.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: NULL encodes as `[0]`, zero bits.
#[test]
fn null_complete_encoding() {
    let limits = Limits::default();
    let encoded = Empty.encode_uper(&limits).unwrap();
    check_encoding(&encoded, &[0x00], 0, "NULL");
    write_rust_vector("null.bin", &encoded.bytes);

    let decoded = Empty::decode_uper(&[0x00, 0x7f], &limits).unwrap();
    assert_eq!(decoded.consumed_bits, 0);
    assert_eq!(decoded.consumed_bytes, 1);
    assert!(Empty::decode_uper(&[], &limits).is_err());
    assert!(Empty::decode_uper(&[0x01], &limits).is_err());
}

/// Ensure generated ASN.1 names can overlap Rust and runtime API names safely.
///
/// # Parameters and returns
/// No parameters or return value. Exercises names `Limits`, `Error`, `Decoded`,
/// `Result`, and `Ok` against emitted method and runtime names.
///
/// # Errors and panics
/// Panics if these generated types shadow Rust/runtime paths or fail their
/// basic UPER round trips.
///
/// # Source, history, and example
/// Original source: generated Rust name-collision regression. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// for the initial Rust compiler slice. Example: `Decoded::new(1)` encodes.
#[test]
fn generated_runtime_name_collisions_are_safe() {
    let runtime_limits = Limits::default();
    let generated_limits = AsnLimits::new(true);
    assert!(generated_limits.value());

    let generated_error = AsnError;
    let encoded_null = generated_error.encode_uper(&runtime_limits).unwrap();
    assert_eq!(encoded_null.bytes, [0x00]);

    let encoded_integer = Decoded::new(1)
        .unwrap()
        .encode_uper(&runtime_limits)
        .unwrap();
    check_encoding(&encoded_integer, &[0x80], 1, "Decoded name collision");
    assert_eq!(
        Decoded::decode_uper(&encoded_integer.bytes, &runtime_limits)
            .unwrap()
            .value
            .value(),
        1
    );

    let generated_result = AsnResult::new(true);
    let encoded_result = generated_result.encode_uper(&runtime_limits).unwrap();
    check_encoding(&encoded_result, &[0x80], 1, "Result name collision");
    assert!(
        AsnResult::decode_uper(&encoded_result.bytes, &runtime_limits)
            .unwrap()
            .value
            .value()
    );

    let generated_ok = AsnOk::new(false);
    let encoded_ok = generated_ok.encode_uper(&runtime_limits).unwrap();
    check_encoding(&encoded_ok, &[0x00], 1, "Ok name collision");
    assert!(!AsnOk::decode_uper(&encoded_ok.bytes, &runtime_limits)
        .unwrap()
        .value
        .value());
}

/// Check bounded signed INTEGER vectors, spare codes, and constructor bounds.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Count` for `-10..10`.
///
/// # Errors and panics
/// Panics if a golden vector, prefix-consumption value, range check, or spare
/// code rejection differs from the fixed UPER expectations.
///
/// # Source, history, and example
/// Original source: generated type contract and X.691 constrained whole number.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: -1 has offset 9, encoded `0x48`.
#[test]
fn bounded_integer_golden_vectors_and_errors() {
    let limits = Limits::default();
    for (value, octet, filename) in [
        (-10, 0x00, "count_min.bin"),
        (-1, 0x48, "count_minus_one.bin"),
        (0, 0x50, "count_zero.bin"),
        (10, 0xa0, "count_max.bin"),
    ] {
        let encoded = Count::new(value).unwrap().encode_uper(&limits).unwrap();
        check_encoding(&encoded, &[octet], 5, "Count");
        write_rust_vector(filename, &encoded.bytes);

        let decoded = Count::decode_uper(&[octet, 0xab], &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bits, 5);
        assert_eq!(decoded.consumed_bytes, 1);
    }

    assert!(Count::new(-11).is_err());
    assert!(Count::new(11).is_err());
    assert!(Count::decode_uper(&[], &limits).is_err());
    assert!(Count::decode_uper(&[0xa8], &limits).is_err());

    // Match the C decoder policy: low unused bits in a final octet are ignored.
    let padded = Count::decode_uper(&[0x51], &limits).unwrap();
    assert_eq!(padded.value.value(), 0);
}

/// Check a singleton INTEGER's complete zero-width representation.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Singleton` at value 5.
///
/// # Errors and panics
/// Panics if the value is not represented by one zero complete byte and no
/// meaningful bits, or if empty input is accepted as a complete value.
///
/// # Source, history, and example
/// Original source: generated type contract and X.691 constrained whole number.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: range `5..5` encodes as `[0]`.
#[test]
fn singleton_integer_complete_encoding() {
    let limits = Limits::default();
    let encoded = Singleton::new(5).unwrap().encode_uper(&limits).unwrap();
    check_encoding(&encoded, &[0x00], 0, "Singleton");
    write_rust_vector("singleton.bin", &encoded.bytes);

    let decoded = Singleton::decode_uper(&[0x00], &limits).unwrap();
    assert_eq!(decoded.value.value(), 5);
    assert_eq!(decoded.consumed_bits, 0);
    assert_eq!(decoded.consumed_bytes, 1);
    assert!(Singleton::decode_uper(&[], &limits).is_err());
    assert!(Singleton::decode_uper(&[0x01], &limits).is_err());
}

/// Decode bytes written by the live C encoder through generated Rust types.
///
/// # Parameters and returns
/// No parameters or return value. Reads every shared BOOLEAN, NULL, bounded
/// INTEGER, and singleton vector from `ASN1C_C_VECTORS`.
///
/// # Errors and panics
/// Panics if the C fixture did not write a vector, if Rust rejects it, or if
/// Rust's bytes or decoded semantic value differ.
///
/// # Source, history, and example
/// Original source: new asn1c bidirectional interoperability test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// live C-to-Rust decode coverage. Example: decode C's `count_minus_one.bin` as -1.
#[test]
fn c_encoder_vectors_decode_in_rust() {
    let limits = Limits::default();
    for (value, filename) in [(false, "bool_false.bin"), (true, "bool_true.bin")] {
        let c_bytes = read_c_vector(filename);
        assert_eq!(
            Flag::new(value).encode_uper(&limits).unwrap().bytes,
            c_bytes
        );
        assert_eq!(
            Flag::decode_uper(&c_bytes, &limits).unwrap().value.value(),
            value
        );
    }

    let c_null = read_c_vector("null.bin");
    assert_eq!(Empty.encode_uper(&limits).unwrap().bytes, c_null);
    assert_eq!(
        Empty::decode_uper(&c_null, &limits).unwrap().consumed_bytes,
        1
    );

    for (value, filename) in [
        (-10, "count_min.bin"),
        (-1, "count_minus_one.bin"),
        (0, "count_zero.bin"),
        (10, "count_max.bin"),
    ] {
        let c_bytes = read_c_vector(filename);
        assert_eq!(
            Count::new(value)
                .unwrap()
                .encode_uper(&limits)
                .unwrap()
                .bytes,
            c_bytes
        );
        assert_eq!(
            Count::decode_uper(&c_bytes, &limits).unwrap().value.value(),
            value
        );
    }

    let c_singleton = read_c_vector("singleton.bin");
    assert_eq!(
        Singleton::new(5)
            .unwrap()
            .encode_uper(&limits)
            .unwrap()
            .bytes,
        c_singleton
    );
    assert_eq!(
        Singleton::decode_uper(&c_singleton, &limits)
            .unwrap()
            .value
            .value(),
        5
    );
}

/// Check all edge encodings of the full signed i64 constraint range.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Wide` without a C parity
/// claim because the current C accumulator does not cover this width.
///
/// # Errors and panics
/// Panics if a fixed 64-bit vector, decoded semantic value, or bit count differs.
///
/// # Source, history, and example
/// Original source: generated type contract and the full inclusive i64 range.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: `i64::MIN` encodes as eight zero bytes.
#[test]
fn full_i64_range_golden_vectors() {
    let limits = Limits::default();
    for (value, bytes) in [
        (i64::MIN, [0x00; 8]),
        (-1, [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        (i64::MAX, [0xff; 8]),
    ] {
        let encoded = Wide::new(value).unwrap().encode_uper(&limits).unwrap();
        check_encoding(&encoded, &bytes, 64, "Wide");

        let decoded = Wide::decode_uper(&bytes, &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bits, 64);
        assert_eq!(decoded.consumed_bytes, 8);
    }
}

/// Check configured input, output, and meaningful-work ceilings.
///
/// # Parameters and returns
/// No parameters or return value. Uses one generated BOOLEAN and the public
/// runtime `Limits` fields to exercise each resource independently.
///
/// # Errors and panics
/// Panics if a request above a configured limit succeeds or an exact-limit
/// request fails.
///
/// # Source, history, and example
/// Original source: runtime resource contract. Version/date: 0.1.0, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial Rust compiler test.
/// Example: set `max_work_bits: 0` and require a one-bit BOOLEAN encode to fail.
#[test]
fn resource_limits_are_enforced() {
    let defaults = Limits::default();
    let no_input = Limits {
        max_input_bytes: 0,
        ..defaults.clone()
    };
    let input_error = Flag::decode_uper(&[0x80], &no_input).unwrap_err();
    assert!(matches!(
        input_error,
        Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        }
    ));

    let no_output = Limits {
        max_output_bytes: 0,
        ..defaults.clone()
    };
    let output_error = Flag::new(true).encode_uper(&no_output).unwrap_err();
    assert!(matches!(
        output_error,
        Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        }
    ));

    let no_work = Limits {
        max_work_bits: 0,
        ..defaults.clone()
    };
    let work_error = Flag::new(true).encode_uper(&no_work).unwrap_err();
    assert!(matches!(
        work_error,
        Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        }
    ));

    let one_bit = Limits {
        max_input_bytes: 1,
        max_output_bytes: 1,
        max_work_bits: 1,
    };
    assert_eq!(Flag::new(true).encode_uper(&one_bit).unwrap().bytes, [0x80]);
    assert!(Flag::decode_uper(&[0x80, 0x00], &one_bit).is_err());

    let wide = Wide::new(i64::MAX).unwrap();
    let seven_output_bytes = Limits {
        max_output_bytes: 7,
        ..defaults.clone()
    };
    let output_error = wide.encode_uper(&seven_output_bytes).unwrap_err();
    assert!(matches!(
        output_error,
        Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        }
    ));

    let sixty_three_work_bits = Limits {
        max_work_bits: 63,
        ..defaults
    };
    let work_error = wide.encode_uper(&sixty_three_work_bits).unwrap_err();
    assert!(matches!(
        work_error,
        Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        }
    ));
}

/// Exercise deterministic byte mutations and every truncated i64 prefix.
///
/// # Parameters and returns
/// No parameters or return value. Iterates bounded one-byte mutations and all
/// prefixes of one full-width INTEGER vector.
///
/// # Errors and panics
/// Panics if a decoder panics for any tested byte string. Ordinary decode
/// errors are expected and accepted.
///
/// # Source, history, and example
/// Original source: generated Rust parser-safety test plan. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// with bounded primitive decoders. Example: decode every single-octet prefix.
#[test]
fn deterministic_mutations_never_panic() {
    let limits = Limits::default();
    for octet in u8::MIN..=u8::MAX {
        let one_byte = [octet];
        assert!(std::panic::catch_unwind(|| {
            let _ = Flag::decode_uper(&one_byte, &limits);
            let _ = Count::decode_uper(&one_byte, &limits);
            let _ = Empty::decode_uper(&one_byte, &limits);
        })
        .is_ok());
    }

    let complete = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    for prefix_len in 0..=complete.len() {
        assert!(std::panic::catch_unwind(|| {
            let _ = Wide::decode_uper(&complete[..prefix_len], &limits);
        })
        .is_ok());
    }
}
