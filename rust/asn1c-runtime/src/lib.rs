//! Safe, bounded UPER and CER primitives for generated ASN.1 Rust code.
//!
//! This initial crate covers BOOLEAN, NULL, and bounded signed INTEGER values.
//! It uses only the Rust standard library and applies caller-configurable input,
//! output, and work limits before reading bits or allocating output storage.
//!
//! Copyright (c) 2003-2017 Lev Walkin and contributors; 2022-2026 Mouse and
//! contributors. Redistribution and use are permitted under the BSD 2-Clause
//! terms in the accompanying `LICENSE`. The software is provided "as is";
//! see `LICENSE` for the complete disclaimer.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

/// Default maximum number of input bytes accepted by one operation (1 MiB).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Default maximum number of output bytes produced by one operation (1 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default maximum number of wire bits processed by one operation (8 MiBits).
pub const DEFAULT_MAX_WORK_BITS: usize = 8 * 1024 * 1024;

/// Resource ceilings applied by each primitive operation.
///
/// The byte limits apply to the complete provided input slice and the complete
/// encoded output buffer. `max_work_bits` bounds meaningful UPER bits or total
/// CER output bits processed by one operation. These finite defaults are
/// configurable by each caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of the entire input slice accepted by a decode operation.
    pub max_input_bytes: usize,
    /// Maximum size of an encoded output buffer, including padding bytes.
    pub max_output_bytes: usize,
    /// Maximum UPER bits or CER output bits processed per operation.
    pub max_work_bits: usize,
}

/// Resource whose configured ceiling was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Supplied input bytes exceeded `Limits::max_input_bytes`.
    InputBytes,
    /// Encoded output bytes exceeded `Limits::max_output_bytes`.
    OutputBytes,
    /// Codec work bits exceeded `Limits::max_work_bits`.
    WorkBits,
}

/// A bounded encoding and the number of meaningful bits it contains.
///
/// For UPER, `bit_len` counts meaningful bits and excludes final-byte padding.
/// For CER, `bit_len` counts every bit in the complete octet-aligned TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// Encoded bytes, including codec-specific complete-value framing.
    pub bytes: Vec<u8>,
    /// UPER meaningful bits or total octet-aligned CER wire bits.
    pub bit_len: usize,
}

/// A decoded value and its prefix consumption in bits and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<T> {
    /// Decoded ASN.1 value.
    pub value: T,
    /// Number of meaningful bits consumed from the input prefix.
    pub consumed_bits: usize,
    /// Number of whole bytes occupied by the consumed prefix.
    pub consumed_bytes: usize,
}

impl<T> Decoded<T> {
    /// Transform the decoded value while preserving its input consumption.
    ///
    /// # Parameters
    /// `self` is the decoded result; `transform` maps its value to a new type.
    ///
    /// # Returns
    /// A result containing the transformed value and unchanged consumption.
    ///
    /// # Errors and panics
    /// This method returns no error. A panic from `transform` is propagated.
    ///
    /// # Source, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
    /// 2026-10-11. Responsible party: asn1c maintainers. History: introduced
    /// with the initial runtime slice. Example: `decoded.map(|value| !value)`.
    pub fn map<U, F>(self, transform: F) -> Decoded<U>
    where
        F: FnOnce(T) -> U,
    {
        Decoded {
            value: transform(self.value),
            consumed_bits: self.consumed_bits,
            consumed_bytes: self.consumed_bytes,
        }
    }
}

/// Error returned for invalid constraints, malformed input, or exhausted limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The lower constraint bound is greater than the upper bound.
    InvalidBounds {
        /// Inclusive lower bound supplied by the caller.
        lower: i64,
        /// Inclusive upper bound supplied by the caller.
        upper: i64,
    },
    /// A value does not fit its inclusive constraint range.
    ValueOutOfRange {
        /// Value supplied to the encoder or validator.
        value: i64,
        /// Inclusive lower bound supplied by the caller.
        lower: i64,
        /// Inclusive upper bound supplied by the caller.
        upper: i64,
    },
    /// The input ended before the requested number of bits was available.
    NeedMoreBits {
        /// Minimum meaningful bits required to decode the value.
        required_bits: usize,
        /// Bits available in the supplied input slice.
        available_bits: usize,
    },
    /// The input ended before a complete zero-width encoding byte was available.
    NeedMoreBytes {
        /// Minimum whole bytes required to decode the value.
        required_bytes: usize,
        /// Whole bytes available in the supplied input slice.
        available_bytes: usize,
    },
    /// Input bits are not a valid encoding of the selected constrained type.
    InvalidEncoding {
        /// Static explanation of the malformed encoding.
        reason: &'static str,
    },
    /// The requested input, output, or work exceeds the configured limit.
    LimitExceeded {
        /// Resource for which the configured ceiling was exceeded.
        resource: Resource,
        /// Configured resource ceiling.
        limit: usize,
        /// Requested resource amount.
        requested: usize,
    },
    /// A checked length or bit-count calculation overflowed `usize`.
    SizeOverflow,
    /// Fallible output-buffer reservation failed.
    AllocationFailed {
        /// Number of output bytes requested from the allocator.
        requested_bytes: usize,
    },
}

impl Default for Limits {
    /// Return the runtime's finite per-operation resource limits.
    ///
    /// # Parameters and returns
    /// No parameters. Returns limits for 1 MiB input, 1 MiB output, and 8 MiBits
    /// of work.
    ///
    /// # Errors and exceptions
    /// This method cannot fail and raises no exception.
    ///
    /// # Source, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
    /// 2026-10-11. Responsible party: asn1c maintainers. History: introduced
    /// with the initial runtime slice. Example: `let limits = Limits::default();`.
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_work_bits: DEFAULT_MAX_WORK_BITS,
        }
    }
}

impl fmt::Display for Error {
    /// Write a human-readable description of this error.
    ///
    /// # Parameters and returns
    /// `self` is the error and `formatter` is the destination. Returns the
    /// formatter's result.
    ///
    /// # Errors and exceptions
    /// Returns the formatter's error if writing fails; raises no exception.
    ///
    /// # Source, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
    /// 2026-10-11. Responsible party: asn1c maintainers. History: introduced
    /// with the initial runtime slice. Example: `format!("{error}")`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBounds { lower, upper } => {
                write!(formatter, "invalid INTEGER bounds {lower}..={upper}")
            }
            Self::ValueOutOfRange {
                value,
                lower,
                upper,
            } => write!(formatter, "INTEGER {value} is outside {lower}..={upper}"),
            Self::NeedMoreBits {
                required_bits,
                available_bits,
            } => write!(
                formatter,
                "need {required_bits} bits, only {available_bits} are available"
            ),
            Self::NeedMoreBytes {
                required_bytes,
                available_bytes,
            } => write!(
                formatter,
                "need {required_bytes} bytes, only {available_bytes} are available"
            ),
            Self::InvalidEncoding { reason } => {
                write!(formatter, "invalid ASN.1 encoding: {reason}")
            }
            Self::LimitExceeded {
                resource,
                limit,
                requested,
            } => write!(
                formatter,
                "{resource:?} limit {limit} exceeded by request for {requested}"
            ),
            Self::SizeOverflow => formatter.write_str("size calculation overflowed"),
            Self::AllocationFailed { requested_bytes } => {
                write!(
                    formatter,
                    "could not reserve {requested_bytes} output bytes"
                )
            }
        }
    }
}

/// Mark runtime errors as standard library errors.
///
/// # Parameters and returns
/// No parameters or return value.
///
/// # Errors and exceptions
/// This marker implementation cannot fail and raises no exception.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
/// 2026-10-11. Responsible party: asn1c maintainers. History: introduced with
/// the initial runtime slice. Example: `fn report(e: &dyn std::error::Error)`.
impl std::error::Error for Error {}

/// Encode one UPER BOOLEAN bit.
///
/// # Parameters
/// `value` is the ASN.1 boolean; `limits` bounds output bytes and work bits.
///
/// # Returns
/// One byte containing the value in its most significant bit and `bit_len` 1.
///
/// # Errors and exceptions
/// Returns a typed limit or allocation error. It raises no exception.
///
/// # Source, history, and example
/// Original source: `BOOLEAN_encode_uper` in `skeletons/BOOLEAN_uper.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial constrained-UPER runtime. Example:
/// `encode_boolean(true, &Limits::default())?`.
pub fn encode_boolean(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    let bit_len = 1;
    let byte_len = encoded_byte_len(bit_len)?;
    check_work_limit(bit_len, limits)?;

    // Reserve only after both configured output and allocator bounds are checked.
    let mut bytes = allocate_zeroed(byte_len, limits)?;
    write_bits(&mut bytes, u64::from(value), bit_len)?;

    Ok(Encoded { bytes, bit_len })
}

/// Decode a one-bit UPER BOOLEAN prefix.
///
/// # Parameters
/// `input` is the encoded prefix; `limits` bounds the full input slice and work.
///
/// # Returns
/// The boolean value, one meaningful bit consumed, and one byte consumed.
///
/// # Errors and exceptions
/// Returns `NeedMoreBits`, a configured limit error, or a length-overflow error.
/// It raises no exception. The seven low padding bits are deliberately ignored.
///
/// # Source, history, and example
/// Original source: `BOOLEAN_decode_uper` in `skeletons/BOOLEAN_uper.c` and
/// complete-input behavior in `skeletons/uper_decoder.c`. Version/date:
/// Rust port slice, 2026-10-11. Responsible party: asn1c maintainers. History:
/// initial constrained-UPER runtime. Example: `decode_boolean(&[0x80], limits)`.
pub fn decode_boolean(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    check_input_limit(input, limits)?;
    require_bits(input, 1)?;
    check_work_limit(1, limits)?;

    // Only the first meaningful bit is read; C-compatible padding is ignored.
    let value = read_bits(input, 1)? != 0;
    Ok(Decoded {
        value,
        consumed_bits: 1,
        consumed_bytes: 1,
    })
}

/// Encode a UPER NULL complete encoding.
///
/// # Parameters
/// `limits` bounds the one-byte complete encoding and bit-work budget.
///
/// # Returns
/// A single zero byte with `bit_len == 0`, matching complete UPER behavior.
///
/// # Errors and exceptions
/// Returns a configured output-limit or allocation error. It raises no exception.
///
/// # Source, history, and example
/// Original source: `NULL_encode_uper` and `uper_encode_to_new_buffer` in
/// `skeletons/NULL_uper.c` and `skeletons/uper_encoder.c`. Version/date:
/// Rust port slice, 2026-10-11. Responsible party: asn1c maintainers. History:
/// initial constrained-UPER runtime. Example: `encode_null(limits)`.
pub fn encode_null(limits: &Limits) -> Result<Encoded, Error> {
    check_work_limit(0, limits)?;
    let bytes = allocate_zeroed(1, limits)?;
    Ok(Encoded { bytes, bit_len: 0 })
}

/// Decode a complete zero-width UPER NULL prefix.
///
/// # Parameters
/// `input` is the complete-value prefix; `limits` bounds the full slice.
///
/// # Returns
/// Unit value, zero meaningful bits consumed, and one complete-encoding byte.
///
/// # Errors and exceptions
/// Returns `NeedMoreBytes`, `InvalidEncoding`, a limit error, or `SizeOverflow`.
/// It raises no exception. A nonzero zero-width byte is malformed.
///
/// # Source, history, and example
/// Original source: `NULL_decode_uper` and `uper_decode_complete` in
/// `skeletons/NULL_uper.c` and `skeletons/uper_decoder.c`. Version/date:
/// Rust port slice, 2026-10-11. Responsible party: asn1c maintainers. History:
/// initial constrained-UPER runtime. Example: `decode_null(&[0], limits)`.
pub fn decode_null(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, 1)?;
    check_work_limit(0, limits)?;
    if input[0] != 0 {
        return Err(Error::InvalidEncoding {
            reason: "nonzero complete-encoding filler for a zero-width value",
        });
    }

    Ok(Decoded {
        value: (),
        consumed_bits: 0,
        consumed_bytes: 1,
    })
}

/// Validate an INTEGER against inclusive signed bounds.
///
/// # Parameters
/// `value` is the value to check; `lower` and `upper` are inclusive bounds.
///
/// # Returns
/// `Ok(())` if bounds are ordered and contain `value`.
///
/// # Errors and exceptions
/// Returns `InvalidBounds` or `ValueOutOfRange`; it raises no exception.
///
/// # Source, history, and example
/// Original source: bounded-value checks in `skeletons/INTEGER_uper.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial constrained-UPER runtime. Example:
/// `validate_integer(4, 0, 10)?`.
pub fn validate_integer(value: i64, lower: i64, upper: i64) -> Result<(), Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }
    if value < lower || value > upper {
        return Err(Error::ValueOutOfRange {
            value,
            lower,
            upper,
        });
    }
    Ok(())
}

/// Encode a constrained signed INTEGER as a UPER bit prefix.
///
/// # Parameters
/// `value` is the INTEGER; `lower` and `upper` are inclusive bounds; `limits`
/// bounds output bytes and meaningful work bits.
///
/// # Returns
/// The offset from `lower` in the minimum fixed bit width. Singleton ranges use
/// a complete zero-width encoding represented by one zero byte.
///
/// # Errors and exceptions
/// Returns constraint, limit, length, or allocation errors. It raises no
/// exception. Arithmetic uses widened checked representations.
///
/// # Source, history, and example
/// Original source: constrained path in `INTEGER_encode_uper` in
/// `skeletons/INTEGER_uper.c`. Version/date: Rust port slice, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial constrained-UPER
/// runtime. Example: `encode_integer(-1, -2, 2, limits)`.
pub fn encode_integer(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;
    let (_, bit_len) = integer_shape(lower, upper)?;

    // Widen before subtracting so the full signed range remains representable.
    let offset = i128::from(value) - i128::from(lower);
    let offset = u64::try_from(offset).map_err(|_| Error::SizeOverflow)?;
    let byte_len = encoded_byte_len(bit_len)?;
    check_work_limit(bit_len, limits)?;

    // The range shape proves that this fixed-width offset fits in the output.
    let mut bytes = allocate_zeroed(byte_len, limits)?;
    write_bits(&mut bytes, offset, bit_len)?;
    Ok(Encoded { bytes, bit_len })
}

/// Encode one BOOLEAN as a complete CER TLV.
///
/// # Parameters
/// `value` is the ASN.1 boolean; `limits` bounds output bytes and wire-bit work.
///
/// # Returns
/// The minimal BOOLEAN TLV (`01 01 00` or `01 01 FF`) with total wire bits.
///
/// # Errors and exceptions
/// Returns a configured limit, checked-size, or allocation error. It raises no
/// exception and allocates only after both resource limits have been checked.
///
/// # Source, version, history, and example
/// Original source: CER primitive encoding contract in X.690 and the asn1c
/// BER primitive encoder. Version/date: Rust CER slice, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial CER encoder slice.
/// Example: `encode_boolean_cer(true, &Limits::default())?`.
pub fn encode_boolean_cer(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    let contents = [if value { 0xff } else { 0x00 }];
    encode_cer_tlv(0x01, &contents, limits)
}

/// Encode one NULL as its complete CER TLV.
///
/// # Parameters
/// `limits` bounds output bytes and total wire-bit work.
///
/// # Returns
/// The canonical NULL TLV `05 00` with `bit_len` equal to 16.
///
/// # Errors and exceptions
/// Returns a configured limit, checked-size, or allocation error. It raises no
/// exception and allocates only after both resource limits have been checked.
///
/// # Source, version, history, and example
/// Original source: CER primitive encoding contract in X.690 and the asn1c
/// BER primitive encoder. Version/date: Rust CER slice, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial CER encoder slice.
/// Example: `encode_null_cer(&Limits::default())?`.
pub fn encode_null_cer(limits: &Limits) -> Result<Encoded, Error> {
    encode_cer_tlv(0x05, &[], limits)
}

/// Encode a bounded signed INTEGER as a minimal CER TLV.
///
/// # Parameters
/// `value` is the signed value; `lower` and `upper` are inclusive ASN.1 bounds;
/// `limits` bounds output bytes and total wire-bit work.
///
/// # Returns
/// The INTEGER tag, minimal short-form length, and shortest signed two's-
/// complement content, with `bit_len` equal to the complete TLV size in bits.
///
/// # Errors and exceptions
/// Returns `InvalidBounds`, `ValueOutOfRange`, a configured limit, checked-size,
/// or allocation error. It raises no exception and allocates after validation.
///
/// # Source, version, history, and example
/// Original source: CER INTEGER rules in X.690 and the asn1c BER integer
/// encoder. Version/date: Rust CER slice, 2026-10-11. Responsible party:
/// asn1c maintainers. History: initial i64 CER encoder slice. Example:
/// `encode_integer_cer(-129, i64::MIN, i64::MAX, &Limits::default())?`.
pub fn encode_integer_cer(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;

    // Retain only the shortest signed two's-complement representation.
    let full = value.to_be_bytes();
    // state variable: marks the first byte of the minimal signed representation.
    let mut first = 0;
    while first + 1 < full.len() {
        let current = full[first];
        let next = full[first + 1];
        if (current == 0x00 && next & 0x80 == 0) || (current == 0xff && next & 0x80 != 0) {
            first += 1;
        } else {
            break;
        }
    }

    encode_cer_tlv(0x02, &full[first..], limits)
}

/// Assemble a short-form CER TLV and enforce output and work ceilings.
///
/// # Parameters
/// `tag` is the one-octet identifier; `contents` is the primitive payload;
/// `limits` supplies maximum output bytes and wire work bits.
///
/// # Returns
/// A complete TLV with a short-form definite length and total bits in `bit_len`.
///
/// # Errors and exceptions
/// Returns `InvalidEncoding` for content requiring a different length form,
/// `SizeOverflow`, `LimitExceeded`, or `AllocationFailed`. It raises no
/// exception; length and work arithmetic is checked before allocation.
///
/// # Source, version, history, and example
/// Original source: new safe Rust helper for CER primitive encoders.
/// Version/date: Rust CER slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial CER encoder slice. Example:
/// `encode_cer_tlv(0x05, &[], limits)` returns `[05 00]`.
fn encode_cer_tlv(tag: u8, contents: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    if contents.len() > 127 {
        return Err(Error::InvalidEncoding {
            reason: "CER primitive content requires a longer length form",
        });
    }

    // Compute and charge the complete octet-aligned TLV before allocation.
    let byte_len = contents.len().checked_add(2).ok_or(Error::SizeOverflow)?;
    let bit_len = byte_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;
    let mut bytes = allocate_zeroed(byte_len, limits)?;
    bytes[0] = tag;
    bytes[1] = u8::try_from(contents.len()).map_err(|_| Error::SizeOverflow)?;
    bytes[2..].copy_from_slice(contents);

    Ok(Encoded { bytes, bit_len })
}

/// Decode a constrained signed INTEGER prefix from UPER.
///
/// # Parameters
/// `input` is the encoded prefix; `lower` and `upper` are inclusive bounds;
/// `limits` bounds the entire slice and meaningful work bits.
///
/// # Returns
/// The decoded INTEGER plus the meaningful bit and byte prefix consumption.
///
/// # Errors and exceptions
/// Returns invalid bounds, truncation, malformed encodings or spare codes,
/// limit errors, or checked-size errors. It raises no exception; a zero-width
/// value requires a zero complete byte.
///
/// # Source, history, and example
/// Original source: constrained path in `INTEGER_decode_uper` and complete
/// handling in `skeletons/uper_decoder.c`. Version/date: Rust port slice,
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// constrained-UPER runtime. Example: `decode_integer(input, -2, 2, limits)`.
pub fn decode_integer(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    let (span, bit_len) = integer_shape(lower, upper)?;
    check_input_limit(input, limits)?;

    // C's complete decoder uses one zero byte for a value with no content bits.
    if bit_len == 0 {
        require_bytes(input, 1)?;
        check_work_limit(0, limits)?;
        if input[0] != 0 {
            return Err(Error::InvalidEncoding {
                reason: "nonzero complete-encoding filler for a singleton INTEGER",
            });
        }
        return Ok(Decoded {
            value: lower,
            consumed_bits: 0,
            consumed_bytes: 1,
        });
    }

    require_bits(input, bit_len)?;
    check_work_limit(bit_len, limits)?;
    let offset = u128::from(read_bits(input, bit_len)?);
    if offset > span {
        return Err(Error::InvalidEncoding {
            reason: "spare constrained INTEGER code",
        });
    }

    // The range check above makes this widened sum fall within the i64 bounds.
    let decoded = i128::from(lower) + i128::try_from(offset).map_err(|_| Error::SizeOverflow)?;
    let value = i64::try_from(decoded).map_err(|_| Error::InvalidEncoding {
        reason: "constrained INTEGER result is outside i64",
    })?;
    Ok(Decoded {
        value,
        consumed_bits: bit_len,
        consumed_bytes: encoded_byte_len(bit_len)?,
    })
}

/// Compute the offset span and minimum fixed UPER bit width for signed bounds.
///
/// # Parameters and returns
/// `lower` and `upper` are inclusive signed bounds. Returns the nonnegative
/// widened span and the number of bits needed to represent every offset.
///
/// # Errors and exceptions
/// Returns `InvalidBounds`; it raises no exception and cannot overflow `i128`.
///
/// # Source, history, and example
/// Original source: the range-width concept in `skeletons/INTEGER_uper.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: introduced to safely cover all i64 bounds. Example:
/// `integer_shape(i64::MIN, i64::MAX)?` returns span `u64::MAX`, width 64.
fn integer_shape(lower: i64, upper: i64) -> Result<(u128, usize), Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }

    // i128 subtraction safely represents the complete i64 signed span.
    let span = (i128::from(upper) - i128::from(lower)) as u128;
    let bit_len = if span == 0 {
        0
    } else {
        (u128::BITS - span.leading_zeros()) as usize
    };
    Ok((span, bit_len))
}

/// Check the complete supplied slice against the configured input ceiling.
///
/// # Parameters and returns
/// `input` is the whole caller-provided slice; `limits` supplies its byte cap.
/// Returns `Ok(())` when the slice fits.
///
/// # Errors and exceptions
/// Returns `LimitExceeded`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime budget helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `check_input_limit(&[0x80], limits)?`.
fn check_input_limit(input: &[u8], limits: &Limits) -> Result<(), Error> {
    enforce_limit(Resource::InputBytes, input.len(), limits.max_input_bytes)
}

/// Check the meaningful-bit budget for one primitive operation.
///
/// # Parameters and returns
/// `work_bits` is the planned meaningful work; `limits` supplies its ceiling.
/// Returns `Ok(())` when the planned work fits.
///
/// # Errors and exceptions
/// Returns `LimitExceeded`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime budget helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `check_work_limit(1, limits)?`.
fn check_work_limit(work_bits: usize, limits: &Limits) -> Result<(), Error> {
    enforce_limit(Resource::WorkBits, work_bits, limits.max_work_bits)
}

/// Return an error if a requested resource exceeds its configured ceiling.
///
/// # Parameters and returns
/// `resource` identifies the budget; `requested` is the amount used; `limit`
/// is the permitted maximum. Returns `Ok(())` if `requested <= limit`.
///
/// # Errors and exceptions
/// Returns `LimitExceeded`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime budget helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `enforce_limit(Resource::WorkBits, 1, 8)?`.
fn enforce_limit(resource: Resource, requested: usize, limit: usize) -> Result<(), Error> {
    if requested > limit {
        return Err(Error::LimitExceeded {
            resource,
            limit,
            requested,
        });
    }
    Ok(())
}

/// Require enough whole input bytes for a zero-width complete encoding.
///
/// # Parameters and returns
/// `input` is the available slice; `required_bytes` is the required prefix.
/// Returns `Ok(())` when that prefix exists.
///
/// # Errors and exceptions
/// Returns `NeedMoreBytes`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: complete-value behavior in `skeletons/uper_decoder.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial runtime slice. Example: `require_bytes(input, 1)?`.
fn require_bytes(input: &[u8], required_bytes: usize) -> Result<(), Error> {
    if input.len() < required_bytes {
        return Err(Error::NeedMoreBytes {
            required_bytes,
            available_bytes: input.len(),
        });
    }
    Ok(())
}

/// Require a meaningful number of bits in the supplied input prefix.
///
/// # Parameters and returns
/// `input` is the available slice; `required_bits` is the prefix width.
/// Returns `Ok(())` when enough bits are present.
///
/// # Errors and exceptions
/// Returns `NeedMoreBits` or `SizeOverflow`; it raises no exception.
///
/// # Source, history, and example
/// Original source: bit-availability checks in `skeletons/uper_decoder.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial runtime slice. Example: `require_bits(input, 1)?`.
fn require_bits(input: &[u8], required_bits: usize) -> Result<(), Error> {
    // Check before multiplication so even extreme caller slices cannot wrap.
    let available_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    if available_bits < required_bits {
        return Err(Error::NeedMoreBits {
            required_bits,
            available_bits,
        });
    }
    Ok(())
}

/// Compute the whole-byte buffer size for a meaningful bit count.
///
/// # Parameters and returns
/// `bit_len` is the number of meaningful bits. Returns the padded byte count,
/// using one byte for a complete zero-width encoding.
///
/// # Errors and exceptions
/// Returns `SizeOverflow`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: `uper_encode_to_new_buffer` in `skeletons/uper_encoder.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial runtime slice. Example: `encoded_byte_len(1)?`.
fn encoded_byte_len(bit_len: usize) -> Result<usize, Error> {
    if bit_len == 0 {
        return Ok(1);
    }
    bit_len
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(Error::SizeOverflow)
}

/// Allocate a zero-filled output buffer after checking limits fallibly.
///
/// # Parameters and returns
/// `byte_len` is the requested complete output size; `limits` supplies its cap.
/// Returns a zero-initialized vector of that size.
///
/// # Errors and exceptions
/// Returns `LimitExceeded` or `AllocationFailed`; it raises no exception.
///
/// # Source, history, and example
/// Original source: new safe Rust runtime allocation helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `allocate_zeroed(1, limits)?`.
fn allocate_zeroed(byte_len: usize, limits: &Limits) -> Result<Vec<u8>, Error> {
    enforce_limit(Resource::OutputBytes, byte_len, limits.max_output_bytes)?;
    let mut bytes = Vec::new();

    // Reserve fallibly before resizing the buffer to prevent implicit growth.
    bytes
        .try_reserve_exact(byte_len)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: byte_len,
        })?;
    bytes.resize(byte_len, 0);
    Ok(bytes)
}

/// Read up to 64 bits from the most significant end of a byte slice.
///
/// # Parameters and returns
/// `input` is the bit source; `bit_len` is the number of leading bits to read.
/// Returns those bits as a right-aligned `u64`.
///
/// # Errors and exceptions
/// Returns `InvalidEncoding`, `NeedMoreBits`, or `SizeOverflow`; it raises no
/// exception and performs no allocation.
///
/// # Source, history, and example
/// Original source: bit helpers in `skeletons/asn_bit_data.c` and constrained
/// helpers in `skeletons/uper_support.c`. Version/date: Rust port slice,
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `read_bits(&[0x80], 1)?` returns `1`.
fn read_bits(input: &[u8], bit_len: usize) -> Result<u64, Error> {
    if bit_len > u64::BITS as usize {
        return Err(Error::InvalidEncoding {
            reason: "bit width exceeds the integer accumulator",
        });
    }
    require_bits(input, bit_len)?;

    // state variable: accumulates bits in wire order without unchecked indexing.
    let mut value = 0_u64;
    for position in 0..bit_len {
        let byte = *input.get(position / 8).ok_or(Error::SizeOverflow)?;
        let shift = 7 - (position % 8);
        value = (value << 1) | u64::from((byte >> shift) & 1);
    }
    Ok(value)
}

/// Write up to 64 bits from a right-aligned value into a zero-filled output.
///
/// # Parameters and returns
/// `output` is the destination; `value` contains the bits; `bit_len` is their
/// width. Returns `Ok(())` after writing bits in most-significant-first order.
///
/// # Errors and exceptions
/// Returns `InvalidEncoding` or `SizeOverflow` for an invalid internal shape.
/// It raises no exception and performs no allocation.
///
/// # Source, history, and example
/// Original source: bit helpers in `skeletons/asn_bit_data.c` and constrained
/// helpers in `skeletons/uper_support.c`. Version/date: Rust port slice,
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `write_bits(&mut [0], 1, 1)` writes `0x80`.
fn write_bits(output: &mut [u8], value: u64, bit_len: usize) -> Result<(), Error> {
    if bit_len > u64::BITS as usize || output.len() < encoded_byte_len(bit_len)? {
        return Err(Error::InvalidEncoding {
            reason: "output buffer is too small for the bit width",
        });
    }

    // Leave the final byte's unused low bits zero as required by the encoding.
    for position in 0..bit_len {
        let source_shift = bit_len - position - 1;
        let bit = (value >> source_shift) & 1;
        if bit != 0 {
            let target = output.get_mut(position / 8).ok_or(Error::SizeOverflow)?;
            *target |= 1 << (7 - (position % 8));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test BOOLEAN wire values, prefix consumption, and permissive padding.
    ///
    /// Original source: UPER BOOLEAN contract in the C skeleton. Version/date:
    /// 2026-10-11. Inputs: true/false bytes and padding variants. Returns: no
    /// value; assertions fail on mismatch. Errors: none expected. Responsible
    /// party: asn1c maintainers. History: initial Rust runtime tests.
    /// Example: verifies true encodes as the leading bit `0x80`.
    #[test]
    fn boolean_vectors_and_padding() {
        let limits = Limits::default();
        let encoded = encode_boolean(true, &limits).expect("encode true");
        assert_eq!(encoded.bytes, [0x80]);
        assert_eq!(encoded.bit_len, 1);

        // Padding is ignored, but the first meaningful bit determines truth.
        for (byte, expected) in [(0x80, true), (0xff, true), (0x7f, false)] {
            let decoded = decode_boolean(&[byte], &limits).expect("decode boolean");
            assert_eq!(decoded.value, expected);
            assert_eq!(decoded.consumed_bits, 1);
            assert_eq!(decoded.consumed_bytes, 1);
        }
        assert_eq!(encode_boolean(false, &limits).unwrap().bytes, [0]);
    }

    /// Test BOOLEAN and NULL truncation and resource-budget boundaries.
    ///
    /// Original source: complete UPER decoding contract in the C skeleton.
    /// Version/date: 2026-10-11. Inputs: empty slices and zero limits. Returns:
    /// no value; assertions fail on mismatch. Errors: expected typed errors.
    /// Responsible party: asn1c maintainers. History: initial runtime tests.
    /// Example: empty BOOLEAN input must request one more bit.
    #[test]
    fn truncation_and_zero_budgets() {
        let defaults = Limits::default();
        assert!(matches!(
            decode_boolean(&[], &defaults),
            Err(Error::NeedMoreBits {
                required_bits: 1,
                available_bits: 0
            })
        ));
        assert!(matches!(
            decode_integer(&[], 0, 5, &defaults),
            Err(Error::NeedMoreBits {
                required_bits: 3,
                available_bits: 0
            })
        ));
        assert!(matches!(
            decode_null(&[], &defaults),
            Err(Error::NeedMoreBytes {
                required_bytes: 1,
                available_bytes: 0
            })
        ));

        // Empty work budgets reject BOOLEAN work but still permit zero-width NULL.
        let zero_work = Limits {
            max_work_bits: 0,
            ..defaults.clone()
        };
        assert!(matches!(
            encode_boolean(true, &zero_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        assert_eq!(encode_null(&zero_work).unwrap().bytes, [0]);
    }

    /// Test the zero-width complete encoding shared by NULL and singleton INTEGER.
    ///
    /// Original source: `uper_decode_complete` and NULL UPER operations in C.
    /// Version/date: 2026-10-11. Inputs: zero, nonzero, and empty bytes. Returns:
    /// no value; assertions fail on mismatch. Errors: malformed filler and
    /// truncation are expected. Responsible party: asn1c maintainers. History:
    /// initial runtime tests. Example: NULL encodes as `[0]`, with zero bits.
    #[test]
    fn null_and_singleton_zero_width_rules() {
        let limits = Limits::default();
        let null = encode_null(&limits).unwrap();
        assert_eq!(null.bytes, [0]);
        assert_eq!(null.bit_len, 0);
        let decoded_null = decode_null(&[0, 0xaa], &limits).unwrap();
        assert_eq!(decoded_null.value, ());
        assert_eq!(decoded_null.consumed_bits, 0);
        assert_eq!(decoded_null.consumed_bytes, 1);
        assert!(matches!(
            decode_null(&[1], &limits),
            Err(Error::InvalidEncoding { .. })
        ));

        // Singleton INTEGER also consumes the complete zero filler byte.
        let singleton = encode_integer(9, 9, 9, &limits).unwrap();
        assert_eq!(singleton.bytes, [0]);
        assert_eq!(singleton.bit_len, 0);
        assert_eq!(decode_integer(&[0], 9, 9, &limits).unwrap().value, 9);
        assert!(matches!(
            decode_integer(&[0x80], 9, 9, &limits),
            Err(Error::InvalidEncoding { .. })
        ));
    }

    /// Test signed constrained INTEGER offsets and the complete i64 range.
    ///
    /// Original source: bounded INTEGER path in `INTEGER_uper.c`. Version/date:
    /// 2026-10-11. Inputs: signed subrange and `i64::MIN..=i64::MAX`. Returns:
    /// no value; assertions fail on mismatch. Errors: none expected. Responsible
    /// party: asn1c maintainers. History: initial runtime tests. Example: full
    /// i64 bounds require exactly 64 meaningful bits without signed overflow.
    #[test]
    fn integer_signed_range_and_full_i64_span() {
        let limits = Limits::default();
        for value in -2..=2 {
            let encoded = encode_integer(value, -2, 2, &limits).unwrap();
            assert_eq!(encoded.bit_len, 3);
            let expected = [0x00, 0x20, 0x40, 0x60, 0x80][(value + 2) as usize];
            assert_eq!(encoded.bytes, [expected]);
            let mut with_suffix = encoded.bytes.clone();
            with_suffix.push(0xaa);
            let consumed = decode_integer(&with_suffix, -2, 2, &limits).unwrap();
            assert_eq!(
                (
                    consumed.value,
                    consumed.consumed_bits,
                    consumed.consumed_bytes
                ),
                (value, 3, 1)
            );
        }

        // Widened span math preserves both endpoints of the entire i64 domain.
        for value in [i64::MIN, -1, 0, i64::MAX] {
            let encoded = encode_integer(value, i64::MIN, i64::MAX, &limits).unwrap();
            assert_eq!(encoded.bit_len, 64);
            assert_eq!(encoded.bytes.len(), 8);
            if value == i64::MIN {
                assert_eq!(encoded.bytes, [0; 8]);
            } else if value == i64::MAX {
                assert_eq!(encoded.bytes, [0xff; 8]);
            }
            assert_eq!(
                decode_integer(&encoded.bytes, i64::MIN, i64::MAX, &limits)
                    .unwrap()
                    .value,
                value
            );
        }
    }

    /// Test invalid ranges, spare constrained codes, and truncated integers.
    ///
    /// Original source: constrained whole-number checks in the C skeleton.
    /// Version/date: 2026-10-11. Inputs: inverted bounds, spare codes, and short
    /// bit prefixes. Returns: no value; assertions fail on mismatch. Errors:
    /// expected typed errors. Responsible party: asn1c maintainers. History:
    /// initial runtime tests. Example: range 0..=5 has invalid three-bit codes 6-7.
    #[test]
    fn malformed_and_spare_integer_codes() {
        let limits = Limits::default();
        assert!(matches!(
            validate_integer(0, 1, 0),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            encode_integer(6, 0, 5, &limits),
            Err(Error::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            decode_integer(&[0xc0], 0, 5, &limits),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_integer(&[0xff], 0, 511, &limits),
            Err(Error::NeedMoreBits {
                required_bits: 9,
                available_bits: 8
            })
        ));
    }

    /// Exhaust all first-byte patterns for a constrained three-bit INTEGER.
    ///
    /// Original source: deterministic malformed-input campaign for this runtime.
    /// Version/date: 2026-10-11. Inputs: all 256 byte values. Returns: no value;
    /// assertions fail on mismatch. Errors: codes above the range must be
    /// rejected. Responsible party: asn1c maintainers. History: initial tests.
    /// Example: low padding variations preserve the same decoded integer.
    #[test]
    fn integer_byte_pattern_mutation_loop() {
        let limits = Limits::default();
        for byte in 0_u8..=u8::MAX {
            let code = i64::from(byte >> 5);
            let result = decode_integer(&[byte], 0, 5, &limits);
            if code <= 5 {
                let decoded = result.expect("in-range constrained code");
                assert_eq!(decoded.value, code);
                assert_eq!(decoded.consumed_bits, 3);
            } else {
                assert!(matches!(result, Err(Error::InvalidEncoding { .. })));
            }
        }
    }

    /// Test decoded mapping and input, output, and work budget enforcement.
    ///
    /// Original source: new runtime result/budget contract. Version/date:
    /// 2026-10-11. Inputs: constrained BOOLEAN and INTEGER operations with small
    /// limits. Returns: no value; assertions fail on mismatch. Errors: budget
    /// errors are expected. Responsible party: asn1c maintainers. History:
    /// initial runtime tests. Example: map preserves the original bit counts.
    #[test]
    fn limits_and_mapped_consumption() {
        let defaults = Limits::default();
        let decoded = decode_boolean(&[0x80], &defaults).unwrap();
        let mapped = decoded.map(|value| if value { 7 } else { -7 });
        assert_eq!(mapped.value, 7);
        assert_eq!(mapped.consumed_bits, 1);
        assert_eq!(mapped.consumed_bytes, 1);

        // Independent caps fail before bit processing or allocation.
        let no_input = Limits {
            max_input_bytes: 0,
            ..defaults.clone()
        };
        let no_output = Limits {
            max_output_bytes: 0,
            ..defaults.clone()
        };
        let too_little_work = Limits {
            max_work_bits: 2,
            ..defaults.clone()
        };
        let exact_limits = Limits {
            max_input_bytes: 1,
            max_output_bytes: 1,
            max_work_bits: 3,
        };
        assert!(decode_boolean(&[0x80], &exact_limits).is_ok());
        assert!(encode_boolean(true, &exact_limits).is_ok());
        assert!(encode_integer(1, 0, 7, &exact_limits).is_ok());
        assert!(encode_null(&exact_limits).is_ok());
        assert!(matches!(
            decode_boolean(&[0x80], &no_input),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        assert!(matches!(
            encode_null(&no_output),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert!(matches!(
            encode_integer(1, 0, 7, &too_little_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        assert!(validate_integer(5, 0, 5).is_ok());
        assert!(matches!(
            validate_integer(6, 0, 5),
            Err(Error::ValueOutOfRange { .. })
        ));
    }

    /// Test canonical CER BOOLEAN and NULL encodings and their wire-bit counts.
    ///
    /// Original source: X.690 CER primitive encoding rules. Version/date:
    /// 2026-10-11. Inputs: both BOOLEAN values and NULL. Returns: no value;
    /// assertions fail on mismatch. Errors: none expected. Responsible party:
    /// asn1c maintainers. History: added with the CER primitive slice.
    /// Example: TRUE must encode with content octet `FF`.
    #[test]
    fn cer_boolean_and_null_vectors() {
        let limits = Limits::default();
        let true_value = encode_boolean_cer(true, &limits).unwrap();
        assert_eq!(true_value.bytes, [0x01, 0x01, 0xff]);
        assert_eq!(true_value.bit_len, 24);
        let false_value = encode_boolean_cer(false, &limits).unwrap();
        assert_eq!(false_value.bytes, [0x01, 0x01, 0x00]);
        assert_eq!(false_value.bit_len, 24);
        let null_value = encode_null_cer(&limits).unwrap();
        assert_eq!(null_value.bytes, [0x05, 0x00]);
        assert_eq!(null_value.bit_len, 16);
    }

    /// Test minimal CER INTEGER content at sign-boundary and i64 endpoints.
    ///
    /// Original source: X.690 CER INTEGER encoding rules. Version/date:
    /// 2026-10-11. Inputs: 0, signed-byte boundaries, and both i64 endpoints.
    /// Returns: no value; assertions fail on mismatch. Errors: none expected.
    /// Responsible party: asn1c maintainers. History: added with CER support.
    /// Example: 128 requires a leading zero content octet.
    #[test]
    fn cer_integer_minimal_signed_vectors() {
        let limits = Limits::default();
        let vectors: &[(i64, &[u8])] = &[
            (0, &[0x02, 0x01, 0x00]),
            (127, &[0x02, 0x01, 0x7f]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (-128, &[0x02, 0x01, 0x80]),
            (-129, &[0x02, 0x02, 0xff, 0x7f]),
            (-1, &[0x02, 0x01, 0xff]),
            (i64::MIN, &[0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            (
                i64::MAX,
                &[0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        // Every fixture also checks that complete wire octets determine bit_len.
        for (value, expected) in vectors {
            let encoded = encode_integer_cer(*value, i64::MIN, i64::MAX, &limits)
                .expect("encode CER INTEGER");
            assert_eq!(encoded.bytes, *expected, "value {value}");
            assert_eq!(encoded.bit_len, expected.len() * 8, "value {value}");
        }
    }

    /// Test CER INTEGER bounds and exact output/work ceilings.
    ///
    /// Original source: runtime constraint checks and CER resource contract.
    /// Version/date: 2026-10-11. Inputs: invalid bounds, out-of-range values,
    /// and exact or insufficient limits. Returns: no value; assertions fail on
    /// mismatch. Errors: typed constraint and resource errors are expected.
    /// Responsible party: asn1c maintainers. History: added with CER support.
    /// Example: a three-byte BOOLEAN succeeds with 24 work bits.
    #[test]
    fn cer_validation_and_resource_limits() {
        let limits = Limits {
            max_input_bytes: 0,
            max_output_bytes: 3,
            max_work_bits: 32,
        };
        assert_eq!(encode_boolean_cer(true, &limits).unwrap().bit_len, 24);
        assert!(matches!(
            encode_null_cer(&limits),
            Ok(Encoded { bit_len: 16, .. })
        ));
        assert!(matches!(
            encode_integer_cer(128, i64::MIN, i64::MAX, &limits),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                limit: 3,
                requested: 4,
            })
        ));
        assert!(matches!(
            encode_integer_cer(2, 3, 1, &limits),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            encode_integer_cer(6, 0, 5, &limits),
            Err(Error::ValueOutOfRange { .. })
        ));

        // Charge work for the complete TLV, including tag and length octets.
        let too_little_work = Limits {
            max_work_bits: 23,
            ..limits.clone()
        };
        assert!(matches!(
            encode_boolean_cer(true, &too_little_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 24,
                ..
            })
        ));
        let too_little_integer_work = Limits {
            max_output_bytes: 4,
            max_work_bits: 31,
            ..limits.clone()
        };
        assert!(matches!(
            encode_integer_cer(128, i64::MIN, i64::MAX, &too_little_integer_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 32,
                ..
            })
        ));
        let no_null_output = Limits {
            max_output_bytes: 1,
            ..limits
        };
        assert!(matches!(
            encode_null_cer(&no_null_output),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                requested: 2,
                ..
            })
        ));
    }
}
