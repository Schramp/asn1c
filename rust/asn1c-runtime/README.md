# asn1c-runtime

`asn1c-runtime` is the initial safe Rust runtime crate for Rust code generated
by asn1c. This first implementation provides constrained UPER primitives for
BOOLEAN, NULL, and bounded INTEGER values, plus CER encoding for those same
generated primitive types. It is a foundation, not a complete ASN.1 runtime or
a claim of codec parity.

The crate uses Rust 2021 and only the standard library. It forbids unsafe Rust.
Input, output, and bit-work limits are caller-configurable through `Limits`;
the defaults are 1 MiB for input, 1 MiB for output, and 8 MiBits of work per
operation. CER encoding uses the output and work limits; input limits apply to
the entire supplied decode slice, including any unused suffix. Prefix decoders
report both meaningful bits and whole bytes consumed.

```rust
use asn1c_runtime::{decode_boolean, encode_boolean, encode_boolean_cer, Limits};

let limits = Limits::default();
let encoded = encode_boolean(true, &limits)?;
assert_eq!(encoded.bytes, [0x80]);
assert_eq!(encoded.bit_len, 1);

let decoded = decode_boolean(&encoded.bytes, &limits)?;
assert!(decoded.value);
assert_eq!(decoded.consumed_bits, 1);

let cer = encode_boolean_cer(true, &limits)?;
assert_eq!(cer.bytes, [0x01, 0x01, 0xff]);
assert_eq!(cer.bit_len, 24);
# Ok::<(), asn1c_runtime::Error>(())
```

`Encoded.bit_len` excludes final-byte padding. BOOLEAN decoding reads the most
significant bit and preserves the C decoder's permissive handling of the
remaining padding bits. A complete zero-width UPER value is represented by one
zero byte with `bit_len == 0`; decoding an empty slice requests more input, and
a nonzero zero-width byte is invalid. Constrained INTEGER decoding rejects
spare bit patterns outside the declared range. CER results contain complete
TLV bytes, so `bit_len` equals `bytes.len() * 8`. This runtime slice provides no
CER decoder. The runtime exposes `encode_boolean_cer`, `encode_null_cer`, and
`encode_integer_cer`; generated Rust wrappers expose an encode-only
`encode_cer` method when CER is selected.

Run the crate checks from the repository root:

```sh
cargo fmt --manifest-path rust/asn1c-runtime/Cargo.toml --check
cargo test --offline --manifest-path rust/asn1c-runtime/Cargo.toml
cargo clippy --offline --manifest-path rust/asn1c-runtime/Cargo.toml \
  --all-targets -- -D warnings
```
