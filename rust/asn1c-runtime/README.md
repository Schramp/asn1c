# asn1c-runtime

`asn1c-runtime` is the initial safe Rust runtime crate for Rust code generated
by asn1c. This first implementation provides constrained UPER primitives for
BOOLEAN, NULL, and bounded INTEGER values. It is a foundation, not a complete
ASN.1 runtime or a claim of codec parity.

The crate uses Rust 2021 and only the standard library. It forbids unsafe Rust.
Input, output, and bit-work limits are caller-configurable through `Limits`;
the defaults are 1 MiB for input, 1 MiB for output, and 8 MiBits of work per
operation. Input limits apply to the entire supplied slice, including any
unused suffix. Prefix decoders report both meaningful bits and whole bytes
consumed.

```rust
use asn1c_runtime::{decode_boolean, encode_boolean, Limits};

let limits = Limits::default();
let encoded = encode_boolean(true, &limits)?;
assert_eq!(encoded.bytes, [0x80]);
assert_eq!(encoded.bit_len, 1);

let decoded = decode_boolean(&encoded.bytes, &limits)?;
assert!(decoded.value);
assert_eq!(decoded.consumed_bits, 1);
# Ok::<(), asn1c_runtime::Error>(())
```

`Encoded.bit_len` excludes final-byte padding. BOOLEAN decoding reads the most
significant bit and preserves the C decoder's permissive handling of the
remaining padding bits. A complete zero-width UPER value is represented by one
zero byte with `bit_len == 0`; decoding an empty slice requests more input, and
a nonzero zero-width byte is invalid. Constrained INTEGER decoding rejects
spare bit patterns outside the declared range.

Run the crate checks from the repository root:

```sh
cargo fmt --manifest-path rust/asn1c-runtime/Cargo.toml --check
cargo test --offline --manifest-path rust/asn1c-runtime/Cargo.toml
cargo clippy --offline --manifest-path rust/asn1c-runtime/Cargo.toml \
  --all-targets -- -D warnings
```
