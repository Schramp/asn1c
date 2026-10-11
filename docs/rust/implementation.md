# Initial Rust implementation

This is the first slice of the [stage-one plan](stage-one-plan.md), implemented
with three supervised Luna agents. The full conversion remains incomplete.
The existing C parser and semantic fixer feed a separate Rust output backend.
The matching runtime uses `std`, forbids unsafe Rust, and has no dependencies.

## Compiler mode and output

`--rust` selects the complete Rust output mode. It generates a Cargo package
with typed Rust bindings, UPER methods, and a local copy of the Rust runtime.
The Rust mode defaults to its currently implemented codec set, initially UPER.
An explicit request for an unavailable codec fails before publishing output;
the C compiler's default codec set does not silently select Rust codecs.

```sh
asn1c --rust -D generated schema.asn1
cargo check --offline --manifest-path generated/Cargo.toml
```

For a source checkout, select its matching assets explicitly when necessary:

```sh
./asn1c/asn1c --rust -S skeletons -D generated schema.asn1
```

The output contains `Cargo.toml`, `src/lib.rs`, one Rust source file per ASN.1
module, and `runtime/` with a Cargo path dependency. The generated package is
named `asn1c-generated`. Module names are normalized for Rust and namespace
collisions are diagnosed. The default output directory is `asn1c-rust`.

An ownership manifest records generated files. Output is staged before
publication. Regeneration accepts an empty directory or a prior generated
directory containing only owned files; unrelated files, build artifacts, and
symlinks cause a failure that preserves the prior directory. Generate into a
fresh directory after adding application code or running Cargo there.

## Implemented boundary

| Feature | First slice |
| --- | --- |
| Top-level BOOLEAN | UPER encoding and prefix decoding |
| Top-level NULL | UPER complete zero-width encoding and prefix decoding |
| Direct bounded INTEGER | Nonextensible finite signed i64 range; UPER codecs |
| Runtime limits | Input bytes, output bytes, and meaningful bit work |
| BER/DER/CER, OER, APER, XER, JER, CBOR | Planned; unavailable in Rust mode |
| Collections, strings, ENUMERATED, aliases, imports, tagged types | Planned; rejected in this slice |
| Encoding controls, information objects, parameterized types | Planned; rejected in this slice |

BOOLEAN and INTEGER wrappers expose constructors, value getters, and
`encode_uper` / `decode_uper` methods. INTEGER construction checks the declared
range. NULL is a unit struct. Codecs return typed errors for truncation,
malformed codes, invalid constraints, exceeded limits, or allocation failure.

`Encoded` carries output bytes and meaningful bit length. `Decoded<T>` carries
the value and consumed bits and bytes. Prefix decoding may leave a suffix;
input limits cover the entire supplied slice. For C compatibility, unused
padding bits are accepted. NULL and singleton INTEGER complete encodings use
one zero byte with zero meaningful bits; empty input requests more data and a
nonzero filler byte is rejected.

The defaults are 1 MiB input, 1 MiB output, and 8 MiBits of work per primitive
operation. Applications can supply smaller or larger finite limits. The
[runtime README](../../rust/asn1c-runtime/README.md) documents the existing API.

## Validation and next work

The runtime has tests for independent vectors, signed and full-i64 endpoints,
singleton ranges, spare codes, truncation, padding, consumption, and limits.
A deterministic mutation test exhausts every first-byte pattern of a small
constrained INTEGER. The compiler integration harness builds generated Cargo
packages offline and checks CLI failures, schema gates, output ownership,
repeat generation, and C interoperability. Rust CI checks runtime formatting,
unit tests, Clippy, generated codecs, and installed runtime packaging.

Local acceptance on 2026-10-11 passed seven runtime tests, nine generated Rust
tests, seven C compiler regression scripts, and 27 C smoke scripts. Eight wire
vectors were exchanged in each direction between generated C and Rust codecs.
The separately committed CER dispatch correction passed 47 skeleton tests.
A staged installation generated a BOOLEAN/NULL/bounded INTEGER crate that
built offline using its installed runtime assets. The new CI workflow remains
subject to execution on the hosted runner.

These are first-slice gates. The [test migration plan](testing.md) remains the
stage-wide target; additional primitive types and constructed UPER types come
next, followed by the remaining codec families. No whole-runtime parity or
minimum Rust version is claimed by this initial implementation.
