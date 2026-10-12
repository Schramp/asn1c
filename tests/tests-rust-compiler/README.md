# Generated Rust compiler tests

`check-rust-backend.sh` exercises the first generated Rust slice in a temporary
directory. Its ten generated conformance cases cover BOOLEAN, NULL, bounded and
singleton INTEGER, and a full `i64`-range INTEGER with UPER. It checks CER
encodings for BOOLEAN, NULL, and bounded signed `i64` INTEGER against fixed
vectors; selected `Count`, `Singleton`, and `SignBounds` values are also
compared with a separately generated C encoder. Rust-produced CER TLVs are
passed to the generated C decoder for semantic checks. Rust emits no CER
decoder. The Rust crate builds offline with its copied runtime.

The harness covers codec selection as well as wire behavior. The default Rust
mask contains UPER and CER; `-gen-UPER` retains both, `-no-gen-UPER` selects
CER-only output, and `-no-gen-CER` leaves UPER enabled. CER-only generation is
also checked with explicit `-gen-CER -no-gen-UPER`, and `-no-gen-BER` does not
change the independent Rust codec mask. Disabling both codecs and requesting
unsupported codecs are rejected before output publication. The generated
dual-codec, CER-only, and UPER-only APIs are each checked to omit `decode_cer`.

C remains a comparison implementation rather than a protocol oracle. Fixed
vectors and Rust-side malformed-input checks provide independent checks. The
exact supported scope and unimplemented families are listed in
[`coverage.json`](coverage.json); the harness does not claim codec-wide or
type-wide parity.

If Cargo or `rustc` is unavailable, Automake marks the test skipped with status
77.

Negative compiler cases cover unsupported types, constraints, selectors, and
name collisions before output publication. Destination checks cover unrelated
files, interior symlinks, traversal entries, oversized ownership manifests,
and deterministic regeneration. Runtime-name overlaps are positive compilation
cases. `LIB`, `Core`, and `Asn1cRuntime` modules are checked for safe filenames
and pass an offline Cargo check.

The harness is registered in the normal test suite. It can also be run from a
configured build tree with:

```sh
make -C tests/tests-rust-compiler check
```
