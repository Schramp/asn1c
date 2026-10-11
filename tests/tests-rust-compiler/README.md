# Generated Rust compiler tests

`check-rust-backend.sh` exercises the first generated Rust slice in a temporary
directory. It checks BOOLEAN, NULL, bounded and singleton INTEGER, and a full
i64-range INTEGER using UPER. The Rust crate is built offline with its vendored
runtime. A separately generated C project exchanges live UPER vectors in both
directions with the generated Rust crate. C is a comparison implementation,
while fixed vectors and Rust-side malformed-input checks provide independent
checks.

The exact scope and the families not implemented by this slice are recorded
in [`coverage.json`](coverage.json). This suite does not claim codec-wide or
type-wide parity. If Cargo or `rustc` is unavailable, Automake marks the test
skipped with status 77.

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
