# Rust conversion: first stage

This directory defines the first stage of converting asn1c to Rust: generate Rust
types and codecs backed by a Rust implementation of the runtime currently in
`skeletons/`, and migrate the relevant codec tests. The compiler frontend remains
in C during this stage. The Rust target is a proposal; this documentation does
not add a Rust runtime or a working Rust generation option.

The user confirmed on 2026-10-11 that this change should commit documentation
only, cover all current codecs incrementally, and use safe Rust with `std`.

Start with the [architecture decision](architecture.md) and
[implementation plan](stage-one-plan.md). Supporting designs describe the
[runtime](runtime.md), [code generator](code-generation.md), and
[test migration](testing.md).

The baseline inspected for this plan is commit
`5a0ccf24ede9b176e8fd76861bf4855ed95f5105` on `vlm_master`.
Implementation must recheck that baseline against subsequent changes, especially
security fixes, schema semantics, and the test inventory.

Sol supervises implementation and accepts integration; three Luna agents own
bounded coding assignments. The plan specifies their dependencies, file
ownership, handoff requirements, and acceptance gates. No implementation agents
should treat a proposed interface in these documents as an existing API.
