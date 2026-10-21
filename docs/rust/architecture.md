# ADR: Generate Rust codecs while retaining the C frontend

**Status:** Accepted conversion direction; initial UPER and CER slices implemented.
**Date:** 2026-10-11.
**Deciders:** Repository maintainer; Sol supervises Luna implementation agents.
**Baseline:** `5a0ccf24ede9b176e8fd76861bf4855ed95f5105`.

## Context

The first stage must produce usable Rust codecs and convert appropriate runtime
and generated-code tests. The user selected all current codecs delivered
incrementally, with `std` and safe Rust. Rewriting the ASN.1 parser, semantic
fixer, and command-line application in Rust is a later stage.

The existing language seam is incomplete. The target enum and dispatch table in
[asn1c_lang.h](../../libasn1compiler/asn1c_lang.h) and
[asn1c_lang.c](../../libasn1compiler/asn1c_lang.c) support C only.
[asn1_compile](../../libasn1compiler/asn1compiler.c) explicitly selects C, applies
encoding controls, walks fixed expressions, and invokes a C-oriented output
writer. The streams in [asn1c_out.h](../../libasn1compiler/asn1c_out.h), the
[constraint emitter](../../libasn1compiler/asn1c_constraint.c), the
[IOC emitter](../../libasn1compiler/asn1c_ioc.c), and the
[output saver](../../libasn1compiler/asn1c_save.c) contain C-specific behavior.

Runtime implementations span primitives, constructed types, constraints,
bit/octet processing, and codec-specific helpers; they are listed in
[skeletons/Makefile.am](../../skeletons/Makefile.am).
[README.md](../../README.md) lists BER decoding/DER encoding, OER, UPER, APER,
XER, JER, and CBOR. That table is an inventory starting point, not proof that
every type, direction, or canonical variant is implemented. For example,
[CI](../../.github/workflows/c-cpp.yml) explicitly limits PKIX JER testing to
encoding because of ANY open types.

The C [BER decoder](../../skeletons/ber_decoder.h) remains permissive for
`ATS_BER` and `ATS_DER`. `ATS_CER` uses the strict
[CER decoder](../../skeletons/cer_decoder.h), which re-encodes with the
descriptor-driven CER encoder and requires byte-identical input. Rust adds an
initial CER encoding and strict decoding slice for BOOLEAN, NULL, and bounded
nonextensible INTEGER values fitting `i64`. See the
[binary audit](../binary-codec-support.md).

## Decision

Add an opt-in Rust backend to the existing C compiler. Reuse the fixed semantic
tree, module/import resolution, tags, parameter specialization, PDU selection,
and encoding-control interpretation. Keep backend emission and output packaging
separate. Extract small language-neutral semantic helpers where existing helpers
combine semantic analysis with C emission; do not make Rust parse generated C.

Create a native Rust runtime at `rust/asn1c-runtime/`. The initial UPER
primitive implementation and CER encoding and strict decoding for BOOLEAN,
NULL, and bounded nonextensible `i64` INTEGER values are present; remaining
coverage is a conversion target. It implements codec behavior without calling C codecs.
Keep the C runtime as the compatibility baseline and differential test
participant.
Generated Rust should use typed structs/enums, checked semantic metadata, and
small codec traits or typed helpers. It should not copy raw C descriptor offsets,
`void *` operations, pointer sentinels, or mutable global inheritance tables.

Generate explicit codec implementations for each supported type/codec pair.
Share primitive encoding algorithms, cursor management, length handling, and
validation in the runtime. Keep field ordering, tags, defaults, extension maps,
and open-type selection visible in generated metadata or typed code. A small
internal semantic representation may normalize these facts, but introducing a
general-purpose interchange format is not a prerequisite for the first slice.

Both runtime and generated crates prohibit `unsafe` code. Third-party
dependencies require an explicit inventory and review: a prohibition in this
repository does not establish that dependency internals contain no `unsafe`.
Start with no runtime dependencies if the first slice can meet its requirements;
review any bigint, XML, JSON, or CBOR dependency before adding it.

## Generated output and compiler behavior

The user selected `--rust` as a major top-level flag. It switches the complete
generation path: Rust types, codec implementations, runtime assets, naming,
output writer, and Cargo build metadata. C remains the default without this
flag. Reject incompatible C-only output/layout modes rather than applying them
to Rust output. Preserve shared ASN.1 parsing and semantic processing.

Use existing `-gen-*`/`-no-gen-*` syntax for codec selection. Track explicit
selection separately from legacy default flags. `--rust` currently defaults to
UPER and CER encoding and reports its support boundary. `-no-gen-UPER` permits
CER-only output. Explicitly requested unsupported codecs or schema features
are errors; never silently drop them.
As families are qualified, add them to the Rust default until all current
families are supported. Shared frontend inspection remains available in C mode;
incompatible inspection/output combinations with `--rust` receive diagnostics.

By default, generate a self-contained Cargo project with a copied runtime source
crate under `runtime/` and a local path dependency. Include only required sources
and preserve their licensing notices. This supports offline consumption and
matches the existing copied-skeleton deployment model. A separately distributed
runtime with a pinned compatible version is a later packaging option. A runtime
with external dependencies must vendor or otherwise provide them before claiming
that generated projects build offline.

Use module-qualified Rust names and deterministic paths. Resolve keyword,
normalized-identifier, case-insensitive filename, and runtime-name collisions.
Preflight supported features, names, paths, and options before writing output.
Write into a staging directory and publish only a complete output set, with an
owned-file manifest and failure cleanup. Do not overwrite unrelated user files.
Define repeated generation and changed-schema cleanup explicitly in the writer.

## Safety and compatibility contract

Wire compatibility and semantic compatibility are the target; C layout or ABI
compatibility is not required. Constraints remain attached to their originating
schema even when several types share Rust storage. Fixed-width integers are
selected from schema bounds, not the compiler host's C `long`; unbounded ASN.1
integers need an arbitrary-precision representation.

Malformed bytes, invalid values, and inconsistent descriptors must return typed
errors. Check lengths, shifts, cursor arithmetic, and limits before advancing,
accumulating, or allocating. A shared decode context carries depth, total input,
allocation, collection, extension, and work budgets across nested/open-type
decodes; nested calls must not reset budgets. Bound encode work and output too.
Use fallible allocation on input-driven paths and avoid input-driven `unwrap`,
`expect`, indexing panics, and recursion without depth checks.

Safe Rust alone does not establish absence of allocation aborts, stack overflow,
or denial of service. Review formatting, cloning, temporary buffers, canonical
sorting, and destruction of recursively owned values as part of this contract.
Limits and APIs must be exercised with very small budgets and deeply nested
inputs. The implementation must document residual process-level allocation
failure limitations rather than promise absolute crash immunity.

Expose complete-message decoding separately from prefix or incremental decoding.
PER consumption is measured in bits; other codec consumption is measured in the
appropriate byte/text unit. Incomplete input differs from malformed input, and
an incremental decoder must preserve progress without repeated unbounded
reparsing or inconsistent state. Exact streaming interfaces are frozen in the
foundation milestone after a small prototype and review.

Unknown extensions have an explicit decode policy. Preserve existing successful
skip/relay behavior where supported, using typed unknown ordinals or codec-tagged
opaque data rather than `LONG_MAX` markers. Strict rejection remains available.
Do not promise relay after a decoder intentionally skips bytes, and do not relay
opaque encodings into a different transfer syntax without a semantic value.

Standards correctness and current C behavior are separate evidence. Differential
tests can detect divergence but can share a defect. Each ported rule needs an
identified governing rule or justified repository policy and independent vectors
where feasible. JER duplicate-member rejection is repository policy; do not
invent a normative first/last-wins requirement.

## Options considered

| Option | Benefit | Cost or limit | Decision |
| --- | --- | --- | --- |
| Rust backend and runtime | Reuses fixed semantics | Two backends to maintain | Select |
| Rewrite entire compiler | One final language | Larger frontend risk; delays codecs | Defer |
| Bind Rust to C codecs | Fast prototype | C runtime and unsafe boundary | Reject |
| Translate mechanically | Recognizable algorithms | Pointer/state assumptions | Source reference only |
| Adopt another runtime | Potential reuse | Semantic/codec audit required | Evaluate components |

The chosen approach still has substantial cost: ASN.1 constraints, canonical
ordering, extension handling, and open-type dispatch cannot be replaced by Rust
serialization derives without a semantic audit. No speed improvement is assumed.

## Consequences and action items

The C tool remains necessary to generate Rust during stage one. Consumers of the
generated project need a Rust toolchain; C-only consumers retain their existing
requirements. Cargo support is opt-in for repository builds, while dedicated CI
always exercises the qualified Rust target.

- [ ] Freeze runtime/generator/test contracts before independent coding.
- [ ] Implement the staged work packages in the [plan](stage-one-plan.md).
- [ ] Maintain a type/codec/direction/variant/feature coverage ledger.
- [ ] Preserve and extend C tests while adding Rust counterparts.
- [ ] Qualify standalone generation, distribution, and all codec families.
- [ ] Revisit compiler/frontend conversion after the stage-one acceptance gate.
