# Rust code generation architecture

**Status:** Proposed plan; documentation only
**Date:** 2026-10-11
**Baseline:** `5a0ccf24ede9b176e8fd76861bf4855ed95f5105`
**Scope:** An opt-in Rust target that reuses the C parser and fixer, emits a
standalone Cargo crate with a safe Rust runtime, and adds codec support in
reviewed increments.

## Decision summary

Keep parsing, module assembly, standard-module loading, and semantic fixing in
the existing C front end. After `asn1f_process()` succeeds, select a backend
that lowers the fixed ASN.1 tree. Preserve C as the default target and keep its
current output and option behavior. Add Rust as an opt-in target; its generator
must produce Rust files and Cargo metadata through a Rust-specific writer and
runtime rather than reuse the C source emitter or C skeleton dependency list.

The target includes all current encoding families over time: BER/DER, UPER,
APER, OER, XER, JER, and CBOR. During early Rust development, the user must
select at least one codec explicitly. Each selected codec and requested schema
feature must pass capability checks before any output is published. Once the
Rust target is qualified, its default may enable every qualified codec.

The generated crate includes a copy of the matching runtime sources under its
own directory and refers to it with a Cargo path dependency. Both runtime and
generated code forbid unsafe code. This restriction does not automatically
cover third-party crates; audit their safety and licenses separately. Start
without runtime dependencies if the first slice can meet its requirements;
review any later bigint, XML, JSON, or CBOR dependency. Claim offline builds
only when every dependency is included or vendored. A future shared-runtime
option must validate a compatible runtime version and API.

## Existing pipeline and backend coupling

The command-line driver parses all input modules, merges them, establishes
standard namespaces, and runs the fixer before invoking `asn1_compile()`.
That is the right shared front-end boundary: Rust generation can consume the
resolved tree, including references, specializations, tags, constraints,
extension markers, imports, and information-object metadata. See the driver
flow at [`asn1c/asn1c.c`](../../asn1c/asn1c.c#L469),
[`asn1c/asn1c.c`](../../asn1c/asn1c.c#L522), and
[`asn1c/asn1c.c`](../../asn1c/asn1c.c#L534).

There is a small target-language dispatch table, but it is not a decoupled
backend interface. [`asn1c_lang.h`](../../libasn1compiler/asn1c_lang.h#L6)
stores one callback per expression kind, and
[`asn1c_lang.c`](../../libasn1compiler/asn1c_lang.c#L7) accepts only C.
[`asn1compiler.c`](../../libasn1compiler/asn1compiler.c#L31) initializes C
name-clash tracking and unconditionally selects C. Its visitors write to
[`asn1c_out.h`](../../libasn1compiler/asn1c_out.h#L14)'s C-oriented include,
declaration, table, and code streams. The C visitors in
[`asn1c_C.c`](../../libasn1compiler/asn1c_C.c#L152) call C type naming,
descriptor, and skeleton helpers directly.

The writer is also C-specific.
[`asn1c_save.c`](../../libasn1compiler/asn1c_save.c#L620) creates one `.c` and
one `.h` per generated top-level type, writes C preambles and include guards,
and emits C support files and Makefile fragments.
[`asn1c_fdeps.c`](../../libasn1compiler/asn1c_fdeps.c#L76) reads a tagged
dependency format. Its entries in
[`file-dependencies`](../../skeletons/file-dependencies#L1) name C `.c` and
`.h` skeleton files. Rust can share language-neutral traversal metadata; it
needs a separate output model, naming pass, dependency plan, and serializer.

Information-object table processing has reusable semantic inputs, but its
current lowering is C output:
[`asn1c_ioc.c`](../../libasn1compiler/asn1c_ioc.c#L77) resolves a table and
[`asn1c_ioc.c`](../../libasn1compiler/asn1c_ioc.c#L418) emits values through
the C output stream. Encoding controls are applied before backend generation
by [`asn1c_encoding.c`](../../libasn1compiler/asn1c_encoding.c#L185), while
custom XER/JER operation generation is in the C visitor. Extract shared
semantic helpers where they are coupled to C output; then apply each encoding
control only in Rust codecs that implement its behavior.

## Proposed integration points

1. Keep `asn1p_parse_file()`, module merging, standard namespace setup, and
   `asn1f_process()` in `asn1c/asn1c.c`. No Rust parser or second semantic
   fixer is proposed.
2. Extract language-option parsing and compile dispatch before modifying the
   large CLI `main()` in [`asn1c/asn1c.c`](../../asn1c/asn1c.c#L107). Keep each
   changed critical callable at or below 200 lines and McCabe complexity 20.
   Split pre-existing oversized callables that must change; do not waive the
   source limits or broaden this into unrelated cleanup. Preserve C behavior
   with existing regressions.
3. Add a target selection value to compiler options and pass it into
   `asn1_compile()`. Replace the unconditional C selection with an early
   backend selection and capability-validation step.
4. Keep existing C callback registration, C naming, streams, skeleton copying,
   Makefile output, and generated files on the C path.
5. Add Rust-specific lowering and writing code in
   `libasn1compiler/asn1c_rust.c` and `asn1c_rust.h`, registered in
   `libasn1compiler/Makefile.am`. These are proposed filenames, not existing
   files. Lower the fixed AST into a checked representation before writing.
6. Add runtime crate sources under `rust/asn1c-runtime/` and include
   them in Automake distribution and package-data installation. Resolve these
   sources independently of `-S`, which currently names the directory used
   for C skeletons and standard ASN.1 modules.
7. Give Rust its own identifier sanitizer and collision checker. Keep ASN.1
   names in diagnostics and retain a deterministic mapping from ASN.1 module,
   type, and member names to Rust paths.
8. Add a generated-crate test harness under a Rust compiler test directory.
   It should invoke the built compiler, use offline Cargo when dependencies
   are local or vendored, and inspect outputs. Existing parser/fixer tests
   remain shared; C output tests remain
   the regression gate for the default target.

The backend contract should be deliberately small: accept the fixed tree and
resolved compiler options; report supported codecs and schema features; build
the backend's checked representation; calculate its complete output manifest;
then write a staged output tree or return a diagnostic. Do not generalize the
existing `OUT()` macros or C stream enum into a universal text-emission system.
Freeze shared headers, manifest wiring, CLI, and build hooks under Sol's
ownership. Codec work should use exclusive runtime and generator paths and the
reviewed runtime API; send shared-interface changes to Sol for serial
integration before dependent work continues. Before handoff, check every
changed callable against the project's length and complexity limits and split
pre-existing oversized functions that the work must modify.

## Generated crate layout

Use one generated crate rooted at the requested destination directory:

```text
Cargo.toml
Cargo.lock                 # policy is frozen in M0
src/lib.rs
src/asn1/mod.rs
src/asn1/<module>.rs
runtime/Cargo.toml
runtime/src/lib.rs
runtime/src/<runtime modules>.rs
```

Copy only the required runtime sources and preserve their license notices.
The `Cargo.toml` declares a local path dependency on the copied runtime. The
crate root re-exports generated ASN.1 modules. One Rust source module per ASN.1
module keeps imports and repeated type names unambiguous. Generated file names
use a Rust-specific sanitizer; collisions after sanitization must
be detected before output. A stable suffix derived from the full ASN.1 module
identity may disambiguate module file names, but the user-facing Rust module
path should remain predictable and be recorded in the manifest.

Calculate the full output manifest before writing. Refuse an unmarked
destination that contains user files at managed paths. Stage the complete
crate, then publish it only after generation succeeds. For regeneration, use a
manifest to identify the old crate's owned files, preserve unrelated files,
and clean stale generated files through a documented replacement procedure.
Failure cleanup must leave either the old crate or the complete new crate.

The local runtime copy isolates generated crates from a globally installed
runtime update. Start with no runtime dependencies if the first slice can meet
its requirements. If later codecs need external crates, review each dependency
and include its source plus local Cargo configuration before claiming offline
builds. Preserve dependency license notices. Record the generator/runtime
version pairing. A future shared-runtime option must validate a compatible
runtime version and API; Rust ABI compatibility is not a requirement.

## Initial ASN.1-to-Rust type model

The mapping below is the API proposal, not a claim about implemented Rust
support. Use public safe value types and runtime wrappers where Rust's built-in
types cannot represent every valid ASN.1 value or preserve enough data for
encoding. Start with correctness and a stable public API; avoid target-machine
integer-width heuristics.

| ASN.1 form | Proposed Rust representation | Notes |
| --- | --- | --- |
| BOOLEAN | `bool` | Constraint checking remains codec/runtime behavior. |
| NULL | `()` | The codec still validates the encoded NULL form. |
| INTEGER | fixed-width or runtime `Integer` | Select width from schema bounds; use arbitrary precision otherwise. |
| ENUMERATED | generated enum | Extensible types need an unknown numeric variant. |
| REAL | runtime `Real` | Must preserve special values and source precision; `f64` alone is insufficient. |
| BIT STRING | runtime `BitString` | Store bytes and bit length; validate unused bits and size. |
| OCTET STRING | `Vec<u8>` or constrained newtype | Preserve byte values and enforce size constraints. |
| UTF8String | `String` or constrained newtype | Validate ASN.1 size and alphabet constraints. |
| Other character strings | runtime `AsnString` newtype | Preserve ASN.1 repertoire and encoding semantics. |
| OBJECT IDENTIFIER | runtime `ObjectIdentifier` | Use checked arcs; do not assume every arc fits a machine integer. |
| RELATIVE-OID | runtime `RelativeOid` | Same checked-arithmetic requirement as OID arcs. |
| UTCTime, GeneralizedTime | runtime time wrapper or validated text newtype | Canonical rules need explicit APIs. |
| SEQUENCE, SET | generated `struct` | Required fields are values; optional/defaulted fields track presence. |
| CHOICE | generated `enum` | Include an unknown extension variant when the type is extensible. |
| SEQUENCE OF, SET OF | `Vec<T>` newtype | Retain SET OF ordering rules in codec logic. |
| Type reference | module-qualified reference | Use public newtypes for aliases that add constraints or API identity. |
| ANY / open type | runtime `OpenType` or generated typed enum | Preserve unknowns; use IOC metadata when resolved. |

The runtime should include a bounded reader/writer abstraction, structured
decode errors with offsets and paths, constraint errors, tag metadata, and
codec-specific state. Every decode context must carry mandatory default
budgets for depth, total input, allocation, collection items, extensions, and
work. Nested and open-type decoders share those budgets; callers can configure
them. Encoders also bound work and output. Defaults need rationale and tests.
Check arithmetic and limits before advancing, accumulating, allocating, or
sorting. Input-driven allocation must be fallible, and malformed input must
return typed errors without input-driven panics. Safe Rust cannot guarantee
that every process-level allocation failure avoids aborting; document residual
limits and review recursion, cloning, formatting, and teardown behavior.

## Semantic lowering requirements

- **Modules, imports, aliases:** Resolve references from the fixed tree and emit
  module-qualified Rust paths. Respect exports/imports and avoid `use` name
  collisions. Preserve ASN.1 alias identity with a newtype when the alias adds
  constraints, tags, or public meaning; otherwise use a documented type alias.
- **Recursion:** Build a reference graph and identify recursive strongly
  connected components. Add `Box<T>` only on required by-value recursive edges;
  `Vec<T>` and other indirections do not need another box. Handle recursive
  aliases and cycles across imported modules explicitly.
- **Tags:** Keep universal/application/context/private class, tag number, and
  implicit/explicit mode as encoding metadata. Do not create a Rust wrapper
  solely because a type has a tag. The codec must consume effective tags after
  fixing, including module tagging defaults and nested explicit tags.
- **Constraints:** Lower the fixed constraint tree into checked runtime
  predicates for ranges, unions/intersections, SIZE, permitted alphabets,
  component constraints, and collection sizes as each form is supported.
  Provide `validate()` and checked constructors where practical. Codecs must
  enforce constraints at their specified encoding/decoding boundaries; an
  unchecked construction API must not bypass decoder validation.
- **Extensibility:** Preserve extensible ENUMERATED and CHOICE values and
  unknown SEQUENCE/SET extension additions when the selected codec can identify
  and retain them. A single untyped byte vector is not enough for every codec:
  BER needs complete unknown TLVs, while PER/OER and text encodings have
  different extension payload boundaries. Define codec-aware unknown-field
  storage before claiming round-trip support. Preserve current successful
  skip/relay behavior where supported, and offer strict rejection. Do not
  promise relay after a decoder skips bytes or across transfer syntaxes without
  a semantic value.
- **Information object classes:** Lower object sets and component-relation
  constraints into typed dispatch metadata. Generate a safe typed enum for
  known table rows plus an opaque unknown form where the codec permits it.
  Do not emit C descriptors or reproduce the C IOC output stream. Validate
  duplicate keys and unresolved references before writing.
- **Open types:** Distinguish a raw open type from a statically resolved table
  alternative. Resolve selector-to-payload relationships from the fixed tree;
  preserve unknown alternatives only when the chosen codec can retain enough
  wire information to re-encode them. Defer unsupported dynamic cases with a
  location-aware error instead of substituting an unrelated Rust type.
- **Encoding controls:** Use the shared parser representation and control
  application pass. Implement XER/JER rename and representation directives in
  their codecs, with duplicate generated-name checks. Reject a requested codec
  when a recognized control has no implementation for that codec.
- **Parameterized types:** Reuse the fixer's resolved specializations. Emit
  generic Rust types only if parameter substitution and constraints can be
  expressed without changing ASN.1 semantics; otherwise emit each resolved
  specialization with deterministic names and diagnostics for unsupported
  unresolved parameters.

The decode API must distinguish complete-message decoding from prefix or
incremental decoding. Incomplete input and malformed input are different
results. Report PER consumption in bits and other consumption in the relevant
byte or text unit. Nested decoders must share one budget and incremental state
must not trigger repeated unbounded reparsing. Freeze these interfaces after a
small M0 prototype and review.

## CLI behavior and diagnostics

Add `-lang=c|rust`, spelled `-lang=rust` for the Rust target. The current CLI
uses `getopt()` at [`asn1c/asn1c.c`](../../asn1c/asn1c.c#L130) with an optstring
that does not occupy `-l`; existing forms
such as `-gen-UPER` are handled by the leading short option consuming the rest
of the token. The new `-l` branch can follow that convention while accepting
only exact values `ang=c` and `ang=rust`. Test the token handling rather than
assuming GNU long-option behavior. Omitting `-lang` must preserve today's C
default and output byte-for-byte wherever practical.

The C driver's default compiler flags enable all current codecs. Rust needs a
separate explicit-codec mask so an early Rust release does not inherit requests
for every codec by accident. Track each explicit `-gen-*` and `-no-gen-*`
option; for early Rust releases, fail if no codec is explicitly selected.
Generate only selected codecs that pass the capability check. Once Rust is
qualified, its default may enable every qualified codec family. C keeps its
existing defaults.

Validate all flags and the complete schema before creating output files. An
unsupported CLI combination should be an `EX_USAGE` diagnostic; an unsupported
ASN.1 feature should be an input diagnostic with module, type, source line,
codec, and feature. Do not silently ignore a C-specific option or emit a Rust
`compile_error!` placeholder in generated output. Keep the existing exit-status
categories documented in [`asn1c/asn1c.c`](../../asn1c/asn1c.c#L793).

The option capability table should initially classify flags as follows:

| Option family | Rust handling |
| --- | --- |
| `-D`, `-pdu`, `-fgen-only-pdu-deps`, `-flist-deps` | Preserve where the generated crate meaning is defined. |
| `-gen-*`, `-no-gen-*` codecs | Support per codec; reject requested unsupported codecs or schema features. |
| C storage flags such as `-fwide-types`, `-flong-size`, `-finteger-native-type` | Reject as C-only. |
| C layout/output flags such as `-findirect-choice`, `-funnamed-unions`, `-fno-include-deps` | Reject as C-only. |
| `-S` | Keep as the C skeleton/standard-module directory; Rust uses its installed runtime assets. |
| `-P`, `-R`, C helper/example flags | Reject until Rust-specific semantics are defined. |
| parser/fixer flags and `-E` / `-F` | Preserve because they run before backend selection. |

Where a shared option affects only C code generation, explicitly classify it
as C-only instead of treating it as a harmless no-op. Add CLI tests for the
default C target, valid Rust selection, invalid language values, explicit and
disabled codec sets, missing explicit selection, C-only options under Rust,
unsupported schema features, and diagnostics before any files are written.

## Build, packaging, and tests

Add runtime sources to the Automake distribution and package data. Build-time
tests should use the compiler-built crate generator and configured runtime
source directory. Generated output
should contain only the runtime modules required by selected codecs and schema.
The first slice should need no external crates. Review and vendor later
dependencies with local Cargo configuration before claiming offline builds.

For each feature increment, test three layers:

1. **Runtime unit tests:** valid and malformed primitive encodings, exact
   boundary lengths, truncated inputs, overflow arithmetic, constraint
   failures, shared budget exhaustion, recursion limits, and unknown extension
   policy. Maintain fuzz targets and a regression corpus for decoder inputs.
2. **Generated-crate tests:** compile representative ASN.1 modules, exercise
   public type construction and validation, run each requested codec, and
   confirm a Cargo build; require offline execution when all dependencies are
   local or vendored. Include imports, alias chains,
   recursive types, tags, extensible forms, IOC/open types, and encoding
   controls as those features enter the capability matrix.
3. **Interoperability tests:** for supported schema/codec intersections,
   compare Rust encode/decode behavior with existing C-generated codecs and
   checked reference vectors. Test both directions, malformed input, and
   semantic values. Do not use agreement with the C implementation alone as
   evidence of standards correctness; include normative vectors and boundary
   cases.

Put Rust integration scripts in a separate test directory and register them in
Automake's `TESTS`. Dedicated Rust CI must exercise them; Cargo stays optional
for C-only builds. Record vector provenance and semantic differences in
fixtures. The M0 ledger maps each
relevant C schema/test to its Rust counterpart, codec, direction, variant,
constraints, extension policy, result, or source-backed exclusion.

## Implementation supervision and ownership

Sol owns architecture, shared interfaces, assignments, CLI/dispatch, build and
CI wiring, integration, review, and release claims. Runtime, generator, and
test work use exclusive paths after their interfaces are frozen. Agents do not
edit shared headers, CLI, manifests, build files, CI, or the coverage ledger in
parallel. Shared-file proposals go to Sol for serial integration. Each handoff
names the supported matrix, dependencies, owned paths, reference rules and
fixtures, required negative cases, commands, and evidence. See the detailed
[stage-one plan](stage-one-plan.md) for the assignment template and owners.

Keep `-lang=rust` opt-in and C behavior on the existing path. The Rust driver
must reject a missing codec selection during early development. If a requested
codec or schema feature is not implemented, fail before publishing any crate.
Do not expose a user-facing type-only crate as a fallback. M1 may test writer
plumbing internally; M2 is the first generated UPER slice.

## Milestones and completion gates

1. **M0, baseline and contracts:** Build a coverage ledger for existing C
   codec/type/direction/variant behavior and applicable tests. Freeze integer,
   bit-string, error, cursor, constraint, tag, codec-context, unknown-extension,
   resource-budget, and generator/writer contracts. Prototype streaming and
   consumption semantics. Select Cargo edition, MSRV, licensing, dependencies,
   and default limits with evidence.
2. **M1, foundation and harness:** Add Rust selection and capability
   diagnostics, name/path validation, a checked semantic representation,
   staged Cargo output, local runtime packaging, and generated-crate tests.
   Test that missing or unsupported codec requests fail without publishing
   partial output. Keep Cargo optional for C-only builds and preserve C tests.
3. **M2, first UPER slice:** Support NULL, BOOLEAN, bounded INTEGER,
   nonextensible ENUMERATED, bounded OCTET STRING, and BIT STRING. Include a
   small SEQUENCE only after field traversal is reviewed. Test bit consumption,
   truncation, bound edges, invalid application values, and small budgets.
   Compare Rust/C in both directions, use independent vectors, and provide
   generated API documentation and a usage example.
4. **M3, APER and semantic foundations:** Port APER alignment, length
   fragmentation, and open-type helpers separately from UPER. Expand PER to
   strings, time, REAL, arbitrary INTEGERs, constructed types, tags, defaults,
   extensions, and recursion. Complete imports, aliases, parameterized
   specializations, constraints, PDU dependencies, IOC tables, and open types
   in bounded feature assignments.
5. **M4, BER/DER and OER:** Add BER decoding, DER encoding, BER TLV and length
   handling, constructed strings, canonical ordering, and OER encode/decode.
   Qualify supported basic and canonical variants independently. Do not claim
   CER support without a dedicated implementation and tests.
6. **M5, XER/JER/CBOR:** Add bounded tokenization, escaping, names, supported
   encoding controls, exact integer handling, object-member policy, and the
   repository's CBOR mapping. Keep canonical output and permissive decoding
   expectations explicit. Reject duplicate/unknown/trailing JER BIT STRING
   members according to current runtime policy. Disable XML external entities
   if an XML dependency is selected.
7. **M6, qualification and packaging:** Map every applicable existing C test
   and supported behavior cell. Investigate every gap and record source-backed
   exclusions. Test feature combinations, strict/compatible extension policy,
   Rust toolchains, platforms, packaging, VPATH, output paths with spaces,
   streaming, budgets, teardown, fuzz regressions, and generated projects from
   installed and distribution artifacts. Add a Rust converter/example for
   interoperability workflows. Test Linux and macOS, and a 32-bit target when
   an executable runner is available. Keep utility APIs idiomatic; do not clone
   each C helper signature. Useful display support and Rust-native randomized
   test values may accompany the codecs.

Milestones are ordered by dependency, and all codec families remain in scope.
A codec-feature pair is qualified only when its runtime, generator, errors,
generated-crate tests, policy tests, and interoperability evidence pass. The
stage is incomplete while any applicable C cell lacks a Rust counterpart or a
reviewed, source-backed exclusion.

## Open implementation questions

- What resource-limit defaults should generated decoders use, and how can
  callers configure them through the shared decode/encode context APIs?
- Which Cargo edition, minimum supported Rust version, and licensing policy
  should M0 establish for the runtime and generated projects?
- Which dependencies, if any, are needed for bigint, XML, JSON, or CBOR support,
  and how will their code and licenses be vendored for offline builds?
- What exact internal representation should `Real` use to preserve values
  across BER/OER/PER and textual codecs without reducing values to `f64`?
- Which constrained aliases are public newtypes versus aliases, and what is the
  supported source-compatibility policy when generated APIs change?
- What manifest/version format should govern overwriting output from an older
  generator, and what recovery behavior is required after a disk error?
- Which reference-vector sources and Rust fuzzing toolchain are available in
  project CI?

## Source map

The line references above describe baseline commit
`5a0ccf24ede9b176e8fd76861bf4855ed95f5105`. The fixed expression model and
its fields for constraints, tags, markers, encoding controls, modules, and
object tables are in [`asn1p_expr.h`](../../libasn1parser/asn1p_expr.h#L116) and
[`asn1p_module.h`](../../libasn1parser/asn1p_module.h#L46). The callback table
and C implementation list are in [`asn1c_lang.h`](../../libasn1compiler/asn1c_lang.h#L6)
and [`asn1c_C.h`](../../libasn1compiler/asn1c_C.h#L20). Build integration is
currently listed in
[`Makefile.am`](../../libasn1compiler/Makefile.am#L10),
[`asn1c/Makefile.am`](../../asn1c/Makefile.am#L4), and
[`skeletons/Makefile.am`](../../skeletons/Makefile.am#L4).
