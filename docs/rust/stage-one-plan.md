# Stage-one implementation plan

**Date:** 2026-10-11.
**Status:** Implementation underway; the full stage remains incomplete.
**Baseline:** `5a0ccf24ede9b176e8fd76861bf4855ed95f5105`.

The [first implementation](implementation.md) begins M1/M2 with a standalone
Cargo package, safe UPER BOOLEAN/NULL/bounded INTEGER runtime, CER encode and
strict decode methods for that primitive slice, and generated-code tests. It is a subset of
M2; ENUMERATED, strings, and constructed types remain pending, along with the
subsequent codec families and stage-wide qualification.

The deliverable is an opt-in Rust output target in the C compiler, a native safe
Rust runtime replacing the role of `skeletons/` for that target, and Rust coverage
for the applicable existing codec tests. All current codec families are in scope:
BER decoding, strict CER decoding, DER and CER encoding, OER, UPER,
APER, XER, JER, and the repository's CBOR mapping. Canonical variants and
individual type/direction support are qualified separately. Rust uses `std`;
`no_std`, a Rust parser/fixer, and C ABI wrappers are deferred. See the
[architecture decision](architecture.md).

## Definition of completion

Stage one is complete only when all these conditions have recorded evidence:

1. The existing compiler generates a standalone Cargo project from supported
   schemas; its codecs build and run without linking the C runtime.
2. Each existing supported C type/codec/direction/variant/feature cell has a Rust
   counterpart with wire and semantic tests. Every existing applicable runtime
   or generated-code test has a mapped counterpart. An unsupported C cell or a
   C-specific test can have a reviewed exclusion with a source-backed reason.
   An unimplemented supported Rust cell keeps the stage incomplete.
3. All runtime families, scalar/string/time types, collections, tagged values,
   imports, aliases, recursion, defaults, constraints, extensions, supported
   encoding controls, and supported IOC/open-type behavior are covered. C
   features with known limits receive equally precise Rust diagnostics.
4. Malformed/truncated input and invalid values return bounded, documented
   results. Streaming, exact consumption, strict extension policy, and allocation
   and work limits pass their dedicated tests.
5. Generation is deterministic, validates unsupported combinations before
   publishing output, and handles name/path collisions and regeneration safely.
6. C regression CI still passes; Rust CI, differential checks, maintained fuzz
   regressions, packaging tests, and the source-rule checks pass.
7. Documentation describes only qualified support. Every residual limitation is
   in the coverage ledger and release notes; no blanket parity claim precedes
   these gates.

Early milestones are useful Rust slices, not completion of this stage.
Calendar and performance estimates are deferred until the first complete slice
provides measured implementation and test costs.

## Evidence and coverage ledger

M0 creates a machine-readable ledger owned by Sol and the test agent. Each row
records schema/test ID, ASN.1 feature, codec, direction, canonical/basic variant,
constraint/extension policy, C source/fixture, Rust counterpart, expected result,
status, and exclusion rationale where applicable. Counts must distinguish source
files, harness invocations, enabled target configurations, and executed tests.

Audit function-table slots and actual implementations, not just filenames or
the README encoding table. Preserve known gaps such as PKIX JER open-type
decoding. Record the repository's CBOR mapping explicitly; a generic CBOR parser
does not establish ASN.1 mapping parity. For disputed standards behavior, inspect
the governing primary text and record the rule separately from project policy.
The binary audit routes `ATS_CER` input to strict `cer_decode`, which checks
that the descriptor-driven CER encoder reproduces the input byte for byte.
`ATS_BER` and `ATS_DER` input remain permissive. Rust has a primitive CER
slice with encoding and strict decoding.

## Sol and Luna working agreement

Sol owns architecture, interface acceptance, assignment boundaries, integration,
review, and release claims. Use three Luna coding agents at a time, with Sol as
the fourth active participant. Start them only when implementation is requested;
the maintainer subsequently authorized implementation on 2026-10-11.

Dispatch coding assignments with the `gpt-6-luna` model and isolated assignment
context (`fork_turns="none"`). Include the required contract and source paths
in each prompt. Sol remains the supervising parent and reviews every handoff.
If Luna is unavailable, report that before substituting another model.

Each assignment must specify:

- One milestone and a bounded feature subset, with named dependencies.
- Exclusive file ownership and shared-file changes routed through Sol.
- Frozen interfaces and the exact allowed behavior/diagnostic matrix.
- Source algorithms, governing rules, fixtures, and required negative cases.
- Commands and expected evidence for acceptance, including documentation updates.
- A handoff listing changes, tests actually run, failures, limitations, and risks.

Sol monitors agents through their progress messages and status updates, answers
interface questions, and checks integration as each package lands. If an agent
fails, reproduces a persistent error, or writes outside its scope, stop that
assignment, inspect its partial diff, and dispatch a narrowed correction. Test
failure keeps dependent work from being accepted; it is not a completion report.

Agents never concurrently edit shared interfaces, CLI dispatch, Cargo manifests,
coverage-ledger schema, build files, or CI. Sol integrates those edits serially.
Stop dependent work when an interface changes; update its contract and notify
all affected agents before resuming. Never treat another agent's report as test
evidence without checking its artifacts and logs.

Use the main checkout for accepted changes. If isolated worktrees are introduced,
assign explicit refs and exclusive paths, then carry accepted patches back to
the main checkout. Agents do not merge, push, or commit independently. Sol makes
small reviewed commits after the required gates pass and reports any remaining
failures. Remove only stale temporary `target/**/*.lock` files after Rust builds;
preserve `Cargo.lock` according to the chosen reproducibility policy.

## Milestones and dependencies

### M0: Baseline, contracts, and delivery matrix

Sol supervises three read-only audits, then freezes the initial contracts.
Update the inventory against the implementation baseline and inspect the current
parser/fixer and runtime tests. Define the output layout, integer/bit-string/error
representations, cursor behavior, constraint metadata, decode/encode context,
unknown-extension policy, and codec trait signatures. Keep codec-specific payload
types separate. Prototype difficult interfaces before freezing them.

Inventory manual/unregistered suites too, including `tests/tests-integer-native`;
active Automake entries alone do not account for every existing semantic test.

Choose and record the Cargo edition and minimum supported Rust version through
actual builds, not the local latest toolchain alone. Define the dependency and
licensing policy. Initial default resource limits must have a rationale and tests;
make caller limits configurable and never treat them as ASN.1 protocol limits.

**Exit:** Versioned contract, support ledger, concrete first schema and vectors,
assignment list, and a C baseline with failures classified. No coding agent
should infer missing ABI/API decisions independently.

### M1: Buildable foundations, generation seam, and harness

Run these disjoint coding assignments concurrently after M0:

| Agent | Owned work | Proposed paths | Acceptance |
| --- | --- | --- | --- |
| Luna A | Runtime and models | Runtime `src/core/`, `src/types/` | Cursors, limits, validation |
| Luna B | Generator and writer | `libasn1compiler/asn1c_rust*.[ch]` | Crate, names, diagnostics |
| Luna C | Test harness | `tests/tests-rust-compiler/` | Compile, run, compare |

Paths in the table are proposed, not existing interfaces. Sol owns new shared
runtime files beneath `rust/asn1c-runtime/` outside the assigned source paths,
headers, manifest wiring, language enum/dispatch, CLI, build/install hooks, and
any extracted semantic helper. Luna B proposes those shared edits to Sol.
Runtime unit tests live with the runtime; Luna C owns independent integration
fixtures and vectors so it can find errors without mirroring implementation.

Keep the C frontend and C generation tests passing. Validate malformed schemas
and option combinations; do not insert assertion-based failures for user input.
Select the complete Rust generation mode through `--rust`; it defaults to
currently qualified codecs. Explicit unsupported codec requests fail. The
generated Cargo manifest uses a local copied runtime.

**Exit:** Empty/minimal generated crates build; known unsupported schemas/codecs
produce nonzero diagnostics without publishing incomplete output. C tests and
runtime foundation tests pass; no code path relies on C codec FFI.

### M2: First end-to-end UPER slice

Use Luna A for UPER primitives, Luna B for typed codec emission, and Luna C for
cross-language fixtures. Start with NULL, BOOLEAN, bounded INTEGER, nonextensible
ENUMERATED, and bounded OCTET STRING/BIT STRING. Include a small SEQUENCE only
after its exact field traversal contract is reviewed. Reject unsupported
combinations explicitly; do not emulate them using a different codec.

Fixtures exercise lower/upper bounds, zero-bit constrained values, empty strings,
bit tails, exact consumed bits, truncated determinants/payloads, invalid ordinals,
invalid application values, and small resource budgets. Test both C encode to
Rust decode and Rust encode to C decode using independently specified bytes.
Validate Cargo output away from the source/build tree and without C runtime
libraries. Include generated API documentation and a usage example.

**Exit:** A user can generate and use Rust UPER for the declared slice, with
repeatable byte/bit results and documented exclusions. Sol reviews the complete
flow before extending primitives or dispatch interfaces. The first delivered
slice also includes CER encode and strict decode methods for BOOLEAN, NULL,
and bounded INTEGER; the broader CER matrix remains a later M4 acceptance target.

### M3: APER and full semantic/type foundations

Port APER alignment, normally-small values, lengths, fragmentation, and open-type
helpers without blindly substituting UPER calls. Extend both PER codecs across
arbitrary INTEGERs, permitted alphabets, strings/time/REAL, collections, nested
constructed types, tags as relevant, optional/default fields, extensions,
canonical/declaration ordering, and recursion. Work in bounded type-family
assignments; arbitrary INTEGER, REAL, and IOC work require dedicated review.

Complete aliases/imports, parameterized specializations, PDU dependencies, nested
SIZE/element constraints, syntax-aware supported CONTAINING constraints, and
IOC/open-type selection. Preserve the known scope of existing features: this
baseline's CONTAINING change explicitly leaves OCTET STRING coverage unfinished.
Do not claim that gap has disappeared merely because the runtime is Rust.

Prioritize the existing check-126, check-548, check-550, check-552, check-561,
check-563, check-569, and check-570 regressions. Verify exact file/target names in
the [test migration design](testing.md). Carry strict and compatible extension
policies through both generated tests and runtime tests.

**Exit:** The ledger's qualified PER cells pass positive, malformed, streaming,
canonical-order, extension, and semantic tests; unsupported cells remain visible.

### M4: BER/DER/CER and OER

Port BER TLV parsing, definite/indefinite lengths, tag stacks, incremental state,
constructed strings, and DER encoding/canonical ordering. Distinguish supported
BER decoding from a dedicated strict DER decoder; the existing C API uses
`ber_decode` for DER input and strict `cer_decode` for CER input. Preserve the
C descriptor-driven CER encoder and strict re-encode-and-compare CER decoder.
The current Rust CER primitive slice encodes and strictly decodes; expand its
matrix to every C-supported descriptor/value cell, with reviewed exclusions
only for forms the C encoder does not support. Keep Rust strict CER decoding
and permissive BER decoding separately qualified.
Port OER length and presence determinants, constraints, open types, and ordering.
Qualify basic/canonical variants independently, including malformed encodings.

Maintain the three lanes: runtime algorithms, generator/type metadata, and tests.
Shared safe cursors may be reused; codec-specific rules remain separate. Include
PKIX fixtures, constructed values, long tags/lengths, duplicate root tags, and
default/SET ordering. Verify cross-language semantics before claiming canonical
byte equality for any variant.

**Exit:** Ledger cells for BER decoding, strict CER decoding, DER/CER encoding,
and OER cover the qualified C type/feature matrix and the required Rust counterparts.
Resource, streaming, and canonical-versus-permissive behavior gates pass for
these codecs.

### M5: XER, JER, and CBOR

Port XER tokenization/escaping, whitespace, names, supported encoding controls,
empty values, and supported basic/canonical output. Port JER mappings, exact
integers, names, enum text, BASE64, object-member policies, and open types within
the current supported domain. Port the repository's CBOR value/type mapping and
supported encoder/decoder behavior, not only generic CBOR syntax.

Reject duplicate/unknown/trailing JER BIT STRING members consistently with the
current runtime policy. Bound textual token size, nesting, total work, output,
and intermediate allocation. Do not route arbitrary ASN.1 INTEGERs through
floating-point JSON values. Disable external entity resolution if an XML
dependency is introduced, and test the intended tokenizer behavior.

These codec families can overlap M4 after interfaces stabilize, using disjoint
codec paths; Sol keeps total active Luna agents at three and protects generator
and test ownership. Retain a test lane throughout rather than completing all
runtime code before integration.

**Exit:** Every targeted textual/CBOR cell has positive, invalid, policy, and
cross-language fixtures, with encoding controls and mapping limits documented.

### M6: Stage-wide qualification and packaging

Close the coverage ledger against the current C baseline. Map every applicable
test; inspect every exclusion. Verify feature-off builds, each qualified codec
alone, full features, strict extension policy, selected toolchain/MSRV, and Linux
and macOS builds. Add a 32-bit target check where a runner can execute it, and
record any execution gap rather than calling compilation a runtime test.

Test recursive-value teardown, encoder failures, shared budgets, incremental
state, large schemas, imports/IOC, and malformed generated metadata. Run the C
baseline, Rust checks, differential suite, fuzz regression corpus, and bounded
fuzz campaigns with recorded seeds, time, and coverage. Compare clean release
performance and peak memory only as measurements; correctness is the gate and
no speedup target is assumed.

Distribute runtime sources/templates through Autotools install/dist hooks; keep
Cargo optional for C-only builds. Add a dedicated Rust CI job, verify generated
projects from installed artifacts and distribution tarballs, and exercise VPATH
builds and output paths with spaces. Supply a Rust converter/example application
for interoperability workflows where the existing C converter has a Rust peer.

**Exit:** All completion conditions are satisfied, the documentation matches the
ledger, and Sol records test evidence and remaining C-domain limits. Only then
propose stage-two conversion of the compiler itself.

## Review gates for every implementation handoff

- Sol checks the governing rule, current C behavior, and proposed compatibility.
- Runtime and generated code prohibit `unsafe`; input-driven allocation and
  panic paths are reviewed, and nested budgets retain one shared accounting.
- Critical callable complexity is at most 20; callable length at most 200 source
  lines; code lines at most 120 characters. Split algorithms along meaningful
  codec steps rather than suppressing these checks.
- Existing oversized functions touched for backend selection or option parsing
  need a focused split into documented helpers too. Merely adding a language
  branch to the current large CLI function would not meet these rules. Preserve
  its C behavior with the existing option/status tests and new Rust-option cases.
- Every new/changed function carries purpose, source, dated version/history,
  inputs, results/errors/panic behavior, responsible party, and a use example.
  Structs/enums and their members are documented; state variables are annotated
  with the phrase "state variable". Comment small blocks when useful for clarity.
- Tests cover expected and unexpected inputs independently of implementation;
  schema vectors, wire bytes, policy cases, and fuzz regressions accompany code.
- Generated source must meet the same documentation and source limits. CI checks
  representative generated projects, not only handwritten runtime files.
- Required checks pass before committing. Sol inspects diffs and test logs,
  updates support/docs/ChangeLog, and integrates into the main local repository.

The first foundation task must select or implement a reproducible checker for
function size and cyclomatic complexity, documenting its counting convention for
Rust expressions and macros. Until automated checks exist, review and record
each critical unit; an unmeasured assertion of compliance is insufficient.

## Assignment template for coding agents

Use this template when implementation is requested. Replace placeholders before
dispatch, and choose the Luna model explicitly with isolated assignment context.

```text
Implement <milestone/package> in /Users/ur20980/src/asn1c.
Read the applicable AGENTS.md and docs/rust/ contracts first.
Edit only <owned paths>; propose shared-file changes to Sol.
Depends on accepted commit <ref> and interface contract <version>.
Supported schemas/codecs/policies: <explicit matrix>.
Source algorithms/rules and independent fixtures: <paths and rule references>.
Reject unsupported or malformed inputs with <defined outcomes>.
Required checks: <commands and expected results>.
Update inline docs, package docs, tests, and fuzz regressions as appropriate.
Do not commit, push, or modify another agent's files.
Report changed paths, executed checks/results, gaps, and interface concerns.
```

## Risks and decision points

The largest risks are backend coupling, constraint semantics, canonical ordering,
streaming/resource accounting, open-type dispatch, and apparent parity inferred
from round trips alone. The milestone gates and independent vectors address these
directly. Dependency choice, minimum Rust version, default limits, and exact
public API names remain proposed decisions for M0; the confirmed scope does not
depend on guessing them now. Material compatibility changes need a concrete
explanation and maintainer direction before their integration.
