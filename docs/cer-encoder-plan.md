# CER encoding and Rust toolchain implementation plan

**Status:** Implemented and locally qualified for the documented scope.
**Date:** 2026-10-11.
**Qualification updated:** 2026-10-12.
**Baseline:** `673b16c5`, the first safe Rust output slice.
**Supervisor:** Sol; three Luna agents implement disjoint work packages.

## Scope and evidence

Add a native CER encoder to the C runtime and CER encoding to the Rust output
mode. Keep the existing C parser and semantic frontend. The initial Rust types
remain BOOLEAN, NULL, and finite, nonextensible INTEGER ranges within signed
64-bit storage. Rust CER decoding, strings, collections, open types, and the
remaining codec families are later increments in the [conversion plan](rust/stage-one-plan.md).

C CER decoding already uses the BER decoder, including constructed indefinite
lengths. It accepts compatible BER and does not verify every canonical CER rule.
The new encoder must produce canonical bytes; permissive decoding is not evidence
that an encoder is canonical. The [codec ledger](binary-codec-support.md) records
the qualified directions and limitations.

The governing rules reviewed for this increment are in
[ITU-T X.690 (08/2015)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-201508-S%21%21PDF-E&lang=e&type=items):

- Section 9.1: constructed values use indefinite lengths; primitive lengths use
  their shortest representation.
- Section 9.2: BIT STRING, OCTET STRING, and restricted character strings use
  primitive encoding through 1000 content octets, then primitive fragments inside
  a constructed wrapper. Every nonfinal fragment has 1000 content octets. The
  BIT STRING unused-bit octet counts toward that limit.
- Section 9.3: SET ordering uses tag class and number. An untagged CHOICE uses its
  smallest possible tag, including nested choices, rather than its selected tag.
- Sections 11.1–11.5: canonical scalar content and omission of equal DEFAULTs.
- Section 11.6: SET OF ordering compares final encoded octets, treating a shorter
  comparison operand as zero padded without emitting that padding.

These rules require independent byte vectors. A round trip through the shared
BER decoder alone cannot detect incorrect fragmentation, ordering, or defaults.

## C encoder decision

Implement a bounded descriptor walker in `skeletons/cer_encoder.c` with public
declarations in `cer_encoder.h`. Use the existing operation kind, member metadata,
tags, and type specifics. Preserve the descriptor operation-table ABI. Add:

```c
cer_encode(opt_codec_ctx, td, sptr, callback, application_key);
cer_encode_to_buffer(opt_codec_ctx, td, sptr, buffer, buffer_size);
```

Route generic `ATS_CER` encoding and converter `-ocer` to this encoder. Existing
BER decoding remains the route for generic CER input and converter `-icer`.

Keep tag wrappers, constructed lengths, string segmentation, SET ordering, and
SET OF sorting inside the CER walker. Existing DER primitive encoders may supply
scalar content only where canonical content is established and checked. Capture
that content through a copied descriptor with one intrinsic universal tag, then
apply the original CER tag chain in the walker. This avoids inheriting the DER
adapter's small tag-chain limit and keeps failure results tied to the caller's
descriptor. Reject
unsupported opaque encodings, including raw ANY, instead of relabeling arbitrary
bytes as canonical CER. A selected open type can be encoded through its resolved
typed descriptor when its metadata is supported.

Validate descriptors, missing required values, lengths, BIT STRING unused bits,
collection counts, tag chains, output arithmetic, callback results, and recursion
before processing or allocation. Bound temporary storage and recursion; document
the implemented limits and error behavior. Propagate allocation and callback
failures without publishing a success result. Preserve generic buffer sizing
semantics and test direct fixed-buffer failure separately.

The implemented compile-time ceilings are 30 recursive levels and 30 tags per
descriptor chain through `ASN_STACK_OVERFLOW_LIMIT`. An explicit member tag adds
one chain layer; an implicit member tag replaces the outer layer. Check this
bound before reading tag arrays. The remaining ceilings are 64 MiB encoded output through
`ASN_CER_MAX_ENCODED_SIZE`, 128 MiB aggregate active scratch through
`ASN_CER_MAX_SCRATCH_SIZE`, 1,000,000 collection entries through
`ASN_CER_MAX_ELEMENTS`, and 4,000,000 descriptor/value visits through
`ASN_CER_MAX_WORK_ITEMS`. The shared visit counter bounds recursive metadata
walks even when they do not emit bytes. The final header documents the accepted
constants and their override semantics. The existing byte-based stack check follows its
normal build configuration; the explicit depth bound also applies under
sanitizers. Unsupported raw REAL decimal or noncanonical content is rejected;
supported special and canonical binary content is checked before emission.

Place CER skeleton assets in the existing BER dependency closure. CER encoding
depends on the shared BER/DER substrate. `ASN_DISABLE_CER_SUPPORT` independently
disables the encoder; disabling only CER encoding retains BER-based CER decoding.
Code with BER disabled must not reference unavailable CER symbols.

### BER-family decoder integration

Generated CER round trips exposed an existing decoder limitation: indefinite
explicit wrappers around definite primitive TLVs were rejected by the shared
tag checker. Add a separate bounded primitive-header helper that preserves the
existing checker ABI, validates each explicit layer, and checks all trailing
end-of-contents octets before publishing a scalar value. Bound explicit tag
chains with `BER_EXPLICIT_TAG_DEPTH_LIMIT` (30 by default).

For OCTET STRING and BIT STRING decoding, retain incremental parser state while
checking wrapper cardinality, child tags, parent lengths, and exact EOC pairs.
Close completed definite parent frames before requesting more bytes. Built-in
operation identities identify universal fragment tags when an implicit outer tag
differs from the string's intrinsic tag: BIT STRING uses tag 3, while OCTET
STRING and restricted character strings use tag 4. Explicit wrapper levels continue to
require the descriptor tag. This also requires the relevant built-in operation
assets in the BER dependency closure when CER encoding is disabled.

Independent decoder regressions cover one-shot and incremental input, definite
BER wrappers and strings, nested indefinite CER wrappers, retagged universal
fragments, wrong tags/forms, duplicate explicit children, and truncated or
malformed EOCs. CER input continues to use permissive BER decoding; these fixes
do not introduce a strict canonical CER validator.

NativeInteger metadata may be absent or use a zero field width for its default
native `long` storage. Preserve those valid cases and accept supported explicit
widths; reject malformed widths before allocation or conversion. The unber tool
embeds primitive decoder sources without typed-decoder support, so its internal
stub must satisfy the new helper symbol while retaining raw TLV inspection.

### Alternatives considered

| Approach | Benefit | Limitation | Decision |
| --- | --- | --- | --- |
| Descriptor walker using existing kinds | Preserves ABI and generated descriptors | Must validate type specifics | Select |
| New operation-table CER slot | Per-type implementation seam | ABI and every initializer change | Defer |
| Convert a DER byte stream blindly | Small prototype | Loses static CHOICE ordering and semantic defaults | Reject |
| Rust bindings to C CER | Reuses runtime | Violates the safe native Rust direction | Reject |

## Rust runtime and generation

Add safe, dependency-free helpers for canonical BOOLEAN, NULL, and bounded signed
INTEGER TLVs. TRUE content is `ff`; signed INTEGER content uses minimal two's
complement bytes. Return the existing `Encoded` result, with `bit_len` equal to
the entire TLV length in bits. Check schema bounds and existing output/work
limits before fallible allocation. Runtime and generated crates forbid unsafe.

Generate `encode_cer` only when CER is selected and UPER methods only when UPER is
selected. Preserve fully qualified runtime/core paths, output preflight, staging,
ownership manifests, and offline Cargo packaging. Unsupported schema features
or codecs fail before publishing output. No Rust CER decode method is exposed in
this increment.

`--rust` switches the entire output mode to Rust, including types, codec methods,
runtime sources, and Cargo metadata. C remains the default output mode.

| Selection | C behavior | Rust behavior |
| --- | --- | --- |
| Default | Existing defaults plus CER encoder | UPER and CER |
| `-gen-CER` | Enable CER and its BER substrate | Enable CER |
| `-no-gen-CER` | Disable CER encoder; retain BER decoder | Disable CER |
| `-no-gen-BER` | Disable BER substrate and CER encoder | BER selection only; does not disable CER |
| `--rust -no-gen-UPER` | Switch output mode | CER encoding only |
| `--rust -no-gen-CER` | Switch output mode | UPER encoding and decoding |
| Rust with no supported codec selected | Not applicable | Diagnostic, no published project |

Add `A1C_GEN_CER = 0x1000000000` without reusing existing codec bits. Keep C and
Rust selection state separate so legacy C defaults do not contaminate Rust mode.

## Supervised work packages

| Agent | Owned changes | Required handoff |
| --- | --- | --- |
| Luna C CER | Skeleton encoder, BER wrapper/string integration, converter, dependency lists | API, limits, supported types, independent vectors |
| Luna Rust CER | Rust runtime, generator, CLI, generated configuration, C/Rust and decoder regressions | Codec mask, APIs, fault injection, cross-language bytes |
| Luna documentation | README, installation, ChangeLog, codec ledger, Rust docs, TeX/PDF, Markdown/man page | Accurate support boundaries, regeneration steps, changed PDF pages |
| Sol supervisor | Plan, generic dispatch, generated C regressions, fuzz integration, packaging, review, validation, commits | Reviewed diff, complete qualification evidence |

Agents edit the main local checkout in disjoint scopes and do not commit. Freeze
shared interfaces before integration. Coordinate compiler builds and test relinks
to avoid stale or concurrently replaced archives. Sol reviews standards details,
failure behavior, generated dependency closure, and documentation claims before
committing the complete change.

## Qualification and delivery gates

- [x] Independent scalar vectors, including INTEGER sign-boundary cases and TRUE.
- [x] OCTET/BIT/character string boundaries at, below, and above 1000 content
  octets, plus final fragments and nonzero BIT STRING unused bits.
- [x] Nested and explicit/implicit tags, SEQUENCE/SET/CHOICE, DEFAULT omission,
  static minimum CHOICE tag order, and SET OF final-CER byte order.
- [x] Invalid descriptors/values, missing fields, opaque ANY, malformed primitive
  content, tiny buffers, callback failure, allocation/output/depth limits.
- [x] C generic dispatch, converter output, generated dependency closure, and
  independent encoder/BER compile-disable combinations.
- [x] Existing BER-family fuzz corpora exercise CER encoding after successful
  decode, with unsupported/resource failures accepted and output discarded.
- [x] Rust runtime and generated-crate tests, negative schema/CLI combinations,
  selected-method availability, offline builds, format/lint checks, C byte exchange.
- [x] Rebuilt skeleton libraries and affected existing C/compiler suites.
- [x] Full generated-converter smoke suite, including legacy codec combinations.
- [x] All user-facing support tables and Rust stage-one documents agree with
  implementation; future coverage is explicitly labeled as planned.
- [x] `asn1c-usage.tex` and regenerated `asn1c-usage.pdf` agree; inspect changed
  PDF pages for clipping, layout, tables, and complete CER/Rust sections.
- [x] `asn1c.man.md` and regenerated `asn1c.1` agree; verify rendered options.
- [x] Installation and source distribution include runtime assets and new docs.
- [x] Record exact tests and residual limitations, then commit reviewed changes.

## Qualification evidence

### Follow-up design for the three generated C test failures

On 2026-10-12, `tests/tests-c-compiler/test-suite.log` reported 68/71 passes
after `cb8c9e8d`. The failed tests were `check-25.-fwide-types.c`, `check-60.c`,
and `check-62.c`. Their causes require two separate changes:

1. Correct fragment tags in both CER output and BER input matching. The fixed
   mutation in test 25 changes a nested OCTET STRING fragment tag from 4 to
   VisibleString tag 26 without changing the value size. It must be rejected
   at that nesting level. X.690 (2021), sections 8.7.3.2 and 8.23.3, require
   OCTET STRING fragments inside constructed restricted character strings;
   section 9.2 constrains their primitive form and size without replacing that
   tag rule. Keep the outer descriptor tags and explicit tag-chain validation
   separate from fragment tags. Retain randomized corruption coverage and
   add independent positive fragmentation and fixed negative vectors.
2. Restore legacy opaque `ANY` container compatibility. Test 60 serializes an
   empty explicitly tagged `ANY`; test 62 preserves several complete TLVs in
   one such container. These are existing permissive runtime representations,
   not evidence of canonical or single-value open-type conformance. Exempt
   only opaque `ANY` from the typed-string exact-one-child checks. Continue
   checking parent lengths, bounded nesting, complete child headers, and exact
   EOC markers, including incremental input and malformed fixtures. Typed
   string wrappers must retain their cardinality checks.
   `data-62-24-L.ber` also preserves an exact `00 00` pair as opaque bytes in
   a definite `ANY` frame. Retain this bounded compatibility case without
   treating it as a terminator. Malformed tag-zero headers and missing
   required EOCs remain failures; the compatibility is not normative BER
   validation of the unknown payload type.

Sol supervises two Luna implementation agents and a third Luna reviewer.
Implementation ownership is split between `ANY` frame state and fragment-tag
resolution/encoding. The release gate is the complete generated C suite,
freshly rebuilt skeleton libraries and their tests, and the generated CER
converter check. Existing Rust source is unaffected; C interoperability
coverage must continue to pass.

The follow-up passes all 71 generated C checks, including the three previously
failing tests, under the configured ASan/UBSan test flags. Fresh normal, strict,
and C89 skeleton archives were rebuilt before the linked skeleton suite, which
passes 52/52. The generated CER converter check passes CER-enabled,
CER-disabled, and BER-disabled builds, with independent long UTF8String,
VisibleString, and BMPString vectors. The generated Rust harness passes its
10 conformance checks and C UPER/CER interoperability checks. The main build,
source line-length and function size/complexity checks, and shell syntax
checks pass. The updated man page and 97-page PDF were regenerated; the
corrected manual pages 66–67 were inspected visually. No additional long
fuzz campaign or source-distribution rebuild is claimed for this follow-up.

The primary reference for this correction is
[X.690 (2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items).

### Initial CER implementation qualification

The final main build passes. Fresh normal, strict, and C89 skeleton archives
were rebuilt before relinking the skeleton suite: 52/52 checks pass. The compiler
suite passes 7/7 checks. All 28 generated-converter smoke checks pass, including
legacy codec-disable combinations. The unber suite passes 1/1 checks, and unber inspects an
actual CER fixture successfully. The CER-specific generated C check passes its
CER-enabled, CER-disabled, and BER-disabled configurations. It checks independent
bytes and re-decodes/re-encodes structural values, including typed open types,
retagged primitives, and long string fragments. The revised primitive adapter
also has independent vectors for four explicit wrappers around native INTEGER,
raw INTEGER, and a fragmented OCTET STRING, with BER re-decode. A generated
named-alias INTEGER case checks the actual frontend metadata for this chain.

The Rust runtime suite passes 10 tests, and the fresh generated Rust harness
passes 10 conformance tests plus codec-selection and rejected-schema cases.
Fresh generated C references verify UPER/CER byte parity, and the C decoder
consumes Rust-generated UPER/CER output. Runtime formatting and runtime/generated
Clippy checks pass with warnings denied. Installed C and CER-only Rust projects
build and pass their checks using installed runtime assets and offline Cargo.

A short ASan/UBSan libFuzzer qualification processed 660,325 mutations in 16
seconds without a sanitizer failure. Successful BER decoding feeds the new CER
encoder; a known seed also checks independent expected CER bytes. The randomized
driver compiles with CER or BER disabled. This is bounded qualification, not a
long fuzz campaign or proof that every malformed input is covered.

The Markdown/man page was regenerated and its rendered options checked. The
TeX manual was compiled with XeLaTeX into the tracked 97-page PDF; changed pages
14 and 66-69 were inspected visually for CER/Rust content and layout. Source
whitespace checks pass; new critical functions were reviewed for the repository
size and complexity limits. Hosted Rust CI and a minimum Rust compiler version
have not been qualified.

The source distribution contains all 13 required new/runtime/documentation assets;
all 60 reviewed changed files match the main checkout after the plan refresh.
A failing gate keeps its implementation under revision; it does not justify a
broader support claim.

### 2026-10-13 CER smoke-test locale incident

The reported Ubuntu/GCC build-and-check job prompted a portability review of
`tests/tests-asn1c-smoke/check-CER.sh`. Its long retagged BIT STRING expected
vector contains 999 payload octets with value `0xff`. GNU awk on the local
investigation machine emitted `c3 bf` for `printf "%c", 255` under
`LC_ALL=en_US.UTF-8`, and `ff` under `LC_ALL=C`. The UTF-8 output is the
two-byte encoding of U+00FF, which shifts the expected vector away from the
single byte required for each payload octet.

The authenticated GitHub job log confirms that the generated converter compiled
and linked successfully before the test failed at this comparison:

```text
rbits-long.expected rbits-long.actual differ: byte 8, line 1
FAIL check-CER.sh (exit status: 1)
```

This is the same first-payload-byte failure reproduced locally. The fixture's
locale-sensitive character conversion explains that failure and is corrected
by the byte-oriented output below. The CI log does not record the selected awk
implementation or locale, so those exact runner settings remain unverified.

The single-octet behavior can be checked directly with:

```sh
LC_ALL=en_US.UTF-8 gawk 'BEGIN { printf "%c", 255 }' | od -An -tx1
LC_ALL=C gawk 'BEGIN { printf "%c", 255 }' | od -An -tx1
```

The complete pre-fix smoke test used a PATH wrapper to select GNU awk, with
`LC_ALL=en_US.UTF-8`, `CC=clang`, and `CFLAGS=-O0`. From the configured
smoke-test build directory, it exited at the `rbits-long.expected` /
`rbits-long.actual` comparison and reported a difference at character 8, the
first payload octet after the seven-byte header. The test command was:

```sh
awk_wrapper=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-awk.XXXXXX")
ln -s "$(command -v gawk)" "$awk_wrapper/awk"
git show 8367a5cf:tests/tests-asn1c-smoke/check-CER.sh > "$awk_wrapper/check-CER-before.sh"
LC_ALL=en_US.UTF-8 PATH="$awk_wrapper:$PATH" CC=clang CFLAGS=-O0 \
    bash "$awk_wrapper/check-CER-before.sh"
```

The command extracts the original script from the investigated commit and
requires GNU awk and the named UTF-8 locale to be installed. The fixture now emits each
payload byte with Bash's explicit octal `printf '\377'` escape, avoiding
locale-sensitive character conversion. The existing full-vector `cmp`
remains the regression check.

Post-fix qualification on 2026-10-13:

- The configured `make -C tests/tests-asn1c-smoke check TESTS=check-CER.sh`
  passes with the local Clang build (1 test, 0 failures).
- The complete smoke test with GNU awk, `LC_ALL=en_US.UTF-8`, Clang, and
  `CFLAGS=-O0` passes all byte comparisons, round trips, malformed-fragment
  rejection, invalid open-type selectors, and disabled-codec checks.
- `bash -n tests/tests-asn1c-smoke/check-CER.sh` and `git diff --check` pass.
- A local GCC 15 attempt stopped before running the vectors because the macOS
  toolchain could not find `threads.h`. This is a qualification limitation;
  the Ubuntu/GCC execution has not been reproduced locally.

The associated [GitHub Actions job 115297086973](https://github.com/mouse07410/asn1c/actions/runs/38397712490/job/115297086973)
was inspected on 2026-10-13 after authenticated log access became available.
Its failure output at 12:37:16 UTC matches the local reproduction. The fixed
script passes locally, including the environment that reproduced this error;
a hosted CI run of the patch has not yet been performed.

## Residual limits and next increments

The shared BER decoder accepts compatible noncanonical input under `ATS_CER`.
It can still reject scalar chains that mix definite and indefinite lengths among
nested constructed wrapper layers; this is the pre-existing tag-checker limit.
Canonical CER wrapper chains and tested all-definite BER chains are covered by
this increment. Strict CER canonical validation is a separate future feature.

The C encoder rejects opaque ANY, unresolved open types, unknown primitive
operations, and unsupported raw REAL/time forms described in the codec ledger.
Resource ceilings are intentional API limits. Rust CER remains the primitive
encoding slice described above; broader types and CER decoding follow the staged
conversion plan. These boundaries must remain explicit in every support table.
