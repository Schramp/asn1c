# Rust runtime test migration plan

Status: planning document for baseline
`5a0ccf24ede9b176e8fd76861bf4855ed95f5105` (2026-10-11). The Rust runtime
and test targets did not exist at that baseline. The initial primitive UPER
and CER implementation now has runtime unit tests and a
[generated-code integration harness](../../tests/tests-rust-compiler/README.md).
Commands and coverage for additional codec families below remain acceptance
targets. See the [first implementation](implementation.md) for current limits.

## Scope and ownership

The target is the codec runtime in `rust/asn1c-runtime` and a generated Rust
integration harness in `tests/tests-rust-compiler`. The parser, fixer, compiler
front end, and C code generator stay in C. Keep their parser, command-line,
textual-output, warning, generated-C compilation, and C ABI tests in the
existing C suites. Do not delete existing C tests or count them as Rust tests.

Runtime unit tests own codec algorithms, primitive operations, constraints,
error handling, and resource limits. Test resumable input only for APIs that
currently support it or for a separately approved Rust interface. The generated
Rust harness owns schema-to-codegen-to-runtime behavior. Reuse schemas and
vectors and invoke the `--rust` backend within its supported subset.

Keep the C implementation as the comparison implementation throughout the
migration. It is not the protocol oracle. Treat any C/Rust disagreement as a
triage signal and resolve it against the applicable ASN.1 rules, independently
reviewed vectors, and documented project policy. Record vector provenance as a
normative example, independently derived encoding, or external interoperability
vector. Do not call a value a standard vector without a supporting source.

## Baseline inventory

Counts below come from the named Automake lists or a defined file glob at the
stated baseline. They are inventory counts, not counts of independent behavior.

| Suite | Baseline inventory | Rust treatment |
| --- | --- | --- |
| `tests/tests-asn1c-compiler` | 7 scripts; 224 schemas; 160 snapshots | Retain C frontend checks; reuse schemas. |
| `tests/tests-asn1c-smoke` | 26 shell checks | Keep C build tests; add Rust runtime smoke cases. |
| `tests/tests-c-compiler` | 71 entries: 69 always, 2 under `TEST_64BIT` | Keep all; port runtime assertions to Rust. |
| `tests/tests-skeletons` | 46 base; 25 m32 checks | Port runtime behavior; retain C API/ABI checks. |
| `tests/tests-randomized` | 19 bundles | Keep C runs; add deterministic Rust generation. |
| Project integration | 3 `run.sh` suites | Keep C runs; add Rust-generated integration cases. |

Compiler fixture counts use top-level `*.asn1` and `*.asn1.+*` globs under
`tests/tests-asn1c-compiler/`. The integration count covers the three suites
registered in [tests/Makefile.am](../../tests/Makefile.am); it does not include
standalone/manual runners.

The randomized C driver covers BER, DER, canonical OER, basic PER, canonical
UPER, canonical APER, canonical XER, and JER. CBOR is absent from that driver.
When CER encoding is enabled, successfully decoded BER-family corpus values also
feed the generic `ATS_CER` encoder. This exercises encoding over corpus inputs;
it is not a long fuzz campaign and does not make CER input decoding canonical.
Separate CBOR tests live in `tests/tests-skeletons/check-CBOR.c`,
`tests/tests-c-compiler/check-src/check-202.-gen-CBOR.c`, and the PKIX job in
`.github/workflows/c-cpp.yml`. Track CBOR as the repository's ASN.1-to-CBOR
mapping, not as an ASN.1 encoding rule.

The generic C dispatcher supports more modes than the randomized driver. Build
the ledger from `skeletons/asn_application.h`, the actual encode/decode switches
in `skeletons/asn_application.c`, descriptor operation slots, and codec feature
guards. Keep these variants distinct: BER, DER, basic and canonical OER,
unaligned basic and canonical PER, aligned basic and canonical PER, basic and
canonical XER, JER, minified JER, and CBOR. Qualify each type/direction cell
against actual descriptor operations and enabled features; a syntax enum or
codec source file alone does not establish support.

The binary-dispatch regression routes `ATS_CER` input to the existing BER
decoder. CER-compatible input decoding remains permissive; test valid
indefinite/segmented encodings, incomplete and malformed input, and the shared
BER decoder's input behavior. C CER encoding now has a separate native
descriptor walker. Its tests cover canonical string fragments and ordering for
`SET` and `SET OF`; decoder selector acceptance still does not establish strict
canonical validation. Rust currently implements CER encoding only for
BOOLEAN, NULL, and bounded nonextensible INTEGER values fitting `i64`, with no
CER decoder. See [the binary audit](../binary-codec-support.md).

CI runs GCC `make check`, `make distcheck`, and Clang sanitizer `make check`.
Each configures with `--disable-test-fuzzer`. Normal CI therefore runs randomized
round trips but skips optional LibFuzzer campaigns. Keep required tests
deterministic and bounded; run time-based fuzzing in a separate opt-in job.

Useful current C commands from a configured build tree are:

```sh
make check
make -C tests/tests-asn1c-compiler check
make -C skeletons libasn1cskeletons.la
make -C tests/tests-skeletons check-APER-INTEGER-x691-range check-JER
./tests/tests-skeletons/check-APER-INTEGER-x691-range
./tests/tests-skeletons/check-JER
make -C tests/tests-c-compiler check \
  TESTS='check-src/check-548.-gen-APER.c check-src/check-561.-gen-UPER.-gen-APER.c'
make -C tests/tests-randomized check FUZZ_TIME=1
```

Rebuild the skeleton library before focused skeleton checks so they link the
current code, then run the test executables. The last command bounds optional
fuzz time when LibFuzzer is enabled; CI's configuration skips those campaigns.
Do not count generated build directories as source inventory. Automake creates
per-case directories below `tests/tests-c-compiler`, and randomized tests create
temporary directories below `tests/tests-randomized`.

## Coverage ledger

The current primitive slice is recorded in
[`tests/tests-rust-compiler/coverage.json`](../../tests/tests-rust-compiler/coverage.json).
It covers the qualified UPER BOOLEAN/NULL/INTEGER cases, encode-only CER
primitive vectors, codec-selection boundaries, and compiler/output safety
checks. It is not a stage-wide map of the existing C runtime.

Before expanding beyond this first slice, materialize the planned stage-wide
mapping at `tests/tests-rust-compiler/coverage.tsv`. Use one row for each
applicable schema, ASN.1 feature, codec variant, direction, and policy cell.
Include these fields:

```text
schema | test_id | c_source | rust_counterpart | type | asn1_feature
codec | variant | direction | policy | expected_result | vector_source
chunk_profile | budget_profile | c_status | rust_status | rationale
```

Record both implementation statuses separately. `c_status` is `covered`,
`unsupported:<source-backed reason>`, or `not-applicable`. `rust_status` is
`pending`, `covered`, or `not-applicable`. A pending Rust cell supported by C
keeps the stage incomplete. A C-unsupported cell may be excluded only after
review and with evidence. A C-specific assertion may be marked `not-applicable`
to Rust only with a specific reason such as parser diagnostics, C symbol names,
C struct layout, or C ABI. Lack of Rust implementation is never an exclusion.

`chunk_profile` must say `one-shot` or name the resumable API and its supported
split points. Do not imply that all codecs have resumable decoders. Record
one-shot truncation expectations separately from incremental `need more`
behavior. `rust_counterpart` names the concrete unit or generated test. `variant`
distinguishes basic/canonical and aligned/unaligned modes.

The ledger must map every active test source listed below, every applicable
runtime assertion, the conditional 64-bit and m32 cases, all 26 smoke checks,
all 19 randomized bundles, and all three project integration suites. Fail the
Rust coverage check for unmapped sources, missing supported directions, or
unreviewed exclusions. Do not infer a support matrix from the README encoding
table or from randomized driver coverage.

At final qualification, no C-supported Rust cell may remain pending or be
relabelled unsupported to pass the gate. Every exclusion must identify either
an unsupported C cell or a specific C-only test property and its rationale.

## Test assertions

Use deterministic helpers in `rust/asn1c-runtime` and the generated Rust
harness. Failures must report schema, codec variant, direction, vector or seed,
and a replayable input.

* For valid values, check semantic value, constraints, and exact consumed length.
  Check encoded bit counts for APIs that expose them. For PER, keep meaningful
  bit count separate from final-byte padding.
* For canonical or project-canonical encodings, compare complete reviewed
  vectors and bit counts. For BER and other encodings with multiple valid forms,
  compare semantics unless a specific canonical mode or vector requires bytes.
* For each fixed wire vector, test strict byte prefixes. For PER APIs that accept
  bit offsets, also test relevant bit prefixes. On resumable APIs, split input at
  documented boundaries and verify continuation. On one-shot APIs, verify the
  documented truncated/malformed result without requiring chunk resumption.
* Test trailing bytes, invalid padding, empty input, malformed complete input,
  and capacities below, at, and above the encoded size. Errors must not report
  lengths beyond supplied buffers or leave a partial value marked valid.
* Compare semantics across compatible codecs using common values. Never compare
  bytes across different encodings. Compare C/Rust bytes only for deterministic
  modes with matching options and reviewed vectors.
* Cover omitted and present defaults, extensible roots/additions, unknown
  extensions, open types, nested constraints, tagged CHOICE and collections,
  plus values that decode but fail a separate constraint check.
* Cover REAL positive and negative zero, finite boundaries, infinities, and NaN
  where supported. Compare the specified semantic class; require byte equality
  only when the selected mode defines a unique representation.
* Bound input bytes, depth, collection elements, output bytes, allocations, and
  work. Malformed or adversarial input must return a documented error or budget
  result without panic, unbounded allocation, or process abort.

Tests and runtime code must use safe Rust. Use checked arithmetic for lengths,
offsets, bit counts, and allocation sizes. Unknown PER ENUMERATED extensions
have two policies: permissive mode preserves distinct values for lossless relay;
strict mode rejects. Test and record them separately.

## Priority regression map

Reuse these fixtures and vectors. Add negative, truncation, and resource-budget
cases without weakening existing C assertions.

| Case | Existing target | Rust acceptance focus |
| --- | --- | --- |
| CHOICE maps | 561 | UPER and APER map both index directions. |
| ENUMERATED | 548 | Root, additions, unknown ordinals, relay, strict policy. |
| String alphabet | 550 | Extension sizes, alphabet widths, exact bit counts. |
| Wide APER INTEGER | x691-range | Boundaries, malformed lengths, metadata/storage fit. |
| JER object | check-JER | Duplicate, unknown, malformed, and truncated members. |
| IOC identifier | 563 | Integer and OCTET STRING identifiers in both PER modes. |
| Tagged collection | 566 | Implicit/explicit tags in generated Rust values. |
| CONTAINING | 569 | Valid/invalid embedded PER values and constraints. |
| Collection size | 570 | Decode/constraint separation and nested bounds. |
| Nested constraints | 575 | Constraint metadata survives generation to runtime. |

Sources and existing coverage:

* **561:** `tests/tests-asn1c-compiler/561-choice-canonical-order-OK.asn1`
  and `tests/tests-c-compiler/check-src/check-561.-gen-UPER.-gen-APER.c`.
  Preserve `72 00` at 10 UPER bits and `40 c8` at 16 APER bits. Decode and
  re-encode, then cover alternatives with differing declaration/canonical order.
* **548:** `548-enum-interleaved-ext-OK.asn1`, generated UPER and APER sources,
  and `check-PER-NativeEnumerated.c`, `check-APER-NativeEnumerated.c`, and
  `check-PER-strict-ext.c`. Cover non-monotone assignments, sparse maps, short
  and long normally-small ordinals, forward-compatible marker values, exact
  relay bytes, and strict rejection.
* **550:** `550-uper-string-size-ext-OK.asn1` and
  `check-550.-gen-UPER.c`. Preserve IA5 widths, constrained alphabets,
  canonical indexes, zero-bit alphabets, forward-decode, invalid alphabets,
  nested following fields, and exact bit counts.
* **APER INTEGER:**
  `tests/tests-skeletons/check-APER-INTEGER-x691-range.c`,
  `check-APER-INTEGER.c`, and `skeletons/INTEGER_aper.c`. Preserve valid
  17-, 36-, and 64-bit cases, signed offsets, malformed 33-bit determinants,
  and the C fixed-width 65-bit metadata rejection. That final regression is
  tied to the C accumulator. Rust validation must reject metadata inconsistent
  with its selected storage; do not impose a 64-bit ceiling if Rust supports a
  valid 65-bit bounded integer with a wider representation. Add generated
  descriptor coverage and require validation before alignment/payload reads.
* **JER:** `tests/tests-skeletons/check-JER.c` and
  `skeletons/BIT_STRING_jer.c`. Preserve valid `value`/`length` objects in normal
  and minified modes. Reject duplicate, unknown, missing, malformed, trailing,
  and truncated members. Cover whitespace and the documented strict duplicate
  rejection policy.
* **563:** `563-ios-extensible-identifier-OK.asn1` and
  `check-563.-gen-UPER.-gen-APER.c`. Preserve extensibility metadata for integer
  and OCTET STRING identifiers, inherited/explicit subtype constraints, and the
  `7f 01 00` 24-bit vector in UPER and APER.
* **566:** `566-sequence-of-tagged-choice-OK.asn1` and
  `check-tagged-choice-sequence-of.sh`. Keep shell assertions about fixed ASN.1
  and generated C tags as C-only tests. Add generated Rust value checks for
  implicit/explicit tags through `SEQUENCE OF`, `SET OF`, and bare CHOICE.
* **569:** `569-bitstring-containing-OK.asn1` and
  `check-569.-gen-UPER.c`. Existing checks cover constraint validity, unused
  bits, wrappers, and random fill, but not direct encode/decode vectors. Add
  actual UPER round trips plus invalid embedded encodings.
* **570:** `570-collection-size-OK.asn1` and `check-570.c`. Preserve the
  separation between successful BER decode and constraint validation. Cover
  collection bounds, element constraints, unbounded size, and nested `Holder`.
* **575:** `575-nested-constrained-sequence-of-OK.asn1`,
  `libasn1parser/asn1p_y.y`, and the issue entry in `ChangeLog`. Keep parser
  checks in C and add a generated Rust constraint check. At this baseline, the
  fixture has no active `tests-c-compiler/Makefile.am` entry; explicitly add it
  to the migration ledger and test harness.

Also map cross-codec open types from `check-211.c` and
`check-212.-fcompound-names.c`, OER extension skipping from
`check-544.-gen-OER.c`, and defaults, BER, XER, JER, and CBOR from their
skeleton/generated suites. The current #569 test is constraint/random-fill
coverage, and #575 is not an active runtime test; neither fixture presence nor
the issue number alone is evidence of complete coverage.

## Complete source inventory and mapping

For generated-C tests, port every codec/value assertion to a generated Rust
counterpart. Split mixed tests by assertion. Retain C-only assertions for C
symbol names, C struct/union layout, C warnings, C ABI, and generated C text.
Do not exclude runtime behavior because the original test also checks a C flag.

The 46 base `check_PROGRAMS` in `tests/tests-skeletons/Makefile.am` are:

```text
check-ber_tlv_tag, check-length, check-bits, check-copy, check-OIDs,
check-GeneralizedTime, check-OCTET_STRING, check-UTF8String, check-UTCTime,
check-INTEGER, check-BER-NativeInteger-uint64, check-REAL,
check-XER, check-XER-base64, check-XER-octstr-auto, check-XER-octstr-pdu,
check-XER-empty-names, check-XER-empty-optionals, check-XER-formatting,
check-XER-formatting-regression, check-XER-CHOICE-formatting, check-JER,
check-CBOR, check-OER-support, check-OER-INTEGER, check-OER-NativeEnumerated,
check-APER-support, check-APER-OCTET_STRING, check-APER-INTEGER,
check-APER-INTEGER-constraint, check-APER-INTEGER-semiconstrained,
check-APER-INTEGER-extensible-semi, check-APER-INTEGER-srbid,
check-APER-INTEGER-f1ap, check-APER-INTEGER-x691-range, check-UPER-support,
check-UPER-UniversalString, check-UPER-PrintableString, check-UPER-INTEGER,
check-UPER-INTEGER-semiconstrained, check-recursive-overflow,
check-PER-opentype, check-PER-NativeEnumerated, check-APER-NativeEnumerated,
check-PER-nsnnwn, check-PER-strict-ext
```

The 25 `EXPLICIT_M32` programs reuse the corresponding
`check_32_*_SOURCES` in that Makefile. Keep them as C word-size/ABI checks.
Mirror value and wire properties on a Rust 32-bit target when available. Do not
claim Rust 32-bit qualification when the target was skipped.

The 71 generated-C sources declared in
`tests/tests-c-compiler/Makefile.am` are:

```text
check-03.-fwide-types.c, check-119.-fwide-types.-gen-UPER.c,
check-119.-gen-UPER.c, check-126.-gen-UPER.c, check-126.-gen-APER.c,
check-127.-gen-UPER.c, check-131.-gen-UPER.c, check-132.-gen-UPER.c,
check-133.-gen-UPER.c, check-135.-gen-OER.c, check-148.c, check-19.c,
check-22.-fwide-types.c, check-24.-fwide-types.c, check-25.-fwide-types.c,
check-30.-fwide-types.c, check-31.-fwide-types.c, check-32.c, check-33.c,
check-35.c, check-39.c, check-41.-fwide-types.c, check-41.c, check-42.c,
check-43.c, check-44.c, check-46.c, check-48.c, check-50.c, check-59.c,
check-60.c, check-62.c, check-65.c, check-70.-fwide-types.c, check-70.c,
check-72.-fcompound-names.c, check-73.c, check-92.-findirect-choice.c,
check-92.c, check-158.-fcompound-names.c, check-159.c, check-164.c,
check-539.-gen-UPER.c, check-540.-gen-UPER.c, check-541.-gen-UPER.c,
check-542.-gen-UPER.c, check-543.-gen-UPER.c, check-544.-gen-OER.c,
check-545.-gen-UPER.c, check-546.-gen-UPER.c, check-547.c,
check-548.-gen-UPER.c, check-548.-gen-APER.c, check-550.-gen-UPER.c,
check-552.-gen-UPER.-gen-APER.c, check-561.-gen-UPER.-gen-APER.c,
check-563.-gen-UPER.-gen-APER.c, check-569.-gen-UPER.c, check-570.c,
check-173.-findirect-choice.-fcompound-names.-gen-UPER.-gen-APER.c,
check-184.c, check-185.c, check-201.c, check-202.-gen-CBOR.c, check-203.c,
check-204.c, check-211.c, check-212.-fcompound-names.c, check-213.c,
check64-134.-gen-UPER.c, check64-136.-gen-OER.c
```

The last two are conditional on `TEST_64BIT`. Generated-C LibFuzzer entry
points are `check-42.c`, `check-70.c`, `check-70.-fwide-types.c`, `check-203.c`,
and `check-204.c`. Keep those C fuzz targets. Add deterministic malformed-input
mutations before introducing a separate Rust fuzz target.

The 26 smoke cases in `tests/tests-asn1c-smoke/Makefile.am` are:

```text
check-INTEGER, check-INTEGER_0_1, check-ENUMERATED_foo, check-NULL,
check-BOOLEAN, check-BIT_STRING, check-OBJECT_IDENTIFIER, check-RELATIVE-OID,
check-SEQUENCE_f_INTEGER, check-CHOICE_f_INTEGER, check-OCTET_STRING,
check-IA5String, check-IA5String_SIZE_1, check-UTF8String, check-REAL,
check-SET_OF_INTEGER, check-SEQUENCE_OF_INTEGER, check-Time,
check-skeleton-name-clash, check-JER-open-type, check-JER-enumerated-opentype,
check-encoding-instructions, check-APER-inline-constrained-ioc,
check-fprefix-link, check-fprefix-anon-typedef, check-CONTAINING
```

`check-skeleton-name-clash.sh`, `check-fprefix-link.sh`, and
`check-fprefix-anon-typedef.sh` test C names, files, or linking; retain them as
C-only. Port any runtime assertions from other smoke cases.

Keep all seven compiler scripts active:
`check-parsing.sh`, `check-version-string.sh`, `check-options.sh`,
`check-generated-warnings.sh`, `check-exit-status.sh`,
`check-tagged-choice-sequence-of.sh`, and
`check-pdu-deps-primitive-helpers.sh`. The parser, fixer, compiler options,
warnings, text snapshots, and dependency-file output remain C-only. Reuse
relevant schemas for Rust runtime semantics.

The randomized bundle sources are `00-NULL`, `01-BOOLEAN`, `02-INTEGER`,
`03-ENUMERATED`, `04-REAL`, `05-BIT-STRING`, `06-OCTET-STRING`,
`07-VisibleString`, `08-OBJECT-IDENTIFIER`, `09-RELATIVE-OID`, `10-UTF8String`,
`11-BMPString`, `12-UniversalString`, `13-UTCTime`, `14-GeneralizedTime`,
`15-CHOICE`, `16-SEQUENCE`, `17-SEQUENCE-OF`, and `19-SET-OF`. Keep the C
round trips and map every applicable type/mode to deterministic Rust generation.
The three existing integration scripts are `tests/ioc-v2x/run.sh`,
`tests/ieee1609-ioc/run.sh`, and `tests/f1ap-regression/run.sh`.

Also map the standalone
[integer-native suite](../../tests/tests-integer-native/README.md), which is
not registered in the top-level Automake test list. Preserve its C option and
storage-selection checks. Reuse `oversized-integers.asn1` and the semantic
assertions in `test_constraints.c`, `test_cval.c`, and `test_int32.c` for Rust
integer limits, unsigned/signed distinctions, and constrained UPER round trips.
Keep `test_bigint.c` for the retained C frontend helpers; add independent Rust
integer tests where the corresponding runtime semantics are ported. M0 must
review manual runners and unregistered test sources as well as active lists,
recording applicable coverage or a specific C-only/obsolete disposition.

## Delivery waves

Each wave adds Rust tests and ledger rows while the full C suite continues to
run. A wave passes only when its tests pass, vectors have documented provenance,
and no earlier coverage is lost.

1. **M0/M1: inventory and harness.** Freeze the ledger schema and support
   matrix. Create generated-test selection and prove it is deterministic. Keep
   frontend/parser/fixer tests in C and do not begin codec implementation.
2. **M2: constrained UPER slice.** Start with NULL, BOOLEAN, bounded INTEGER,
   nonextensible ENUMERATED, and bounded BIT/OCTET STRING. Add constraints,
   empty values, bit tails, exact consumed bits, truncation, invalid ordinals,
   invalid application values, and small budgets. Use check-127, check-131,
   check-133 and the applicable `check-UPER-*` skeleton tests.
3. **M3: APER and semantic/type foundations.** Add both PER modes across
   extensions, constrained numbers/alphabets, strings, constructed values,
   tags, defaults, open types, IOC, and CONTAINING. Prioritize 126, 548, 550,
   552, 561, 563, and 569 plus the APER skeleton tests. Include malformed
   metadata and strict/permissive extension policies.
4. **M4: BER/DER/CER and OER.** Add BER decode and CER-compatible input,
   DER/CER encoding, lengths, tags, ordering, OER variants, extensions, open
   types, nested collection limits, and issues 570/575. Map the complete
   C-supported CER encoder domain to Rust or reviewed exclusions. Test decode
   success separately from constraint failure and keep BER permissiveness
   distinct from strict canonical validation.
5. **M5: XER, JER, and CBOR.** Add basic/canonical XER, JER and minified JER,
   strict malformed-object policy, base64, and the complete CBOR support matrix.
   Do not imply JER decode for PKIX open types where C lacks it.
6. **M6: qualification.** Close the ledger against all applicable C-supported
   cells. Run deterministic random generation, malformed mutations, every
   supported feature configuration, generated modules, and cross-codec
   semantic comparisons. Keep GCC, Clang sanitizer, and distcheck lanes required;
   add a separate bounded fuzz job after deterministic gates pass.

These case IDs name existing sources; they do not prove that current tests cover
every operation. In particular, #569 lacks an explicit codec vector, x691-range
tests low-level metadata, and #575 is not an active C runtime test.

## Determinism, fuzzing, and build matrix

The Rust randomized suite should use standard-library test facilities and a
fixed, printed seed. Generate boundary, just-outside, extension, empty, and
large-but-budgeted values from ASN.1 constraints. Mutate each reviewed vector at
length determinants, tags, extension bits, choice indexes, alphabets, JSON
member names, and integer boundaries. Print the seed and exact input on failure.

Keep existing C randomized and LibFuzzer tests in their established
configurations. Add a Rust fuzz campaign only after deterministic tests and
resource limits are in place. Set per-input time, size, nesting, allocation, and
work limits. Do not use an unbounded duration, fetched corpus, or nondeterministic
assertion as a required merge gate.

The Rust CI matrix should include default and all features, no default codec
features, each supported minimal feature subset, strict and permissive unknown
extension policies, and stable formatting/build/test checks. Test 32-bit Rust
where a target and runner are available; report a skipped target explicitly.
Package and feature names are not defined at this baseline, so choose and record
them in the manifest before adding exact CI commands. No Cargo command runs until
the proposed manifests exist.

## Acceptance and limits

For each wave, run its focused C test and Rust counterpart, then `make check`.
Before final qualification, run GCC and Clang sanitizer jobs, `make distcheck`,
all supported Rust feature configurations, and the full ledger check. Keep C as
the comparison implementation; use standards and reviewed vectors to settle
correctness disagreements.

This inventory is specific to the stated baseline. Recount Automake entries and
refresh the ledger when tests change. Build outputs under test directories are
not source inventory items.
