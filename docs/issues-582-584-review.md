# Issues #582–#584: extension-root review

Reviewed against the 2021 editions of ITU-T X.680, X.690, X.691, and X.693.
[Ruud Schramp (@Schramp)](https://github.com/Schramp) reported
[issue #582](https://github.com/mouse07410/asn1c/issues/582),
[issue #583](https://github.com/mouse07410/asn1c/issues/583), and
[issue #584](https://github.com/mouse07410/asn1c/issues/584). The reports
credit cross-validation with gambas-asn1, C++, and Rust, assisted by Claude
Code.

## Shared model, separate defects

These reports share a broader lesson: extension syntax has different meanings
and encoding visibility for different ASN.1 constructs and transfer syntaxes.
Each compiler and runtime path must apply the construct-specific rule; a
single generic "preserve the extension root" transformation is incorrect.
They are separate defects in three code paths:

* **#582, extensible permitted alphabets:** an extensible `FROM` alphabet was
  incorrectly treated as an unconstrained alphabet for PER, producing 8-bit
  characters instead of the built-in effective alphabet for these
  known-multiplier strings. Constraint intersections also needed separate
  abstract-value validation. A separate validation path accepted a character
  excluded by `EXCEPT`.
* **#583, extension addition groups:** a synthetic SEQUENCE used to hold group
  components was emitted as an XML/BER wrapper. The ASN.1 group is a flat set
  of components in those encodings, while its storage remains a pointer to a
  C structure.
* **#584, `EXTENSIBILITY IMPLIED` on ENUMERATED:** the fixer inserted implied
  markers for constructed types but did not normalize enumerations before
  assigning their root and extension values.

The fixes therefore remain type-specific. #582 uses the built-in effective
alphabet for PER while applying ASN.1 constraints to values. #583 marks the
synthetic group in generated descriptors and flattens it in the BER and XER
runtimes. #584 inserts an implied ENUMERATED marker before enum numbering,
using the defining module for imported types.

## Reproduction vectors

### #582 — extensible `FROM`

The regression module is [582-alphabet-OK.asn1](../tests/tests-asn1c-compiler/582-alphabet-OK.asn1).
For the reporter's value (`"ab"` in each of `word`, `ia5`, and `sizedFrom`),
the original converter emitted `02 61 62 02 61 62 16 16 20`: it used
unconstrained, 8-bit characters. The corrected vectors use the built-in
effective alphabet: UPER `02 c3 88 0b 0e 21 c3 88` (62 bits) and APER
`02 61 62 02 61 62 10 61 62` (72 bits).

The security review also found that the original converter accepted `"x"`
for `VisibleString (FROM ("a".."z" EXCEPT "x"))`, returning DER
`1a 01 78`. The constraint validator now expands the open `FROM` alphabet
before set algebra and applies `EXCEPT`/`ALL EXCEPT` separately from PER maps.
The focused regression rejects the excluded character, verifies empty-alphabet
handling, and checks direct serial subtypes against equivalent aliases.

Review of generated UniversalString validation also reproduced a signed-shift
UBSan failure for a character starting with `0x80`: byte promotion made
`ch[0] << 24` a signed operation before assigning the result to `uint32_t`.
Generated checkers now convert bytes to `uint32_t` before shifting. Closed
alphabet tests reject `0x80000000` and `0xffffffff` without undefined behavior.

Range intersection and subtraction now propagate allocation errors without
asserting, silently dropping a restriction, or losing partially transferred
interval ownership. A unit-test allocator sweeps each allocation failure in
a successful split/transfer control case; the sweep passes ASan, UBSan,
unsigned-overflow checks, and LeakSanitizer.

The new randomized cases exposed a separate test-data generation defect:
OCTET STRING random filling sampled raw bounds without honoring sparse PER
alphabet maps, producing punctuation in NumericString values. The filler now
samples valid map entries and validates each complete temporary candidate
against type and member constraints before replacing existing storage.
Retries are limited to 128; restrictive constraints may return `ARFILL_FAILED`
without changing the prior value. This is a best-effort generator, not a
guarantee that every satisfiable constraint will yield a sample. Tests cover
NumericString, PrintableString, exclusions, empty/fixed/semi-constrained sizes,
malformed bounds, oversized requests, and failure atomicity. This fixes test
data generation; it is not presented as a remotely reachable decoder flaw.

### #583 — extension addition groups

The reproduction is [583-extension-groups-OK.asn1](../tests/tests-asn1c-compiler/583-extension-groups-OK.asn1).
Its `Rec` value has `id=1`, `before=TRUE`,
`g1=3`, and `after=2`. The original output used the synthetic group wrapper;
for DER it produced `30 0e 80 01 01 81 01 ff a2 03 80 01 03 83 01 02`.
The standard flat form is `30 0c 80 01 01 81 01 ff 82 01 03 84 01 02`; the
original decoder rejected that form with status 65.

The runtime now decodes and re-encodes flat XER group fields as siblings
(`g1`, then optional `g2`) and leaves the parent field following the group
available to the parent decoder. The isolated converter round-tripped the
group-present and group-absent forms, passed input buffers of sizes 1–80 for
`g1`, and sizes 1–100 for `g1` plus `g2`. It rejected `g2` without required
`g1`. The focused assembly regression passed flat BER/DER/XER encoding and
decoding, unchanged UPER/APER vectors, all XER split points, strict BER split
decoding, malformed-group cases, unknown-extension framing, and DER
recursion-depth recovery.

The CER SEQUENCE encoder also omits the synthetic group TLV while preserving
the enclosing indefinite-length SEQUENCE. Root's independent converter
confirmed the exact bytes `30 80 80 01 01 81 01 ff 82 01 03 84 01 02 00 00`,
strict CER decode/re-encode, and BER decoding in 1–17 byte chunks. The new
group-body helper validates the synthetic descriptor, charges work and
recursion depth, enforces the configured element bound, and uses the encoder's
existing bounded scratch buffers; SET handling is unchanged.

This fix covers SEQUENCE extension addition groups. Pre-existing SET groups
retain their nested encoding behavior; CHOICE extension groups are outside
this change.

Security review exercised the decoder with 3,598 one-octet mutations of the
BER vector and every truncation length under ASan, UBSan, and unsigned-integer
overflow sanitization, with no sanitizer finding. Root review of the draft
BER decoder caught state-resumption, stale wrapper/tag-to-member routing, and
premature success at a parent tag. Those cases were corrected in the BER path
and the focused assembly regression passed strict split decoding,
malformed-group cases, and unknown-extension framing. A later root review found
an off-by-one in the optional-tail boundary check. The corrected check requires
every remaining child to be optional, and regressions reject a missing final
mandatory child at a definite frame end, an indefinite end marker, and the next
parent field.

The security review also found that the DER SEQUENCE sizing pass returned on
a child-encoding or missing-mandatory-pointer error without decrementing the
thread-local recursion-depth counter. A sanitized failure-injection test
reproduced the counter changing from zero to one; repeated invalid encodes
could reduce the allowance available to later valid encodes on that thread.
The follow-up fix and regression for repeated child-encoding failure followed
by a successful encode passed in the focused assembly regression.

The same review found an invalid in-memory OCTET STRING encoder value that
crashed during DER encoding: a non-null `OCTET_STRING_t` with `buf == NULL` and
`size == 1`. The original implementation dereferenced the null buffer; the
original ASan probe exited after a zero-page read. The DER encoder now rejects
null values, missing storage for nonempty strings, unrepresentable lengths,
and invalid BIT STRING unused-bit metadata before callbacks. It also avoids
zero-length payload callbacks. The standalone
[`check-OCTET_STRING-der-guard.c`](../tests/tests-skeletons/check-OCTET_STRING-der-guard.c)
regression passed a local ASan/UBSan/unsigned-overflow build, including empty
null-buffer values, a partial BIT STRING byte, invalid sizes and metadata,
and callback failure. This is an invalid encoder-input hardening result, not a
claim about remotely supplied decoder input.

The generated group member keeps pointer storage. Code generation adds the
`ATF_EXTENSION_GROUP` member flag and sets
`asn_SEQUENCE_specifics_t.extension_group` on the synthetic SEQUENCE
descriptor. Regenerate generated C and use the matching skeleton headers and
runtime together; the added descriptor metadata changes the generated/runtime
interface.

### #584 — implied ENUMERATED extensibility

The regression module is [584-implied-enum-OK.asn1](../tests/tests-asn1c-compiler/584-implied-enum-OK.asn1).
The reporter's `green` / `high` value encoded as UPER `0x30` before the fix;
the corrected UPER and APER vectors are both `0x14` with six significant
bits. The enum codec tests also exercise explicit markers, imported enum
ownership, unknown extension ordinals, invalid root ordinals, and truncated
root and extension indexes. INTEGER and BIT STRING named values remain
unchanged.

## Standards references

Current clause numbers below refer to the 2021 editions. Some report text
cited older clause numbers; those references were renumbered in the current
editions.

* **#582:** [X.691 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I!!PDF-E&lang=e&type=items), clauses 10.3.11–10.3.12 (permitted-alphabet visibility), 10.3.20–10.3.21 (serial and set algebra), and 30.4 Note 2 and 30.5 (known-multiplier alphabet encoding).
* **#583:** [X.680 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I!!PDF-E&lang=e&type=items), clauses 25.6.3 (bracketed notation), 25.8 and 25.10 (automatic tags), 25.13 (mandatory components of a present group), and 25.18–25.20 (XML representation); [X.690 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I!!PDF-E&lang=e&type=items), clause 8.9; [X.691 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I!!PDF-E&lang=e&type=items), clause 19.9; and [X.693 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.693-202102-I!!PDF-E&lang=e&type=items), clause 8.3.1.
* **#584:** [X.680 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I!!PDF-E&lang=e&type=items), clause 13.4, and [X.691 (02/2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I!!PDF-E&lang=e&type=items), clause 14.3.

## Security review scope

The review covered compiler constraint/group normalization, generated metadata,
untrusted BER/XER/PER input, partial-object ownership, and invalid in-memory DER
encoder values. Generated type descriptors remain trusted metadata. The fixes
do not claim a complete audit of other transfer syntaxes or pre-existing SET
group handling.

The new decoder and encoder helpers were kept below 20 in a conservative
branch-count scan and below 200 source lines. Existing large BER/XER state
machines and the general constraint evaluator remain legacy units; this work
does not claim that the entire repository meets those size/complexity limits.

## Validation

Validation used the configured sanitizer-enabled C regression environment and
an additional LLVM 22 ASan/UBSan/LeakSanitizer build where noted:

| Check | Result |
| --- | --- |
| Top-level build | Passed |
| Parser unit test | 1/1 passed |
| Fixer/range unit tests | 2/2 passed |
| Compiler scripts, including reviewed generated-output references | 7/7 passed |
| Generated C regressions | 74/74 passed |
| Runtime/skeleton regressions | 59/59 passed |
| Clean issue-specific generated C regressions | 3/3 passed |
| Additional UniversalString high-bit regression | Passed under UBSan |
| Range allocation-failure sweep | Passed ASan, UBSan, unsigned-overflow checks and LSan |
| Random-fill guard | Passed configured sanitizers and a separate LLVM 22 LSan build |
| Selected randomized alphabets, normal build flags | 18/18 passed: nine cases in default and native modes, UPER and APER |
| Independent #583 converter | Exact DER/CER, flat XER, unchanged UPER/APER, BER chunks 1–17 passed |
| Independent DER failure probes | Invalid OCTET STRING rejected; SEQUENCE depth restored from 0 to 0 |
| Decoder libFuzzer smoke run | 2,070,594 inputs in 16 seconds; no codec sanitizer or leak finding |

The runtime check libraries were explicitly rebuilt with
`make -C skeletons check` before running `make -C tests/tests-skeletons check`;
`make all` alone does not rebuild these check-only libraries. This includes
normal, C89, and strict-unknown-extension library builds. The final generated-C
run passed all 74 tests; 24 tests whose random-fill objects predated the final
helper changes were additionally rebuilt and passed. The selected randomized
cases used an eight-unit budget and generated values without skipped fills.
The release archive was built and checked for the new documentation, fixtures,
standalone regressions, and fuzz seeds.

The initial LLVM 22 fuzz run reported 56 leaked bytes from libFuzzer's own
`StartRssThread`, rather than from codec allocation stacks. The successful run
kept LeakSanitizer enabled and disabled that background monitor with
`-rss_limit_mb=0 -purge_allocator_interval=-1`. Both runs used four decoder
entry points and a 512-byte maximum input. This bounded smoke run is not an
exhaustive security proof.
