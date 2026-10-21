# JER converter and BER string review

Reviewed against `vlm_master` commit `9064c57bb603578e17e5b406e07cb79c4bc570ba`
on 2026-10-21. The public branch still pointed at that commit during review.

## Reports and credits

Ruud Schramp (@Schramp) reported
[issue #578](https://github.com/mouse07410/asn1c/issues/578), provided
[PR #579](https://github.com/mouse07410/asn1c/pull/579), and reported
[issue #581 with a patch](https://github.com/mouse07410/asn1c/issues/581).
Their reports credit investigation with Claude Code. @mr-j0nes independently
provided [PR #580](https://github.com/mouse07410/asn1c/pull/580) and its initial
BER regression test. The asn1c maintainers, assisted by Codex and Luna agents,
reviewed the fixes and added the security corrections and extended tests here.

## JER input: issue #578 and PR #579

The original converter special case for JER files larger than its read buffer
called `asn_decode()` once and returned the partially or completely allocated
structure without checking the decode status. It discarded bytes after the
first PDU. A file containing two records could therefore produce only the
first record and exit successfully. Malformed or truncated input could also
bypass the normal decode failure handling.

The report's reproduction uses this module:

```asn1
BigTest DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Big ::= SEQUENCE { id INTEGER, data OCTET STRING }
END
```

Generate a converter with `asn1c -pdu=Big big.asn1`, build it with
`make -f converter-example.mk`, then provide two concatenated JER objects whose
combined size exceeds 8192 bytes. Convert with `-ijer -oxer` and count `<id>`
elements. Each input PDU must have a corresponding output PDU.

An isolated 10,070-byte, three-PDU fixture produced one record with the original
`9064c57b` converter and three with PR #579's converter. The extended fix's
sanitized smoke test also checks 400 small records whose total exceeds 8 KiB.

PR #579 removes the early return and restores normal result checking and
remainder buffering. The integrated fix retains that behavior and hardens
the affected buffering path; the regression script also checks large single
values and invalid input. Input is read in checked chunks into a retained
buffer, eliminating the signed `file_size + 1` calculation and unchecked
geometric allocation growth. Pipes work without seeking. JER input must be
finite: decoding starts at EOF and memory use remains proportional to total
input size, with no configurable total-input quota. This is appropriate for
the sample file converter, not an unrestricted live-stream service.
The [incremental JER proposal](jer-streaming-design.md) describes a staged
replacement for this workaround; it is a design, not implemented behavior.

The shared converter loop also rejects stream read errors instead of retrying
forever, and validates decoder consumption before subtracting retained lengths.
The touched critical helpers stay within 200 lines and a conservative source
branch count of 20; their parameters, error handling, and provenance are
documented in the source.

This converter handles a sequence of ASN.1 values;
successful earlier values may already have been written when a later value
fails. Callers requiring an atomic output file should stage output and check
the converter's exit status before accepting it.

## BER string tags: issue #581 and PR #580

Issue #581 and PR #580 describe the same defect. An IMPLICIT tag can replace
an EXPLICIT wrapper tag in the effective wire chain while the descriptor's
`all_tags` array still records the replaced tag:

```asn1
Retag DEFINITIONS IMPLICIT TAGS ::= BEGIN
Label ::= [9] EXPLICIT UTF8String
Label2 ::= [1] Label
T2 ::= SEQUENCE { l Label2 }
END
```

`<T2><l>A</l></T2>` encodes as `30 05 a1 03 0c 01 41`. Before the fix,
the BER decoder expected the replaced `[9]` at the inner wrapper level and
rejected the UTF8String tag `0c`. This prevents decoding the encoder's own DER.

Re-linking a generated `Label2` converter with the original `9064c57b` decoder
reproduced exit status 65 and `Decode failed at byte 4` for legal DER. The same
original decoder accepted the superseded `[9]` wrapper form. The corrected
decoder accepts the effective chain and rejects that superseded wrapper.

The corrected lookup uses `td->tags[level]` within the effective wrapper chain.
The initial correction retained the final `all_tags` entry below that chain.
The subsequent standards review found that generated character-string aliases
can end that array with their character-string tag instead of OCTET STRING.
For built-in string operations, component matching must therefore enforce the
operation's fragment tag after explicit wrappers: universal 4 for octet and
restricted character strings, or universal 3 for bit strings. Descriptor-only
fallback remains for custom operations. See the standards verification below.

PR #580 changed both lookups to `tags`. For `VisibleString`, `tags` contains
universal tag 26, while `all_tags` ends in universal OCTET STRING tag 4.
Consequently, the PR accepts a tag-26 child where the existing descriptor and
fragment validation require tag 4. This is an input-validation regression;
this review does not establish a memory-corruption exploit.

The failed [C/C++ CI run](https://github.com/mouse07410/asn1c/actions/runs/39618816953)
confirms the same failure in `build-and-check`, `clang-sanitizers`, and
`distcheck`: `check-src/check-25.-fwide-types.c` aborts because the
"VisibleString chunk used as OCTET fragment" mutation returns `RC_OK`.
Restoring the descriptor's fragment fallback fixes that CI regression without
weakening the rejection test or changing the CI workflow. The subsequent alias
correction below addresses metadata that does not end in a component tag.

## Regression coverage

`tests/tests-asn1c-smoke/check-JER-multi-pdu.sh` exercises real generated JER
converters. `tests/tests-skeletons/check-BER-expected-tag.c` tests effective
wrapper tags and fragment rejection directly, and
`tests/tests-asn1c-smoke/check-BER-retag.sh` checks generated descriptors.
The existing generated C check-25 retains its malformed-fragment and
incremental-decoding coverage. The retagged-string randomized bundle extends
the existing corpus generation and optional LibFuzzer path.

Run the linked skeleton and generated converter regressions with:

```sh
make -j8
make -j8 check -C skeletons
make -j8 check -C tests/tests-skeletons
make -j8 check -C tests/tests-asn1c-smoke
make -j8 check -C tests/tests-c-compiler
make -j8 check -C tests/tests-randomized TESTS=bundles/20-retagged-strings-bundle.txt
```

The randomized bundle participates in ordinary `make check`; explicit corpus
generation is available through `make -C tests/tests-randomized check-corpus`.
Tests establish the covered behavior, not the absence of all vulnerabilities.

## Initial validation of d4e2da5a on 2026-10-21

The generated C suite passes 71/71, including the CI-failing check-25 mutation.
The linked skeleton suite passes 57/57. Seven targeted smoke tests pass:
`check-JER-multi-pdu.sh`, `check-BER-retag.sh`, `check-JER-open-type.sh`,
`check-JER-enumerated-opentype.sh`, `check-binary-format-selectors.sh`,
`check-CER.sh`, and `check-PER-single-flavor.sh`. The new nine-case randomized
bundle and existing corpus-policy checks pass. Normal and C89 converter build
checks also pass. The exhaustive type-by-codec smoke build matrix was stopped
in favor of these affected-path checks; it is not reported as a complete run.

The dedicated JER smoke test additionally passes with
`-fsanitize=address,undefined,unsigned-integer-overflow`,
`-fno-sanitize-recover=all`, and `-fno-omit-frame-pointer`. The BER direct
regression passes under ASan/UBSan; linking it instead with PR #580's decoder
object reproduces four invalid-tag acceptance failures. The full generated C
suite uses the configured ASan/UBSan, unsigned-overflow and nullability checks.
These are local results; the remote GitHub CI jobs were not rerun by this review.

`make dist` passes and includes the new tests, randomized bundle, and this
review. Both new smoke scripts also pass with the sanitizer flags above using
skeletons extracted from that distribution archive and the locally built
compiler, exercising source paths outside the checkout. A complete local
`make distcheck` was not run.

## Standards verification on 2026-10-21

Checked the official in-force editions:

* [ITU-T X.680 (02/2021)](https://www.itu.int/rec/T-REC-X.680-202102-I/en).
* [ITU-T X.690 (02/2021)](https://www.itu.int/rec/T-REC-X.690-202102-I/en),
  including [Erratum 1](https://www.itu.int/rec/T-REC-X.690-202109-I!Err1/en).
* [ITU-T X.697 (02/2021)](https://www.itu.int/rec/T-REC-X.697-202102-I/en).
* [ECMA-404, second edition](https://ecma-international.org/wp-content/uploads/ECMA-404.pdf).

| Changed behavior | Applicable clauses and conclusion |
| --- | --- |
| IMPLICIT over EXPLICIT | X.680 31.2.6-31.2.7 and X.690 8.14.2-8.14.4: replacing `[9]` with `[1]` preserves the inner UTF8String encoding. The superseded wrapper must not be expected. |
| Constructed string fragments | X.690 8.7.3.2 and 8.23.3 require universal OCTET STRING components, including nested components. Clause 8.6.4.1 requires universal BIT STRING components for bit strings. |
| BER versus canonical forms | X.690 9.1-9.2 restrict CER lengths and fragments; 10.1-10.2 restrict DER. Constructed string fixtures use BER input; DER output contains primitive string content beneath any explicit wrappers. |
| Complete JER values | X.697 6.4-6.5 and 7.6.2 preserve per-value encoding semantics; 25.3 and 27.3 cover the fixtures' hexadecimal octets and object fields. Buffering and multi-PDU file framing are application choices. Concatenated PDUs are separate JSON texts, not one JSON document or an ASN.1 SEQUENCE OF. |
| JSON whitespace | ECMA-404 clause 4 permits CR, LF, TAB, and SPACE around tokens. The small multi-PDU regression now exercises all four. |

X.690 Erratum 1 corrects Figure 4's high-tag-number example; it does not amend
these tagging or fragment clauses. The official X.690 PDF was downloaded and
read directly when the browser's PDF fetch timed out.

This review also exposed a remaining alias-fragment validation gap in
`d4e2da5a`: alias metadata admitted a repeated UTF8String tag as a component.
The generated `Label2` converter accepted `a1 05 2c 03 0c 01 41` with status 0;
the standard-conforming fragment at that position uses `04`, rather than `0c`.
The follow-up correction preserves effective wrapper matching and enforces the
built-in component tag at fragment depths, with fixed-vector and generated
alias regressions. The legacy check-25 positive fixture also used tag 26 for
components of an IMPLICIT VisibleString, contrary to the same clauses. Its
three component tags now use OCTET STRING; each former tag placement remains
an explicit rejection mutation, alongside the original inner-tag rejection.
The published X.690 8.23.5 primitive and constructed "Jones" examples provide
independent positive vectors. This is verification of the changed paths and covered
vectors, rather than a claim of complete ASN.1 conformance for the runtime.

Follow-up validation passes 71/71 generated C tests and 57/57 linked skeleton
tests, plus the expanded BER alias smoke, CER smoke, and four-whitespace JER
smoke tests. Normal/C89 runtime build checks and direct ASan/UBSan regressions
also pass. The corrected check-25 retains its deterministic mutations and
incremental-decoding checks.
