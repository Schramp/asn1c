# Issue #582: extensible permitted alphabets

Issue #582, reported by [Ruud Schramp (@Schramp)](https://github.com/mouse07410/asn1c/issues/582),
was cross-validated with
`gambas-asn1`, assisted by Claude Code. The compiler emitted unconstrained
8-bit characters instead of the built-in effective alphabets for extensible
`FROM` constraints. The original case declares `VisibleString` and
`IA5String` fields with `FROM ("a".."z", ...)`, plus a `VisibleString` whose
size is separately constrained to `1..8`. Encoding `"ab"` in all three fields
previously produced UPER bytes `02 61 62 02 61 62 16 16 20`. The corrected
encoding is `02 c3 88 0b 0e 21 c3 88` (62 bits). The APER regression vector is
`02 61 62 02 61 62 10 61 62` (72 bits).

## Standard behavior

The implementation follows [ITU-T X.691 (02/2021), ISO/IEC 8825-2:2021][x691]:

- Clauses 10.3.11 and 10.3.12 make extensible permitted-alphabet constraints
  non-PER-visible and define the effective alphabet as the characters that can
  occur in a value, falling back to the unconstrained type's full alphabet.
- Clause 10.3.20 preserves separately visible constraints, such as `SIZE`,
  while removing non-visible extensible alphabet constraints from PER coding.
- Clause 10.3.21 ignores non-visible operands of an `INTERSECTION`; it also
  says that `EXCEPT` and its following set are ignored for PER encoding.
- Clauses 30.5.1, 30.5.2, and 30.5.4 define the effective alphabet, bit width,
  and character-to-code mapping. NumericString always needs canonical ranking
  for its 11-character built-in alphabet. PrintableString uses the ISO/IEC 646
  values directly when the upper bound fits the bit width (as the full built-in
  alphabet does); narrower alphabets may need canonical ranking.
- Clause 30.4's extension bit concerns types extensible for PER encoding. An
  extensible `FROM` constraint is instead omitted from the effective alphabet;
  it does not add an alphabet-extension bit. A separate extensible `SIZE`
  constraint retains its own PER behavior.

## Implementation

Alphabet validation now has its own abstract-range mode, separate from PER
range generation. During abstract validation, an extensible `FROM` subtree is
expanded to its enclosing type alphabet before subsequent serial or
intersection constraints are applied. This accepts characters outside the
listed root while preserving a later closed restriction and alias subtyping.
Constraint normalization first applies the X.680 50.11/52.5 subtype rules,
which remove earlier extension markers and additions before a serial subtype
constraint. Expansion therefore applies only to an extensible `FROM` marker
that remains in the normalized tree. Direct serial and alias-subtype
regressions verify that closed alphabet and independent `SIZE` restrictions
remain equivalent. The general-purpose range API and PER map calculation
remain distinct.

The PER compiler now calculates the effective alphabet independently. It omits
extensible permitted-alphabet clauses from the PER range, keeps separately
visible `SIZE` ranges, and builds sparse alphabet maps from the effective PER
range rather than reusing the validation table. This preserves compact
NumericString and PrintableString coding. Non-extensible narrowed alphabets
retain their existing restrictions and coding.

Abstract validation applies binary `EXCEPT` subtraction and `ALL EXCEPT` to
the validation range. This does not alter PER behavior: X.691 10.3.21 requires
those clauses to be ignored for PER. Subtracting the entire permitted set
produces an empty alphabet; the generated checker accepts only the empty
string.

## Security review and regression coverage

The regression test covers the original byte vectors, character values beyond
the listed extensible root, invalid VisibleString and IA5String code units,
closed alias and intersection restrictions, non-extensible narrowed alphabets,
`EXCEPT`, `ALL EXCEPT`, and the empty-alphabet case. NumericString and
PrintableString round-trip under both PER variants; a NumericString index
outside the 11-character map and truncated Rec streams are rejected. The
randomized VisibleString bundle now includes extensible alphabets, serial and
intersection restrictions, aliases, exclusions, IA5String, NumericString,
PrintableString, BMPString, and UniversalString.

The PER lookup emitter checks range and interval bounds before indexing fixed
tables. Interval subtraction checks integer endpoints before adding or
subtracting one. If abstract or PER range computation fails, code generation
fails instead of omitting the generated constraint checker. These controls
avoid converting an allocation or malformed-range failure into unconstrained
acceptance. The generated UniversalString checker casts each octet to
`uint32_t` before shifting, avoiding signed-shift undefined behavior for code
units with the high bit set. Closed-alphabet tests reject `0x80000000` and
`0xffffffff` values; the high-bit case also exercises this path under UBSan.

Focused runtime checks are in
`tests/tests-c-compiler/check-src/check-582.-gen-UPER.-gen-APER.c`, with the
ASN.1 types in `tests/tests-asn1c-compiler/582-alphabet-OK.asn1`.

The related random-fill security review found that the generator could sample
raw character values instead of valid entries in a sparse PER alphabet map,
and could ignore a caller-supplied member constraint. The OCTET STRING filler
now samples through the active value-to-code map, validates the complete
candidate against the effective constraints, and retries at most 128 times.
It installs the candidate only after validation, so exhausted retries preserve
the caller's existing value. Regression coverage in
`tests/tests-skeletons/check-OCTET_STRING-rfill-guard.c` checks NumericString
and PrintableString characters, a member-level `EXCEPT` callback, zero-length
values, malformed PER bounds, and failure atomicity.

[x691]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I!!PDF-E&lang=e&type=items
