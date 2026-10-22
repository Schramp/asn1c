# SEQUENCE extension addition groups (#583)

[Ruud Schramp (@Schramp)](https://github.com/Schramp) reported
[issue #583](https://github.com/mouse07410/asn1c/issues/583), with the
reproduction cross-checked against gambas-asn1 and Claude Code.

## Behavior

For a SEQUENCE extension addition group, the bracketed component list is
treated as components of the enclosing SEQUENCE. BER, DER, CER, and XER
therefore encode the group members as siblings; they do not emit a synthetic
SEQUENCE TLV or an `<ext1>` XML element. CER retains the indefinite length and
end-of-contents marker of the enclosing SEQUENCE. A present group still
requires its mandatory members. PER retains one open type for the group, as
required by X.691.

The regression value is `id=1`, `before=TRUE`, `g1=3`, and `after=2` for:

```asn1
Rec ::= SEQUENCE {
    id INTEGER (0..255),
    ...,
    before BOOLEAN,
    [[ g1 INTEGER (0..15), g2 BOOLEAN OPTIONAL ]],
    after INTEGER (0..3)
}
```

Its flat BER/DER encoding is:

```text
30 0c 80 01 01 81 01 ff 82 01 03 84 01 02
```

The reported compiler instead emitted a constructed `[2]` group wrapper and
tagged the following field as `[3]`. The fix marks the parser's synthetic
group expression, applies automatic tags and SEQUENCE tag-run checks to its
leaf components in enclosing order, and emits `ATF_EXTENSION_GROUP` plus
`asn_SEQUENCE_specifics_t.extension_group` in generated descriptors.

The generated C value keeps the existing nested pointer representation for
the group. The metadata lets the BER decoder retain incremental state in that
group allocation while consuming flat sibling TLVs. DER omits the wrapper and
uses checked size accumulation. XER reads and writes group members alongside
the enclosing SEQUENCE's other components. The group descriptor remains a
SEQUENCE for PER, preserving the single-open-type group encoding.

The CER SEQUENCE encoder recognizes the same generated member flag and appends
the synthetic group's child encodings directly to the enclosing SEQUENCE body.
It validates the synthetic descriptor, counts the group toward the existing
work and recursion limits, checks its element array against the configured
element ceiling, and stores emitted children in the existing bounded scratch
buffers. This keeps CER's indefinite parent framing while omitting an `a2`
group wrapper. SET member collection and ordering do not use this path.

## Scope and compatibility

This change handles extension addition groups in SEQUENCE. SET groups retain
their prior nested behavior and are not claimed as fixed here. CHOICE
extension addition groups were already flattened by the parser and are not
changed by this work.

The current parser grammar accepts a component list inside `[[...]]` but has
no version-prefix production for extension groups, so versioned group notation
is outside this change.

The added `extension_group` member changes `asn_SEQUENCE_specifics_t`, and
generated parent descriptors use the new `ATF_EXTENSION_GROUP` flag.
Regenerate generated C and compile it with the matching updated skeleton
headers and runtime. Mixing descriptors and skeletons from different
versions can misinterpret the descriptor metadata.

Tag validation follows the flattened SEQUENCE component order and its
optional-run boundaries. A regression includes adjacent mandatory components
with the same explicit tag across a group boundary; the group checker must not
reject those solely because their tags match. The existing extension-marker
normalization remains unchanged, including removal of the second marker before
tag fixup.

## Decoder and encoder hardening

The BER group-body decoder bounds each child decode by the enclosing definite
SEQUENCE remainder, preserves child state across input splits, and leaves the
parent's next component or an indefinite-length end marker for the parent
decoder. It only ends a group at a tag boundary when all remaining group
members may be absent. Missing mandatory group members fail at definite
frame end, an indefinite-length end marker, or a following parent field.
Unknown extension additions remain the parent's responsibility to skip; the
parent must consume the complete frame without consuming a following PDU.

The focused C regression exercises valid flat and indefinite BER, every byte
split of the BER and XER vectors, every one-byte mutation of the BER vector,
truncated prefixes, an unknown extension followed by another PDU, an old
synthetic-wrapper encoding, optional and mandatory group members, DER sizing
failure recovery, and UPER/APER golden vectors. A libFuzzer entry exercises
BER, XER, UPER, and APER complete decoders, checks reported consumption
against input size, and frees every partial result. Seed inputs are stored in
`tests/tests-c-compiler/data-583/`.

Review of the DER sizing path found that child-encoding and missing-mandatory
errors could return without restoring the thread-local encoding recursion
depth. The encoder now restores depth on every post-increment failure path and
checks size accumulation before addition. The regression repeats an invalid
child encode, then verifies that an empty OCTET STRING and a valid value still
encode with the depth counter restored.

The group boundary tests also guard against treating a required final member
as optional. The decoder compares the remaining optional run against the full
number of unprocessed members; a strict-prefix comparison would incorrectly
accept a group missing its final required child.

## Standards and validation

The implementation follows the 2021 editions of the relevant standards:

* [ITU-T X.680 (02/2021)][x680], clauses 25.6.3 (component-list notation),
  25.8 and 25.10 (automatic tags), 25.13 (mandatory members in a present
  group), and 25.18–25.20 (XML representation).
* [ITU-T X.690 (02/2021)][x690], clause 8.9 (SEQUENCE BER/CER contents).
* [ITU-T X.691 (02/2021)][x691], clause 19.9 (extension addition groups in PER).
* [ITU-T X.693 (02/2021)][x693], clause 8.3.1 (XML encoding).

[x680]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I!!PDF-E&lang=e&type=items
[x690]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I!!PDF-E&lang=e&type=items
[x691]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I!!PDF-E&lang=e&type=items
[x693]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.693-202102-I!!PDF-E&lang=e&type=items

The final clean focused C assembly run passed all three checks for issues
#582–#584. The #583 check covers multiple groups in one SEQUENCE, an untagged
CHOICE group member, the mandatory-final-member boundary, and malformed CER
input. The independent integration converter confirmed the flat DER vector,
exact CER bytes `30 80 80 01 01 81 01 ff 82 01 03 84 01 02 00 00`, strict CER
decode/re-encode, BER decoding in chunks of 1–17 bytes, unchanged PER vectors,
and flat XER.
