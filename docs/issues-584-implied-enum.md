# Issue #584: `EXTENSIBILITY IMPLIED` and `ENUMERATED`

## Report

[Ruud Schramp (@Schramp)](https://github.com/mouse07410/asn1c/issues/584)
reported that `EXTENSIBILITY IMPLIED` did not make
otherwise unmarked `ENUMERATED` types extensible. The reproduction used an
`AUTOMATIC TAGS EXTENSIBILITY IMPLIED` module with a named `Colour` type and an
inline `ENUMERATED` type inside a `SEQUENCE`. Encoding the value `green` / `high`
produced UPER byte `0x30` instead of `0x14` (six significant bits after the fix).

The report was cross-validated with `gambas-asn1`, with assistance from Claude
Code.

## Cause and fix

The fixer added implicit extension markers to `SEQUENCE`, `SET`, and `CHOICE`
types, but did not normalize `ENUMERATED` values before assigning their
numbers. Consequently, the generator emitted non-extensible enumeration
descriptors and omitted the ENUMERATED extension bit from PER encodings.

Enum normalization now inserts a trailing marker before numbering when the
defining module has `EXTENSIBILITY IMPLIED` and the enum has no explicit
marker. The defining module is used for imported types. An existing explicit
marker remains the root boundary. INTEGER and BIT STRING named values are
outside this enum-specific transformation.

## Validation and security

The regression fixture covers named and inline enums, an alias, explicit
extension markers, imported enums with differing owner and consumer module
flags, and non-extensible INTEGER and BIT STRING named values. The codec test
checks the UPER golden encoding and exercises valid, unknown-extension, and
truncated ENUMERATED inputs through both UPER and APER. Unknown extension
ordinals remain representable by the runtime's reserved marker value. Tests
also reject truncated extension indexes, truncated root indexes, and an
out-of-range root ordinal, and release any partial decode objects returned on
failure. Marker creation handles both expression and identifier allocation
failures and attaches the node through the expression API so ownership remains
with the enum.

The compiler exit-status regression also checks that an enumeration with two
explicit extension markers is rejected with a fatal diagnostic and nonzero
status.

The relevant provisions are [ITU-T X.680 (02/2021), clause 13.4](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I!!PDF-E&lang=e&type=items)
and [ITU-T X.691 (02/2021), clause 14.3](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I!!PDF-E&lang=e&type=items).
