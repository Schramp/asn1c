# Binary codec support and dispatch

Source-audited on 2026-10-11 against generated descriptors, the generic
dispatcher, and CER regression cases. This records available operations, not
blanket support for every ASN.1 type or proof of canonical conformance.

| Selector | C encoder | C decoder |
| --- | --- | --- |
| `ATS_BER` | DER encoder; valid BER output | `ber_decode` |
| `ATS_DER` | `der_encode` | `ber_decode` |
| `ATS_CER` | `cer_encode` | `ber_decode` |
| Basic/canonical OER | `oer_encode` | `oer_decode` |
| Basic/canonical UPER | UPER encoder | `uper_decode_complete` |
| Basic/canonical APER | APER encoder | `aper_decode_complete` |
| `ATS_CBOR` | `cbor_encode` | `cbor_decode` |

The table follows [asn_application.c](../skeletons/asn_application.c), its
`ASN_DISABLE_*_SUPPORT` guards, and each type's operation descriptor where
applicable. CER is a direct descriptor walker rather than an operation-table
slot, so its support depends on the descriptor kinds and canonical value forms
handled by that walker.

## CER encoding and decoding

[ber_decoder.h](../skeletons/ber_decoder.h) advertises decoding BER, DER, and
CER. The implementation handles indefinite-length constructed values,
end-of-contents markers, and segmented strings. `asn_decode(ATS_CER, ...)`
uses this BER decoder; it does not check that input follows CER's canonical
restrictions. The generated converter accepts `-icer` for the same BER-family
input path.

For scalar descriptors with explicit or named tags, CER input with indefinite
constructed wrappers ending in a definite primitive is supported. Tested BER
compatibility also includes a definite constructed child. A nested scalar
wrapper chain that mixes definite and indefinite lengths among its constructed
layers can still be rejected by the pre-existing `ber_check_tags` limitation.
This is a BER-family input limitation, not strict CER canonical validation; it
does not restrict CER encoder output.

The C runtime provides `cer_encode()` and `asn_encode(ATS_CER, ...)`, and the
generated converter accepts `-ocer`. The C target enables CER encoding by
default alongside BER support. `-no-gen-CER` disables CER encoding support;
it need not remove the CER skeleton source from the shared BER-family
dependency closure. `-no-gen-BER` also disables the shared BER-family
dependencies. The encoder walks generated type descriptors; support is limited
to descriptor kinds and canonical value forms that the walker implements. It
does not add a CER operation-table slot or change that ABI.

The current descriptor set covers BOOLEAN, NULL, raw and native
INTEGER/ENUMERATED, raw REAL, native REAL stored as `float` or `double`,
OBJECT IDENTIFIER and RELATIVE-OID with minimal complete base-128 arcs,
BIT STRING, OCTET STRING, UTCTime, and GeneralizedTime. Built-in character
strings are supported when their primitive operation matches a recognized
runtime encoder: UTF8String, NumericString, PrintableString, IA5String,
VisibleString/ISO646String, ObjectDescriptor,
GeneralString, GraphicString, VideotexString, TeletexString/T61String,
UniversalString, and BMPString. SEQUENCE, SET, CHOICE, SEQUENCE OF, and SET OF
are supported through generated descriptors. Generated member metadata
supplies tags and defaults; the encoder omits default-valued members. `SET`
fields are ordered by their minimum effective tag, including the minimum
alternative tag for a CHOICE.
`SET OF` elements are ordered by their final CER encodings, comparing shorter
encodings as if zero octets were appended for comparison only. Long supported
strings use 1000-content-octet fragments; BIT STRING fragments reserve one
content octet for the unused-bit count, leaving at most 999 payload octets.
Named BIT STRING values remove trailing zero bits; ordinary BIT STRING values
preserve them. Member and explicit/implicit tag metadata is applied at each
descriptor boundary.

Typed open-type members are encoded when the parent selector resolves a
concrete type. Opaque `ANY` and unresolved standalone open types are rejected;
the encoder does not pass through arbitrary stored bytes. REAL encoding is
limited to zero, special values, and minimal binary base-2 forms whose exponent
uses at most eight octets; decimal and noncanonical raw forms are rejected.
Unknown or custom primitive operations are also rejected. UTCTime values are
validated and normalized to UTC seconds with `Z`, for output years 1950
through 2049. GeneralizedTime accepts adapter-parsable hour-, minute-, and
second-precision forms with an explicit `Z` or signed numeric offset; output
is normalized to seconds with `Z`. Fractional seconds accept a comma or period
on input, are limited to nine digits, and use a period in output with trailing
zeroes removed. Fractional hours or minutes, missing zones, and excess
fractional precision are rejected. Calendar and zone fields are validated,
and normalization must stay within the four-digit year range 0001–9999.

Primitive content capture uses a shallow descriptor copy with one resolved
intrinsic tag; the CER walker applies the original descriptor and member
wrappers afterward. CER tag-chain bounds therefore apply to those effective
wrappers, independent of the primitive content adapter's tag limit.

Resource ceilings default to 64 MiB encoded output, 128 MiB aggregate active
scratch storage, 1,000,000 collection elements, 4,000,000 descriptor/value
visits, and recursion depth 30. Descriptor tag chains are also capped at 30 by
default. Both depth and tag-chain limits use `ASN_STACK_OVERFLOW_LIMIT`; the
existing optional codec-context stack limit also applies to recursive
traversal. An additional explicit member tag counts as another tag-chain layer,
while a replacement tag does not. Excess tag chains return `EOVERFLOW` before
the tag array is read. The four CER ceilings are configurable through
`ASN_CER_MAX_ENCODED_SIZE`, `ASN_CER_MAX_SCRATCH_SIZE`, `ASN_CER_MAX_ELEMENTS`,
and `ASN_CER_MAX_WORK_ITEMS`. Invalid values or malformed descriptor/count
metadata return `EBADF`; exceeding configured element-count, tag-chain, depth,
output, scratch, or work limits returns `EOVERFLOW`. Unsupported forms return
`ENOENT`, a short direct buffer
returns `ENOSPC`, and allocation or callback failures are reported as `ENOMEM`
or `EIO`.

The Rust backend currently emits CER encoding for top-level BOOLEAN, NULL, and
finite nonextensible INTEGER ranges that fit in `i64`. It has no CER decoder.
Rust codec defaults include UPER and CER; `-no-gen-UPER` selects CER-only
generation. Other Rust types and codecs remain outside this implemented slice.

CER is a constrained form of BER. The primary
[X.690 (2015) text, sections 9.1, 9.2, 9.3, and 11.6][x690]
specifies indefinite lengths for constructed encodings, segmented string
forms, tag ordering for `SET` components, and ordering of complete `SET OF`
encodings. String fragments use the 1000-content-octet boundary. CER encoding
implements these rules for its supported descriptors. Input remains permissive
BER decoding, not strict CER canonical-form validation.

## Other binary families

No additional mismatch was found between the generic binary selectors and their
implemented codec families. Basic/canonical OER and PER decode selectors share
the same family entrypoint. DER and CER decode selectors share the BER decoder;
the selector alone is not a strict canonicality check.

CBOR uses a separate repository mapping for ASN.1 values. It is not an ASN.1
encoding rule. Claims of complete deterministic encoding require checking more
than shortest integer/length forms, including floating-point choices and map
ordering under [RFC 8949 section 4.2](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2).
This change does not establish blanket deterministic-CBOR conformance.

The generated converter accepts `-iber`, `-ider`, and `-icer` as BER-family
input selectors. Output supports `-oder` and `-ocer` for their respective
encoding rules.

## Verification

The corrected tag-capture encoder passes the linked skeleton suite (52/52) and
the fresh Rust harness (10 generated conformance checks). The Rust harness
includes fresh C UPER/CER reference comparisons, C decoding of generated Rust
UPER/CER bytes, codec-selection, and negative-schema checks. The unchanged C
compiler suite passes 7/7. A fresh ASan/UBSan fuzz run processed 660,325
mutations in 16 seconds without a sanitizer failure, and independent seed bytes
passed. This is a short fuzz run, not a long campaign.

The generated CER converter script passes for all three C codec-disable
variants, including direct generated multi-wrapper vectors and CER re-decoding.
All 28 generated smoke tests and the installed-toolchain qualification also
pass. Source-distribution qualification passed with all 13 required assets
present. The randomized driver is wired to feed BER-decoded corpus values to
generic `ATS_CER` encoding. The generic BER decoder remains permissive under the
CER selector; applications that need strict canonical validation must validate
that requirement separately.

[x690]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-201508-S%21%21PDF-E&lang=e&type=items
