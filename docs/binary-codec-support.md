# Binary codec support and dispatch

Audited on 2026-10-11 against `3e255014` and the accompanying dispatcher fix.
This records available operations, not blanket support for every ASN.1 type or
proof of canonical conformance.

| Selector | Encoder | Decoder |
| --- | --- | --- |
| `ATS_BER` | DER encoder; valid BER output | `ber_decode` |
| `ATS_DER` | `der_encode` | `ber_decode` |
| `ATS_CER` | Unsupported (`ENOENT`) | `ber_decode` |
| Basic/canonical OER | `oer_encode` | `oer_decode` |
| Basic/canonical UPER | UPER encoder | `uper_decode_complete` |
| Basic/canonical APER | APER encoder | `aper_decode_complete` |
| `ATS_CBOR` | `cbor_encode` | `cbor_decode` |

The table follows [asn_application.c](../skeletons/asn_application.c), guarded
by each `ASN_DISABLE_*_SUPPORT` macro, and each type's operation descriptor.
An absent operation remains unsupported; selectors do not synthesize codecs.

## CER correction

[ber_decoder.h](../skeletons/ber_decoder.h) already advertised decoding BER,
DER, and CER. The implementation handles indefinite-length constructed values,
end-of-contents markers, and segmented strings. The generic dispatcher rejected
`ATS_CER` instead of reaching that decoder. The correction adds CER to the
BER/DER decode cases and keeps CER encoding unsupported.

The README's former CER table cell said "not supported" in the encoder column;
it already listed `ber_decode` for CER input. The earlier Rust plan read this
too broadly. CER decoding belongs in the Rust parity target, using the same
permissive input semantics as the C BER decoder. A dedicated CER encoder or
strict canonical validator is additional work.

CER is a constrained form of BER. The primary
[X.690 (2015) text, sections 9.1 and 9.2][x690]
specifies indefinite lengths for constructed encodings and primitive string
segments at the 1000-content-octet boundary. Tests include such valid CER input
and BER input that does not satisfy CER's string-form rules. Accepting both
documents compatibility without claiming canonical validation.

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

The generated converter gains `-ider` and `-icer` aliases alongside `-iber`.
Both aliases select the shared BER-family operation slot. Output continues to
use `-oder`; there is no `-ocer` encoder selector.

## Verification

The binary dispatch regression tests exercise all enabled binary selector
families with independent vectors, CER-compatible segmented/indefinite input,
incomplete and malformed input, decoder dispatch, and unsupported CER encoding.
The full skeleton suite passed 47 tests, and a separately compiled dispatcher
with `ASN_DISABLE_BER_SUPPORT` rejected CER with `RC_FAIL` and `ENOENT`.
The generated-converter smoke test checks all three BER-family input aliases
and rejects a CER output selector. Rebuild the skeleton library before relinking
focused tests to avoid stale code.

[x690]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-201508-S%21%21PDF-E&lang=e&type=items
