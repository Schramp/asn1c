# Issue #585: BER REAL explicit exponent length

[Issue #585](https://github.com/mouse07410/asn1c/issues/585) reports that
`asn_REAL2double()` reads an extra exponent octet for binary REAL format `11`.
The defect is confirmed in the local runtime: the three reported contents
vectors produced rejection, zero, and rejection, respectively.

| REAL contents (hex) | Expected value | Before | After |
| --- | --- | --- | --- |
| `83 01 00 01` | 1 | EINVAL | 1 |
| `83 02 00 00 01` | 1 | 0 | 1 |
| `83 03 00 00 01 01` | 2 | ERANGE | 2 |

## Interpretation and compatibility

[ITU-T X.690 (2021), 8.5.7.4(d)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items)
describes the second contents octet as the count X of exponent octets.
The published text also gives an endpoint of X+3, which is inconsistent
with that count when starting at the third octet. This implementation follows
the explicit count: the exponent occupies offsets 2 through X+1, with the
mantissa starting at offset X+2. This resolves the report's ambiguity in favor
of the count, rather than claiming the endpoint wording is unambiguous.

The same clause requires minimal exponent sign extension. The padded X=2
and X=3 report vectors exercise the decoder's permissive behavior; they are
not evidence of strict BER conformance. Minimal two-octet exponents +128
and -129 are tested separately. This change preserves permissive decoding
of redundant sign octets and does not add a strict BER validator.

The converter now uses actual byte counts for every exponent format. It
validates the explicit length byte before reading it and requires a nonempty
exponent followed by at least one mantissa octet. Invalid lengths and
truncation return EINVAL. The existing limit of three exponent octets remains:
complete inputs with X >= 4 return ERANGE. Sign, bases 2/8/16, scaling, and
finite-result handling remain unchanged. A null result pointer returns EINVAL.

The conversion code is split into decimal, binary, and dispatch functions to
keep the touched runtime units below 200 lines and cyclomatic complexity 20.
Decimal conversion retains its existing trailing-NUL buffer contract.
Regenerate or rebuild generated applications with the updated REAL.c runtime.

## Regression validation

`tests/tests-skeletons/check-REAL.c` checks the reported vectors through raw
conversion and NativeReal BER TLV decoding. Additional cases cover signed
exponents, bases and scaling, malformed/truncated contents in every exponent
format, null output, and all explicit length octets from 0 through 255.
The raw binary inputs use exact-size heap allocations so AddressSanitizer
can detect reads beyond supplied contents. The older binary generator now
expects EINVAL when it deliberately constructs an absent mantissa.

Reproduce the runtime build and tests from the configured repository root:

```sh
make -C skeletons -j4 libasn1cskeletons.la libasn1cskeletons_c89.la libasn1cskeletons_strict.la
make -C tests/tests-skeletons -j4 check
```

The regression was also linked against the original REAL.c and failed at
the X=1 assertion before any null-output test, demonstrating that it detects
the original defect. See ChangeLog for the release entry.
