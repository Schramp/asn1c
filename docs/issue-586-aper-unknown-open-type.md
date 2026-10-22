# Issue #586: retain unknown APER open types

[Issue #586](https://github.com/mouse07410/asn1c/issues/586) is confirmed.
With the receiver schema from the report, `00010107` decodes and re-encodes
as four identical octets. Before this fix, `00020180` decodes with `RC_OK`,
but `aper_encode_to_new_buffer()` returns -1: the SEQUENCE decoder discarded
the unknown open-type contents instead of retaining a selected alternative.

This is a relay capability fix. It does not assert that PER requires an
implementation to reproduce received encodings.

## Representation and lifetime

When APER generation is enabled, the compiler appends an `ANY_t` alternative
to each open-type wrapper whose governing information-object set is extensible.
Its normal name is `asn1cUnknown`; a numeric suffix avoids a collision with a
known alternative. The descriptor marks this alternative with
`ATF_OPEN_TYPE_UNKNOWN`. Runtime dispatch uses that flag, not the member name.
Known alternatives keep their existing presence indices.

The buffer holds the payload octets, including the inner encoding's padding,
but excludes the outer APER length determinants. The ordinary CHOICE operations
own this buffer: copying duplicates it, comparison includes its contents,
changing the selected alternative releases it, and freeing/resetting the
containing message releases it. No global pointer registry or hidden allocation
is involved. Applications must use the generated presence discriminator and
normal ASN.1 ownership operations when constructing or replacing a value.

The ownership regressions also exposed two existing runtime defects. `ANY_t`
has a smaller structure and a different length field from `OCTET_STRING_t`,
so ANY now has copy and comparison functions that use its actual layout.
Its printer validates the signed length and supplies an explicit OCTET STRING
view, avoiding a padding- and byte-order-dependent length read through a cast.
CHOICE copying validates presence indices and releases a populated destination's
previous alternative before copying a different one. Partial-copy failures
retain a safely releasable destination.
The SEQUENCE extension refactoring preserves the existing NULL-placeholder
acceptance rule and now frees a placeholder allocation before omitting it from
the decoded tree; the sanitizer regression detects the former allocation leak.

Regenerate generated C and rebuild applications with the matching runtime.
The added union alternative may change structure sizes. Previously generated
descriptors lack the opaque alternative and cannot retain unknown values.
Disabling APER generation omits the new opaque alternative.
An associated declaration fix also makes optional open-type fields pointers,
matching their existing `ATF_POINTER` metadata. Their synthetic typedef remains
a structure type. Optional wrappers must also be regenerated.

## Validation and limits

The decoder retains unknown contents only for an explicitly extensible object
set. An unknown identifier in a sealed set fails decoding. Encoding validates
the relationship between the identifier's selected type and the stored CHOICE
alternative, so changing an identifier between known and unknown types cannot
silently encode the previous value using the wrong type. Applications replacing
an identifier must also supply the corresponding value.

Building the decoder skeletons with `ASN_REJECT_UNKNOWN_EXTENSIONS` also
rejects unknown identifiers in extensible sets before retaining the payload.

Opaque contents can be relayed using APER. They do not acquire an ASN.1 abstract
value or a representation in another transfer syntax. Re-encoding preserves
payload bytes and emits ordinary APER length framing; alternative fragmentation
boundaries or nonminimal received length forms need not be reproduced exactly.
The report's one-octet Boolean payload round-trips byte for byte.

The implementation checks length arithmetic and available contents before
allocation, supports fragmented lengths, and rejects missing fragment contents
or terminators. An empty opaque payload is retained as empty. Applications
remain responsible for protocol-specific IE criticality and resource policies.

## Regression coverage

The generated-schema regression is registered with the compiler tests:

```sh
make -j4
make -C tests/tests-asn1c-compiler check
make -C tests/tests-skeletons check
make -C tests/tests-asn1c-smoke check
```

The fixtures are in `tests/tests-asn1c-compiler/issue-586/`. They exercise the
reported known/unknown vectors, opaque ownership, malformed input, and
fragmentation boundaries through generated code, with APER-only and combined
codec builds. The generated-output references for extensible parameterized
information-object sets include the additional opaque alternative.

Validation on 2026-10-22 passed the normal, C89, and strict runtime archive
builds, all 59 skeleton tests, all 8 compiler tests, all 31 smoke checks, and
generated-C regressions 126 (APER), 173 (indirect IOC choices), and 583 (PER extension groups).
The complete generated-schema regression also passed with AddressSanitizer,
UndefinedBehaviorSanitizer, and LeakSanitizer in both codec configurations.
A separate sanitized strict-mode driver accepted the known report vector and
rejected the unknown identifier.

The reusable `ISSUE586_FUZZ` entry point decoded arbitrary `Field` values and
checked opaque semantic round trips for 120,314 inputs in a 46-second run,
with all three sanitizers enabled and no findings. Seeds included the report
vectors, malformed lengths, empty contents, and two complete 64 KiB fragments
followed by their zero-length terminator. The input ceiling is 256 KiB.
The run used `-rss_limit_mb=0` to avoid a leak in libFuzzer's own macOS RSS
monitor thread; LeakSanitizer remained enabled.

To run the generated regression under sanitizers from the repository root
(using a compiler with those sanitizer runtimes):

```sh
top_srcdir="$PWD" top_builddir="$PWD" CC=clang \
  CFLAGS='-g -O1 -fsanitize=address,undefined' \
  ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  tests/tests-asn1c-compiler/check-issue-586.sh
```

For libFuzzer, generate the fixture into a separate build directory, build its
`libasncodec.a` with `-fsanitize=fuzzer-no-link,address,undefined`, and compile
`issue-586.c` with `-DISSUE586_FUZZ -fsanitize=fuzzer,address,undefined` against
that library. Keep the generated directory on the compiler's include path.
