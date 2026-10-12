# CER encoding and Rust toolchain implementation plan

**Status:** Accepted design; implementation and qualification in progress.
**Date:** 2026-10-11.
**Baseline:** `673b16c5`, the first safe Rust output slice.
**Supervisor:** Sol; three Luna agents implement disjoint work packages.

## Scope and evidence

Add a native CER encoder to the C runtime and CER encoding to the Rust output
mode. Keep the existing C parser and semantic frontend. The initial Rust types
remain BOOLEAN, NULL, and finite, nonextensible INTEGER ranges within signed
64-bit storage. Rust CER decoding, strings, collections, open types, and the
remaining codec families are later increments in the [conversion plan](rust/stage-one-plan.md).

C CER decoding already uses the BER decoder, including constructed indefinite
lengths. It accepts compatible BER and does not verify every canonical CER rule.
The new encoder must produce canonical bytes; permissive decoding is not evidence
that an encoder is canonical. The [codec ledger](binary-codec-support.md) records
the qualified directions and limitations.

The governing rules reviewed for this increment are in
[ITU-T X.690 (08/2015)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-201508-S%21%21PDF-E&lang=e&type=items):

- Section 9.1: constructed values use indefinite lengths; primitive lengths use
  their shortest representation.
- Section 9.2: BIT STRING, OCTET STRING, and restricted character strings use
  primitive encoding through 1000 content octets, then primitive fragments inside
  a constructed wrapper. Every nonfinal fragment has 1000 content octets. The
  BIT STRING unused-bit octet counts toward that limit.
- Section 9.3: SET ordering uses tag class and number. An untagged CHOICE uses its
  smallest possible tag, including nested choices, rather than its selected tag.
- Sections 11.1–11.5: canonical scalar content and omission of equal DEFAULTs.
- Section 11.6: SET OF ordering compares final encoded octets, treating a shorter
  comparison operand as zero padded without emitting that padding.

These rules require independent byte vectors. A round trip through the shared
BER decoder alone cannot detect incorrect fragmentation, ordering, or defaults.

## C encoder decision

Implement a bounded descriptor walker in `skeletons/cer_encoder.c` with public
declarations in `cer_encoder.h`. Use the existing operation kind, member metadata,
tags, and type specifics. Preserve the descriptor operation-table ABI. Add:

```c
cer_encode(opt_codec_ctx, td, sptr, callback, application_key);
cer_encode_to_buffer(opt_codec_ctx, td, sptr, buffer, buffer_size);
```

Route generic `ATS_CER` encoding and converter `-ocer` to this encoder. Existing
BER decoding remains the route for generic CER input and converter `-icer`.

Keep tag wrappers, constructed lengths, string segmentation, SET ordering, and
SET OF sorting inside the CER walker. Existing DER primitive encoders may supply
scalar content only where canonical content is established and checked. Reject
unsupported opaque encodings, including raw ANY, instead of relabeling arbitrary
bytes as canonical CER. A selected open type can be encoded through its resolved
typed descriptor when its metadata is supported.

Validate descriptors, missing required values, lengths, BIT STRING unused bits,
collection counts, tag chains, output arithmetic, callback results, and recursion
before processing or allocation. Bound temporary storage and recursion; document
the implemented limits and error behavior. Propagate allocation and callback
failures without publishing a success result. Preserve generic buffer sizing
semantics and test direct fixed-buffer failure separately.

The proposed compile-time ceilings are 30 recursive levels through
`ASN_STACK_OVERFLOW_LIMIT`, 64 MiB encoded output through
`ASN_CER_MAX_ENCODED_SIZE`, 128 MiB aggregate active scratch through
`ASN_CER_MAX_SCRATCH_SIZE`, 1,000,000 collection entries through
`ASN_CER_MAX_ELEMENTS`, and 4,000,000 descriptor/value visits through
`ASN_CER_MAX_WORK_ITEMS`. The shared visit counter bounds recursive metadata
walks even when they do not emit bytes. The final header documents the accepted
constants and their override semantics. The existing byte-based stack check follows its
normal build configuration; the explicit depth bound also applies under
sanitizers. Unsupported raw REAL decimal or noncanonical content is rejected;
supported special and canonical binary content is checked before emission.

Place CER skeleton assets in the existing BER dependency closure. CER encoding
depends on the shared BER/DER substrate. `ASN_DISABLE_CER_SUPPORT` independently
disables the encoder; disabling only CER encoding retains BER-based CER decoding.
Code with BER disabled must not reference unavailable CER symbols.

### Alternatives considered

| Approach | Benefit | Limitation | Decision |
| --- | --- | --- | --- |
| Descriptor walker using existing kinds | Preserves ABI and generated descriptors | Must validate type specifics | Select |
| New operation-table CER slot | Per-type implementation seam | ABI and every initializer change | Defer |
| Convert a DER byte stream blindly | Small prototype | Loses static CHOICE ordering and semantic defaults | Reject |
| Rust bindings to C CER | Reuses runtime | Violates the safe native Rust direction | Reject |

## Rust runtime and generation

Add safe, dependency-free helpers for canonical BOOLEAN, NULL, and bounded signed
INTEGER TLVs. TRUE content is `ff`; signed INTEGER content uses minimal two's
complement bytes. Return the existing `Encoded` result, with `bit_len` equal to
the entire TLV length in bits. Check schema bounds and existing output/work
limits before fallible allocation. Runtime and generated crates forbid unsafe.

Generate `encode_cer` only when CER is selected and UPER methods only when UPER is
selected. Preserve fully qualified runtime/core paths, output preflight, staging,
ownership manifests, and offline Cargo packaging. Unsupported schema features
or codecs fail before publishing output. No Rust CER decode method is exposed in
this increment.

`--rust` switches the entire output mode to Rust, including types, codec methods,
runtime sources, and Cargo metadata. C remains the default output mode.

| Selection | C behavior | Rust behavior |
| --- | --- | --- |
| Default | Existing defaults plus CER encoder | UPER and CER |
| `-gen-CER` | Enable CER and its BER substrate | Enable CER |
| `-no-gen-CER` | Disable CER encoder; retain BER decoder | Disable CER |
| `-no-gen-BER` | Disable BER substrate and CER encoder | BER selection only; does not disable CER |
| `--rust -no-gen-UPER` | Switch output mode | CER encoding only |
| `--rust -no-gen-CER` | Switch output mode | UPER encoding and decoding |
| Rust with no supported codec selected | Not applicable | Diagnostic, no published project |

Add `A1C_GEN_CER = 0x1000000000` without reusing existing codec bits. Keep C and
Rust selection state separate so legacy C defaults do not contaminate Rust mode.

## Supervised work packages

| Agent | Owned changes | Required handoff |
| --- | --- | --- |
| Luna C CER | Skeleton encoder, generic dispatch, converter, C tests, skeleton dependency lists | API, limits, supported types, independent vectors |
| Luna Rust CER | Rust runtime, generator, CLI selection, generated configuration, Rust tests | Codec mask, APIs, negative cases, cross-language bytes |
| Luna documentation | README, installation, ChangeLog, codec ledger, Rust docs, TeX/PDF, Markdown/man page | Accurate support boundaries, regeneration steps, changed PDF pages |
| Sol supervisor | This plan, packaging, interface review, integration, validation, commits | Reviewed diff, complete qualification evidence |

Agents edit the main local checkout in disjoint scopes and do not commit. Freeze
shared interfaces before integration. Coordinate compiler builds and test relinks
to avoid stale or concurrently replaced archives. Sol reviews standards details,
failure behavior, generated dependency closure, and documentation claims before
committing the complete change.

## Qualification and delivery gates

- [ ] Independent scalar vectors, including INTEGER sign-boundary cases and TRUE.
- [ ] OCTET/BIT/character string boundaries at, below, and above 1000 content
  octets, plus final fragments and nonzero BIT STRING unused bits.
- [ ] Nested and explicit/implicit tags, SEQUENCE/SET/CHOICE, DEFAULT omission,
  static minimum CHOICE tag order, and SET OF final-CER byte order.
- [ ] Invalid descriptors/values, missing fields, opaque ANY, malformed primitive
  content, tiny buffers, callback failure, allocation/output/depth limits.
- [ ] C generic dispatch, converter output, generated dependency closure, and
  independent encoder/BER compile-disable combinations.
- [ ] Existing BER-family fuzz corpora exercise CER encoding after successful
  decode, with unsupported/resource failures accepted and output discarded.
- [ ] Rust runtime and generated-crate tests, negative schema/CLI combinations,
  selected-method availability, offline builds, format/lint checks, C byte exchange.
- [ ] Rebuilt skeleton libraries and affected existing C/compiler suites.
- [ ] All user-facing support tables and Rust stage-one documents agree with
  implementation; future coverage is explicitly labeled as planned.
- [ ] `asn1c-usage.tex` and regenerated `asn1c-usage.pdf` agree; inspect changed
  PDF pages for clipping, layout, tables, and complete CER/Rust sections.
- [ ] `asn1c.man.md` and regenerated `asn1c.1` agree; verify rendered options.
- [ ] Installation and source distribution include runtime assets and new docs.
- [ ] Record exact tests and residual limitations, then commit reviewed changes.

The acceptance evidence will be appended here after review. A failing gate keeps
its implementation under revision; it does not justify a broader support claim.
