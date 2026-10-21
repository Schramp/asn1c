# Proposal: incremental JER input

Status: design proposal, 2026-10-21. No streaming API or new runtime behavior
is implemented by this document. Responsible party: asn1c maintainers;
design investigation assisted by Codex. Motivated by issue #578, reported
by Ruud Schramp (@Schramp), who also supplied PR #579.

## Goals and memory model

Process files and live messages in input chunks, emit completed PDUs before
source EOF, and avoid rescanning an ever-growing prefix. Support a single
large message as well as a large file containing many messages.

There are three useful milestones with different memory guarantees. Here,
`C` is the input chunk size, `P` the largest encoded PDU, `V` the materialized
ASN.1 value, `D` nesting state, and `M` bounded metadata or deferred content.

| Milestone | Retained memory | Benefit |
| --- | --- | --- |
| Frame one PDU, then use the existing decoder once | O(C + P + V + D) | Large multi-PDU files and early output; a large single PDU still needs buffering. |
| Incremental typed decoding into ordinary generated structures | O(C + V + D + M) | Removes the full encoded-PDU copy, including for large strings. |
| Incremental decoding into an application sink | O(C + D + M), plus sink storage | Can avoid materializing large fields and collections when validation permits it. |

Allocator capacity, arbitrary-precision numeric storage, member-presence maps,
and application storage count toward these bounds. Ordinary generated
structures necessarily retain their decoded strings and collection elements.
Sink mode cannot promise bounded total storage for arbitrary constraints or
out-of-order dependencies; those cases need an explicit buffering/spooling
policy or an unsupported-mode error.

Recommend building these milestones in order, sharing the same lexical
engine. The framing milestone is independently useful, but does not complete
support for a single very large message.

## Current implementation and blockers

The [security review](issues-578-581-security-review.md) describes the current
converter workaround: `read_jer_input()` in
`skeletons/converter-example.c` buffers the entire finite input until EOF.
It prevents the issue #578 data loss and supports pipes, but consumes memory
proportional to the entire input and cannot emit from an endless source.

Simply feeding smaller buffers into the existing decoder is insufficient:

* `pjson_parse()` in `skeletons/jer_support.c` persists an integer parser state,
  while `in_string` and `escaped` are local variables initialized on each call.
  Token finalization also occurs in an end-of-buffer path without an explicit
  distinction between a temporary chunk boundary and final EOF.
* `jer_decode_primitive()` in `skeletons/asn_codecs_prim_jer.c` creates a local
  parsing context and returns zero consumption on `RC_WMORE`, requesting a
  retry from the beginning. `NativeInteger_decode_jer()` likewise explicitly
  requires restarting from the beginning. Native scalar storage has no place
  for an embedded parser context.
* Container decoders such as `SEQUENCE_decode_jer()` retain some state in
  `_asn_ctx`, but their children and token handling must also be restartable.
* OCTET STRING hexadecimal/Base64 conversion currently searches for quotes
  inside the supplied body. An arbitrary fragment may contain neither quote.
  Hexadecimal half-byte state must survive feeds; existing Base64 accumulator
  state does not by itself provide a complete streaming JSON string parser.

These are implementation observations, not a claim that every possible split
has been reproduced as a separate defect. Existing acceptance behavior must
also be audited against the standards before using it as a reference oracle.

## Standards boundary

Checked online against
[ITU-T X.697 (02/2021)](https://www.itu.int/rec/T-REC-X.697-202102-I/en):
clauses 6.4-6.5 permit implementation choices while requiring the prescribed
encoding behavior; 7.6.1-7.6.2 define each complete outermost UTF-8 encoding;
7.6.3 permits JSON string escapes; 27.3.3 permits object-based SEQUENCE members
in any order. Chunking must preserve those semantics, including escaped member
names. Support must account for the applicable encoding instructions, rather
than treating every sequence as an object.

[ECMA-404, second edition](https://ecma-international.org/wp-content/uploads/ECMA-404.pdf),
clauses 4-5 and 8-9, supplies the lexical requirements: JSON values include
scalars; whitespace is TAB, LF, CR or SPACE; strings have escapes; numbers
can extend beyond the current chunk. A read boundary cannot finalize `1`
when the next read might contain `23` or `e2`.

The proposed framing policies below are application conventions. Concatenated
PDUs remain separate complete JER values, rather than a single JSON document
or an implicitly introduced ASN.1 SEQUENCE OF. Input chunk boundaries never
alter ASN.1 constraints or introduce string-fragment encodings on the wire.

## Persistent lexical engine

Use a grammar-aware lexer/parser with an explicit stack and bounded token
fragments. Do not use brace counting alone: braces, commas and quotes inside
strings must have their ordinary string meaning. Process each input byte a
bounded number of times, apart from unavoidable numeric conversion work.

The opaque context owns each state variable across feeds:

| State | Purpose |
| --- | --- |
| JSON grammar stack | Object/array kind and expectation: key, colon, value, comma or close; enforce depth limits before pushing. |
| String state | Opening/closing quote, escape kind, partial Unicode escape and surrogate processing, partial UTF-8 sequence. |
| Scalar state | Literal progress and numeric grammar, including sign, fractional and exponent states. |
| ASN.1 frame stack | Descriptor, destination or sink, current member/element, presence tracking and pending open-type dependencies. |
| Primitive accumulator | Checked native integer, bounded numeric representation, hexadecimal half-byte, Base64 quartet/padding, or string output fragment. |
| Resource accounting | Checked wire/decoded-byte totals, item count, depth, deferred bytes and diagnostic offset. |

Decode JSON escapes before matching member names or applying typed string
conversions. Validate UTF-8 and character repertoire under the applicable
ASN.1 type; document the treatment of surrogate escape sequences against
that type's requirements. Do not silently substitute replacement characters.
Do not apply Unicode normalization to identifiers.

String events distinguish begin, decoded fragment and end. Hexadecimal and
Base64 receivers operate on these fragments, not raw substrings containing
quotes. Validate unfinished pairs/quartets, padding and trailing bits at end,
according to the selected encoding. Native numeric accumulation checks every
multiply/add and signed boundary before updating the value. Arbitrary-precision
integers need their own bounded storage and conversion policy, not a native
integer shortcut. REAL parsing needs bounded lexeme storage or an audited
incremental conversion, with documented numeric-work limits.

Unknown extension values use the same grammar engine in discard mode, still
checking syntax and limits. Member dispatch needs a bounded lookup strategy;
avoid scanning every member name repeatedly for adversarial input. Preserve
OPTIONAL/DEFAULT/null and extension semantics, and detect repeated members
under the applicable ASN.1 rules. Do not inherit accidental legacy acceptance.

## Proposed API contract

Add an opaque stream context separate from the destination structure. Keep
the existing `jer_decode()` signature available. Introduce a separate stream
operation interface for built-in types and an explicit opt-in interface for
custom codecs, so native scalars do not need a new generated layout. Verify
this compatibility strategy with generated aliases, custom operations and
mixed skeleton versions before committing to a public ABI.

The conceptual operations are create, feed, take completed value, reset and
destroy; names and C declarations remain to be designed. Creation fixes the
descriptor, framing policy, limits and destination mode. A feed takes a byte
span and an explicit final-input flag. It returns consumed bytes, status and
an error reason/absolute offset when applicable.

| Status | Required meaning |
| --- | --- |
| NEED_INPUT | The prefix is valid so far; more bytes or explicit final input are required. |
| DONE | One complete typed value is available; consumption stops at its framing boundary. |
| PAUSED | A sink applied backpressure; resume without duplicating accepted events. |
| ERROR | Syntax, type/constraint, resource, allocation or sink failure; reset/destroy required. |

Contract invariants:

1. `consumed <= supplied_size`, including all failure paths. The caller may
   release the consumed prefix immediately; context state must not point into
   it. Any retained lookahead belongs to the context and counts against limits.
2. An unfinished token can consume all supplied bytes if its continuation is
   represented in state. Never require replaying its entire prefix.
3. Empty nonfinal input makes no progress. Zero consumption with nonempty
   input must mean completion, backpressure or an error; callers must not spin.
4. Final input turns unfinished grammar/UTF-8/escapes/numbers into a truncation
   error. A complete number may finalize at an explicit frame end or EOF.
5. In multi-value mode, DONE can leave a suffix in the same feed. The caller
   takes the value, resets per-PDU state and supplies that suffix. A final flag
   still applies to the end of the remaining span, not to the first DONE.
6. In single-text mode, completion includes validation that the remaining
   frame contains only JSON whitespace. This mode needs an explicit frame end.
7. A partially built value remains private to the context. DONE transfers
   ownership; error, cancellation and destruction free all untransferred data.
   Reset preserves configuration but clears all per-PDU state and accounting.
8. Resource exhaustion has a distinct diagnostic from malformed ASN.1/JER.
   Cleanup and destroy are safe after every failure and cancellation point.

No API should advertise incremental support and silently fall back to retaining
the entire source. Unsupported custom operations must fail explicitly before
processing that type; unsupported root operations should fail at creation.

## Framing and converter integration

Offer explicit single-text and multi-PDU policies. Preserve existing adjacent
object-PDU use such as `{}{}`; braces are sufficient to find those boundaries.
For scalar-number PDUs, require separating JSON
whitespace or external framing. `123` cannot identify whether the sender meant
one number or multiple numbers. A transport read boundary provides no answer.
Do not infer a boundary from the requested ASN.1 native integer's range.

The converter should feed its configured read-size chunks and process DONE
values immediately, freeing each value after output. Preserve `-1`, `-n`, file
boundaries, read-error reporting, exact consumption and previous multi-PDU
regressions. Reset stream state between files. A complete object can be emitted
while its pipe remains open; a top-level number without a delimiter must wait.
I/O errors remain failures, even after earlier values have been emitted.

The framing milestone buffers exactly the current PDU, invokes the batch
decoder once at completion and requires successful full-PDU consumption.
Remove whole-source buffering only after this path passes the existing tests
and the new split/framing tests. Then replace per-PDU buffering with typed
incremental receivers as their support matrix becomes complete.

## Limits, sinks and validation

Require explicit finite defaults for wire bytes per PDU, decoded bytes, nesting,
collection items, member-name storage, numeric work/storage and deferred
open-type content. Publish defaults when implementing the API; expose overrides
and distinguish an explicitly unlimited setting from an accidentally zero
limit. Check arithmetic before allocation or counter updates. Apply limits to
discarded unknown values too, including wire bytes spent skipping whitespace.
Live services also need transport deadlines; a parser does not own that clock.

Geometrically grow materialized strings with checked capacity arithmetic,
rather than reallocating/copying the entire output for every tiny fragment.
Use an iterative frame stack with checked allocation and maximum depth.
Raw input work should be linear; large-number work needs separate accounting.

For sink mode, deliver provisional begin/data/end events followed by a PDU
commit, or abort on any later error. Specify accepted-byte/event ownership and
backpressure precisely. Do not replay an accepted callback after resuming, and
prohibit reentrant feed/reset/destroy from callbacks. Applications that cannot
roll back must stage their effects until commit. Ordinary tree mode should
offer the same completion/validation guarantee without exposing partial trees.

Open-type discriminators may follow their values. Buffer deferred content
under a quota, or use an explicit application-supplied spool with checked I/O
and cleanup. Never require a new member order solely to make streaming easy.
Constraints that need retained content or whole-value analysis must have a
defined validation strategy; report unsupported streaming validation rather
than committing a value that was not checked. Separate JER-visible validation
from additional application-requested constraint checks in the API contract.

Existing callback-based JER encoders can emit fragments, but this does not make
arbitrary transcoding possible with bounded memory. Output codecs may need
lengths, sorting or complete values. Select a compatible sink, materialize or
spool explicitly, and document the resulting storage requirements.

## Implementation gates and tests

Each milestone needs its own documented support matrix and regression gate:

1. Build the persistent JSON engine and per-PDU framing adapter. Cover every
   JSON value kind and reject invalid grammar without calling a typed decoder.
   Verify early output using a pipe whose writer has not closed it.
2. Add typed receivers for primitives, strings, SEQUENCE/SET, CHOICE,
   collections and OPEN TYPE, including generated aliases and custom-codec
   opt-in failures. Audit applicable JER encoding instructions and extension
   handling before replacing the batch path for any type.
3. Integrate converter flags and resource diagnostics; document migration and
   limits. Retain the original issue #578 regression and sanitizer coverage.
4. Add sink mode only with explicit transactional ownership, backpressure and
   whole-value validation tests. Include deferred open-type and spool failures.

For small vectors, exercise every two-way cut and every possible partition of
very short vectors. For larger inputs, exercise one-byte chunks and randomized
partitions. Split inside UTF-8, escaped quotes/backslashes, Unicode escapes and
surrogate pairs, names, literals, numeric exponents, hex pairs and Base64
quartets. Include delimiter characters inside strings, all four JSON whitespace
characters, and escaped equivalent member names. Cover valid empty values,
malformed syntax, invalid typed values, incomplete final input and invalid
continuations after an initially valid token prefix.

Test many PDUs in one feed, a single huge PDU, final input with a leftover
suffix, single-text trailing garbage, scalar delimiters, no-progress behavior,
multiple files, exact quota boundaries, excessive nesting/items, allocation
failure, cancellation at each state and sink pause/abort/commit. Where member
order is unrestricted, test discriminator-before-value and value-before-
discriminator. A successful earlier PDU must not hide a later malformed one.

Differential tests compare chunked and complete input results/consumption,
but use independent standards-derived vectors for validity as well: agreement
with the old decoder alone cannot establish conformance. Add a fuzz target
that mutates both input bytes and feed partitions, including final-input timing,
limits and reset/cancellation. Run under ASan/UBSan and allocator fault injection.

Instrument raw-buffer high-water marks separately from materialized value
storage. Demonstrate memory independent of total multi-PDU file length after
framing, and independent of the largest raw token after typed streaming. Use
deterministic work counters to detect repeated-prefix parsing; avoid flaky
wall-clock assertions. Measure sink mode separately, including deferred bytes.
Do not report any of these proposed tests or guarantees as implemented until
their corresponding milestone has passed.
