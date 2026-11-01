# Encoder callback failure handling

`ASN__CALLBACK`, `ASN__CALLBACK2`, `ASN__CALLBACK3`, and `ASN__TEXT_INDENT`
can jump to `cb_failed` in the function where they are expanded. A label in a
caller is not reached by a macro expanded in a helper. Keep a `cb_failed` label
only when that function has a callback macro or an explicit jump to it.

Encoder failure paths follow three rules:

1. Return an `asn_enc_rval_t` with `encoded == -1`. Preserve a child encoder's
   result when propagating its failure, so the failing type and value remain
   identifiable.
2. Release every temporary allocation before returning, including buffers
   still waiting to be written when a final output callback fails.
3. Decrement a recursion-depth counter exactly once for every successful
   increment, including on child and callback failures.

The runtime regression in `tests/tests-skeletons/check-runtime-encoding-failures.c`
injects callback and child failures into UniversalString JER, canonical SET OF
XER, and CHOICE JER. It checks error results, temporary allocation cleanup,
recursion-depth balance, and successful output.

For generated XER TEXT BIT STRING encoders, named-bit output uses callback
macros and needs `cb_failed`. An accepted type with no named bits emits no
callback calls, so its generated function omits the label and callback-only
variables. `tests/tests-asn1c-compiler/check-xer-text-bitstring.sh` compiles
both forms with `-Wall -Werror` and runs their behavior checks.
