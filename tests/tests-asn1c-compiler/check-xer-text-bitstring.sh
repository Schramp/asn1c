#!/bin/sh
#
# Purpose: verify generated XER TEXT BIT STRING code with and without names.
# Original source: ASN.1 XER TEXT BIT STRING encoding-control regression.
# Version/date: 1.0, 2026-10-24.
# Parameters: Automake source/build roots and optional CC, CFLAGS, and MAKE.
# Returns: zero when generated code compiles cleanly and runtime checks pass.
# Errors: generation, compilation, encoding, or decoding failures exit nonzero.
# Responsible party: asn1c maintainers.
# History: added zero-name and named-bit encoder/decoder coverage.
# Example: make check TESTS=check-xer-text-bitstring.sh

set -eu

source_root=$(cd "${abs_top_srcdir:-${top_srcdir:?top_srcdir is required}}" && pwd)
build_root=$(cd "${abs_top_builddir:-${top_builddir:?top_builddir is required}}" && pwd)
compiler="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
schema="$source_root/tests/tests-asn1c-compiler/214-xer-text-bitstring-OK.asn1"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-xer-text-bitstring.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mkdir "$test_root/generated"

if ! "$compiler" -fcompound-names -S "$skeletons" -D "$test_root/generated" \
    "$schema" >"$test_root/generate.log" 2>&1; then
    cat "$test_root/generate.log" >&2
    exit 1
fi

# Compile the generated modules with all common warnings treated as errors.
for module in Empty Named; do
    if ! ${CC:-cc} -std=gnu18 -Wall -Werror ${CFLAGS:-} \
        -I"$test_root/generated" -c "$test_root/generated/$module.c" \
        -o "$test_root/$module.o" >"$test_root/$module-compile.log" 2>&1; then
        cat "$test_root/$module-compile.log" >&2
        exit 1
    fi
done

if ! "${MAKE:-make}" -C "$test_root/generated" -f converter-example.mk \
    CC="${CC:-cc}" libasncodec.a >"$test_root/library-build.log" 2>&1; then
    cat "$test_root/library-build.log" >&2
    exit 1
fi

if ! ${CC:-cc} ${CFLAGS:-} -I"$test_root/generated" \
    "$source_root/tests/tests-asn1c-compiler/check-xer-text-bitstring.c" \
    "$test_root/generated/libasncodec.a" -lm \
    -o "$test_root/check-xer-text-bitstring" \
    >"$test_root/test-compile.log" 2>&1; then
    cat "$test_root/test-compile.log" >&2
    exit 1
fi

"$test_root/check-xer-text-bitstring"
echo "XER TEXT BIT STRING generated-code checks passed"
