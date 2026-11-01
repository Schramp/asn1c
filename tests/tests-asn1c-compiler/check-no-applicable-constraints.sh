#!/bin/sh
# Purpose: Verify no-applicable generated checkers guard against self-calls.
# Original source: asn1c generated-code regression. Version/date: 1.0, 2026-10-23.
# Inputs: Automake source/build roots plus CC, CFLAGS, and MAKE variables.
# Returns: Zero when generated guard checks and runtime constraint calls pass.
# Errors: Compiler, generated build, executable, or source assertion failures exit.
# Responsible party: asn1c maintainers.
# History: Added coverage for OCTET STRING, BIT STRING, and aliased OCTET STRING.
# Example: make check TESTS=check-no-applicable-constraints.sh

set -eu

source_root=$(CDPATH= cd -- "${abs_top_srcdir:-${top_srcdir:?}}" && pwd)
build_root=$(CDPATH= cd -- "${abs_top_builddir:-${top_builddir:?}}" && pwd)
fixture_dir="$source_root/tests/tests-asn1c-compiler/no-applicable-constraints"
compiler="$build_root/asn1c/asn1c"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-no-applicable.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mkdir "$test_root/generated"

if ! "$compiler" -fcompound-names -pdu=all -S "$source_root/skeletons" \
    -D "$test_root/generated" "$fixture_dir/NoApplicable.asn1" \
    >"$test_root/generate.log" 2>&1; then
    cat "$test_root/generate.log" >&2
    exit 1
fi

# Require each no-applicable checker to compare against its own emitted symbol.
for checker in T B Alias; do
    if ! grep -Fq "general_constraints != ${checker}_constraint" \
        "$test_root/generated/${checker}.c"; then
        echo "FAIL: ${checker}.c does not guard its own constraint callback" >&2
        exit 1
    fi
done

if ! CFLAGS="${CFLAGS:-}" "${MAKE:-make}" -C "$test_root/generated" \
    -f converter-example.mk CC="${CC:-cc}" libasncodec.a \
    >"$test_root/build.log" 2>&1; then
    cat "$test_root/build.log" >&2
    exit 1
fi

# Link a small caller that invokes every generated checker under an alarm.
if ! ${CC:-cc} ${CFLAGS:-} -I"$test_root/generated" \
    "$fixture_dir/check-no-applicable-constraints.c" \
    "$test_root/generated/libasncodec.a" -lm \
    -o "$test_root/check-no-applicable-constraints" \
    >"$test_root/test-build.log" 2>&1; then
    cat "$test_root/test-build.log" >&2
    exit 1
fi

if ! "$test_root/check-no-applicable-constraints"; then
    echo "FAIL: a no-applicable generated checker failed or timed out" >&2
    exit 1
fi

echo "No-applicable generated constraint checks passed"
