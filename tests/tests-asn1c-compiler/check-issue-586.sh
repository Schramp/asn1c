#!/bin/sh
#
# Purpose: generate and exercise issue #586 extensible IOC APER open types.
# Original source: issue #586 known/unknown vectors and boundary requirements.
# Version/date: 1.0, 2026-10-22.
# Parameters: Automake roots plus CC, CFLAGS, and MAKE build variables.
# Returns: zero when default and APER-only-PER integration checks pass.
# Errors: compiler, generated build, executable, or text assertion failures exit.
# Responsible party: asn1c maintainers.
# History: added all-codecs, APER-only-PER, and no-APER generation coverage.
# Example: make check TESTS=check-issue-586.sh

set -eu

source_root=$(cd "${abs_top_srcdir:-${top_srcdir:?top_srcdir is required}}" && pwd)
build_root=$(cd "${abs_top_builddir:-${top_builddir:?top_builddir is required}}" && pwd)
fixture_dir="$source_root/tests/tests-asn1c-compiler/issue-586"
compiler="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-586.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

mkdir "$test_root/all-codecs" "$test_root/aper-only" "$test_root/no-aper"

# Generate the complete codec project, then build through its generated makefile.
if ! "$compiler" -fcompound-names -pdu=all -S "$skeletons" \
    -D "$test_root/all-codecs" "$fixture_dir/OpenV1.asn1" \
    >"$test_root/all-codecs/generate.log" 2>&1; then
    cat "$test_root/all-codecs/generate.log" >&2
    exit 1
fi
if ! grep -q 'ATF_OPEN_TYPE_UNKNOWN' "$test_root/all-codecs/Field.c"; then
    echo "FAIL: all-codecs output lacks the APER unknown-row flag" >&2
    exit 1
fi
if ! "${MAKE:-make}" -C "$test_root/all-codecs" -f converter-example.mk \
    CC="${CC:-cc}" libasncodec.a >"$test_root/all-codecs/build.log" 2>&1; then
    cat "$test_root/all-codecs/build.log" >&2
    exit 1
fi
# Split CFLAGS intentionally so sanitizer options reach the test executable too.
if ! ${CC:-cc} ${CFLAGS:-} -I"$test_root/all-codecs" \
    "$fixture_dir/issue-586.c" "$test_root/all-codecs/libasncodec.a" \
    -lm -o "$test_root/all-codecs/issue-586-test" \
    >"$test_root/all-codecs/test-build.log" 2>&1; then
    cat "$test_root/all-codecs/test-build.log" >&2
    exit 1
fi
if ! "$test_root/all-codecs/issue-586-test"; then
    echo "FAIL: all-codecs regression executable" >&2
    exit 1
fi

# Generate a minimal APER-only project with indirect choices, as in issue #586.
if ! "$compiler" -fcompound-names -findirect-choice -fno-include-deps \
    -pdu=all -no-gen-CBOR -no-gen-OER -no-gen-UPER -no-gen-BER \
    -no-gen-JER -no-gen-XER -S "$skeletons" \
    -D "$test_root/aper-only" "$fixture_dir/OpenV1.asn1" \
    >"$test_root/aper-only/generate.log" 2>&1; then
    cat "$test_root/aper-only/generate.log" >&2
    exit 1
fi
if ! "${MAKE:-make}" -C "$test_root/aper-only" -f converter-example.mk \
    CC="${CC:-cc}" libasncodec.a >"$test_root/aper-only/build.log" 2>&1; then
    cat "$test_root/aper-only/build.log" >&2
    exit 1
fi
if ! grep -q 'ATF_OPEN_TYPE_UNKNOWN' "$test_root/aper-only/Field.c"; then
    echo "FAIL: APER-only output lacks the APER unknown-row flag" >&2
    exit 1
fi
if ! ${CC:-cc} ${CFLAGS:-} -I"$test_root/aper-only" \
    "$fixture_dir/issue-586.c" "$test_root/aper-only/libasncodec.a" \
    -lm -o "$test_root/aper-only/issue-586-test" \
    >"$test_root/aper-only/test-build.log" 2>&1; then
    cat "$test_root/aper-only/test-build.log" >&2
    exit 1
fi
if ! "$test_root/aper-only/issue-586-test"; then
    echo "FAIL: APER-only-PER regression executable" >&2
    exit 1
fi

# Fallback generation is APER-specific; UPER-only output must omit the wrapper.
if ! "$compiler" -fcompound-names -pdu=all -no-gen-APER -S "$skeletons" \
    -D "$test_root/no-aper" "$fixture_dir/OpenV1.asn1" \
    >"$test_root/no-aper/generate.log" 2>&1; then
    cat "$test_root/no-aper/generate.log" >&2
    exit 1
fi
if grep -q 'asn1cUnknown' "$test_root/no-aper/Field.h"; then
    echo "FAIL: -no-gen-APER emitted an opaque CHOICE alternative" >&2
    exit 1
fi
if grep -q 'ATF_OPEN_TYPE_UNKNOWN' "$test_root/no-aper/Field.c"; then
    echo "FAIL: -no-gen-APER emitted the APER unknown-row flag" >&2
    exit 1
fi

echo "issue #586 APER open-type integration checks passed"
