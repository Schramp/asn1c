#!/usr/bin/env bash
# Purpose: Verify that APER-only (-no-gen-UPER) and UPER-only (-no-gen-APER)
#          generated projects are self-contained, link, and encode identically
#          to a project generated with both PER flavors.
# Source: Regression for INTEGER_aper.c calling per_*_range_(un)rebase helpers
#         that were only shipped in the CODEC-UPER skeleton section
#         (uper_support.[ch]); they now live in per_support.[ch].
# Version/date: 2026-10-20; responsible party: asn1c maintainers.
# Inputs: top_builddir/top_srcdir, CC, and MAKE supplied by the Automake harness.
# Result/errors: Exit zero on success; shell/build/codec failures return nonzero.
# Example: make check TESTS=check-PER-single-flavor.sh
set -eu

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-per-flavor.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

# Constrained INTEGERs exercise the shared range rebase/unrebase helpers:
# negative lower bound, unsigned ranges above INTMAX_MAX, and an extensible range.
cat > "$test_directory/per.asn1" <<'EOF'
Module DEFINITIONS AUTOMATIC TAGS ::= BEGIN
T ::= SEQUENCE {
    neg  INTEGER (-5..1000),
    wide INTEGER (0..4294967295),
    full64 INTEGER (0..18446744073709551615),
    high64 INTEGER (9223372036854775808..18446744073709551615),
    ext  INTEGER (-10..10, ...),
    list SEQUENCE (SIZE(1..4)) OF INTEGER (-128..127)
}
END
EOF
# Use the existing XER hexadecimal INTEGER form for values above INTMAX_MAX:
# this exercises unsigned native PER without relying on signed decimal parsing.
cat > "$test_directory/value.xer" <<'EOF'
<T>
<neg>-5</neg><wide>4294967295</wide>
<full64>00:FF:FF:FF:FF:FF:FF:FF:FF</full64><high64>00:80:00:00:00:00:00:00:20</high64>
<ext>100</ext><list><INTEGER>-128</INTEGER><INTEGER>127</INTEGER></list>
</T>
EOF

# Purpose: generate/build variant $1 with flavor flags $2 and native uint64 storage.
# Source/history: existing flavor smoke test, extended for unsigned PER metadata.
# Version: 2026-10-20; owner: asn1c maintainers. Returns: build exit status.
# Exceptions: none; set -e stops on errors. Example: build_variant both "".
build_variant() {
    local dir="$test_directory/$1"
    mkdir "$dir"
    # shellcheck disable=SC2086
    "$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
        -D "$dir" -pdu=T -fnative-types -finteger-native-type=uint64 \
        $2 "$test_directory/per.asn1" > /dev/null
    "${MAKE:-make}" -C "$dir" -f converter-example.mk CC="${CC:-cc}" > /dev/null
}

# Purpose: reject files matching glob $2 in generated variant $1.
# Source/history: PER single-flavor regression; version: 2026-10-20.
# Owner: asn1c maintainers. Returns: zero if absent, exits one on leaked files.
# Exceptions: none. Example: assert_absent aper-only "uper_* *_uper.c".
assert_absent() {
    local leaked
    leaked=$(cd "$test_directory/$1" && ls $2 2>/dev/null || true)
    if [ -n "$leaked" ]; then
        echo "$1: unexpected files emitted: $leaked" >&2
        exit 1
    fi
}

# Purpose: encode variant $1 in syntax $2, then compare its decoded XER value.
# Source/history: PER single-flavor regression; version: 2026-10-20.
# Owner: asn1c maintainers. Returns: command/cmp status; set -e stops on failure.
# Exceptions: none. Example: round_trip aper-only aper.
round_trip() {
    local dir="$test_directory/$1"
    "$dir/converter-example" -ixer "-o$2" "$test_directory/value.xer" \
        > "$dir/value.$2"
    "$dir/converter-example" "-i$2" -oxer "$dir/value.$2" > "$dir/back.xer"
    "$dir/converter-example" -ixer -oxer "$test_directory/value.xer" \
        > "$dir/expected.xer"
    cmp "$dir/expected.xer" "$dir/back.xer"
}

build_variant both ""
build_variant aper-only "-no-gen-UPER"
build_variant uper-only "-no-gen-APER"

# Disabled flavor must not leak any of its codec files.
assert_absent aper-only "uper_* *_uper.c"
assert_absent uper-only "aper_* *_aper.c"

round_trip both aper
round_trip both uper
round_trip aper-only aper
round_trip uper-only uper

# Single-flavor builds must produce the same bytes as the combined build.
cmp "$test_directory/both/value.aper" "$test_directory/aper-only/value.aper"
cmp "$test_directory/both/value.uper" "$test_directory/uper-only/value.uper"

echo "OK"
