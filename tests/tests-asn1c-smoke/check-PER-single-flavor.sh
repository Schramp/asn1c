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
# negative lower bound, a full 32-bit unsigned range, and an extensible range.
cat > "$test_directory/per.asn1" <<'EOF'
Module DEFINITIONS AUTOMATIC TAGS ::= BEGIN
T ::= SEQUENCE {
    neg  INTEGER (-5..1000),
    wide INTEGER (0..4294967295),
    ext  INTEGER (-10..10, ...),
    list SEQUENCE (SIZE(1..4)) OF INTEGER (-128..127)
}
END
EOF
cat > "$test_directory/value.xer" <<'EOF'
<T><neg>-5</neg><wide>4294967295</wide><ext>100</ext><list><INTEGER>-128</INTEGER><INTEGER>127</INTEGER></list></T>
EOF

# Generate and build a converter into $1 with extra asn1c flags $2.
build_variant() {
    local dir="$test_directory/$1"
    mkdir "$dir"
    # shellcheck disable=SC2086
    "$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
        -D "$dir" -pdu=T $2 "$test_directory/per.asn1" > /dev/null
    "${MAKE:-make}" -C "$dir" -f converter-example.mk CC="${CC:-cc}" > /dev/null
}

# Fail if any file matching glob $2 was emitted into variant $1.
assert_absent() {
    local leaked
    leaked=$(cd "$test_directory/$1" && ls $2 2>/dev/null || true)
    if [ -n "$leaked" ]; then
        echo "$1: unexpected files emitted: $leaked" >&2
        exit 1
    fi
}

# Encode value.xer with variant $1 into syntax $2, then decode back to XER.
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
