#!/bin/sh
# Purpose: Regress issue #592 for numbered instances, aliases, and long names.
# Source: issue #592 reproducer and PR #593, extended with boundary coverage.
# Version: 2026-10-29. Responsible party: asn1c maintainers.
# Inputs: top_srcdir, top_builddir, CC; returns zero on success, nonzero on failure.
# Exceptions: compiler or generator failures terminate the script.
# History: initial test for issue #592. Example: ./check-issue-592.sh
set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)
ASN1C="${top_builddir}/asn1c/asn1c"
CC=${CC:-cc}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

# Compile dereferences so an incomplete pointer tag fails as in the report.
mkdir "$test_dir/short"
(cd "$test_dir/short" && "$ASN1C" -S "$top_srcdir/skeletons" \
    -fwide-types -no-gen-example \
    "$top_srcdir/tests/tests-asn1c-compiler/issue-592/StructTags.asn1") \
    >"$test_dir/short/generator.log" 2>&1
cat >"$test_dir/short/use.c" <<'EOF'
#include "Bunch.h"
#include "Holder.h"
int use_members(struct Bunch *b, struct Holder *h) {
    return b->field_REAL->list.count + b->field_IA5String->list.count
        + h->a->n.size + h->b->n.size;
}
EOF
"$CC" -I"$test_dir/short" -c "$test_dir/short/use.c" -o "$test_dir/short/use.o"
grep -Eq 'struct Collection_[0-9]+P0[[:space:]]+\*field_REAL;' "$test_dir/short/Bunch.h"
grep -Eq 'struct Collection_[0-9]+P1[[:space:]]+\*field_IA5String;' "$test_dir/short/Bunch.h"
grep -Eq 'struct Base[[:space:]]+\*a;' "$test_dir/short/Holder.h"

# A configured prefix must appear identically in definitions and references.
"$ASN1C" -P -fwide-types -fprefix=Safe_ \
    "$top_srcdir/tests/tests-asn1c-compiler/issue-592/StructTags.asn1" >"$test_dir/prefix.out"
grep -Eq '^typedef struct Safe_Collection_[0-9]+P0 \{' "$test_dir/prefix.out"
grep -Eq 'struct Safe_Collection_[0-9]+P0[[:space:]]+\*field_REAL;' "$test_dir/prefix.out"

# A valid name beyond the former 512-byte buffer must retain its full tag.
long_type=$(awk 'BEGIN { printf "Collection"; for(i = 0; i < 600; i++) printf "X" }')
cat >"$test_dir/LongTags.asn1" <<EOF
LongTags DEFINITIONS ::= BEGIN
$long_type {T} ::= SET OF T
LongBunch ::= SEQUENCE { field-REAL $long_type {REAL} }
END
EOF
"$ASN1C" -P -fwide-types "$test_dir/LongTags.asn1" >"$test_dir/long.out"
long_tag=$(awk -v prefix="$long_type" \
    '$1 == "typedef" && $2 == "struct" && index($3, prefix "_") == 1 { print $3; exit }' \
    "$test_dir/long.out")
test -n "$long_tag"
grep -F "struct $long_tag" "$test_dir/long.out" | grep -F '*field_REAL;' >/dev/null

echo 'PASS: issue #592 struct tags, aliases, and long identifiers'
