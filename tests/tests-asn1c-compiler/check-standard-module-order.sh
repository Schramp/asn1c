#!/bin/sh
# Purpose: ensure standard module import order does not depend on readdir order.
# Source: PR #593 CI failure in run 40966582297.
# Version: 2026-10-30. Responsible party: asn1c maintainers.
# Inputs: top_srcdir and top_builddir; return zero on identical output.
# Exceptions: compiler, file, or comparison errors terminate the script.
# History: initial regression. Example: ./check-standard-module-order.sh
set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)
ASN1C="$top_builddir/asn1c/asn1c"
modules="$top_srcdir/skeletons/standard-modules"
schema="$top_srcdir/tests/tests-asn1c-compiler/104-param-1-OK.asn1"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
mkdir -p "$test_dir/useful-first/standard-modules" "$test_dir/oid-first/standard-modules"

# Populate equivalent directories in opposite creation orders.
useful=ASN1C-UsefulInformationObjectClasses.asn1
oid=ASN1-Object-Identifier-Module.asn1
cp "$modules/$useful" "$test_dir/useful-first/standard-modules/"
cp "$modules/$oid" "$test_dir/useful-first/standard-modules/"
cp "$modules/$oid" "$test_dir/oid-first/standard-modules/"
cp "$modules/$useful" "$test_dir/oid-first/standard-modules/"
cp "$top_srcdir/skeletons/file-dependencies" "$test_dir/useful-first/"
cp "$top_srcdir/skeletons/file-dependencies" "$test_dir/oid-first/"

# Normalize only the temporary directory path before comparing generated code.
"$ASN1C" -S "$test_dir/useful-first" -P -fwide-types "$schema" \
    >"$test_dir/useful.raw"
"$ASN1C" -S "$test_dir/oid-first" -P -fwide-types "$schema" \
    >"$test_dir/oid.raw"
sed "s@$test_dir/useful-first@STANDARD_MODULES@g" \
    "$test_dir/useful.raw" >"$test_dir/useful.out"
sed "s@$test_dir/oid-first@STANDARD_MODULES@g" \
    "$test_dir/oid.raw" >"$test_dir/oid.out"
cmp "$test_dir/useful.out" "$test_dir/oid.out"

echo 'PASS: standard module import order is deterministic'
