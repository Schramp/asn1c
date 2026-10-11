#!/usr/bin/env bash
# Purpose: Verify generated converters expose BER-compatible DER/CER input aliases.
# Source: Repository converter selector table and X.690 BOOLEAN TRUE encoding.
# Version/date: 2026-10-11; responsible party: asn1c maintainers.
# Inputs: top_builddir/top_srcdir, CC, and MAKE supplied by the Automake harness.
# Result/errors: Exit zero on success; shell/build/codec failures return nonzero.
# History: Added for the generic CER dispatch correction.
# Example: make check TESTS=check-binary-format-selectors.sh
set -eu

# Resolve repository paths before entering the isolated generated project.
test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-binary-selectors.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

# BOOLEAN TRUE has the same primitive encoding in BER, DER, and CER.
printf 'Module DEFINITIONS ::= BEGIN Flag ::= BOOLEAN END\n' > "$test_directory/flag.asn1"
printf '\001\001\377' > "$test_directory/true.bin"
"$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
    -D "$test_directory" -pdu=Flag "$test_directory/flag.asn1"
"${MAKE:-make}" -C "$test_directory" -f converter-example.mk \
    CC="${CC:-cc}"

# Each input alias must select the same enabled decoder and produce DER bytes.
for input_format in ber der cer; do
    "$test_directory/converter-example" "-i$input_format" -oder \
        "$test_directory/true.bin" > "$test_directory/$input_format.der"
    cmp "$test_directory/true.bin" "$test_directory/$input_format.der"
done

# The encoder is absent: adding a CER input alias must not advertise CER output.
if "$test_directory/converter-example" -iber -ocer "$test_directory/true.bin" \
    > "$test_directory/unexpected-output" 2> "$test_directory/error.log"; then
    echo "Unexpected CER encoder selector" >&2
    exit 1
fi
