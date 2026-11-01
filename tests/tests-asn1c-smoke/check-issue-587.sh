#!/usr/bin/env bash
#
# Purpose: Compile parameterized object-set specializations in either module order.
# Original source: Regression for mouse07410/asn1c issue #587.
# Version/date: 1.0, 2026-10-23.
# Inputs: ASN.1 compiler, skeleton directory, configured CC and MAKE commands.
# Returns/errors: Zero when both generated projects compile; failures return nonzero.
# Responsible party: asn1c maintainers.
# History: Added coverage for duplicate inner-type suffixes across specializations.
# Example: make check TESTS=check-issue-587.sh

set -euo pipefail

build_root=$(cd "${top_builddir:-../..}" && pwd)
source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-587.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM

asn1c="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
template="$source_root/tests/tests-asn1c-smoke/data/issue-587-template.asn1"
use_module="$source_root/tests/tests-asn1c-smoke/data/issue-587-use.asn1"

# Purpose: Generate and compile one module order and validate both specializations.
# Original source: Issue #587 generated-code regression.
# Version/date: 1.0, 2026-10-23.
# Parameters: $1 output directory; $2 and $3 are template/use ASN.1 input paths.
# Returns/errors: Zero for successful generation and C compilation; otherwise nonzero.
# Responsible party: asn1c maintainers.
# History: Compiles each parameterized object-set specialization in isolation.
# Example: run_case template-first "$template" "$use_module".
run_case() {
    local case_directory=$1
    local template_input=$2
    local use_input=$3
    local generated="$test_directory/$case_directory"

    mkdir -p "$generated"
    if ! "$asn1c" -fcompound-names -findirect-choice -fno-include-deps \
        -no-gen-CBOR -no-gen-OER -no-gen-UPER -no-gen-BER -no-gen-JER \
        -no-gen-XER -S "$skeletons" -D "$generated" \
        "$template_input" "$use_input" > "$generated/asn1c.log" 2>&1; then
        cat "$generated/asn1c.log" >&2
        return 1
    fi

    local generated_c="$generated/ProtocolIE-Field.c"
    local id_callbacks
    local value_callbacks
    local value_descriptors
    id_callbacks=$(grep -Ec '^memb_id_constraint_[0-9]+\(' "$generated_c" || true)
    value_callbacks=$(grep -Ec '^memb_value_constraint_[0-9]+\(' "$generated_c" || true)
    value_descriptors=$(grep -Ec \
        '^asn_TYPE_descriptor_t asn_DEF_value_[0-9]+ = \{' "$generated_c" || true)
    if [[ $id_callbacks -ne 2 || $value_callbacks -ne 2 || $value_descriptors -ne 2 ]]; then
        echo "FAIL: $case_directory emitted unexpected specialization symbols" >&2
        echo "id callbacks: $id_callbacks; value callbacks: $value_callbacks;" \
            "value descriptors: $value_descriptors" >&2
        return 1
    fi

    if ! "${MAKE:-make}" -C "$generated" -f converter-example.mk \
        CC="${CC:-cc}" > "$generated/make.log" 2>&1; then
        cat "$generated/make.log" >&2
        return 1
    fi
}

run_case template-first "$template" "$use_module"
run_case use-first "$use_module" "$template"

echo 'Parameterized object-set order regression passed'
