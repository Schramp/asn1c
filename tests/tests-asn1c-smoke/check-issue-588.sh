#!/usr/bin/env bash

# Compile the issue #588 parameterized alias fixture with generated courtesy
# includes. Both source orders must produce compilable headers and C sources.
set -euo pipefail

top_builddir=${top_builddir:-../..}
top_srcdir=${top_srcdir:-../..}
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
testdir=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-588.XXXXXX")

# Remove generated files after success or failure.
# Source: local smoke-test convention; 2026-10-23; inputs: none;
# result: removed output directory; exceptions: rm errors; owner: asn1c;
# history: introduced for issue #588; example: cleanup
cleanup() {
    rm -rf -- "$testdir"
}
trap cleanup EXIT

asn1c_bin="$(CDPATH= cd -- "$top_builddir" && pwd)/asn1c/asn1c"
skeletons_dir="$(CDPATH= cd -- "$top_srcdir" && pwd)/skeletons"

cd -- "$testdir"

# The include cycle appears only when both the empty extension and the
# Node-valued object set are instantiated by the same template.
# The optional no-dependency mode is the report's workaround. Keep it working
# while checking the default mode in both module orders.
for deps in default no-deps; do
    for order in template-first use-first; do
        mkdir -- "$deps-$order"
        cd -- "$deps-$order"
        if [[ "$order" == template-first ]]; then
            inputs=("$srcdir/data/issue-588-template.asn1" "$srcdir/data/issue-588-use.asn1")
        else
            inputs=("$srcdir/data/issue-588-use.asn1" "$srcdir/data/issue-588-template.asn1")
        fi
        dep_flags=()
        if [[ "$deps" == no-deps ]]; then
            dep_flags=(-fno-include-deps)
        fi
        "$asn1c_bin" -S "$skeletons_dir" -fcompound-names -findirect-choice \
            "${dep_flags[@]}" -no-gen-CBOR -no-gen-OER -no-gen-UPER \
            -no-gen-BER -no-gen-JER -no-gen-XER "${inputs[@]}"

        if [[ "$deps" == default ]]; then
            # Both aliases must be visible before the include can re-enter
            # this header through Field -> Node -> Node-Extension.
            awk '
                /^typedef struct .* ProtocolIE_SingleContainer_.*_t;/ { aliases++; last_alias = NR }
                /^#include "ProtocolIE-Field.h"/ { include_line = NR }
                END { exit !(aliases == 2 && include_line && last_alias < include_line) }
            ' ProtocolIE-SingleContainer.h

            # Each entry point exercises a different path through the cycle.
            # Compile headers independently, including as C++ when available.
            for header in ProtocolIE-SingleContainer.h ProtocolIE-Field.h \
                Node.h Node-Extension.h Top.h; do
                printf '#include "%s"\n' "$header" | \
                    "${CC:-cc}" -std=c11 -fsyntax-only -I. -x c -
                if command -v "${CXX:-c++}" >/dev/null 2>&1; then
                    printf '#include "%s"\n' "$header" | \
                        "${CXX:-c++}" -std=c++11 -fsyntax-only -I. -x c++ -
                fi
            done
        fi

        "${MAKE:-make}" -f converter-example.mk -j2
        cd ..
    done
done
