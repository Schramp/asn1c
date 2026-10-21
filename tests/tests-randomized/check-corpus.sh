#!/bin/sh
# Purpose: Split local corpus coverage into independent, parallel Automake cases.
# Source: new asn1c test helper. Version/date: 2026-10-12.
# Inputs: $1 is the source directory; remaining arguments name bundle files.
# Returns: zero if all cases pass; otherwise a setup or test failure status.
# Exceptions: none; filesystem/awk/make errors terminate the script.
# Responsible party: asn1c maintainers. History: initial opt-in corpus target.
# Example: make -C tests/tests-randomized -j12 check-corpus.
set -eu

source_dir=$1
shift
if [ "$#" -eq 0 ]; then
    echo "Corpus coverage requires at least one bundle" >&2
    exit 1
fi

# Keep unique case names and logs so repeated runs cannot reuse success markers.
case_dir=$(mktemp -d .tmp.corpus-cases.XXXXXX)
run_id=${case_dir##*.}
case_list="$case_dir/cases.list"
: >"$case_list"
bundle_no=0  # State variable: distinguishes equal line numbers across bundles.
for bundle in "$@"; do
    case "$bundle" in
        /*) bundle_path=$bundle ;;
        *) bundle_path="$source_dir/$bundle" ;;
    esac
    if [ ! -f "$bundle_path" ]; then
        echo "Missing corpus bundle: $bundle_path" >&2
        exit 1
    fi
    bundle_no=$((bundle_no + 1))

    # Match the harness's comment filtering and retain each full ASN.1 line.
    # Each file becomes an Automake test, balancing work across the job budget.
    awk -v dir="$case_dir" -v run="$run_id" -v bundle="$bundle_no" '
        { declaration = $0; sub(/--.*/, "", declaration) }
        declaration ~ /[A-Za-z]/ {
            path = sprintf("%s/corpus-%s-%03d-L%d.test", dir, run, bundle, NR)
            print $0 > path
            close(path)
            print path
        }
    ' "$bundle_path" >>"$case_list"
done

# Generated paths contain no whitespace; caller-controlled source paths stay quoted.
case_tests=$(tr '\n' ' ' <"$case_list")
if [ -z "$case_tests" ]; then
    echo "Corpus bundles contain no ASN.1 cases; logs: $case_dir" >&2
    exit 1
fi
echo "Local corpus coverage: $(wc -l < "$case_list") cases; logs: $case_dir"
${MAKE:-make} check GENERATE_CORPUS=yes LIBFUZZER_CFLAGS= TESTS="$case_tests"
