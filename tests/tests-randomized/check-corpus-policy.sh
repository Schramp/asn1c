#!/bin/sh
# Purpose: Test corpus policy, cache isolation, failures, and job-limit forwarding.
# Source: new asn1c harness regression. Version/date: 2026-10-12.
# Inputs: $1 is the absolute randomized harness path.
# Returns: zero on success; a failed assertion/setup command returns nonzero.
# Exceptions: none; isolated mock tools avoid compiler/fuzzer runtime costs.
# Responsible party: asn1c maintainers. History: initial corpus policy coverage.
# Example: sh check-corpus-policy.sh "$PWD/check-bundles.sh".
set -eu
harness=$1
policy_tmp=$(mktemp -d)
trap 'rm -rf "$policy_tmp"' EXIT HUP INT TERM
mkdir -p "$policy_tmp/asn1c" "$policy_tmp/work"
cp "$harness" "$policy_tmp/harness.sh"
: >"$policy_tmp/random-test-driver.c"

# Simulate only the generated-project interfaces consumed by the real harness.
cat >"$policy_tmp/asn1c/asn1c" <<'EOF'
#!/bin/sh
for arg in "$@"; do [ "$arg" != -P ] || exit 0; done
: >converter-example.mk
EOF
cat >"$policy_tmp/test-param-helper" <<'EOF'
#!/bin/sh
case "$3" in *RMAX=16385*) echo 16385 ;; *) echo 128 ;; esac
EOF
cat >"$policy_tmp/make" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$POLICY_LOG.make"
case "$*" in *all-tests-succeeded*) exit 1 ;; esac
case "$*" in *fuzz) echo fuzz >>"$POLICY_LOG"; exit 0 ;; esac
cp "$POLICY_ROOT/driver" random-test-driver
chmod +x random-test-driver
EOF
cat >"$policy_tmp/driver" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$POLICY_LOG.args"
if [ "${POLICY_SLOW_DRIVER:-0}" = 1 ]; then
    echo "$$" >"$POLICY_LOG.pid"
    exec sleep 10
fi
case "$*" in
    *'-g random-data'*)
        echo generate >>"$POLICY_LOG"
        [ "${POLICY_FAIL_GENERATE:-0}" = 0 ] || exit 1
        mkdir -p random-data/ber
        echo seed >random-data/ber/seed
        ;;
    *' -c') echo roundtrip >>"$POLICY_LOG" ;;
    *' -y') echo copy >>"$POLICY_LOG" ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$policy_tmp/asn1c/asn1c" "$policy_tmp/test-param-helper" "$policy_tmp/make"

# Purpose: Execute one policy combination and assert its phases and exit status.
# Source/version: this regression, 2026-10-12. Inputs: policy, flags, expected
# generation count, expected fuzz count, expected status, optional harness args.
# Returns: zero on matching expectations; assertion failures terminate the test.
# Exceptions: none. Responsible party: asn1c maintainers. History: initial helper.
# Example: run_policy auto '' 0 0 pass.
run_policy() {
    policy=$1; flags=$2; generations=$3; fuzzes=$4; expected=$5
    shift 5
    export POLICY_ROOT="$policy_tmp" POLICY_LOG="$policy_tmp/phases"
    : >"$POLICY_LOG"
    : >"$POLICY_LOG.make"
    if (cd "$policy_tmp/work" && GENERATE_CORPUS="$policy" LIBFUZZER_CFLAGS="$flags" \
        MAKE="$policy_tmp/make" srcdir="$policy_tmp" abs_builddir="$policy_tmp" \
        abs_top_builddir="$policy_tmp" abs_top_srcdir="$policy_tmp" CFLAGS_M32="${POLICY_M32:-}" \
        sh "$policy_tmp/harness.sh" "$@" -t "${POLICY_TYPE:-BOOLEAN}") >"$policy_tmp/output" 2>&1; then
        [ "$expected" = pass ]
    else
        [ "$expected" = fail ]
    fi
    [ "$(grep -c '^generate$' "$POLICY_LOG" || :)" -eq "$generations" ]
    [ "$(grep -c '^fuzz$' "$POLICY_LOG" || :)" -eq "$fuzzes" ]
    if [ "$expected" = pass ]; then
        executions=2
        if [ -n "${POLICY_M32:-}" ]; then executions=4; fi
        [ "$(grep -c '^roundtrip$' "$POLICY_LOG")" -eq "$executions" ]
        [ "$(grep -c '^copy$' "$POLICY_LOG")" -eq "$executions" ]
    fi
}

# Ordinary checks retain round-trip/copy phases while avoiding seed writes.
run_policy auto '' 0 0 pass
if grep -q -- '-j' "$POLICY_LOG.make"; then
    echo "Default inner make unexpectedly overrides the shared job limit" >&2
    exit 1
fi
grep -q 'all-tests-succeeded-corpus-0-fuzz-0:' "$policy_tmp/work/.tmp.random/Makefile"

# Large cases retain their size while reducing the repetitions for each codec.
export POLICY_TYPE='BOOLEAN --RMAX=16385'
: >"$policy_tmp/phases.args"
run_policy auto '' 0 0 pass
[ "$(grep -c -- '-s 16385 -n 8' "$POLICY_LOG.args")" -eq 4 ]
unset POLICY_TYPE

# A sleeping driver must fail promptly and leave no child behind.
export POLICY_SLOW_DRIVER=1 RANDOM_TEST_TIMEOUT=1
run_policy auto '' 0 0 fail
grep -q 'Timed out after 1s' "$policy_tmp/output"
if kill -0 "$(cat "$POLICY_LOG.pid")" 2>/dev/null; then
    echo "Timed-out randomized driver is still running" >&2
    exit 1
fi
unset POLICY_SLOW_DRIVER RANDOM_TEST_TIMEOUT

run_policy no '' 0 0 pass
run_policy yes '' 2 0 pass -j 3
grep -q -- '-j 3' "$POLICY_LOG.make"
grep -q 'all-tests-succeeded-corpus-1-fuzz-0:' "$policy_tmp/work/.tmp.random/Makefile"

# Fuzzing always creates seeds and uses a distinct completion-cache target.
run_policy auto '-fsanitize=fuzzer' 2 2 pass
grep -q 'all-tests-succeeded-corpus-1-fuzz-1:' "$policy_tmp/work/.tmp.random/Makefile"
run_policy yes '-fsanitize=fuzzer' 2 2 pass
export POLICY_M32=-m32
run_policy auto '-fsanitize=fuzzer' 2 2 pass
run_policy yes '-fsanitize=fuzzer' 4 2 pass
unset POLICY_M32
run_policy no '-fsanitize=fuzzer' 0 0 fail
run_policy invalid '' 0 0 fail
run_policy auto '' 0 0 fail -j 0
run_policy auto '' 0 0 fail -j 00
run_policy auto '' 0 0 fail -j invalid
export RANDOM_TEST_TIMEOUT=00000
run_policy auto '' 0 0 fail
unset RANDOM_TEST_TIMEOUT

# A failing generator must fail coverage instead of being reported as skipped.
export POLICY_FAIL_GENERATE=1
run_policy yes '' 2 0 fail

# Check splitting/filtering, no-final-newline input, and invalid bundle errors.
splitter="$(dirname "$harness")/check-corpus.sh"
printf '%s\n' '-- comment' '' 'BOOLEAN -- RMAX=1' >"$policy_tmp/mixed.txt"
printf '%s' 'INTEGER (0..10)' >>"$policy_tmp/mixed.txt"
(cd "$policy_tmp/work" && MAKE="$policy_tmp/make" \
    sh "$splitter" "$policy_tmp" mixed.txt) >"$policy_tmp/split.log" 2>&1
grep -q 'GENERATE_CORPUS=yes LIBFUZZER_CFLAGS= TESTS=' "$POLICY_LOG.make"
split_files=$(find "$policy_tmp/work" -name 'corpus-*.test')
[ "$(printf '%s\n' "$split_files" | wc -l)" -eq 2 ]
if (cd "$policy_tmp/work" && sh "$splitter" "$policy_tmp" missing.txt) \
    >"$policy_tmp/split.log" 2>&1; then
    echo "Missing bundle unexpectedly passed" >&2
    exit 1
fi
printf '%s\n' '-- no cases' >"$policy_tmp/empty.txt"
if (cd "$policy_tmp/work" && sh "$splitter" "$policy_tmp" empty.txt) \
    >"$policy_tmp/split.log" 2>&1; then
    echo "Empty bundle unexpectedly passed" >&2
    exit 1
fi
echo "PASS: corpus policy, failures, cache modes, and job-limit forwarding"
