@CODE_COVERAGE_RULES@

check_PROGRAMS = test-param-helper
dist_check_SCRIPTS = check-bundles.sh
TEST_EXTENSIONS = .txt .test

#Filter out the coverage options from CFLAGS as we don't need
#code coverage data for the tests executables
CFLAGS = $(filter-out $(CODE_COVERAGE_CFLAGS), @CFLAGS@)

# Override single test fuzzing time using "make check FUZZ_TIME=1"
FUZZ_TIME=10
GENERATE_CORPUS=auto
RANDOM_TEST_TIMEOUT=300

TESTS_ENVIRONMENT=                          \
    CC="${CC}"                              \
    MAKE="${MAKE}"                          \
    CFLAGS="${TESTSUITE_CFLAGS} ${CFLAGS}"  \
    CFLAGS_M32="${CFLAGS_M32}"              \
    LDFLAGS="${LDFLAGS}"                    \
    LIBFUZZER_CFLAGS="${LIBFUZZER_CFLAGS}"  \
    FUZZ_TIME="${FUZZ_TIME}"                \
    GENERATE_CORPUS="${GENERATE_CORPUS}"    \
    RANDOM_TEST_TIMEOUT="${RANDOM_TEST_TIMEOUT}" \
    FUZZ_TARGETS="${FUZZ_TARGETS}"          \
    FUZZ_MAX_CORPUS_BYTES="${FUZZ_MAX_CORPUS_BYTES}" \
    FUZZ_ASAN_OPTIONS="${FUZZ_ASAN_OPTIONS}" \
    ASAN_ENV_FLAGS="@ASAN_ENV_FLAGS@"       \
    srcdir=${srcdir}                        \
    abs_builddir=${abs_builddir}            \
    abs_top_srcdir=${abs_top_srcdir}        \
    abs_top_builddir=${abs_top_builddir}    \
    ${srcdir}/check-bundles.sh

TESTS =
TESTS += bundles/00-NULL-bundle.txt
TESTS += bundles/01-BOOLEAN-bundle.txt
TESTS += bundles/02-INTEGER-bundle.txt
TESTS += bundles/03-ENUMERATED-bundle.txt
TESTS += bundles/04-REAL-bundle.txt
TESTS += bundles/05-BIT-STRING-bundle.txt
TESTS += bundles/06-OCTET-STRING-bundle.txt
TESTS += bundles/07-VisibleString-bundle.txt
TESTS += bundles/08-OBJECT-IDENTIFIER-bundle.txt
TESTS += bundles/09-RELATIVE-OID-bundle.txt
TESTS += bundles/10-UTF8String-bundle.txt
TESTS += bundles/11-BMPString-bundle.txt
TESTS += bundles/12-UniversalString-bundle.txt
TESTS += bundles/13-UTCTime-bundle.txt
TESTS += bundles/14-GeneralizedTime-bundle.txt
TESTS += bundles/15-CHOICE-bundle.txt
TESTS += bundles/16-SEQUENCE-bundle.txt
TESTS += bundles/17-SEQUENCE-OF-bundle.txt
TESTS += bundles/19-SET-OF-bundle.txt
TESTS += bundles/20-retagged-strings-bundle.txt

EXTRA_DIST =                    \
    check-corpus.sh             \
    check-corpus-policy.sh      \
    random-test-driver.c        \
    $(srcdir)/bundles/README    \
    $(srcdir)/bundles/*.txt

# Mark the driver recipes recursive so GNU make passes jobserver descriptors
# through the shell/script wrappers. Keep Automake's reporting and environment.
# Both ordinary .txt bundles and dynamically split .test cases use this driver.
run_bundle_test = p='$<'; \
	$(am__set_b); \
	$(am__check_pre) $(TEST_LOG_DRIVER) --test-name "$$f" \
	--log-file $$b.log --trs-file $$b.trs \
	$(am__common_driver_flags) $(AM_TEST_LOG_DRIVER_FLAGS) $(TEST_LOG_DRIVER_FLAGS) -- $(TEST_LOG_COMPILE) \
	"$$tst" $(AM_TESTS_FD_REDIRECT)

%.log: %.txt
	+@$(run_bundle_test)

%.log: %.test
	+@$(run_bundle_test)

# Local-only corpus coverage: one Automake test per ASN.1 case for balanced jobs.
# The recursive invocation inherits -j and explicitly disables timed fuzzing.
.PHONY: check-corpus
check-corpus: test-param-helper
	+$(SHELL) $(srcdir)/check-corpus.sh "$(srcdir)" $(TESTS)

# Cheap policy regressions run even when corpus generation is disabled in CI.
check-local:
	$(SHELL) $(srcdir)/check-corpus-policy.sh "$(abs_srcdir)/check-bundles.sh"

clean-local:
	rm -rf .tmp.*
