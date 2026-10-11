
ACLOCAL_AMFLAGS = -I m4

@CODE_COVERAGE_RULES@
CODE_COVERAGE_IGNORE_PATTERN="tests/*" "lex.yy.c" "y.tab.c" "asn1p_l.l" "asn1p_y.y"

SUBDIRS =                       \
    libasn1common libasn1parser \
    libasn1fix libasn1print     \
    libasn1compiler             \
    asn1-tools asn1c skeletons  \
    tests examples doc

docsdir = $(datadir)/doc/asn1c

docs_DATA = README.md INSTALL.md REQUIREMENTS.md FAQ ChangeLog BUGS .github/copilot-instructions.md

EXTRA_DIST = README.md INSTALL.md REQUIREMENTS.md FAQ LICENSE BUGS .github/copilot-instructions.md

# Preserve documentation paths in release archives and installed documentation.
nobase_dist_docs_DATA = docs/binary-codec-support.md \
    docs/rust/README.md docs/rust/architecture.md docs/rust/stage-one-plan.md \
    docs/rust/runtime.md docs/rust/code-generation.md docs/rust/testing.md \
    docs/rust/implementation.md

# Rust output copies this matching runtime into each generated Cargo package.
# Installing these sources requires no Rust compiler for the C compiler build.
nobase_dist_pkgdata_DATA = rust/asn1c-runtime/Cargo.toml \
    rust/asn1c-runtime/README.md rust/asn1c-runtime/LICENSE \
    rust/asn1c-runtime/src/lib.rs
