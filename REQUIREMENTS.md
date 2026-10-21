
## To compile asn1c compiler itself

A 64-bit build system is strongly recommended for asn1c operation.

A working C99 compiler is required to compile asn1c itself,
such as gcc-4.x or clang-3.4. The default C backend produces C90-compatible
code, which is also upward compatible with C++. The optional `--rust` backend
generates Rust source and Cargo metadata.

### Packages

This notation specifies a minimum required package version (-ver)
or an exact version (=ver). For example, bison=2.x requires the 2.x branch
of bison, not 3.x.

 * automake-1.15
 * libtool
 * bison=2.x
 * flex

The compiler itself is written in C and does not require Rust or Cargo. Rust
is needed to build packages generated with `asn1c --rust` and to run the
optional Rust checks. Generated packages use the Rust 2021 edition, `std`, and
a copied runtime with no third-party dependencies. No minimum Rust compiler
version is currently claimed.

## To compile asn1c-generated code

C:
As a minimum, a compiler supporting the C90. Pretty much any modern C compiler
will do, but gcc or clang is recommended. Note that MSVC++ is not a C compiler.

C++:
A C++11 compliant compiler is recommended.

Rust:
Install Cargo and a Rust toolchain that supports the Rust 2021 edition to
build generated Rust packages. The compiler emits Rust source and Cargo
metadata; it does not invoke Cargo while generating output.

