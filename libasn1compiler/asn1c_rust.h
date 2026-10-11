#ifndef ASN1C_RUST_H
#define ASN1C_RUST_H

#include <asn1parser.h>
#include <stdint.h>

/*
 * Generate the initial safe Rust project from a fixed ASN.1 tree.
 *
 * Parameters:
 *   asn         Fixed parser tree.
 *   runtime_dir Directory containing the asn1c-runtime source crate.
 *   destdir     Destination project directory, or NULL for "asn1c-rust".
 *   codecs      Selected codec bit mask; only A1C_GEN_UPER is supported.
 * Returns zero on success, -1 on validation or output failure.
 * Errors are printed with ASN.1 module, type, and line where applicable.
 * Original source: new asn1c Rust backend. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: initial BOOLEAN, NULL, and
 * bounded INTEGER UPER implementation. Example: called through
 * asn1_compile_with_target() for a Rust compilation request.
 */
int asn1c_rust_compile(asn1p_t *asn, const char *runtime_dir,
                       const char *destdir, uint64_t codecs);

#endif /* ASN1C_RUST_H */
