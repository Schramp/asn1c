/*
 * Purpose: Keep the generated CHOICE descriptor linkable when its branches
 *          contain same-named, constrained native INTEGER members.
 * Original source: Regression coverage for GitHub issue #590.
 * Version: 2026-10-25.
 * Parameters: None.
 * Returns: Zero when the generated top-level descriptor is available;
 *          nonzero otherwise.
 * Exceptions: None.
 * Responsible party: asn1c maintainers.
 * History: Added for the issue #590 nested descriptor regression.
 * Example: Generated and executed by ./run.sh in this directory.
 */
#include "MyChoice.h"

int
main(void) {
    /* Referencing the module descriptor forces its object and nested
     * descriptor references to resolve during linking. */
    return asn_DEF_MyChoice.name == 0;
}
