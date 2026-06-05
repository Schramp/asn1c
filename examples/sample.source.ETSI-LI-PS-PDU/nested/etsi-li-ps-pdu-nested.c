/*
 * etsi-li-ps-pdu-nested.c
 *
 * Two-level ETSI LI PS-PDU decoder.
 *
 * Reads a stream of BER-encoded PS-PDU records from a file.
 * For each PDU whose payload is an EncryptionContainer, the
 * encryptedPayload OCTET STRING is itself a BER-encoded
 * EncryptedPayload wrapped in a zero-padded block (block alignment
 * survives even when encryptionType is "none").
 *
 * bridge_decode_payload() strips the trailing zero padding and
 * BER-decodes the inner EncryptedPayload as a second, independent
 * ASN.1 decode step.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "PS-PDU.h"
#include "PSHeader.h"
#include "Payload.h"
#include "EncryptionContainer.h"
#include "EncryptedPayload.h"
#include "ber_decoder.h"
#include "xer_encoder.h"

/*
 * Bridge between the two ASN.1 decode steps.
 *
 * The OCTET STRING stored in EncryptionContainer.encryptedPayload is
 * block-aligned to a multiple of the cipher block size (typically 16 or
 * 8 bytes).  When encryptionType is "none" the ciphertext is absent and
 * the block is simply zero-padded to the next block boundary.  The BER
 * content of the inner EncryptedPayload always ends before the first
 * trailing zero run, so we strip those bytes before decoding.
 */
static EncryptedPayload_t *
bridge_decode_payload(const OCTET_STRING_t *blob)
{
    size_t len = blob->size;

    /* Strip trailing zero-padding bytes */
    while (len > 0 && blob->buf[len - 1] == 0)
        len--;

    if (len == 0) {
        fprintf(stderr, "  bridge: empty after zero-stripping\n");
        return NULL;
    }

    EncryptedPayload_t *ep = NULL;
    asn_dec_rval_t rv = ber_decode(NULL, &asn_DEF_EncryptedPayload,
                                   (void **)&ep, blob->buf, len);
    if (rv.code != RC_OK) {
        fprintf(stderr, "  bridge: BER decode failed (code=%d, consumed=%zu of %zu)\n",
                (int)rv.code, rv.consumed, len);
        ASN_STRUCT_FREE(asn_DEF_EncryptedPayload, ep);
        return NULL;
    }

    return ep;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.etsi>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc((size_t)fsize);
    if (!buf) { perror("malloc"); fclose(f); return 1; }

    if ((long)fread(buf, 1, (size_t)fsize, f) != fsize) {
        perror("fread"); free(buf); fclose(f); return 1;
    }
    fclose(f);

    size_t offset = 0;
    int pdu_num = 0;
    int inner_decoded = 0;

    while (offset < (size_t)fsize) {
        PS_PDU_t *pdu = NULL;
        asn_dec_rval_t rv = ber_decode(NULL, &asn_DEF_PS_PDU,
                                       (void **)&pdu, buf + offset,
                                       (size_t)fsize - offset);
        if (rv.code != RC_OK) {
            fprintf(stderr, "Outer BER decode failed at offset %zu (PDU #%d)\n",
                    offset, pdu_num + 1);
            ASN_STRUCT_FREE(asn_DEF_PS_PDU, pdu);
            break;
        }
        offset += rv.consumed;
        pdu_num++;

        printf("=== PS-PDU #%d ===\n", pdu_num);
        xer_fprint(stdout, &asn_DEF_PS_PDU, pdu);

        if (pdu->payload &&
            pdu->payload->present == Payload_PR_encryptionContainer &&
            pdu->payload->choice.encryptionContainer) {

            EncryptionContainer_t *ec = pdu->payload->choice.encryptionContainer;
            size_t raw = ec->encryptedPayload.size;
            size_t stripped = raw;
            while (stripped > 0 && ec->encryptedPayload.buf[stripped - 1] == 0)
                stripped--;

            printf("--- EncryptedPayload (%zu bytes, %zu zero-padded) ---\n",
                   stripped, raw - stripped);

            EncryptedPayload_t *ep = bridge_decode_payload(&ec->encryptedPayload);
            if (ep) {
                xer_fprint(stdout, &asn_DEF_EncryptedPayload, ep);
                ASN_STRUCT_FREE(asn_DEF_EncryptedPayload, ep);
                inner_decoded++;
            }
        }

        ASN_STRUCT_FREE(asn_DEF_PS_PDU, pdu);
    }

    free(buf);
    fprintf(stderr, "Decoded %d outer PS-PDUs, %d with inner EncryptedPayload\n",
            pdu_num, inner_decoded);
    return 0;
}
