/*
 * fuzz_frame.c - one frame: header decode/encode round trip, then the payload
 * decoder for its type, then the bcurl -v dumper on the same bytes.
 */
#include "bhttp.h"
#include "dump.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *sink;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    sink = fopen("/dev/null", "w");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t frame[BH_FRAME_MAX];
    uint8_t again[BH_HEADER_LEN];
    struct bh_header h;
    const char *err = NULL;
    size_t avail;

    if (size < BH_HEADER_LEN)
        return 0;
    bh_header_decode(data, &h);
    bh_header_encode(&h, again);
    if (memcmp(data, again, BH_HEADER_LEN) != 0)
        abort();   /* decode/encode must round-trip */
    if (h.length > BH_MAX_PAYLOAD)
        return 0;  /* netio rejects these before the payload is read */
    avail = size - BH_HEADER_LEN;
    if (avail > h.length)
        avail = h.length;
    h.length = (uint16_t)avail;   /* the frame as the reader would have it */
    bh_header_encode(&h, frame);
    /* Exact-size heap copy so ASan sees any read past the payload. */
    {
        uint8_t *pl = malloc(avail ? avail : 1);
        memcpy(pl, data + BH_HEADER_LEN, avail);
        switch (h.type) {
        case BH_REQUEST: {
            struct bh_request rq;
            if (bh_request_parse(pl, avail, &rq, &err) == 0) {
                int present;
                uint64_t v;
                (void)bh_content_length(rq.fields, rq.fields_len, &present, &v, &err);
            } else if (err == NULL) {
                abort();   /* every failure must say why */
            }
            break;
        }
        case BH_RESPONSE: {
            struct bh_response rs;
            if (bh_response_parse(pl, avail, &rs, &err) == 0) {
                int present;
                uint64_t v;
                if (rs.status < 200 || rs.status > 599)
                    abort();
                (void)bh_content_length(rs.fields, rs.fields_len, &present, &v, &err);
            } else if (err == NULL) {
                abort();
            }
            break;
        }
        case BH_GOAWAY: {
            struct bh_goaway g;
            bh_goaway_parse(pl, avail, &g);
            if (avail < 5 && (g.last_id != 0 || g.code != BH_PROTOCOL_ERROR))
                abort();
            break;
        }
        default:
            break;
        }
        memcpy(frame + BH_HEADER_LEN, pl, avail);
        free(pl);
    }
    bh_dump_frame(sink, '<', frame);
    (void)bh_type_name(h.type);
    return 0;
}
