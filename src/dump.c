/*
 * dump.c - human-readable frame dumps for bcurl -v.
 */
#include "dump.h"

#include "bhttp.h"

void bh_put_escaped(FILE *out, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] >= 0x20 && p[i] < 0x7f && p[i] != '\\')
            fputc(p[i], out);
        else
            fprintf(out, "\\x%02x", p[i]);
    }
}

void bh_hexdump(FILE *out, char dir, const uint8_t *p, size_t n)
{
    for (size_t off = 0; off < n; off += 16) {
        size_t row = n - off < 16 ? n - off : 16;

        fprintf(out, "%c   %04zx  ", dir, off);
        for (size_t i = 0; i < 16; i++) {
            if (i < row)
                fprintf(out, "%02x ", p[off + i]);
            else
                fputs("   ", out);
            if (i == 7)
                fputc(' ', out);
        }
        fputs(" |", out);
        for (size_t i = 0; i < row; i++) {
            uint8_t c = p[off + i];
            fputc(c >= 0x20 && c < 0x7f ? c : '.', out);
        }
        fputs("|\n", out);
    }
}

static void dump_fields(FILE *out, char dir, const uint8_t *p, size_t n)
{
    struct bh_fields it;
    struct bh_field f;
    const char *err = NULL;

    bh_fields_init(&it, p, n);
    while (bh_fields_next(&it, &f, &err) == 1) {
        fprintf(out, "%c     ", dir);
        bh_put_escaped(out, f.name, f.name_len);
        fputs(": ", out);
        bh_put_escaped(out, f.value, f.value_len);
        if (f.index != 0)
            fprintf(out, "   [index %u]\n", f.index);
        else
            fputs("   [literal]\n", out);
    }
}

/* Prints the decoded part of the summary line; returns the header block, if any. */
static void describe(FILE *out, const struct bh_header *h, const uint8_t *pl,
                     const uint8_t **fields, size_t *fields_len)
{
    const char *err = NULL;

    *fields = NULL;
    *fields_len = 0;
    switch (h->type) {
    case BH_REQUEST: {
        struct bh_request rq;
        if (bh_request_parse(pl, h->length, &rq, &err) != 0) {
            fprintf(out, "malformed (%s)", err);
            return;
        }
        fprintf(out, "%s ", bh_method_name(rq.method));
        bh_put_escaped(out, rq.path, rq.path_len);
        *fields = rq.fields;
        *fields_len = rq.fields_len;
        return;
    }
    case BH_RESPONSE: {
        struct bh_response rs;
        if (bh_response_parse(pl, h->length, &rs, &err) != 0) {
            fprintf(out, "malformed (%s)", err);
            return;
        }
        fprintf(out, "%u %s", rs.status, bh_reason(rs.status));
        *fields = rs.fields;
        *fields_len = rs.fields_len;
        return;
    }
    case BH_DATA:
        fprintf(out, "%u body bytes", h->length);
        return;
    case BH_GOAWAY: {
        struct bh_goaway g;
        bh_goaway_parse(pl, h->length, &g);
        fprintf(out, "last-id=%lu code=0x%02x (%s)", (unsigned long)g.last_id, g.code,
                g.code == BH_NO_ERROR ? "NO_ERROR" : "PROTOCOL_ERROR");
        return;
    }
    default:
        fputs("unknown type, skipped", out);
        return;
    }
}

void bh_dump_frame(FILE *out, char dir, const uint8_t *frame)
{
    struct bh_header h;
    const char *name;
    const uint8_t *fields;
    size_t fields_len;

    bh_header_decode(frame, &h);
    name = bh_type_name(h.type);
    if (name)
        fprintf(out, "%c %s", dir, name);
    else
        fprintf(out, "%c type 0x%02x", dir, h.type);
    fprintf(out, " id=%lu length=%u flags=0x%02x%s: ", (unsigned long)h.id, h.length,
            h.flags, (h.flags & BH_FLAG_END) ? " (END)" : "");
    describe(out, &h, frame + BH_HEADER_LEN, &fields, &fields_len);
    fputc('\n', out);
    if (fields)
        dump_fields(out, dir, fields, fields_len);
    bh_hexdump(out, dir, frame, BH_HEADER_LEN + (size_t)h.length);
}
