/*
 * fuzz_fields.c - the header block decoder (SPEC 5.3) and content-length
 * (SPEC 6). Differential checks: bh_fields_check agrees with iterating
 * bh_fields_next; a well-formed block re-encoded with bh_put_field decodes to
 * the same (name, value) list; bh_parse_decimal agrees with a reference.
 */
#include "bhttp.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAXF 4096

struct nv {
    const uint8_t *n;
    size_t nl;
    const uint8_t *v;
    size_t vl;
};

static int ref_decimal(const uint8_t *p, size_t n, uint64_t *out)
{
    uint64_t v = 0;
    if (n < 1 || n > 19)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9')
            return -1;
        if (v > (UINT64_MAX - 9) / 10)
            abort();   /* 19 digits must never overflow */
        v = v * 10 + (uint64_t)(p[i] - '0');
    }
    *out = v;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static struct nv got[MAXF];
    static uint8_t out[BH_MAX_PAYLOAD * 4];
    struct bh_fields it;
    struct bh_field f;
    const char *err = NULL;
    int r;
    size_t count = 0;
    uint8_t *p;

    if (size > BH_MAX_PAYLOAD)
        return 0;
    p = malloc(size ? size : 1);
    memcpy(p, data, size);

    {
        uint64_t a = 0, b = 0;
        size_t n = size < 24 ? size : 24;
        int ra = bh_parse_decimal(p, n, &a);
        int rb = ref_decimal(p, n, &b);
        if (ra != rb || (ra == 0 && a != b))
            abort();
    }

    bh_fields_init(&it, p, size);
    while ((r = bh_fields_next(&it, &f, &err)) == 1) {
        if (f.value < p || f.value + f.value_len > p + size)
            abort();
        if (f.index == 0 && (f.name < p || f.name + f.name_len > p + size || f.name_len == 0))
            abort();
        if (f.index > BH_STATIC_COUNT)
            abort();
        for (size_t i = 0; i < f.value_len; i++)
            if (f.value[i] == 0 || f.value[i] == '\n' || f.value[i] == '\r')
                abort();
        if (count < MAXF)
            got[count++] = (struct nv){ f.name, f.name_len, f.value, f.value_len };
    }
    if ((r == 0) != (bh_fields_check(p, size, &err) == 0))
        abort();

    {
        int present = 0;
        uint64_t v = 0;
        (void)bh_content_length(p, size, &present, &v, &err);
    }

    if (r == 0 && count < MAXF) {
        /* Re-encode through bh_put_field and decode again. */
        struct bh_buf b;
        size_t k = 0;
        bh_buf_init(&b, out, sizeof out);
        for (size_t i = 0; i < count; i++) {
            char name[256];
            char *value = malloc(got[i].vl + 1);
            memcpy(name, got[i].n, got[i].nl);
            name[got[i].nl] = '\0';
            memcpy(value, got[i].v, got[i].vl);
            value[got[i].vl] = '\0';
            bh_put_field(&b, name, value);
            free(value);
        }
        if (b.error)
            abort();
        bh_fields_init(&it, out, b.len);
        while ((r = bh_fields_next(&it, &f, &err)) == 1) {
            if (k >= count || f.name_len != got[k].nl || f.value_len != got[k].vl ||
                memcmp(f.name, got[k].n, f.name_len) != 0 ||
                (f.value_len && memcmp(f.value, got[k].v, f.value_len) != 0))
                abort();
            k++;
        }
        if (r != 0 || k != count)
            abort();
    }
    free(p);
    return 0;
}
