/*
 * fuzz_request.c - REQUEST payload (SPEC 5.1) and the path rules. On success
 * the decoded path must really satisfy SPEC 5.1, checked by an independent
 * implementation here.
 */
#include "bhttp.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Independent SPEC 5.1 path check: 0 ok, -1 malformed. */
static int ref_path_ok(const uint8_t *p, size_t n)
{
    size_t q = n;
    if (n < 1)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (p[i] <= 0x1f || p[i] == 0x7f)
            return -1;
        if (p[i] == '?' && q == n)
            q = i;
    }
    if (q == 0 || p[0] != '/')
        return -1;
    for (size_t s = 1; s <= q;) {
        size_t e = s;
        while (e < q && p[e] != '/')
            e++;
        if ((e - s == 1 && p[s] == '.') || (e - s == 2 && p[s] == '.' && p[s + 1] == '.'))
            return -1;
        s = e + 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct bh_request rq;
    const char *err = NULL;
    uint8_t *p;

    if (size > BH_MAX_PAYLOAD)
        return 0;
    p = malloc(size ? size : 1);
    memcpy(p, data, size);

    if (bh_request_parse(p, size, &rq, &err) == 0) {
        if (bh_method_name(rq.method) == NULL || rq.path_len == 0 ||
            rq.path != p + 3 || rq.path + rq.path_len + rq.fields_len != p + size)
            abort();
        if (ref_path_ok(rq.path, rq.path_len) != 0)
            abort();
        if (bh_path_part_len(rq.path, rq.path_len) > rq.path_len)
            abort();
    } else if (err == NULL) {
        abort();
    }
    /* The path checker on its own, against the reference. */
    if ((bh_path_check(p, size, &err) == 0) != (ref_path_ok(p, size) == 0))
        abort();
    free(p);
    return 0;
}
