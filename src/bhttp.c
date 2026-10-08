/*
 * bhttp.c - encode and decode bhttp/1 frames, payloads and header blocks.
 *
 * Invariant used by every parser below: `off <= n` at all times, so `n - off`
 * is the number of unread bytes and never underflows. Each length read from
 * the wire is compared against that before anything is read past it.
 */
#include "bhttp.h"

#include <string.h>

static const char *const static_names[BH_STATIC_COUNT + 1] = {
    NULL,
    "host",            /*  1 */
    "user-agent",      /*  2 */
    "accept",          /*  3 */
    "content-type",    /*  4 */
    "content-length",  /*  5 */
    "last-modified",   /*  6 */
    "date",            /*  7 */
    "server",          /*  8 */
    "location",        /*  9 */
    "allow",           /* 10 */
};

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | (unsigned)p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void bh_header_encode(const struct bh_header *h, uint8_t out[BH_HEADER_LEN])
{
    out[0] = (uint8_t)(h->length >> 8);
    out[1] = (uint8_t)(h->length & 0xffu);
    out[2] = h->type;
    out[3] = h->flags;
    out[4] = (uint8_t)(h->id >> 24);
    out[5] = (uint8_t)((h->id >> 16) & 0xffu);
    out[6] = (uint8_t)((h->id >> 8) & 0xffu);
    out[7] = (uint8_t)(h->id & 0xffu);
}

void bh_header_decode(const uint8_t in[BH_HEADER_LEN], struct bh_header *h)
{
    h->length = get_u16(in);
    h->type = in[2];
    h->flags = in[3];
    h->id = get_u32(in + 4);
}

int bh_type_known(uint8_t type)
{
    return type >= BH_REQUEST && type <= BH_GOAWAY;
}

const char *bh_type_name(uint8_t type)
{
    switch (type) {
    case BH_REQUEST:  return "REQUEST";
    case BH_RESPONSE: return "RESPONSE";
    case BH_DATA:     return "DATA";
    case BH_GOAWAY:   return "GOAWAY";
    default:          return NULL;
    }
}

/* ---- output buffer ---------------------------------------------------- */

void bh_buf_init(struct bh_buf *b, uint8_t *mem, size_t cap)
{
    b->data = mem;
    b->cap = cap;
    b->len = 0;
    b->error = 0;
}

static int reserve(struct bh_buf *b, size_t n)
{
    if (b->error || n > b->cap - b->len) {
        b->error = 1;
        return 0;
    }
    return 1;
}

void bh_put_u8(struct bh_buf *b, uint8_t v)
{
    if (reserve(b, 1))
        b->data[b->len++] = v;
}

void bh_put_u16(struct bh_buf *b, uint16_t v)
{
    if (reserve(b, 2)) {
        b->data[b->len++] = (uint8_t)(v >> 8);
        b->data[b->len++] = (uint8_t)(v & 0xffu);
    }
}

void bh_put_u32(struct bh_buf *b, uint32_t v)
{
    if (reserve(b, 4)) {
        b->data[b->len++] = (uint8_t)(v >> 24);
        b->data[b->len++] = (uint8_t)((v >> 16) & 0xffu);
        b->data[b->len++] = (uint8_t)((v >> 8) & 0xffu);
        b->data[b->len++] = (uint8_t)(v & 0xffu);
    }
}

void bh_put_bytes(struct bh_buf *b, const void *p, size_t n)
{
    if (n > 0 && reserve(b, n)) {
        memcpy(b->data + b->len, p, n);
        b->len += n;
    }
}

/* ---- header block ----------------------------------------------------- */

const char *bh_static_name(unsigned index)
{
    if (index < 1 || index > BH_STATIC_COUNT)
        return NULL;
    return static_names[index];
}

unsigned bh_static_index(const uint8_t *name, size_t len)
{
    for (unsigned i = 1; i <= BH_STATIC_COUNT; i++) {
        const char *s = static_names[i];
        if (strlen(s) == len && memcmp(s, name, len) == 0)
            return i;
    }
    return 0;
}

/* SPEC 5.3: lowercase token characters. */
static int name_byte_ok(uint8_t c)
{
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
        return 1;
    return c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int value_ok(const uint8_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (v[i] == 0x00 || v[i] == 0x0a || v[i] == 0x0d)
            return 0;
    return 1;
}

void bh_put_field(struct bh_buf *b, const char *name, const char *value)
{
    size_t nlen = strlen(name);
    size_t vlen = strlen(value);
    unsigned index = bh_static_index((const uint8_t *)name, nlen);

    if (vlen > 0xffffu || !value_ok((const uint8_t *)value, vlen)) {
        b->error = 1;
        return;
    }
    if (index != 0) {
        bh_put_u8(b, (uint8_t)index);
    } else {
        if (nlen == 0 || nlen > 0xffu) {
            b->error = 1;
            return;
        }
        for (size_t i = 0; i < nlen; i++) {
            if (!name_byte_ok((uint8_t)name[i])) {
                b->error = 1;
                return;
            }
        }
        bh_put_u8(b, 0);
        bh_put_u8(b, (uint8_t)nlen);
        bh_put_bytes(b, name, nlen);
    }
    bh_put_u16(b, (uint16_t)vlen);
    bh_put_bytes(b, value, vlen);
}

void bh_fields_init(struct bh_fields *it, const uint8_t *p, size_t len)
{
    it->p = p;
    it->len = len;
    it->off = 0;
}

int bh_fields_next(struct bh_fields *it, struct bh_field *f, const char **err)
{
    const uint8_t *p = it->p;
    size_t n = it->len;
    size_t off = it->off;
    unsigned index;
    size_t vlen;

    if (off == n)
        return 0;
    index = p[off++];
    if (index > BH_STATIC_COUNT) {
        *err = "header index out of range (11-255)";
        return -1;
    }
    if (index == 0) {
        size_t nlen;
        if (n - off < 1) {
            *err = "header entry truncated before name length";
            return -1;
        }
        nlen = p[off++];
        if (nlen == 0) {
            *err = "empty literal header name";
            return -1;
        }
        if (nlen > n - off) {
            *err = "header name runs past the payload";
            return -1;
        }
        for (size_t i = 0; i < nlen; i++) {
            if (!name_byte_ok(p[off + i])) {
                *err = "invalid byte in header name";
                return -1;
            }
        }
        f->name = p + off;
        f->name_len = nlen;
        off += nlen;
    } else {
        f->name = (const uint8_t *)static_names[index];
        f->name_len = strlen(static_names[index]);
    }
    if (n - off < 2) {
        *err = "header entry truncated before value length";
        return -1;
    }
    vlen = get_u16(p + off);
    off += 2;
    if (vlen > n - off) {
        *err = "header value runs past the payload";
        return -1;
    }
    if (!value_ok(p + off, vlen)) {
        *err = "NUL, CR or LF in header value";
        return -1;
    }
    f->index = index;
    f->value = p + off;
    f->value_len = vlen;
    it->off = off + vlen;
    return 1;
}

int bh_fields_check(const uint8_t *p, size_t len, const char **err)
{
    struct bh_fields it;
    struct bh_field f;
    int r;

    bh_fields_init(&it, p, len);
    while ((r = bh_fields_next(&it, &f, err)) == 1)
        ;
    return r == 0 ? 0 : -1;
}

int bh_fields_find(const uint8_t *p, size_t len, const char *name, struct bh_field *out)
{
    struct bh_fields it;
    const char *err = NULL;
    size_t nlen = strlen(name);

    bh_fields_init(&it, p, len);
    while (bh_fields_next(&it, out, &err) == 1) {
        if (out->name_len == nlen && memcmp(out->name, name, nlen) == 0)
            return 1;
    }
    return 0;
}

int bh_content_length(const uint8_t *fields, size_t len, int *present, uint64_t *value,
                      const char **err)
{
    static const char name[] = "content-length";
    struct bh_fields it;
    struct bh_field f;
    const char *ignored = NULL;

    *present = 0;
    *value = 0;
    bh_fields_init(&it, fields, len);
    while (bh_fields_next(&it, &f, &ignored) == 1) {
        uint64_t v;
        if (f.name_len != sizeof name - 1 || memcmp(f.name, name, sizeof name - 1) != 0)
            continue;
        if (bh_parse_decimal(f.value, f.value_len, &v) != 0) {
            *err = "content-length is not 1-19 ASCII digits";
            return -1;
        }
        if (*present && v != *value) {
            *err = "conflicting content-length values";
            return -1;
        }
        *present = 1;
        *value = v;
    }
    return 0;
}

/* ---- REQUEST ---------------------------------------------------------- */

const char *bh_method_name(uint8_t method)
{
    switch (method) {
    case BH_GET:    return "GET";
    case BH_HEAD:   return "HEAD";
    case BH_POST:   return "POST";
    case BH_PUT:    return "PUT";
    case BH_DELETE: return "DELETE";
    default:        return NULL;
    }
}

size_t bh_path_part_len(const uint8_t *path, size_t len)
{
    const uint8_t *q = memchr(path, '?', len);
    return q ? (size_t)(q - path) : len;
}

int bh_path_check(const uint8_t *path, size_t len, const char **err)
{
    size_t plen;
    size_t start;

    for (size_t i = 0; i < len; i++) {
        if (path[i] < 0x20 || path[i] == 0x7f) {
            *err = "control byte in path";
            return -1;
        }
    }
    plen = bh_path_part_len(path, len);
    if (plen == 0 || path[0] != '/') {
        *err = "path does not start with /";
        return -1;
    }
    /* Segments are the runs between slashes; reject "." and "..". */
    start = 1;
    while (start <= plen) {
        const uint8_t *slash = memchr(path + start, '/', plen - start);
        size_t end = slash ? (size_t)(slash - path) : plen;
        size_t seg = end - start;
        if ((seg == 1 && path[start] == '.') ||
            (seg == 2 && path[start] == '.' && path[start + 1] == '.')) {
            *err = "dot segment in path";
            return -1;
        }
        start = end + 1;
    }
    return 0;
}

int bh_request_parse(const uint8_t *p, size_t n, struct bh_request *rq, const char **err)
{
    size_t plen;

    if (n < 4) {   /* Method, Path Length and at least one path byte */
        *err = "REQUEST payload shorter than 4 bytes";
        return -1;
    }
    rq->method = p[0];
    if (bh_method_name(rq->method) == NULL) {
        *err = "unknown method code";
        return -1;
    }
    plen = get_u16(p + 1);
    if (plen == 0) {
        *err = "empty path";
        return -1;
    }
    if (plen > n - 3) {
        *err = "path runs past the payload";
        return -1;
    }
    rq->path = p + 3;
    rq->path_len = plen;
    if (bh_path_check(rq->path, rq->path_len, err) != 0)
        return -1;
    rq->fields = p + 3 + plen;
    rq->fields_len = n - 3 - plen;
    return bh_fields_check(rq->fields, rq->fields_len, err);
}

/* ---- RESPONSE and GOAWAY ---------------------------------------------- */

int bh_response_parse(const uint8_t *p, size_t n, struct bh_response *rs, const char **err)
{
    if (n < 2) {
        *err = "RESPONSE payload shorter than 2 bytes";
        return -1;
    }
    rs->status = get_u16(p);
    if (rs->status < 200 || rs->status > 599) {
        *err = "status outside 200-599";
        return -1;
    }
    rs->fields = p + 2;
    rs->fields_len = n - 2;
    return bh_fields_check(rs->fields, rs->fields_len, err);
}

void bh_goaway_parse(const uint8_t *p, size_t n, struct bh_goaway *g)
{
    if (n < 5) {
        g->last_id = 0;
        g->code = BH_PROTOCOL_ERROR;
        return;
    }
    g->last_id = get_u32(p);
    g->code = p[4];   /* raw; anything but BH_NO_ERROR means BH_PROTOCOL_ERROR */
}

/* ---- helpers ---------------------------------------------------------- */

const char *bh_reason(unsigned status)
{
    switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "";
    }
}

int bh_parse_decimal(const uint8_t *p, size_t n, uint64_t *out)
{
    uint64_t v = 0;

    if (n == 0 || n > 19)   /* 19 digits always fit in 64 bits */
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9')
            return -1;
        v = v * 10u + (uint64_t)(p[i] - '0');
    }
    *out = v;
    return 0;
}
