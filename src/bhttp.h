/*
 * bhttp.h - the bhttp/1 wire format (see SPEC.md).
 *
 * Pure encode/decode: nothing in here touches a socket. Every parser takes a
 * pointer and a length, checks each length before it is used, and never reads
 * outside [p, p + n).
 */
#ifndef BHTTP_H
#define BHTTP_H

#include <stddef.h>
#include <stdint.h>

/* SPEC 3: the fixed frame header. */
#define BH_HEADER_LEN  8u
#define BH_MAX_PAYLOAD 16384u
#define BH_FRAME_MAX   (BH_HEADER_LEN + BH_MAX_PAYLOAD)

/* SPEC 4: frame types. Every other value is unknown and is skipped. */
#define BH_REQUEST  0x01u
#define BH_RESPONSE 0x02u
#define BH_DATA     0x03u
#define BH_GOAWAY   0x04u

#define BH_FLAG_END 0x01u

/* SPEC 4: GOAWAY codes. */
#define BH_NO_ERROR       0x00u
#define BH_PROTOCOL_ERROR 0x01u

/* SPEC 5.1: method codes. */
enum bh_method {
    BH_GET = 0x01,
    BH_HEAD = 0x02,
    BH_POST = 0x03,
    BH_PUT = 0x04,
    BH_DELETE = 0x05
};

/* SPEC 5.3: the static header table has exactly ten entries, 1..10. */
#define BH_STATIC_COUNT 10u

struct bh_header {
    uint16_t length;   /* payload bytes after the header */
    uint8_t type;
    uint8_t flags;
    uint32_t id;       /* request ID; 0 = the connection */
};

void bh_header_encode(const struct bh_header *h, uint8_t out[BH_HEADER_LEN]);
void bh_header_decode(const uint8_t in[BH_HEADER_LEN], struct bh_header *h);
int bh_type_known(uint8_t type);
const char *bh_type_name(uint8_t type);   /* "REQUEST", ..., or NULL */

/*
 * A bounded output buffer. Writes that do not fit, and values that the wire
 * format cannot carry, set `error` and are dropped; check it once at the end.
 */
struct bh_buf {
    uint8_t *data;
    size_t cap;
    size_t len;
    int error;
};

void bh_buf_init(struct bh_buf *b, uint8_t *mem, size_t cap);
void bh_put_u8(struct bh_buf *b, uint8_t v);
void bh_put_u16(struct bh_buf *b, uint16_t v);
void bh_put_u32(struct bh_buf *b, uint32_t v);
void bh_put_bytes(struct bh_buf *b, const void *p, size_t n);

/* Header block (SPEC 5.3). */
const char *bh_static_name(unsigned index);                  /* NULL unless 1..10 */
unsigned bh_static_index(const uint8_t *name, size_t len);   /* 0 if not in table */

/* Appends one entry: indexed if the name is in the table, literal otherwise. */
void bh_put_field(struct bh_buf *b, const char *name, const char *value);

struct bh_field {
    unsigned index;            /* 1..10, or 0 for a literal name */
    const uint8_t *name;
    size_t name_len;
    const uint8_t *value;
    size_t value_len;
};

struct bh_fields {
    const uint8_t *p;
    size_t len;
    size_t off;
};

void bh_fields_init(struct bh_fields *it, const uint8_t *p, size_t len);
/* 1 = *f filled, 0 = end of block, -1 = malformed (*err says why). */
int bh_fields_next(struct bh_fields *it, struct bh_field *f, const char **err);
/* 0 if the whole block is well formed, -1 otherwise. */
int bh_fields_check(const uint8_t *p, size_t len, const char **err);
/* First field called `name` in a block that passed bh_fields_check. */
int bh_fields_find(const uint8_t *p, size_t len, const char *name, struct bh_field *out);

/* REQUEST payload (SPEC 5.1). */
struct bh_request {
    uint8_t method;
    const uint8_t *path;
    size_t path_len;
    const uint8_t *fields;
    size_t fields_len;
};

const char *bh_method_name(uint8_t method);   /* NULL if not a v1 method */
int bh_request_parse(const uint8_t *p, size_t n, struct bh_request *rq, const char **err);
int bh_path_check(const uint8_t *path, size_t len, const char **err);
size_t bh_path_part_len(const uint8_t *path, size_t len);   /* bytes before '?' */

/* RESPONSE payload (SPEC 5.2). */
struct bh_response {
    uint16_t status;
    const uint8_t *fields;
    size_t fields_len;
};

int bh_response_parse(const uint8_t *p, size_t n, struct bh_response *rs, const char **err);

/*
 * GOAWAY payload (SPEC 4): never fails; a short payload reads as Last-ID 0,
 * Code 0x01. `code` is the raw byte: treat any value but BH_NO_ERROR as
 * BH_PROTOCOL_ERROR.
 */
struct bh_goaway {
    uint32_t last_id;
    uint8_t code;
};

void bh_goaway_parse(const uint8_t *p, size_t n, struct bh_goaway *g);

/*
 * SPEC 6: content-length in a well-formed header block. Every copy must be
 * 1..19 ASCII digits and all copies equal. Returns 0 with *present (0 or 1)
 * and *value set, or -1 with *err.
 */
int bh_content_length(const uint8_t *fields, size_t len, int *present, uint64_t *value,
                      const char **err);

/* Helpers. */
const char *bh_reason(unsigned status);
/* Parses 1..19 ASCII digits; 0 on success, -1 otherwise. */
int bh_parse_decimal(const uint8_t *p, size_t n, uint64_t *out);

#endif
