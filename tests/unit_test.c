/*
 * unit_test.c - unit tests for the codec in src/bhttp.c.
 *
 * The byte strings here are written out by hand from SPEC.md, so the codec is
 * checked against the spec rather than against itself.
 */
#include "bhttp.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond)                                                           \
    do {                                                                      \
        checks++;                                                             \
        if (!(cond)) {                                                        \
            failures++;                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,  \
                    #cond);                                                   \
        }                                                                     \
    } while (0)

#define BYTES(...) ((const uint8_t[]){ __VA_ARGS__ })
#define LEN(...) sizeof((const uint8_t[]){ __VA_ARGS__ })

static void test_header(void)
{
    struct bh_header h = { 0x1234, BH_DATA, BH_FLAG_END, 0xdeadbeefu };
    struct bh_header back;
    uint8_t out[BH_HEADER_LEN];
    static const uint8_t want[] = { 0x12, 0x34, 0x03, 0x01, 0xde, 0xad, 0xbe, 0xef };

    bh_header_encode(&h, out);
    CHECK(memcmp(out, want, sizeof want) == 0);
    bh_header_decode(want, &back);
    CHECK(back.length == 0x1234 && back.type == BH_DATA && back.flags == BH_FLAG_END &&
          back.id == 0xdeadbeefu);
    CHECK(bh_type_known(0x01) && bh_type_known(0x04));
    CHECK(!bh_type_known(0x00) && !bh_type_known(0x05) && !bh_type_known(0x80));
}

static void test_static_table(void)
{
    static const char *const names[] = {
        "host", "user-agent", "accept", "content-type", "content-length",
        "last-modified", "date", "server", "location", "allow",
    };

    for (unsigned i = 0; i < 10; i++) {
        CHECK(strcmp(bh_static_name(i + 1), names[i]) == 0);
        CHECK(bh_static_index((const uint8_t *)names[i], strlen(names[i])) == i + 1);
    }
    CHECK(bh_static_name(0) == NULL && bh_static_name(11) == NULL);
    CHECK(bh_static_index((const uint8_t *)"Host", 4) == 0);
}

static void test_put_field(void)
{
    uint8_t mem[64];
    struct bh_buf b;

    bh_buf_init(&b, mem, sizeof mem);
    bh_put_field(&b, "host", "localhost:9000");
    bh_put_field(&b, "x-a", "1");
    CHECK(!b.error);
    {
        static const uint8_t want[] = {
            0x01, 0x00, 0x0e, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', ':', '9', '0', '0', '0',
            0x00, 0x03, 'x', '-', 'a', 0x00, 0x01, '1',
        };
        CHECK(b.len == sizeof want && memcmp(mem, want, sizeof want) == 0);
    }

    bh_buf_init(&b, mem, sizeof mem);
    bh_put_field(&b, "Bad-Name", "x");
    CHECK(b.error);
    bh_buf_init(&b, mem, sizeof mem);
    bh_put_field(&b, "x", "a\r\nb");
    CHECK(b.error);
    bh_buf_init(&b, mem, 4);
    bh_put_field(&b, "host", "toolong");
    CHECK(b.error);
}

static int fields_ok(const uint8_t *p, size_t n)
{
    const char *err = NULL;
    return bh_fields_check(p, n, &err) == 0;
}

static void test_fields(void)
{
    struct bh_fields it;
    struct bh_field f;
    const char *err = NULL;
    const uint8_t *block = BYTES(0x04, 0x00, 0x02, 'h', 'i', 0x00, 0x01, 'z', 0x00, 0x00);

    bh_fields_init(&it, block, 10);
    CHECK(bh_fields_next(&it, &f, &err) == 1);
    CHECK(f.index == 4 && f.name_len == 12 && memcmp(f.name, "content-type", 12) == 0);
    CHECK(f.value_len == 2 && memcmp(f.value, "hi", 2) == 0);
    CHECK(bh_fields_next(&it, &f, &err) == 1);
    CHECK(f.index == 0 && f.name_len == 1 && f.name[0] == 'z' && f.value_len == 0);
    CHECK(bh_fields_next(&it, &f, &err) == 0);

    CHECK(fields_ok(NULL, 0));
    CHECK(fields_ok(BYTES(0x0a, 0x00, 0x00), 3));                 /* index 10 */
    CHECK(!fields_ok(BYTES(0x0b, 0x00, 0x00), 3));                /* index 11 */
    CHECK(!fields_ok(BYTES(0xff, 0x00, 0x00), 3));
    CHECK(!fields_ok(BYTES(0x01), 1));                            /* no value length */
    CHECK(!fields_ok(BYTES(0x01, 0x00), 2));
    CHECK(!fields_ok(BYTES(0x01, 0x00, 0x02, 'a'), 4));           /* value past end */
    CHECK(!fields_ok(BYTES(0x00), 1));                            /* no name length */
    CHECK(!fields_ok(BYTES(0x00, 0x00, 0x00, 0x00), 4));          /* empty name */
    CHECK(!fields_ok(BYTES(0x00, 0x05, 'a', 'b'), 4));            /* name past end */
    CHECK(!fields_ok(BYTES(0x00, 0x01, 'A', 0x00, 0x00), 5));     /* uppercase */
    CHECK(!fields_ok(BYTES(0x00, 0x01, ' ', 0x00, 0x00), 5));
    CHECK(!fields_ok(BYTES(0x00, 0x01, ':', 0x00, 0x00), 5));
    CHECK(fields_ok(BYTES(0x00, 0x01, '`', 0x00, 0x00), 5));      /* backtick is a token char */
    CHECK(!fields_ok(BYTES(0x01, 0x00, 0x01, 0x00), 4));          /* NUL in value */
    CHECK(!fields_ok(BYTES(0x01, 0x00, 0x01, '\r'), 4));
    CHECK(!fields_ok(BYTES(0x01, 0x00, 0x01, '\n'), 4));
    CHECK(fields_ok(BYTES(0x01, 0x00, 0x01, 0xff), 4));           /* other bytes are fine */
}

static int request_ok(const uint8_t *p, size_t n, struct bh_request *rq)
{
    const char *err = NULL;
    return bh_request_parse(p, n, rq, &err) == 0;
}

static int path_ok(const char *path)
{
    const char *err = NULL;
    return bh_path_check((const uint8_t *)path, strlen(path), &err) == 0;
}

static void test_request(void)
{
    struct bh_request rq;
    /* SPEC 10: GET / with no headers */
    const uint8_t *min = BYTES(0x01, 0x00, 0x01, '/');

    CHECK(request_ok(min, 4, &rq));
    CHECK(rq.method == BH_GET && rq.path_len == 1 && rq.path[0] == '/' && rq.fields_len == 0);
    CHECK(request_ok(BYTES(0x02, 0x00, 0x01, '/', 0x03, 0x00, 0x03, '*', '/', '*'), 10, &rq));
    CHECK(rq.method == BH_HEAD && rq.fields_len == 6);

    CHECK(!request_ok(min, 0, &rq));
    CHECK(!request_ok(min, 2, &rq));
    CHECK(!request_ok(BYTES(0x00, 0x00, 0x01, '/'), 4, &rq));     /* method 0 */
    CHECK(!request_ok(BYTES(0x06, 0x00, 0x01, '/'), 4, &rq));     /* method 6 */
    CHECK(request_ok(BYTES(0x05, 0x00, 0x01, '/'), 4, &rq));      /* DELETE parses */
    CHECK(!request_ok(BYTES(0x01, 0x00, 0x00), 3, &rq));          /* empty path */
    CHECK(!request_ok(BYTES(0x01, 0x00, 0x02, '/'), 4, &rq));     /* path past end */
    CHECK(!request_ok(BYTES(0x01, 0xff, 0xff, '/'), 4, &rq));
    CHECK(!request_ok(BYTES(0x01, 0x00, 0x01, '/', 0x0b), 5, &rq)); /* bad header */

    CHECK(path_ok("/"));
    CHECK(path_ok("/index.html"));
    CHECK(path_ok("/a/b/"));
    CHECK(path_ok("//a"));
    CHECK(path_ok("/a..b/...x/.hidden"));
    CHECK(path_ok("/%2e%2e/x"));
    CHECK(path_ok("/a?x=/../y"));                 /* dot segments only count before '?' */
    CHECK(!path_ok(""));
    CHECK(!path_ok("a"));
    CHECK(!path_ok("?x"));
    CHECK(!path_ok("/.."));
    CHECK(!path_ok("/../etc/passwd"));
    CHECK(!path_ok("/a/../b"));
    CHECK(!path_ok("/a/./b"));
    CHECK(!path_ok("/."));
    CHECK(!path_ok("/a/.."));
    CHECK(!path_ok("/a/..?q"));
    CHECK(!path_ok("/a\tb"));
    CHECK(!path_ok("/a\x7f"));
    CHECK(!path_ok("/a?\x01"));                   /* control bytes are banned everywhere */
    {
        const char *err = NULL;
        CHECK(bh_path_check(BYTES('/', 'a', 0x00, 'b'), 4, &err) != 0);
    }
    CHECK(bh_path_part_len((const uint8_t *)"/a?b?c", 6) == 2);
    CHECK(bh_path_part_len((const uint8_t *)"/abc", 4) == 4);
}

static void test_response_goaway(void)
{
    struct bh_response rs;
    struct bh_goaway g;
    const char *err = NULL;

    CHECK(bh_response_parse(BYTES(0x01, 0x94), 2, &rs, &err) == 0 && rs.status == 404);
    CHECK(bh_response_parse(BYTES(0x00, 0xc8, 0x05, 0x00, 0x01, '0'), 6, &rs, &err) == 0);
    CHECK(rs.status == 200 && rs.fields_len == 4);
    CHECK(bh_response_parse(BYTES(0x00, 0xc7), 2, &rs, &err) != 0);   /* 199 */
    CHECK(bh_response_parse(BYTES(0x02, 0x58), 2, &rs, &err) != 0);   /* 600 */
    CHECK(bh_response_parse(BYTES(0x00), 1, &rs, &err) != 0);
    CHECK(bh_response_parse(BYTES(0x00, 0xc8, 0x0c), 3, &rs, &err) != 0);

    bh_goaway_parse(BYTES(0x00, 0x00, 0x00, 0x07, 0x00), 5, &g);
    CHECK(g.last_id == 7 && g.code == BH_NO_ERROR);
    bh_goaway_parse(BYTES(0x00, 0x00, 0x01, 0x00, 0x01, 0xaa, 0xbb), 7, &g);
    CHECK(g.last_id == 256 && g.code == BH_PROTOCOL_ERROR);
    bh_goaway_parse(BYTES(0x00, 0x00), 2, &g);
    CHECK(g.last_id == 0 && g.code == BH_PROTOCOL_ERROR);
}

static void test_buf_and_decimal(void)
{
    uint8_t mem[3];
    struct bh_buf b;
    uint64_t v = 0;

    bh_buf_init(&b, mem, sizeof mem);
    bh_put_u16(&b, 0x0102);
    CHECK(!b.error && b.len == 2 && mem[0] == 1 && mem[1] == 2);
    bh_put_u16(&b, 0x0304);
    CHECK(b.error && b.len == 2);
    bh_put_u8(&b, 9);   /* sticky: nothing more is written */
    CHECK(b.len == 2);

    CHECK(bh_parse_decimal((const uint8_t *)"0", 1, &v) == 0 && v == 0);
    CHECK(bh_parse_decimal((const uint8_t *)"16384", 5, &v) == 0 && v == 16384);
    CHECK(bh_parse_decimal((const uint8_t *)"9999999999999999999", 19, &v) == 0);
    CHECK(bh_parse_decimal((const uint8_t *)"12345678901234567890", 20, &v) != 0);
    CHECK(bh_parse_decimal((const uint8_t *)"", 0, &v) != 0);
    CHECK(bh_parse_decimal((const uint8_t *)"-1", 2, &v) != 0);
    CHECK(bh_parse_decimal((const uint8_t *)"1 ", 2, &v) != 0);
}

int main(void)
{
    test_header();
    test_static_table();
    test_put_field();
    test_fields();
    test_request();
    test_response_goaway();
    test_buf_and_decimal();
    printf("unit tests: %d checks, %d failed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
