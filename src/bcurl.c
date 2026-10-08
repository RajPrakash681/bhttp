/*
 * bcurl - fetch URLs over bhttp/1.
 *
 *     bcurl [-v] URL [URL...]
 *
 * URL is [bhttp://]host[:port][/path] (port 9000 if omitted). All URLs must
 * name the same host and port: they are fetched in order over ONE TCP
 * connection, which is never reopened. Bodies go to stdout. -v dumps every
 * frame sent (>) and received (<) to stderr.
 *
 * Exit status: 0 if every response was 2xx/3xx, 4 if the worst was 4xx,
 * 5 if the worst was 5xx, 2 on a connection or protocol error (the
 * remaining URLs are then not fetched), 1 on a usage error.
 */
#include "bhttp.h"
#include "dump.h"
#include "netio.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define CLIENT_NAME "bcurl/1.0"
#define DEFAULT_PORT "9000"
#define TIMEOUT_MS 30000

enum {
    EXIT_OK = 0,
    EXIT_USAGE = 1,
    EXIT_PROTOCOL = 2,
    EXIT_4XX = 4,
    EXIT_5XX = 5
};

struct url {
    const char *text;          /* as given, for messages */
    char host[256];            /* for getaddrinfo: no brackets */
    char port[6];
    char authority[272];       /* host header: as written, plus :port */
    const char *path;          /* points into text, or "/" */
    size_t path_len;
    size_t slash;              /* 1: send a '/' before path ("host?q") */
};

struct client {
    int fd;
    int verbose;
    uint8_t tx[BH_FRAME_MAX];
    uint8_t rx[BH_FRAME_MAX];
};

/* ---- URLs ------------------------------------------------------------- */

static int host_byte_ok(unsigned char c)
{
    return c > 0x20 && c < 0x7f && c != '/' && c != '?' && c != '#' && c != '@';
}

/* The host[:port] part ends at the end of the URL or at one of "/?#". */
static int ends_authority(char c)
{
    return c == '\0' || c == '/' || c == '?' || c == '#';
}

static int parse_url(const char *text, struct url *u, const char **err)
{
    const char *p = text;
    const char *scheme = strstr(text, "://");
    const char *slash = strchr(text, '/');
    const char *host;
    size_t hlen;
    int bracketed = 0;

    memset(u, 0, sizeof *u);
    u->text = text;
    if (strncasecmp(p, "bhttp://", 8) == 0) {
        p += 8;
    } else if (scheme && (!slash || scheme < slash)) {
        *err = "only bhttp:// URLs are supported";
        return -1;
    }

    if (*p == '[') {                          /* [IPv6 literal] */
        const char *close = strchr(p, ']');
        if (!close) {
            *err = "unterminated [ in host";
            return -1;
        }
        bracketed = 1;
        host = p + 1;
        hlen = (size_t)(close - host);
        p = close + 1;
    } else {
        host = p;
        while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#')
            p++;
        hlen = (size_t)(p - host);
    }
    if (hlen == 0 || hlen >= sizeof u->host) {
        *err = "missing or overlong host";
        return -1;
    }
    for (size_t i = 0; i < hlen; i++) {
        if (!host_byte_ok((unsigned char)host[i])) {
            *err = "invalid character in host";
            return -1;
        }
    }
    memcpy(u->host, host, hlen);
    u->host[hlen] = '\0';

    if (*p == ':') {
        const char *digits = ++p;
        unsigned long v = 0;
        while (*p >= '0' && *p <= '9' && p - digits < 5)
            v = v * 10u + (unsigned long)(*p++ - '0');
        if (p == digits || v == 0 || v > 65535 || !ends_authority(*p)) {
            *err = "invalid port";
            return -1;
        }
        snprintf(u->port, sizeof u->port, "%lu", v);
    } else if (!ends_authority(*p)) {
        *err = "unexpected character after host";
        return -1;
    } else {
        memcpy(u->port, DEFAULT_PORT, sizeof DEFAULT_PORT);
    }

    /* host header: the host as written (with brackets for IPv6), then :port */
    snprintf(u->authority, sizeof u->authority, bracketed ? "[%s]:%s" : "%s:%s", u->host,
             u->port);

    /*
     * SPEC 11: the path runs to the end, minus any #fragment, which is never
     * sent. An empty path is "/", and "?q" is sent as "/?q".
     */
    u->path = p;
    u->path_len = strcspn(p, "#");
    if (u->path_len == 0) {
        u->path = "/";
        u->path_len = 1;
    } else if (*p == '?') {
        u->slash = 1;
    }
    if (u->slash + u->path_len > 0xffffu) {
        *err = "path too long";
        return -1;
    }
    return 0;
}

static int same_origin(const struct url *a, const struct url *b)
{
    return strcasecmp(a->host, b->host) == 0 && strcmp(a->port, b->port) == 0;
}

/* ---- connection ------------------------------------------------------- */

static void describe_peer(int fd, char *out, size_t cap)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;
    char addr[INET6_ADDRSTRLEN] = "?";
    unsigned port = 0;

    if (getpeername(fd, (struct sockaddr *)&ss, &len) == 0) {
        if (ss.ss_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)&ss;
            inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof addr);
            port = ntohs(sin->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)(const void *)&ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof addr);
            port = ntohs(sin6->sin6_port);
        }
    }
    snprintf(out, cap, "%s port %u", addr, port);
}

/*
 * Opens the one connection. A name may resolve to several addresses (say ::1
 * and 127.0.0.1); they are tried in order until one accepts. Refused
 * attempts are not connections: exactly one TCP connection is established.
 */
static int dial(const struct url *u)
{
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *ai;
    int fd = -1;
    int saved = 0;
    int one = 1;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(u->host, u->port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "bcurl: %s: %s\n", u->host, gai_strerror(rc));
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            saved = errno;
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        saved = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "bcurl: cannot connect to %s port %s: %s\n", u->host, u->port,
                strerror(saved));
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

/* ---- one request ------------------------------------------------------ */

static int send_request(struct client *c, const struct url *u, uint32_t id)
{
    struct bh_buf b;
    struct bh_header h;

    bh_buf_init(&b, c->tx + BH_HEADER_LEN, BH_MAX_PAYLOAD);
    bh_put_u8(&b, BH_GET);
    bh_put_u16(&b, (uint16_t)(u->slash + u->path_len));   /* parse_url checked the sum */
    bh_put_bytes(&b, "/", u->slash);
    bh_put_bytes(&b, u->path, u->path_len);
    bh_put_field(&b, "host", u->authority);
    bh_put_field(&b, "user-agent", CLIENT_NAME);
    bh_put_field(&b, "accept", "*/*");
    if (b.error) {
        fprintf(stderr, "bcurl: %s: request does not fit in one frame\n", u->text);
        return -1;
    }
    h.length = (uint16_t)b.len;
    h.type = BH_REQUEST;
    h.flags = BH_FLAG_END;
    h.id = id;
    bh_header_encode(&h, c->tx);
    if (c->verbose)
        bh_dump_frame(stderr, '>', c->tx);
    if (bh_send_frame(c->fd, c->tx, &h) != BH_IO_OK) {
        fprintf(stderr, "bcurl: %s: send failed: %s\n", u->text, strerror(errno));
        return -1;
    }
    return 0;
}

static const char *read_failure(int r)
{
    switch (r) {
    case BH_IO_EOF:
    case BH_IO_TRUNC:   return "connection closed before the response was complete";
    case BH_IO_TIMEOUT: return "timed out waiting for the server";
    case BH_IO_TOOBIG:  return "frame longer than 16384 bytes";
    default:            return "read failed";
    }
}

/* Progress of one response. */
struct reply {
    int have_response;
    unsigned status;
    int have_length;
    uint64_t content_length;
    uint64_t body;
};

static int protocol_error(const struct url *u, const char *what)
{
    fprintf(stderr, "bcurl: %s: protocol error: %s\n", u->text, what);
    return -1;
}

static int on_response(const struct client *c, const struct url *u, uint32_t id,
                       const struct bh_header *h, struct reply *r)
{
    struct bh_response rs;
    const char *err = NULL;

    if (r->have_response)
        return protocol_error(u, "second RESPONSE for one request");
    if (h->id == 0)
        return protocol_error(u, "server reported a connection error (RESPONSE with ID 0)");
    if (h->id != id)
        return protocol_error(u, "RESPONSE for another request ID");
    if (bh_response_parse(c->rx + BH_HEADER_LEN, h->length, &rs, &err) != 0)
        return protocol_error(u, err);
    if (bh_content_length(rs.fields, rs.fields_len, &r->have_length, &r->content_length,
                          &err) != 0)
        return protocol_error(u, err);
    r->have_response = 1;
    r->status = rs.status;
    return (h->flags & BH_FLAG_END) ? 1 : 0;
}

static int on_data(const struct client *c, const struct url *u, uint32_t id,
                   const struct bh_header *h, struct reply *r)
{
    if (!r->have_response)
        return protocol_error(u, "DATA before RESPONSE");
    if (h->id != id)
        return protocol_error(u, "DATA for another request ID");
    if (h->length > 0 &&
        io_write_full(STDOUT_FILENO, c->rx + BH_HEADER_LEN, h->length) != BH_IO_OK) {
        fprintf(stderr, "bcurl: writing to stdout: %s\n", strerror(errno));
        return -1;
    }
    r->body += h->length;
    return (h->flags & BH_FLAG_END) ? 1 : 0;
}

/* Returns 1 when the response is complete, 0 for more, -1 on an error. */
static int on_frame(const struct client *c, const struct url *u, uint32_t id,
                    const struct bh_header *h, struct reply *r)
{
    struct bh_goaway g;

    switch (h->type) {
    case BH_RESPONSE:
        return on_response(c, u, id, h, r);
    case BH_DATA:
        return on_data(c, u, id, h, r);
    case BH_GOAWAY:
        bh_goaway_parse(c->rx + BH_HEADER_LEN, h->length, &g);
        fprintf(stderr, "bcurl: %s: server sent GOAWAY (last-id %lu, code 0x%02x) before the "
                "response was complete; the request was not processed\n", u->text,
                (unsigned long)g.last_id, (unsigned)g.code);
        return -1;
    case BH_REQUEST:
        return protocol_error(u, "server sent a REQUEST");
    default:
        return 0;   /* unknown type: already consumed, skip it (SPEC 4) */
    }
}

/*
 * Before reusing the connection: anything the server sent since the last
 * response can only be unknown frames (skipped) or a GOAWAY, after which no
 * further REQUEST may be sent (SPEC 4). Returns 0 if the connection is usable.
 */
static int check_between_requests(struct client *c, const struct url *next)
{
    for (;;) {
        struct pollfd pfd;
        struct bh_header h;
        struct bh_goaway g;
        int rc;

        pfd.fd = c->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 0) <= 0)
            return 0;   /* nothing pending */
        rc = bh_read_frame(c->fd, c->rx, &h, io_now_ms() + TIMEOUT_MS);
        if (rc == BH_IO_EOF) {
            fprintf(stderr, "bcurl: %s: server closed the connection\n", next->text);
            return -1;
        }
        if (rc != BH_IO_OK) {
            fprintf(stderr, "bcurl: %s: %s\n", next->text, read_failure(rc));
            return -1;
        }
        if (c->verbose)
            bh_dump_frame(stderr, '<', c->rx);
        if (h.type == BH_GOAWAY) {
            bh_goaway_parse(c->rx + BH_HEADER_LEN, h.length, &g);
            fprintf(stderr, "bcurl: %s: server sent GOAWAY (last-id %lu, code 0x%02x); "
                    "not sending more requests\n", next->text, (unsigned long)g.last_id,
                    (unsigned)g.code);
            return -1;
        }
        if (bh_type_known(h.type))
            return protocol_error(next, "unexpected frame between responses");
    }
}

/* Fetches one URL on the open connection. Returns 0 with *status set, or -1. */
static int fetch(struct client *c, const struct url *u, uint32_t id, unsigned *status)
{
    struct reply r;
    int done = 0;

    memset(&r, 0, sizeof r);
    if (id > 1 && check_between_requests(c, u) != 0)
        return -1;
    if (send_request(c, u, id) != 0)
        return -1;
    while (!done) {
        struct bh_header h;
        int rc = bh_read_frame(c->fd, c->rx, &h, io_now_ms() + TIMEOUT_MS);

        if (rc != BH_IO_OK) {
            if (c->verbose && rc == BH_IO_TOOBIG)
                bh_hexdump(stderr, '<', c->rx, BH_HEADER_LEN);
            fprintf(stderr, "bcurl: %s: %s\n", u->text, read_failure(rc));
            return -1;
        }
        if (c->verbose)
            bh_dump_frame(stderr, '<', c->rx);
        done = on_frame(c, u, id, &h, &r);
        if (done < 0)
            return -1;
    }
    if (r.have_length && r.body != r.content_length) {
        fprintf(stderr, "bcurl: %s: protocol error: body is %llu bytes, content-length says %llu\n",
                u->text, (unsigned long long)r.body, (unsigned long long)r.content_length);
        return -1;
    }
    *status = r.status;
    return 0;
}

/* ---- main ------------------------------------------------------------- */

static int exit_code_for(unsigned status)
{
    if (status >= 500)
        return EXIT_5XX;
    if (status >= 400)
        return EXIT_4XX;
    return EXIT_OK;
}

/* Severity: ok < 4xx < 5xx < protocol error. */
static int severity(int code)
{
    switch (code) {
    case EXIT_4XX:      return 1;
    case EXIT_5XX:      return 2;
    case EXIT_PROTOCOL: return 3;
    default:            return 0;
    }
}

static int worse(int a, int b)
{
    return severity(b) > severity(a) ? b : a;
}

static void usage(void)
{
    fputs("usage: bcurl [-v] URL [URL...]\n"
          "  URL: [bhttp://]host[:port][/path]   (port defaults to " DEFAULT_PORT ")\n"
          "  every URL must name the same host and port; one connection is used for all\n"
          "  -v  hexdump every frame sent (>) and received (<) on stderr\n"
          "exit: 0 2xx/3xx, 4 4xx, 5 5xx, 2 connection or protocol error, 1 usage\n",
          stderr);
}

int main(int argc, char **argv)
{
    struct client *c;
    struct url *urls;
    int nurls;
    int verbose = 0;
    int result = EXIT_OK;
    int opt;

    while ((opt = getopt(argc, argv, "vh")) != -1) {
        if (opt == 'v') {
            verbose = 1;
            continue;
        }
        usage();
        return opt == 'h' ? EXIT_OK : EXIT_USAGE;
    }
    nurls = argc - optind;
    if (nurls < 1) {
        usage();
        return EXIT_USAGE;
    }
    signal(SIGPIPE, SIG_IGN);

    urls = calloc((size_t)nurls, sizeof *urls);
    c = malloc(sizeof *c);
    if (urls == NULL || c == NULL) {
        fputs("bcurl: out of memory\n", stderr);
        free(urls);
        free(c);
        return EXIT_PROTOCOL;
    }
    for (int i = 0; i < nurls; i++) {
        const char *err = NULL;
        if (parse_url(argv[optind + i], &urls[i], &err) != 0) {
            fprintf(stderr, "bcurl: %s: %s\n", argv[optind + i], err);
            result = EXIT_USAGE;
        } else if (i > 0 && !same_origin(&urls[0], &urls[i])) {
            fprintf(stderr, "bcurl: %s: every URL must use %s port %s (one connection)\n",
                    argv[optind + i], urls[0].host, urls[0].port);
            result = EXIT_USAGE;
        }
    }
    if (result != EXIT_OK)
        goto out;

    c->verbose = verbose;
    c->fd = dial(&urls[0]);
    if (c->fd < 0) {
        result = EXIT_PROTOCOL;
        goto out;
    }
    if (verbose) {
        char peer[INET6_ADDRSTRLEN + 16];
        describe_peer(c->fd, peer, sizeof peer);
        fprintf(stderr, "* connected to %s (one connection for %d URL%s)\n", peer, nurls,
                nurls == 1 ? "" : "s");
    }
    for (int i = 0; i < nurls; i++) {
        unsigned status = 0;
        if (fetch(c, &urls[i], (uint32_t)i + 1, &status) != 0) {
            result = EXIT_PROTOCOL;
            if (i + 1 < nurls)
                fprintf(stderr, "bcurl: not fetching the remaining %d URL%s\n", nurls - i - 1,
                        nurls - i - 1 == 1 ? "" : "s");
            break;
        }
        if (status >= 400)
            fprintf(stderr, "bcurl: %s: %u %s\n", urls[i].text, status, bh_reason(status));
        result = worse(result, exit_code_for(status));
    }
    if (verbose)
        fputs("* closing connection\n", stderr);
    close(c->fd);
out:
    free(urls);
    free(c);
    return result;
}
