/*
 * bserve - serve files from a directory over bhttp/1.
 *
 *     bserve [-t idle_seconds] ROOT PORT
 *
 * Listens on 0.0.0.0:PORT (0 picks a free port; the log line says which) and
 * forks one process per connection. Each process reads frames until the peer
 * closes, the connection idles out, or the framing breaks (SPEC 2, 7).
 *
 * Why fork: a connection's whole state (two 16 KiB frame buffers and a file
 * descriptor) lives in its own address space, so one connection can neither
 * corrupt nor crash another or the listener, and nothing needs a lock. The
 * cost, a process per client, is fine for a course-sized server.
 */
#include "bhttp.h"
#include "netio.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SERVER_NAME "bserve/1.0"
#define DEFAULT_IDLE_SECONDS 30
#define DEFAULT_MAX_CONNECTIONS 64
#define LINGER_MS 2000
#define LINGER_MAX_BYTES (1u << 20)
#define LISTEN_BACKLOG 64

#if defined(__GNUC__)
#define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#else
#define PRINTF_LIKE(f, a)
#endif

struct config {
    char root[PATH_MAX];   /* realpath of ROOT */
    size_t root_len;
    int root_fd;           /* ROOT itself, opened once at startup */
    int idle_ms;
};

struct conn {
    int fd;
    char peer[INET6_ADDRSTRLEN + 8];
    const struct config *cfg;
    uint32_t last_done;            /* last request answered completely */
    unsigned requests;
    uint8_t rx[BH_FRAME_MAX];      /* frames as they arrive; also file chunks */
    uint8_t tx[BH_FRAME_MAX];      /* RESPONSE and error frames */
    uint8_t req[BH_MAX_PAYLOAD];   /* REQUEST payload, kept while its body is read */
};

/* What one request turned into, for the log line. */
struct exchange {
    uint32_t id;
    int head;               /* HEAD: headers only */
    unsigned status;
    unsigned long long bytes;
    const char *note;
};

/* What the connection loop does next. */
enum next { KEEP, CLOSE, CLOSE_LINGER };

struct field {
    const char *name;
    const char *value;
};

/* ---- logging ---------------------------------------------------------- */

static void log_line(const char *fmt, ...) PRINTF_LIKE(1, 2);

/* One line per call, written with a single write() so that lines from
 * concurrent connection processes do not interleave. */
static void log_line(const char *fmt, ...)
{
    char line[1024];
    size_t len;
    time_t now = time(NULL);
    struct tm tm;
    va_list ap;
    int n;

    len = gmtime_r(&now, &tm) ? strftime(line, sizeof line, "%Y-%m-%dT%H:%M:%SZ ", &tm) : 0;
    va_start(ap, fmt);
    n = vsnprintf(line + len, sizeof line - len, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    len += (size_t)n;
    if (len > sizeof line - 2)
        len = sizeof line - 2;
    line[len++] = '\n';
    (void)io_write_full(STDERR_FILENO, line, len);
}

/* Printable rendering of untrusted bytes for the log: \xNN escapes, capped. */
static void escape_for_log(const uint8_t *p, size_t n, char *out, size_t cap)
{
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;

    for (size_t i = 0; i < n; i++) {
        if (o + 8 > cap) {
            memcpy(out + o, "...", 3);
            o += 3;
            break;
        }
        if (p[i] >= 0x21 && p[i] < 0x7f && p[i] != '\\') {
            out[o++] = (char)p[i];
        } else {
            out[o++] = '\\';
            out[o++] = 'x';
            out[o++] = hex[p[i] >> 4];
            out[o++] = hex[p[i] & 0x0f];
        }
    }
    out[o] = '\0';
}

static void log_exchange(const struct conn *c, const char *method, const uint8_t *path,
                         size_t path_len, const struct exchange *ex)
{
    char shown[260];

    if (path && path_len > 0)
        escape_for_log(path, path_len, shown, sizeof shown);
    else
        memcpy(shown, "-", 2);
    log_line("%s %s %s %u %llu%s%s%s", c->peer, method ? method : "-", shown, ex->status,
             ex->bytes, ex->note ? " (" : "", ex->note ? ex->note : "", ex->note ? ")" : "");
}

/* Best-effort method and path of a REQUEST that did not parse, for the log. */
static void log_bad_request(const struct conn *c, const uint8_t *p, size_t n,
                            const struct exchange *ex)
{
    const char *method = n >= 1 ? bh_method_name(p[0]) : NULL;
    size_t plen = n >= 3 ? (size_t)(((unsigned)p[1] << 8) | (unsigned)p[2]) : 0;

    if (n < 3 || plen > n - 3)
        plen = 0;
    log_exchange(c, method, plen > 0 ? p + 3 : NULL, plen, ex);
}

/* ---- sending ---------------------------------------------------------- */

static void http_date(time_t t, char out[40])
{
    struct tm tm;

    if (gmtime_r(&t, &tm) == NULL || strftime(out, 40, "%a, %d %b %Y %H:%M:%S GMT", &tm) == 0)
        memcpy(out, "Thu, 01 Jan 1970 00:00:00 GMT", 30);
}

static int send_frame(struct conn *c, uint8_t *frame, uint8_t type, uint8_t flags,
                      uint32_t id, size_t len)
{
    struct bh_header h;

    h.length = (uint16_t)len;
    h.type = type;
    h.flags = flags;
    h.id = id;
    return bh_send_frame(c->fd, frame, &h) == BH_IO_OK ? 0 : -1;
}

/* RESPONSE frame: status, the given fields, then date and server. */
static int send_response(struct conn *c, uint32_t id, unsigned status,
                         const struct field *fields, size_t nfields, int end)
{
    struct bh_buf b;
    char date[40];

    bh_buf_init(&b, c->tx + BH_HEADER_LEN, BH_MAX_PAYLOAD);
    bh_put_u16(&b, (uint16_t)status);
    for (size_t i = 0; i < nfields; i++)
        bh_put_field(&b, fields[i].name, fields[i].value);
    http_date(time(NULL), date);
    bh_put_field(&b, "date", date);
    bh_put_field(&b, "server", SERVER_NAME);
    if (b.error)
        return -1;
    return send_frame(c, c->tx, BH_RESPONSE, end ? BH_FLAG_END : 0, id, b.len);
}

/*
 * A short text/plain response: "404 Not Found\n", or with a detail,
 * "400 Bad Request: path does not start with /\n". `extra` is an optional
 * additional field (location for 301, allow for 405).
 */
static int send_text(struct conn *c, struct exchange *ex, unsigned status,
                     const char *detail, const struct field *extra)
{
    char text[256];
    char clen[24];
    struct field fields[3];
    size_t nfields = 0;
    int n;

    if (detail)
        n = snprintf(text, sizeof text, "%u %s: %s\n", status, bh_reason(status), detail);
    else
        n = snprintf(text, sizeof text, "%u %s\n", status, bh_reason(status));
    if (n < 0)
        return -1;
    if ((size_t)n >= sizeof text)
        n = (int)sizeof text - 1;
    snprintf(clen, sizeof clen, "%d", n);
    fields[nfields++] = (struct field){ "content-type", "text/plain; charset=utf-8" };
    fields[nfields++] = (struct field){ "content-length", clen };
    if (extra)
        fields[nfields++] = *extra;

    ex->status = status;
    if (send_response(c, ex->id, status, fields, nfields, ex->head) != 0)
        return -1;
    if (ex->head)
        return 0;
    memcpy(c->tx + BH_HEADER_LEN, text, (size_t)n);
    if (send_frame(c, c->tx, BH_DATA, BH_FLAG_END, ex->id, (size_t)n) != 0)
        return -1;
    ex->bytes = (unsigned long long)n;
    return 0;
}

static void send_goaway(struct conn *c, uint8_t code)
{
    struct bh_buf b;

    bh_buf_init(&b, c->tx + BH_HEADER_LEN, BH_MAX_PAYLOAD);
    bh_put_u32(&b, c->last_done);
    bh_put_u8(&b, code);
    (void)send_frame(c, c->tx, BH_GOAWAY, 0, 0, b.len);
}

/*
 * SPEC 2: after GOAWAY, stop sending and drain input for a while before
 * closing. Closing a socket with unread input makes TCP send a reset, which
 * can destroy the GOAWAY (and a 400) before the peer has read them.
 */
static void linger_close(int fd)
{
    uint8_t sink[4096];
    int64_t deadline = io_now_ms() + LINGER_MS;
    size_t drained = 0;

    (void)shutdown(fd, SHUT_WR);
    while (drained < LINGER_MAX_BYTES) {
        struct pollfd pfd;
        int64_t left = deadline - io_now_ms();
        ssize_t r;

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (left <= 0 || poll(&pfd, 1, (int)left) <= 0)
            break;
        r = recv(fd, sink, sizeof sink, 0);
        if (r <= 0)
            break;
        drained += (size_t)r;
    }
    close(fd);
}

/* ---- path mapping (SPEC 8) -------------------------------------------- */

static int inside_root(const struct config *cfg, const char *real)
{
    if (cfg->root_len == 1)   /* ROOT is "/" */
        return 1;
    return strncmp(real, cfg->root, cfg->root_len) == 0 &&
           (real[cfg->root_len] == '/' || real[cfg->root_len] == '\0');
}

static int has_hidden_segment(const uint8_t *path, size_t len)
{
    for (size_t i = 0; i + 1 < len; i++)
        if (path[i] == '/' && path[i + 1] == '.')
            return 1;
    return 0;
}

/*
 * Opens `rel`, a path relative to ROOT as realpath() produced it (no ".",
 * "..", empty or symlink components), one component at a time from the ROOT
 * descriptor, never following a symbolic link. If the tree changed after
 * realpath() looked at it (say, a directory was swapped for a symlink out of
 * ROOT), this fails instead of following the link, so whatever it opens is
 * inside ROOT. Returns a descriptor or -1 with errno set.
 */
static int open_beneath(int root_fd, const char *rel)
{
    int dir = root_fd;

    if (*rel == '\0')
        return openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    for (;;) {
        const char *slash = strchr(rel, '/');
        size_t len = slash ? (size_t)(slash - rel) : strlen(rel);
        char name[PATH_MAX];
        int fd = -1;
        int saved;

        if (len == 0 || len >= sizeof name) {
            errno = ENOENT;
        } else {
            memcpy(name, rel, len);
            name[len] = '\0';
            fd = openat(dir, name, slash ? O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                                         : O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        }
        saved = errno;
        if (dir != root_fd)
            close(dir);
        errno = saved;
        if (fd < 0 || slash == NULL)
            return fd;
        dir = fd;
        rel = slash + 1;
    }
}

/*
 * The status for a failed realpath() or open. EINVAL is what macOS realpath()
 * reports when a symlink it saw is replaced while it reads it: a race, so 404.
 */
static unsigned status_for_errno(int err)
{
    if (err == EACCES)
        return 403;
    if (err == ENOENT || err == ENOTDIR || err == ELOOP || err == ENAMETOOLONG ||
        err == EINVAL)
        return 404;
    return 500;
}

/*
 * Maps the path part of a request (no query) to an open regular file under
 * ROOT. Returns 0 with *fd, *st and `real` set, or the HTTP status to send.
 * The path has passed bh_path_check: it starts with '/', has no "." or ".."
 * segments and no NUL or other control bytes.
 *
 * realpath() resolves symlinks so that links inside ROOT work and links out
 * of ROOT are refused; open_beneath() then opens what realpath() named
 * without following anything, which closes the race between the two.
 */
static unsigned open_path(const struct config *cfg, const uint8_t *path, size_t len,
                          int *fd, struct stat *st, char real[PATH_MAX])
{
    char want[PATH_MAX];
    const char *suffix = path[len - 1] == '/' ? "index.html" : "";
    size_t slen = strlen(suffix);
    const char *rel;

    if (has_hidden_segment(path, len))
        return 404;
    if (cfg->root_len + len + slen >= sizeof want)
        return 404;
    memcpy(want, cfg->root, cfg->root_len);
    memcpy(want + cfg->root_len, path, len);
    memcpy(want + cfg->root_len + len, suffix, slen + 1);

    if (realpath(want, real) == NULL)
        return status_for_errno(errno);
    if (!inside_root(cfg, real))
        return 404;
    rel = real + cfg->root_len;
    if (*rel == '/')
        rel++;
    *fd = open_beneath(cfg->root_fd, rel);
    if (*fd < 0)
        return status_for_errno(errno);
    if (fstat(*fd, st) != 0 || !S_ISREG(st->st_mode)) {
        unsigned status = S_ISDIR(st->st_mode) ? (slen > 0 ? 404 : 301) : 404;
        close(*fd);
        *fd = -1;
        return status;
    }
    return 0;
}

static const char *content_type(const char *file)
{
    static const struct {
        const char *ext;
        const char *type;
    } types[] = {
        { "html", "text/html; charset=utf-8" },
        { "htm", "text/html; charset=utf-8" },
        { "css", "text/css; charset=utf-8" },
        { "js", "text/javascript; charset=utf-8" },
        { "json", "application/json" },
        { "txt", "text/plain; charset=utf-8" },
        { "md", "text/markdown; charset=utf-8" },
        { "png", "image/png" },
        { "jpg", "image/jpeg" },
        { "jpeg", "image/jpeg" },
        { "gif", "image/gif" },
        { "svg", "image/svg+xml" },
        { "ico", "image/x-icon" },
        { "pdf", "application/pdf" },
    };
    const char *slash = strrchr(file, '/');
    const char *dot = strrchr(slash ? slash : file, '.');

    if (dot) {
        for (size_t i = 0; i < sizeof types / sizeof types[0]; i++)
            if (strcasecmp(dot + 1, types[i].ext) == 0)
                return types[i].type;
    }
    return "application/octet-stream";
}

/* ---- serving a file --------------------------------------------------- */

/* Reads up to n bytes; fewer means EOF or an error. */
static size_t read_file(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;

    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r > 0)
            got += (size_t)r;
        else if (r < 0 && errno == EINTR)
            continue;
        else
            break;
    }
    return got;
}

/*
 * 200 with the file as DATA frames of up to 16 KiB, the last one with END.
 * The first chunk is read before the RESPONSE goes out, so that a read error
 * can still become a 500. A failure after that closes the connection with no
 * END, as SPEC 6 requires. Returns -1 when the connection must close.
 */
static int send_file(struct conn *c, struct exchange *ex, int fd, const struct stat *st,
                     const char *ctype)
{
    char clen[24];
    char mtime[40];
    struct field fields[3];
    uint64_t left;
    size_t chunk;

    if (st->st_size < 0)
        return send_text(c, ex, 500, "bad file size", NULL);
    left = (uint64_t)st->st_size;
    snprintf(clen, sizeof clen, "%llu", (unsigned long long)left);
    http_date(st->st_mtime, mtime);
    fields[0] = (struct field){ "content-type", ctype };
    fields[1] = (struct field){ "content-length", clen };
    fields[2] = (struct field){ "last-modified", mtime };

    ex->status = 200;
    if (ex->head || left == 0)
        return send_response(c, ex->id, 200, fields, 3, 1);

    chunk = left < BH_MAX_PAYLOAD ? (size_t)left : BH_MAX_PAYLOAD;
    if (read_file(fd, c->rx + BH_HEADER_LEN, chunk) != chunk)
        return send_text(c, ex, 500, "cannot read file", NULL);
    if (send_response(c, ex->id, 200, fields, 3, 0) != 0)
        return -1;
    for (;;) {
        left -= chunk;
        if (send_frame(c, c->rx, BH_DATA, left == 0 ? BH_FLAG_END : 0, ex->id, chunk) != 0)
            return -1;
        ex->bytes += chunk;
        if (left == 0)
            return 0;
        chunk = left < BH_MAX_PAYLOAD ? (size_t)left : BH_MAX_PAYLOAD;
        if (read_file(fd, c->rx + BH_HEADER_LEN, chunk) != chunk) {
            ex->note = "read error mid-file, closing without END";
            return -1;
        }
    }
}

/* GET or HEAD for a path that passed bh_path_check. */
static int serve_path(struct conn *c, struct exchange *ex, const uint8_t *path, size_t len)
{
    char real[PATH_MAX];
    size_t plen = bh_path_part_len(path, len);   /* the query is ignored */
    struct stat st;
    int fd = -1;
    unsigned status = open_path(c->cfg, path, plen, &fd, &st, real);
    int rc;

    if (status == 301) {
        char location[PATH_MAX + 2];   /* open_path checked plen < PATH_MAX */
        struct field f = { "location", location };
        memcpy(location, path, plen);
        location[plen] = '/';
        location[plen + 1] = '\0';
        return send_text(c, ex, 301, NULL, &f);
    }
    if (status != 0)
        return send_text(c, ex, status, NULL, NULL);
    rc = send_file(c, ex, fd, &st, content_type(real));
    close(fd);
    return rc;
}

/* ---- the connection --------------------------------------------------- */

static enum next connection_error(struct conn *c, const char *detail, const char **why)
{
    struct exchange ex = { 0, 0, 0, 0, NULL };

    ex.note = detail;
    (void)send_text(c, &ex, 400, detail, NULL);
    log_exchange(c, NULL, NULL, 0, &ex);
    send_goaway(c, BH_PROTOCOL_ERROR);
    *why = "protocol error";
    return CLOSE_LINGER;
}

/*
 * Reads the next frame into c->rx; anything but KEEP ends the connection.
 * The caller owns the deadline (SPEC 2): only a complete REQUEST, or a DATA
 * frame of an open request body, earns a new one, so a peer that trickles
 * unknown frames cannot keep a connection, and its process, for ever.
 */
static enum next next_frame(struct conn *c, struct bh_header *h, int64_t deadline,
                            const char **why)
{
    char detail[80];

    switch (bh_read_frame(c->fd, c->rx, h, deadline)) {
    case BH_IO_OK:
        return KEEP;
    case BH_IO_EOF:
        *why = "peer closed";
        return CLOSE;
    case BH_IO_TRUNC:
        *why = "peer closed mid-frame";
        return CLOSE;
    case BH_IO_TIMEOUT:
        send_goaway(c, BH_NO_ERROR);
        *why = "idle timeout";
        return CLOSE_LINGER;
    case BH_IO_TOOBIG:
        snprintf(detail, sizeof detail, "frame length %u exceeds %u",
                 (unsigned)h->length, BH_MAX_PAYLOAD);
        return connection_error(c, detail, why);
    default:
        *why = "read error";
        return CLOSE;
    }
}

/*
 * SPEC 6: read a request body through its END before anything else. The
 * body itself is discarded: bserve only implements GET and HEAD.
 */
static enum next drain_body(struct conn *c, uint32_t id, uint64_t *body, const char **why)
{
    int64_t deadline = io_now_ms() + c->cfg->idle_ms;

    for (;;) {
        struct bh_header h;
        enum next nx = next_frame(c, &h, deadline, why);

        if (nx != KEEP)
            return nx;
        if (h.type == BH_DATA && h.id == id) {
            *body += h.length;
            if (h.flags & BH_FLAG_END)
                return KEEP;
            deadline = io_now_ms() + c->cfg->idle_ms;
        } else if (h.type == BH_GOAWAY) {
            *why = "peer sent GOAWAY";
            return CLOSE;
        } else if (bh_type_known(h.type)) {
            return connection_error(c, "frame for another request inside a request body", why);
        }
        /* unknown type: already consumed, skip it (SPEC 4) */
    }
}

/* SPEC 6: a request's content-length, if any, must match the body read. */
static int check_content_length(const struct bh_request *rq, uint64_t body, const char **err)
{
    int present;
    uint64_t value;

    if (bh_content_length(rq->fields, rq->fields_len, &present, &value, err) != 0)
        return -1;
    if (present && value != body) {
        *err = "content-length does not match the body";
        return -1;
    }
    return 0;
}

/* A REQUEST with a nonzero ID: read its body, if any, then answer it. */
static enum next on_request(struct conn *c, const struct bh_header *h, const char **why)
{
    struct exchange ex = { 0, 0, 0, 0, NULL };
    struct bh_request rq;
    const char *err = NULL;
    size_t n = h->length;
    uint64_t body = 0;
    int rc;

    memcpy(c->req, c->rx + BH_HEADER_LEN, n);
    if (!(h->flags & BH_FLAG_END)) {
        enum next nx = drain_body(c, h->id, &body, why);
        if (nx != KEEP)
            return nx;
    }
    c->requests++;
    ex.id = h->id;
    /* SPEC 6: a response to HEAD never has DATA, whatever its status, even a 400 */
    ex.head = n >= 1 && c->req[0] == BH_HEAD;

    if (bh_request_parse(c->req, n, &rq, &err) != 0 ||
        check_content_length(&rq, body, &err) != 0) {
        ex.note = err;
        rc = send_text(c, &ex, 400, ex.note, NULL);
        log_bad_request(c, c->req, n, &ex);
    } else {
        if (rq.method == BH_GET || rq.method == BH_HEAD) {
            rc = serve_path(c, &ex, rq.path, rq.path_len);
        } else {
            struct field allow = { "allow", "GET, HEAD" };
            rc = send_text(c, &ex, 405, NULL, &allow);
        }
        log_exchange(c, bh_method_name(rq.method), rq.path, rq.path_len, &ex);
    }
    if (rc != 0) {
        *why = "write error";
        return CLOSE;
    }
    c->last_done = h->id;
    return KEEP;
}

/* A request error (SPEC 7): 400 for this frame, and the connection stays. */
static enum next request_error(struct conn *c, uint32_t id, const char *detail, const char **why)
{
    struct exchange ex = { 0, 0, 0, 0, NULL };

    ex.id = id;
    ex.note = detail;
    if (send_text(c, &ex, 400, detail, NULL) != 0) {
        *why = "write error";
        return CLOSE;
    }
    log_exchange(c, NULL, NULL, 0, &ex);
    return KEEP;
}

static enum next on_frame(struct conn *c, const struct bh_header *h, const char **why)
{
    /* SPEC 3, 7: ID 0 is the connection; no request can be named by it. */
    if (h->id == 0 && (h->type == BH_REQUEST || h->type == BH_RESPONSE || h->type == BH_DATA))
        return connection_error(c, "REQUEST, RESPONSE or DATA with Request ID 0", why);
    switch (h->type) {
    case BH_REQUEST:
        return on_request(c, h, why);
    case BH_DATA:
        return request_error(c, h->id, "DATA frame outside a request body", why);
    case BH_RESPONSE:
        return request_error(c, h->id, "RESPONSE frame sent to a server", why);
    case BH_GOAWAY:
        *why = "peer sent GOAWAY";
        return CLOSE;
    default:
        return KEEP;   /* unknown type: its payload is already consumed (SPEC 4) */
    }
}

static void serve(struct conn *c)
{
    const char *why = "closed";
    int64_t deadline = io_now_ms() + c->cfg->idle_ms;
    enum next nx = KEEP;

    log_line("%s connect", c->peer);
    while (nx == KEEP) {
        struct bh_header h;

        nx = next_frame(c, &h, deadline, &why);
        if (nx != KEEP)
            break;
        nx = on_frame(c, &h, &why);
        if (h.type == BH_REQUEST)   /* only requests count as activity */
            deadline = io_now_ms() + c->cfg->idle_ms;
    }
    if (nx == CLOSE_LINGER)
        linger_close(c->fd);
    else
        close(c->fd);
    log_line("%s close (%s, %u request%s)", c->peer, why, c->requests,
             c->requests == 1 ? "" : "s");
}

static void format_peer(const struct sockaddr_storage *ss, char *out, size_t cap)
{
    char addr[INET6_ADDRSTRLEN] = "?";
    unsigned port = 0;

    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)ss;
        inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof addr);
        port = ntohs(sin->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)(const void *)ss;
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof addr);
        port = ntohs(sin6->sin6_port);
    }
    snprintf(out, cap, "%s:%u", addr, port);
}

/* Runs in the child process. Returns its exit status. */
static int handle_connection(const struct config *cfg, int fd, const struct sockaddr_storage *ss)
{
    struct conn *c = malloc(sizeof *c);
    struct timeval tv;
    int one = 1;

    if (c == NULL) {
        close(fd);
        return 1;
    }
    memset(c, 0, sizeof *c);
    c->fd = fd;
    c->cfg = cfg;
    format_peer(ss, c->peer, sizeof c->peer);
    /* Frames go out whole in one write each; do not let Nagle hold them. */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    /* A peer that stops reading cannot block us for ever. */
    tv.tv_sec = cfg->idle_ms / 1000;
    tv.tv_usec = (suseconds_t)((cfg->idle_ms % 1000) * 1000);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    serve(c);
    free(c);
    return 0;
}

/* ---- capacity --------------------------------------------------------- */

/*
 * Turns a connection away from the listening process: GOAWAY with code BUSY
 * and Last-ID 0 (nothing was processed), then close. The listener must never
 * wait on a client, so the socket is made non-blocking first; whatever input
 * is already there is drained so that the close does not reset the GOAWAY.
 */
static void refuse(int fd, const struct sockaddr_storage *ss, const char *reason)
{
    uint8_t frame[BH_HEADER_LEN + 5];
    uint8_t sink[4096];
    struct bh_header h = { 5, BH_GOAWAY, 0, 0 };
    char peer[INET6_ADDRSTRLEN + 8];
    int flags = fcntl(fd, F_GETFL);
    size_t drained = 0;
    ssize_t r;

    memset(frame, 0, sizeof frame);   /* Last-ID 0 */
    frame[BH_HEADER_LEN + 4] = BH_BUSY;
    bh_header_encode(&h, frame);
    if (flags >= 0)
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    (void)send(fd, frame, sizeof frame, 0);
    while (drained < sizeof sink * 16 && (r = recv(fd, sink, sizeof sink, 0)) > 0)
        drained += (size_t)r;
    (void)shutdown(fd, SHUT_WR);
    close(fd);
    format_peer(ss, peer, sizeof peer);
    log_line("%s refused (%s)", peer, reason);
}

/* Reaps every connection process that has exited; returns how many. */
static unsigned long reap_children(void)
{
    unsigned long n = 0;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        n++;
    return n;
}

/* ---- startup ---------------------------------------------------------- */

static int open_listener(unsigned port, unsigned *bound)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, LISTEN_BACKLOG) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    *bound = ntohs(sa.sin_port);
    return fd;
}

static int parse_uint(const char *s, unsigned long max, unsigned long *out)
{
    char *end;
    unsigned long v;

    if (*s < '0' || *s > '9')
        return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || *end != '\0' || v > max)
        return -1;
    *out = v;
    return 0;
}

static void usage(void)
{
    fputs("usage: bserve [-t idle_seconds] [-c max_connections] ROOT PORT\n"
          "  serves the files under ROOT over bhttp/1 on 0.0.0.0:PORT (0 = any free port)\n"
          "  -t  close a connection with no request for this long (default 30 s)\n"
          "  -c  serve at most this many connections at once; refuse the rest with\n"
          "      GOAWAY BUSY (default 64)\n",
          stderr);
}

int main(int argc, char **argv)
{
    static struct config cfg;
    unsigned long idle = DEFAULT_IDLE_SECONDS;
    unsigned long max_conns = DEFAULT_MAX_CONNECTIONS;
    unsigned long live = 0;   /* connection processes not yet reaped */
    unsigned long port;
    unsigned bound;
    struct stat st;
    int opt;
    int lfd;

    while ((opt = getopt(argc, argv, "t:c:h")) != -1) {
        if (opt == 't' && parse_uint(optarg, 3600, &idle) == 0 && idle > 0)
            continue;
        if (opt == 'c' && parse_uint(optarg, 100000, &max_conns) == 0 && max_conns > 0)
            continue;
        usage();
        return opt == 'h' ? 0 : 1;
    }
    if (argc - optind != 2 || parse_uint(argv[optind + 1], 65535, &port) != 0) {
        usage();
        return 1;
    }
    if (realpath(argv[optind], cfg.root) == NULL || stat(cfg.root, &st) != 0 ||
        !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "bserve: %s: not a readable directory\n", argv[optind]);
        return 1;
    }
    cfg.root_len = strlen(cfg.root);
    cfg.root_fd = open(cfg.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cfg.root_fd < 0) {
        fprintf(stderr, "bserve: %s: %s\n", cfg.root, strerror(errno));
        return 1;
    }
    cfg.idle_ms = (int)idle * 1000;

    signal(SIGPIPE, SIG_IGN);   /* a vanished peer is a write error, not a signal */
    signal(SIGCHLD, SIG_DFL);   /* reaped in the accept loop, to count them */

    lfd = open_listener((unsigned)port, &bound);
    if (lfd < 0) {
        fprintf(stderr, "bserve: port %lu: %s\n", port, strerror(errno));
        return 1;
    }
    log_line("bserve: listening on 0.0.0.0:%u, root %s, idle timeout %lus, max %lu connections",
             bound, cfg.root, idle, max_conns);

    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int fd = accept(lfd, (struct sockaddr *)&ss, &sl);
        unsigned long reaped;
        pid_t pid;

        if (fd < 0) {
            if (errno != EINTR && errno != ECONNABORTED) {
                struct timespec pause = { 0, 100 * 1000 * 1000 };
                log_line("bserve: accept: %s", strerror(errno));
                nanosleep(&pause, NULL);   /* e.g. out of descriptors: back off */
            }
            continue;
        }
        reaped = reap_children();
        live = reaped < live ? live - reaped : 0;
        if (live >= max_conns) {
            refuse(fd, &ss, "at capacity");
            continue;
        }
        pid = fork();
        if (pid == 0) {
            close(lfd);
            exit(handle_connection(&cfg, fd, &ss));
        }
        if (pid < 0) {
            refuse(fd, &ss, strerror(errno));
            continue;
        }
        live++;
        close(fd);
    }
}
