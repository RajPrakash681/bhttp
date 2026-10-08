/*
 * netio.c - blocking socket I/O with deadlines.
 *
 * Reads wait with poll() so that a deadline covers a whole frame, not just
 * one recv() call: a peer that dribbles one byte every few seconds still
 * hits the deadline.
 */
#include "netio.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int64_t io_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

/* 1 = readable (or error/hangup pending), 0 = deadline passed, -1 = poll failed. */
static int wait_readable(int fd, int64_t deadline)
{
    if (deadline == BH_NO_DEADLINE)
        return 1;
    for (;;) {
        struct pollfd pfd;
        int64_t left = deadline - io_now_ms();
        int r;

        if (left <= 0)
            return 0;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (r > 0)
            return 1;
        if (r == 0)
            return 0;
        if (errno != EINTR)
            return -1;
    }
}

int io_read_full(int fd, void *buf, size_t n, int64_t deadline)
{
    uint8_t *p = buf;
    size_t got = 0;

    while (got < n) {
        ssize_t r;
        int w = wait_readable(fd, deadline);

        if (w == 0)
            return BH_IO_TIMEOUT;
        if (w < 0)
            return BH_IO_ERROR;
        r = recv(fd, p + got, n - got, 0);
        if (r > 0) {
            got += (size_t)r;
        } else if (r == 0) {
            return got == 0 ? BH_IO_EOF : BH_IO_TRUNC;
        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return BH_IO_ERROR;
        }
    }
    return BH_IO_OK;
}

int io_write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;

    while (n > 0) {
        ssize_t w = write(fd, p, n);

        if (w > 0) {
            p += w;
            n -= (size_t)w;
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else {
            return BH_IO_ERROR;   /* includes EAGAIN after SO_SNDTIMEO */
        }
    }
    return BH_IO_OK;
}

int bh_read_frame(int fd, uint8_t *buf, struct bh_header *h, int64_t deadline)
{
    int r = io_read_full(fd, buf, BH_HEADER_LEN, deadline);

    if (r != BH_IO_OK)
        return r;
    bh_header_decode(buf, h);
    if (h->length > BH_MAX_PAYLOAD)
        return BH_IO_TOOBIG;
    if (h->length == 0)
        return BH_IO_OK;
    r = io_read_full(fd, buf + BH_HEADER_LEN, h->length, deadline);
    return r == BH_IO_EOF ? BH_IO_TRUNC : r;
}

int bh_send_frame(int fd, uint8_t *frame, const struct bh_header *h)
{
    if (h->length > BH_MAX_PAYLOAD)
        return BH_IO_TOOBIG;
    bh_header_encode(h, frame);
    return io_write_full(fd, frame, BH_HEADER_LEN + (size_t)h->length);
}
