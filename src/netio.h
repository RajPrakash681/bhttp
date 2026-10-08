/*
 * netio.h - blocking socket I/O with deadlines, and whole-frame reads/writes.
 */
#ifndef NETIO_H
#define NETIO_H

#include <stddef.h>
#include <stdint.h>

#include "bhttp.h"

enum bh_io {
    BH_IO_OK = 0,
    BH_IO_EOF = -1,       /* peer closed before the first byte */
    BH_IO_TRUNC = -2,     /* peer closed in the middle */
    BH_IO_TIMEOUT = -3,   /* deadline passed */
    BH_IO_ERROR = -4,     /* errno says why */
    BH_IO_TOOBIG = -5     /* frame header read; Length > BH_MAX_PAYLOAD */
};

#define BH_NO_DEADLINE (-1)

/* Milliseconds on a monotonic clock. */
int64_t io_now_ms(void);

/* Reads exactly n bytes, or fails. `deadline` is io_now_ms()-based or BH_NO_DEADLINE. */
int io_read_full(int fd, void *buf, size_t n, int64_t deadline);

/* Writes exactly n bytes (short writes and EINTR are retried), or fails. */
int io_write_full(int fd, const void *buf, size_t n);

/*
 * Reads one frame into buf, which must hold BH_FRAME_MAX bytes: the header at
 * buf[0..8), the payload at buf[8..8+length). On BH_IO_TOOBIG *h is valid but
 * the payload has not been read.
 */
int bh_read_frame(int fd, uint8_t *buf, struct bh_header *h, int64_t deadline);

/*
 * Sends one frame. The payload must already sit at frame + BH_HEADER_LEN; the
 * header described by *h is written in front of it and the whole frame goes
 * out in one write call.
 */
int bh_send_frame(int fd, uint8_t *frame, const struct bh_header *h);

#endif
