/*
 * dump.h - human-readable frame dumps for bcurl -v.
 */
#ifndef DUMP_H
#define DUMP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Classic 16-bytes-per-line hexdump with offsets and an ASCII column; every
 * line starts with `dir` ('>' sent, '<' received).
 */
void bh_hexdump(FILE *out, char dir, const uint8_t *p, size_t n);

/*
 * One summary line for the frame, one line per header field if it has a
 * header block, then the hexdump of the whole frame (header and payload).
 * `frame` must hold BH_HEADER_LEN + Length bytes, with Length <= BH_MAX_PAYLOAD.
 */
void bh_dump_frame(FILE *out, char dir, const uint8_t *frame);

/* Writes n bytes with anything outside printable ASCII escaped as \xNN. */
void bh_put_escaped(FILE *out, const uint8_t *p, size_t n);

#endif
