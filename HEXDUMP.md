# Annotated hexdump: one request, one response

One complete bhttp/1 exchange, captured from a real run of the release build on macOS
(Apple Silicon) on 2026-10-08, then taken apart byte by byte. The body is `www/hello.txt`
(14 bytes), so the whole exchange is three frames: 56 bytes from the client, 120 + 22
bytes from the server.

```console
$ ./bserve ./www 9000 &
$ ./bcurl -v localhost:9000/hello.txt
```

## The capture

This is the verbatim output of that run. Lines starting with `>` are frames bcurl sent,
lines starting with `<` are frames it received, and `*` lines are connection events.
Each frame gets a one-line summary, its decoded header fields (with the static-table
index each one used), and a hexdump of every byte of the frame, header included.
Offsets in the hexdump count from the start of the frame.

stderr:

```text
* connected to 127.0.0.1 port 9000 (one connection for 1 URL)
> REQUEST id=1 length=48 flags=0x01 (END): GET /hello.txt
>     host: localhost:9000   [index 1]
>     user-agent: bcurl/1.0   [index 2]
>     accept: */*   [index 3]
>   0000  00 30 01 01 00 00 00 01  01 00 0a 2f 68 65 6c 6c  |.0........./hell|
>   0010  6f 2e 74 78 74 01 00 0e  6c 6f 63 61 6c 68 6f 73  |o.txt...localhos|
>   0020  74 3a 39 30 30 30 02 00  09 62 63 75 72 6c 2f 31  |t:9000...bcurl/1|
>   0030  2e 30 03 00 03 2a 2f 2a                           |.0...*/*|
< RESPONSE id=1 length=112 flags=0x00: 200 OK
<     content-type: text/plain; charset=utf-8   [index 4]
<     content-length: 14   [index 5]
<     last-modified: Thu, 08 Oct 2026 12:01:37 GMT   [index 6]
<     date: Thu, 08 Oct 2026 12:08:46 GMT   [index 7]
<     server: bserve/1.0   [index 8]
<   0000  00 70 02 00 00 00 00 01  00 c8 04 00 19 74 65 78  |.p...........tex|
<   0010  74 2f 70 6c 61 69 6e 3b  20 63 68 61 72 73 65 74  |t/plain; charset|
<   0020  3d 75 74 66 2d 38 05 00  02 31 34 06 00 1d 54 68  |=utf-8...14...Th|
<   0030  75 2c 20 30 38 20 4f 63  74 20 32 30 32 36 20 31  |u, 08 Oct 2026 1|
<   0040  32 3a 30 31 3a 33 37 20  47 4d 54 07 00 1d 54 68  |2:01:37 GMT...Th|
<   0050  75 2c 20 30 38 20 4f 63  74 20 32 30 32 36 20 31  |u, 08 Oct 2026 1|
<   0060  32 3a 30 38 3a 34 36 20  47 4d 54 08 00 0a 62 73  |2:08:46 GMT...bs|
<   0070  65 72 76 65 2f 31 2e 30                           |erve/1.0|
< DATA id=1 length=14 flags=0x01 (END): 14 body bytes
<   0000  00 0e 03 01 00 00 00 01  48 65 6c 6c 6f 2c 20 62  |........Hello, b|
<   0010  68 74 74 70 21 0a                                 |http!.|
* closing connection
```

stdout, and the exit status:

```text
Hello, bhttp!
exit=0
```

The server's log for the same run (stderr of `bserve`):

```text
2026-10-08T12:08:45Z bserve: listening on 0.0.0.0:9000, root /Users/rajprakash/devops-work/bhttp/www, idle timeout 30s
2026-10-08T12:08:46Z 127.0.0.1:65093 connect
2026-10-08T12:08:46Z 127.0.0.1:65093 GET /hello.txt 200 14
2026-10-08T12:08:46Z 127.0.0.1:65093 close (peer closed, 1 request)
```

## Frame 1: REQUEST, client to server (56 bytes)

Every byte of the frame, in order. All integers are big-endian (SPEC 1).

```text
off   bytes                    field         meaning
----  -----------------------  ------------  ---------------------------------------------
                                             -- frame header (SPEC 3) --
0000  00 30                    Length        0x0030 = 48 payload bytes follow the header
0002  01                       Type          0x01 REQUEST
0003  01                       Flags         0x01 END: no request body follows
0004  00 00 00 01              Request ID    1: the first request on this connection
                                             -- REQUEST payload (SPEC 5.1) --
0008  01                       Method        0x01 GET
0009  00 0a                    Path Length   10
000b  2f 68 65 6c 6c 6f 2e 74  Path          "/hello.txt" (raw bytes, no percent-encoding)
      78 74
                                             -- header block: 3 entries (SPEC 5.3) --
0015  01                       Index         1 = host (indexed name, no name bytes sent)
0016  00 0e                    VLen          14
0018  6c 6f 63 61 6c 68 6f 73  Value         "localhost:9000"
      74 3a 39 30 30 30
0026  02                       Index         2 = user-agent
0027  00 09                    VLen          9
0029  62 63 75 72 6c 2f 31 2e  Value         "bcurl/1.0"
      30
0032  03                       Index         3 = accept
0033  00 03                    VLen          3
0035  2a 2f 2a                 Value         "*/*"
```

Check: the payload runs from 0x0008 to 0x0037, which is 48 bytes, matching Length. The
header block ends exactly at the end of the payload, which is how the receiver knows
there are no more entries; there is no entry count.

## Frame 2: RESPONSE, server to client (120 bytes)

```text
off   bytes                    field         meaning
----  -----------------------  ------------  ---------------------------------------------
                                             -- frame header --
0000  00 70                    Length        0x0070 = 112 payload bytes
0002  02                       Type          0x02 RESPONSE
0003  00                       Flags         0x00: END clear, so a body follows in DATA frames
0004  00 00 00 01              Request ID    1: copied from the REQUEST it answers
                                             -- RESPONSE payload (SPEC 5.2) --
0008  00 c8                    Status        0x00c8 = 200 OK
                                             -- header block: 5 entries --
000a  04                       Index         4 = content-type
000b  00 19                    VLen          25
000d  74 65 78 74 2f 70 6c 61  Value         "text/plain; charset=utf-8"
      69 6e 3b 20 63 68 61 72
      73 65 74 3d 75 74 66 2d
      38
0026  05                       Index         5 = content-length
0027  00 02                    VLen          2
0029  31 34                    Value         "14": the body is 14 bytes (frame 3)
002b  06                       Index         6 = last-modified
002c  00 1d                    VLen          29
002e  54 68 75 2c 20 30 38 20  Value         "Thu, 08 Oct 2026 12:01:37 GMT"
      4f 63 74 20 32 30 32 36
      20 31 32 3a 30 31 3a 33
      37 20 47 4d 54
004b  07                       Index         7 = date
004c  00 1d                    VLen          29
004e  54 68 75 2c 20 30 38 20  Value         "Thu, 08 Oct 2026 12:08:46 GMT"
      4f 63 74 20 32 30 32 36
      20 31 32 3a 30 38 3a 34
      36 20 47 4d 54
006b  08                       Index         8 = server
006c  00 0a                    VLen          10
006e  62 73 65 72 76 65 2f 31  Value         "bserve/1.0"
      2e 30
```

Check: 2 status bytes + 5 entries of (1 index + 2 length) bytes + 25 + 2 + 29 + 29 + 10
value bytes = 2 + 15 + 95 = 112, matching Length. All five names came from the static
table, so not one byte of header *name* crossed the wire.

## Frame 3: DATA, server to client (22 bytes)

```text
off   bytes                    field         meaning
----  -----------------------  ------------  ---------------------------------------------
                                             -- frame header --
0000  00 0e                    Length        0x000e = 14 payload bytes
0002  03                       Type          0x03 DATA
0003  01                       Flags         0x01 END: last frame of this body, response done
0004  00 00 00 01              Request ID    1: same request
                                             -- DATA payload (SPEC 6) --
0008  48 65 6c 6c 6f 2c 20 62  Body          "Hello, bhttp!\n"
      68 74 74 70 21 0a
```

The body is 14 bytes, equal to `content-length`, and END is set, so bcurl writes the 14
bytes to stdout, has a complete 200 response, and exits 0. Had the file been larger than
16384 bytes, it would have arrived as several DATA frames with END only on the last.

## What the bytes add up to

| Direction | Frames | Bytes on the wire | Of which framing |
|---|---|---|---|
| client to server | REQUEST | 56 | 8 (header) |
| server to client | RESPONSE, DATA | 120 + 22 = 142 | 16 (two headers) |

For comparison, the same request and response written as HTTP/1.1 text, with the same
header values, would be 85 and 197 bytes (computed, not captured). The savings come from
the indexed names and the length prefixes, which replace `Name: ` and `\r\n` delimiters.

After frame 3 the connection stays open: bcurl had only one URL, so it closed the
connection itself, and bserve logged `peer closed, 1 request`. With more URLs, bcurl
would have sent the next REQUEST, with Request ID 2, on the same connection.
