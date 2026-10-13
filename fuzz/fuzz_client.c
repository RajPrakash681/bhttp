/*
 * fuzz_client.c - bcurl against a hostile server. The input is everything the
 * server sends; bcurl's real fetch() loop runs for three URLs on one
 * connection, exactly as main() drives it, with -v dumping on or off.
 */
#define main bcurl_main
#include "../src/bcurl.c"
#undef main

#include <fcntl.h>
#include <pthread.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct client *cl;
static struct url urls[3];

static void *drain(void *arg)
{
    int fd = *(int *)arg;
    uint8_t buf[65536];
    while (read(fd, buf, sizeof buf) > 0)
        ;
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *err;
    int null = open("/dev/null", O_WRONLY);
    (void)argc;
    (void)argv;
    dup2(null, STDOUT_FILENO);   /* bodies go to stdout */
    close(null);
    cl = calloc(1, sizeof *cl);
    if (parse_url("bhttp://localhost:9000/a.txt", &urls[0], &err) != 0 ||
        parse_url("localhost:9000?q", &urls[1], &err) != 0 ||
        parse_url("localhost:9000/d/#frag", &urls[2], &err) != 0)
        abort();
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int sv[2];
    pthread_t t;
    int big = 1 << 20;

    if (size < 1)
        return 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        abort();
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    if (io_write_full(sv[0], data + 1, size - 1) != BH_IO_OK)
        abort();
    shutdown(sv[0], SHUT_WR);
    pthread_create(&t, NULL, drain, &sv[0]);
    cl->fd = sv[1];
    cl->verbose = data[0] & 1;
    for (uint32_t i = 0; i < 3; i++) {
        unsigned status = 0;
        if (fetch(cl, &urls[i], i + 1, &status) != 0)
            break;
        if (status < 200 || status > 599)
            abort();   /* fetch must never report a status it rejected */
    }
    close(sv[1]);
    pthread_join(t, NULL);
    close(sv[0]);
    return 0;
}
