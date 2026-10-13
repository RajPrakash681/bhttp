/*
 * fuzz_server.c - a whole bserve connection. The input is everything a
 * client sends; it is written into a socketpair and half-closed, and the real
 * per-connection entry point (handle_connection) runs on the other end, with a
 * thread draining what the server writes back. Serves a small tree with a
 * 40000-byte file, a directory, a hidden file and symlinks out of ROOT.
 */
#define main bserve_main
#include "../src/bserve.c"
#undef main

#include <pthread.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct config scfg;

static void *drain(void *arg)
{
    int fd = *(int *)arg;
    uint8_t buf[65536];
    while (read(fd, buf, sizeof buf) > 0)
        ;
    return NULL;
}

static void put(const char *path, size_t n)
{
    FILE *f = fopen(path, "w");
    if (f) {
        for (size_t i = 0; i < n; i++)
            fputc('a' + (int)(i % 26), f);
        fclose(f);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char dir[] = "/tmp/bh-server-XXXXXX";
    char p[PATH_MAX];
    (void)argc;
    (void)argv;
    if (mkdtemp(dir) == NULL)
        abort();
    snprintf(p, sizeof p, "%s/outside", dir);           put(p, 7);
    snprintf(p, sizeof p, "%s/root", dir);              mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/root/a.txt", dir);        put(p, 14);
    snprintf(p, sizeof p, "%s/root/b.bin", dir);        put(p, 40000);
    snprintf(p, sizeof p, "%s/root/e.txt", dir);        put(p, 0);
    snprintf(p, sizeof p, "%s/root/x", dir);            put(p, 16384);
    snprintf(p, sizeof p, "%s/root/index.html", dir);   put(p, 9);
    snprintf(p, sizeof p, "%s/root/d", dir);            mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/root/d/index.html", dir); put(p, 3);
    snprintf(p, sizeof p, "%s/root/.h", dir);           put(p, 2);
    snprintf(p, sizeof p, "%s/root/o", dir);            (void)symlink("../outside", p);
    snprintf(p, sizeof p, "%s/root", dir);
    if (realpath(p, scfg.root) == NULL)
        abort();
    scfg.root_len = strlen(scfg.root);
    scfg.root_fd = open(scfg.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scfg.root_fd < 0)
        abort();
    scfg.idle_ms = 2000;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int sv[2];
    pthread_t t;
    struct sockaddr_storage ss;
    int big = 1 << 20;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        abort();
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    if (io_write_full(sv[0], data, size) != BH_IO_OK)
        abort();
    shutdown(sv[0], SHUT_WR);
    pthread_create(&t, NULL, drain, &sv[0]);
    memset(&ss, 0, sizeof ss);
    (void)handle_connection(&scfg, sv[1], &ss);   /* closes sv[1] */
    pthread_join(t, NULL);
    close(sv[0]);
    return 0;
}
