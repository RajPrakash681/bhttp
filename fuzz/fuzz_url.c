/*
 * fuzz_url.c - bcurl's URL parser (SPEC 11), and the REQUEST bcurl builds
 * from a parsed URL (sent to /dev/null, dumped as with -v).
 */
#define main bcurl_main
#include "../src/bcurl.c"
#undef main

#include <fcntl.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct client *cl;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    cl = calloc(1, sizeof *cl);
    cl->fd = open("/dev/null", O_WRONLY);
    cl->verbose = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct url u, v;
    const char *err = NULL;
    char *text;

    if (size > 70000)
        return 0;
    text = malloc(size + 1);
    memcpy(text, data, size);
    text[size] = '\0';

    if (parse_url(text, &u, &err) == 0) {
        size_t hl = strnlen(u.host, sizeof u.host);
        unsigned long port;
        if (hl == 0 || hl >= sizeof u.host)
            abort();
        port = strtoul(u.port, NULL, 10);
        if (port < 1 || port > 65535)
            abort();
        if (u.slash + u.path_len > 0xffffu || u.path_len == 0)
            abort();
        if (!((u.path_len == 1 && u.path[0] == '/') ||
              (u.path >= text && u.path + u.path_len <= text + size)))
            abort();
        if (memchr(u.path, '#', u.path_len) != NULL)
            abort();   /* the fragment is never sent */
        if (!same_origin(&u, &u))
            abort();
        if (parse_url(text, &v, &err) != 0 || !same_origin(&u, &v))
            abort();
        (void)send_request(cl, &u, 1);
    } else if (err == NULL) {
        abort();
    }
    free(text);
    return 0;
}
