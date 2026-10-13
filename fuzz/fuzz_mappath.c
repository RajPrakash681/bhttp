/*
 * fuzz_mappath.c - bserve's path mapping and open (SPEC 8, open_path) against a real directory
 * tree with symlinks that escape ROOT. Whatever map_path accepts must resolve
 * to a regular file inside ROOT; nothing hidden or outside may come back.
 */
#define main bserve_main
#include "../src/bserve.c"
#undef main

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct config fcfg;

static void put(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char dir[] = "/tmp/bh-mappath-XXXXXX";
    char p[PATH_MAX];
    (void)argc;
    (void)argv;
    if (mkdtemp(dir) == NULL)
        abort();
    /* outside/ is next to root/, with a name that shares root's prefix */
    snprintf(p, sizeof p, "%s/root", dir);         mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/rootx", dir);        mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/rootx/secret", dir); put(p, "secret\n");
    snprintf(p, sizeof p, "%s/outside", dir);      put(p, "outside\n");
    snprintf(p, sizeof p, "%s/root/a.txt", dir);   put(p, "a\n");
    snprintf(p, sizeof p, "%s/root/index.html", dir); put(p, "<p>i</p>\n");
    snprintf(p, sizeof p, "%s/root/d", dir);       mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/root/d/index.html", dir); put(p, "d\n");
    snprintf(p, sizeof p, "%s/root/e", dir);       mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/root/e/index.html", dir); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/root/.hidden", dir); put(p, "h\n");
    snprintf(p, sizeof p, "%s/root/out", dir);     (void)symlink("../outside", p);
    snprintf(p, sizeof p, "%s/root/outx", dir);    (void)symlink("../rootx", p);
    snprintf(p, sizeof p, "%s/root/etc", dir);     (void)symlink("/etc", p);
    snprintf(p, sizeof p, "%s/root/in", dir);      (void)symlink("a.txt", p);
    snprintf(p, sizeof p, "%s/root/loop", dir);    (void)symlink("loop", p);
    snprintf(p, sizeof p, "%s/root/fifo", dir);    (void)mkfifo(p, 0644);
    snprintf(p, sizeof p, "%s/root", dir);
    if (realpath(p, fcfg.root) == NULL)
        abort();
    fcfg.root_len = strlen(fcfg.root);
    fcfg.root_fd = open(fcfg.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fcfg.root_fd < 0)
        abort();
    fcfg.idle_ms = 1000;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char real[PATH_MAX];
    const char *err = NULL;
    uint8_t *p;
    size_t plen;
    unsigned st;

    if (size > BH_MAX_PAYLOAD)
        return 0;
    p = malloc(size ? size : 1);
    memcpy(p, data, size);
    if (bh_path_check(p, size, &err) == 0) {
        plen = bh_path_part_len(p, size);
        int fd = -1;
        struct stat sb;
        st = open_path(&fcfg, p, plen, &fd, &sb, real);
        if (st == 0) {
            struct stat again;
            if (fd < 0 || !S_ISREG(sb.st_mode))
                abort();
            if (strncmp(real, fcfg.root, fcfg.root_len) != 0 ||
                (real[fcfg.root_len] != '/' && real[fcfg.root_len] != '\0'))
                abort();   /* escaped ROOT */
            if (strstr(real + fcfg.root_len, "/.") != NULL)
                abort();   /* hidden file served */
            /* the descriptor must be the file realpath named */
            if (stat(real, &again) != 0 || again.st_ino != sb.st_ino || again.st_dev != sb.st_dev)
                abort();
            (void)content_type(real);
            close(fd);
        } else {
            if (fd >= 0)
                abort();   /* descriptor leaked on an error path */
            if (st != 301 && st != 403 && st != 404 && st != 500)
                abort();
        }
    }
    free(p);
    return 0;
}
