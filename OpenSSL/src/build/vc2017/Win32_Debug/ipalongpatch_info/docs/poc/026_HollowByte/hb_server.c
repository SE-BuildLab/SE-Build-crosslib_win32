/*
 * Measurement server for the HollowByte issue (LP: #2161371): accepts COUNT
 * TCP connections, calls SSL_accept() on each (non-blocking), and reports the
 * heap in use (mallinfo2: uordblks + hblkhd) and VmRSS/VmData at three points:
 *   P1: after COUNT connections were accepted and SSL_accept() called once
 *       (no data yet: fixed per-connection cost - SSL object, 16 KiB init_buf,
 *       read/write buffers)
 *   P2: after every connection delivered its 9 byte header and SSL_accept()
 *       processed it (unpatched: init_buf grown to claimed length + 4 right away;
 *       patched: grown by at most one 16 KiB chunk)
 * usage: hb_server PORT COUNT CERT KEY
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static long proc_kb(const char *key)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;

    if (f == NULL)
        return -1;
    while (fgets(line, sizeof(line), f) != NULL)
        if (strncmp(line, key, strlen(key)) == 0) {
            v = atol(line + strlen(key));
            break;
        }
    fclose(f);
    return v;
}

static size_t heap_in_use(void)
{
    struct mallinfo2 mi = mallinfo2();
    return mi.uordblks + mi.hblkhd;
}

static void report(const char *tag, int count)
{
    printf("%-60s heap_in_use=%10zu bytes  VmRSS=%7ld kB  VmData=%7ld kB\n", tag, heap_in_use(),
           proc_kb("VmRSS:"), proc_kb("VmData:"));
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int port, count, lfd, i, one = 1, ready = 0, got = 0;
    SSL_CTX *ctx;
    SSL **ssl;
    int *fds, *hdr_done;
    struct sockaddr_in sa;
    size_t h0, h1, h2;
    struct pollfd *pfd;

    if (argc != 5)
        return 2;
    port = atoi(argv[1]);
    count = atoi(argv[2]);
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL || SSL_CTX_use_certificate_file(ctx, argv[3], SSL_FILETYPE_PEM) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    ssl = calloc(count, sizeof(*ssl));
    fds = calloc(count, sizeof(*fds));
    hdr_done = calloc(count, sizeof(*hdr_done));
    pfd = calloc(count, sizeof(*pfd));

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(lfd, 512) != 0) {
        perror("bind/listen");
        return 2;
    }
    printf("[server] %s listening on 127.0.0.1:%d, expecting %d connections\n",
           OpenSSL_version(OPENSSL_VERSION), port, count);
    h0 = heap_in_use();
    report("P0 before accepting:", count);

    /* accept all connections, call SSL_accept once (no data -> WANT_READ) */
    for (i = 0; i < count; i++) {
        int fd = accept(lfd, NULL, NULL), r;

        if (fd < 0) {
            perror("accept");
            return 2;
        }
        fcntl(fd, F_SETFL, O_NONBLOCK);
        fds[i] = fd;
        ssl[i] = SSL_new(ctx);
        SSL_set_fd(ssl[i], fd);
        r = SSL_accept(ssl[i]);
        if (r <= 0 && SSL_get_error(ssl[i], r) != SSL_ERROR_WANT_READ) {
            printf("[server] unexpected SSL_accept result on connection %d\n", i);
            ERR_print_errors_fp(stderr);
        }
    }
    h1 = heap_in_use();
    report("P1 all connections accepted, SSL_accept() called, no data yet:", count);
    printf("   per-connection fixed cost: %zu bytes\n", (h1 - h0) / count);

    /* now wait for the 9 byte headers and let SSL_accept() process them */
    while (got < count) {
        int n;

        for (i = 0; i < count; i++) {
            pfd[i].fd = hdr_done[i] ? -1 : fds[i];
            pfd[i].events = POLLIN;
            pfd[i].revents = 0;
        }
        n = poll(pfd, count, 15000);
        if (n <= 0) {
            printf("[server] poll timeout/error with %d of %d headers processed\n", got, count);
            break;
        }
        for (i = 0; i < count; i++) {
            if (pfd[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                int r = SSL_accept(ssl[i]);
                int e = r <= 0 ? SSL_get_error(ssl[i], r) : 0;

                hdr_done[i] = 1;
                got++;
                if (r <= 0 && e != SSL_ERROR_WANT_READ) {
                    printf("[server] connection %d: SSL_accept()=%d error %d (%s)\n", i, r, e,
                           ERR_reason_error_string(ERR_peek_error()));
                    ERR_clear_error();
                } else {
                    ready++;
                }
            }
        }
    }
    h2 = heap_in_use();
    report("P2 every connection delivered its 9 byte header, SSL_accept() -> WANT_READ:", count);
    printf("   %d connections are now waiting for a %s message body that never comes\n", ready,
           "ClientHello");
    printf("   heap growth caused by the 9 byte headers: %zu bytes total = %zu bytes per connection\n",
           h2 - h1, count ? (h2 - h1) / count : 0);
    printf("RESULT: per-connection growth after the header = %zu bytes (%s)\n", count ? (h2 - h1) / count : 0,
           (count && (h2 - h1) / count > 65536) ? "VULNERABLE: init_buf pre-allocated to the claimed size"
                                                  : "OK: buffer grows only with received data");
    for (i = 0; i < count; i++) {
        SSL_free(ssl[i]);
        close(fds[i]);
    }
    SSL_CTX_free(ctx);
    free(ssl); free(fds); free(hdr_done); free(pfd);
    return 0;
}
