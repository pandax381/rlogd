/*
 * Copyright (c) 2014,2015 KLab Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <pthread.h>
#include <ev.h>
#include "common.h"
#include "protocol.h"
#include "buffer.h"

#define APP_NAME "rloggerd"

#define DEFAULT_BUFFER "/var/run/rlogd/rloggerd.buf"
#define DEFAULT_CHUNK DEFAULT_BUFFER_CHUNK_LIMIT
#define DEFAULT_FLUSH DEFAULT_FLUSH_INTERVAL
#define DEFAULT_LISTEN_ADDR DEFAULT_RLOGGERD_SOCKET
#define DEFAULT_TARGET_ADDR DEFAULT_RLOGD_SOCKET

struct opts {
    int debug;
    char *buffer;
    int chunk;
    int flush;
    char *listen;
    char *target;
    char *user;
    int mode;
};

struct context {
    struct opts *opts;
    struct {
        struct ev_io w;
    } listen;
    struct {
        struct ev_io w;
        struct ev_timer retry_w;
    } connect;
    struct timeval tstamp;
    struct buffer buffer;
    int terminate;
    LIST_HEAD(/**/, e_context) head;
};

struct e_context {
    struct context *parent;
    struct ev_io w;
    struct buf rbuf;
    LIST_ENTRY(e_context) lp;
};

static void
on_message (struct e_context *ctx, struct hdr *hdr, size_t len) {
    char *tag;
    size_t tag_len;
    struct entry *s, *e;
    size_t n;

    tag = (char *)(hdr + 1);
    tag_len = ntohs(hdr->off) - sizeof(struct hdr);
    s = e = (struct entry *)(tag + tag_len);
    while ((caddr_t)e < (caddr_t)hdr + len) {
        n = sizeof(struct hdr) + tag_len + (((caddr_t)(e + 1) + ntohl(e->len)) - (caddr_t)s);
        if ((size_t)ctx->parent->opts->chunk < ctx->parent->buffer.len + n) {
            if (e != s) {
                buffer_write(&ctx->parent->buffer, tag, tag_len, s, (caddr_t)e - (caddr_t)s);
                s = e;
            }
            if (ctx->parent->buffer.len) {
                if (buffer_flush(&ctx->parent->buffer) == -1) {
                    // TODO
                }
            }
            n = sizeof(struct hdr) + tag_len + (((caddr_t)(e + 1) + ntohl(e->len)) - (caddr_t)s);
            if ((size_t)ctx->parent->opts->chunk < ctx->parent->buffer.len + n) {
                fprintf(stderr, "warning: entry too long\n");
                s = e;
            }
        }
        e = (struct entry *)((caddr_t)(e + 1) + ntohl(e->len));
    }
    if (e != s) {
        buffer_write(&ctx->parent->buffer, tag, tag_len, s, (caddr_t)e - (caddr_t)s);
    }
}

static void
on_read (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct e_context *ctx;
    ssize_t n;
    struct hdr *hdr;
    size_t len;

    ctx = (struct e_context *)w->data;
    n = read(w->fd, ctx->rbuf.data + ctx->rbuf.len, ctx->rbuf.alloc - ctx->rbuf.len);
    if (n <= 0) {
        if (n) {
            if (errno == EINTR) {
                return;
            }
            perror("recv");
        }
        close(w->fd);
        ev_io_stop(loop, w);
        LIST_REMOVE(ctx, lp);
        free(ctx->rbuf.data);
        free(ctx);
        return;
    }
    ctx->rbuf.len += n;
    hdr = ctx->rbuf.data;
    while (ctx->rbuf.len > sizeof(struct hdr)) {
        len = ntohl(hdr->len);
        if (ctx->rbuf.len < len) {
            break;
        }
        on_message(ctx, hdr, len);
        hdr = (struct hdr *)((caddr_t)hdr + len);
        ctx->rbuf.len -= len;
    }
    if (hdr != ctx->rbuf.data) {
        memmove(ctx->rbuf.data, hdr, ctx->rbuf.len);
    }
}

static void
on_accept (struct ev_loop *loop, struct ev_io *w, int revents) {
    int soc;
    struct e_context *ctx;

    soc = accept(w->fd, NULL, NULL);
    if (soc == -1) {
        perror("accept");
        return;
    }
    ctx = (struct e_context *)malloc(sizeof(struct e_context));
    if (!ctx) {
        fprintf(stderr, "malloc error\n");
        close(soc);
        return;
    }
    memset(ctx, 0, sizeof(struct e_context));
    ctx->parent = (struct context *)w->data;
    ctx->rbuf.alloc = ctx->parent->opts->chunk;
    ctx->rbuf.data = malloc(ctx->rbuf.alloc);
    ev_io_init(&ctx->w, on_read, soc, EV_READ);
    ctx->w.data = ctx;
    ev_io_start(loop, &ctx->w);
    LIST_INSERT_HEAD(&ctx->parent->head, ctx, lp);
}

static void
on_timer (struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct context *ctx;
    struct timeval now, diff;

    ctx = (struct context *)w->data;
    if (!ctx->buffer.len || ctx->buffer.cursor->r != ctx->buffer.cursor->w) {
        return;
    }
    gettimeofday(&now, NULL);
    tvsub(&now, &ctx->buffer.tstamp, &diff);
    if (diff.tv_sec >= (time_t)ctx->opts->flush) {
        if (buffer_flush(&ctx->buffer) == -1) {
            // TODO
        }
    }
}

static void
on_signal (struct ev_loop *loop, struct ev_signal *w, int revents) {
    struct context *ctx;

    fprintf(stderr, "receive signal: signum=%d\n", w->signum);
    ctx = (struct context *)w->data;
    ctx->terminate = 1;
    ev_break(loop, EVBREAK_ALL);
}

static int
wait_ack (struct context *ctx, uint32_t seq) {
    int ret;
    struct pollfd pfd;
    struct hdr ack;
    size_t done = 0;
    ssize_t n;

    pfd.fd = ctx->connect.w.fd;
    pfd.events = POLLIN;
    while (1) {
        if ((ret = poll(&pfd, 1, 1000)) <= 0) {
            if (ret == 0 || errno == EINTR) {
                continue;
            }
            perror("poll");
            return -1;
        }
        n = recv(pfd.fd, (char *)&ack + done, sizeof(ack) - done, 0);
        switch (n) {
        case -1:
            if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            }
            perror("recv");
            return -1;
        case  0:
            fprintf(stderr, "WARNING: connection close.\n");
            if (n) {
                fprintf(stderr, "WARNING: unprocessed %zu bytes data.\n", done);
            }
            return -1;
        }
        done += n;
        if (done < sizeof(ack)) {
            continue;
        }
        if (ntohl(ack.seq) == seq) {
            break;
        }
    }
    return 0;
}

static ssize_t
_sendfile (int out_fd, int in_fd, size_t count) {
    char buf[65536];
    ssize_t n, done = 0;

    while (done < (ssize_t)count) {
        n = read(in_fd, buf, MIN(sizeof(buf), (count - done)));
        if (n <= 0) {
            if (n) {
                if (errno == EINTR) {
                    continue;
                }
                // TODO
                perror("read");
                return -1;
            }
            break;
        }
        writen(out_fd, buf, n);
        done += n;
    }
    return done;
}

static void
on_write (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    char path[PATH_MAX];
    int fd;
    struct hdr hdr;
    ssize_t n, done = 0, len;

    ctx = (struct context *)w->data;
    if (ctx->terminate) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    snprintf(path, sizeof(path), "%s/%s.%d", ctx->opts->buffer, BUFFER_FILE_NAME, ctx->buffer.cursor->r);
    fd = open(path, O_RDWR);
    if (fd == -1) {
        // TODO
        sleep(1);
        return;
    }
    fprintf(stderr, "forward_buffer: %s\n", path);
    while (1) {
        n = read(fd, &hdr, sizeof(hdr) - done);
        if (n <= 0) {
            if (n) {
                if (errno == EINTR) {
                    continue;
                }
                perror("read");
                close(fd);
                return;
            }
            break;
        }
        done += n;
        if (done < (ssize_t)sizeof(hdr)) {
            continue;
        }
        writen(w->fd, &hdr, sizeof(hdr));
        done = 0;
        len = ntohl(hdr.len) - sizeof(hdr);
        while (done < len) {
            n = _sendfile(w->fd, fd, len - done);
            if (n == -1) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                ev_io_stop(loop, w);
                close(w->fd);
                w->fd = -1;
                ev_timer_set(&ctx->connect.retry_w, 3.0, 0.0);
                ev_timer_start(loop, &ctx->connect.retry_w);
                return;
            }
            if (n != (len - done)) {
                fprintf(stderr, "_sendfile error: n=%zd, (len - done)=%zd\n", n, len - done);
                close(fd);
                ev_io_stop(loop, w);
                close(w->fd);
                w->fd = -1;
                ev_timer_set(&ctx->connect.retry_w, 3.0, 0.0);
                ev_timer_start(loop, &ctx->connect.retry_w);
                return;
            }
            done += n;
        }
        if (wait_ack(ctx, ntohl(hdr.seq)) == -1) {
            close(fd);
            ev_io_stop(loop, w);
            close(w->fd);
            w->fd = -1;
            ev_timer_set(&ctx->connect.retry_w, 3.0, 0.0);
            ev_timer_start(loop, &ctx->connect.retry_w);
            return;
        }
        done = 0;
    }
    close(fd);
    ctx->buffer.cursor->r++;
    unlink(path);
}

static void
on_retry (struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct context *ctx;
    int soc, opt;

    ctx = (struct context *)w->data;
    if (ctx->terminate) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    soc = setup_client_socket(ctx->opts->target, DEFAULT_RLOGD_PORT, 0);
    if (soc == -1) {
        ev_timer_set(w, 3.0, 0.0);
        ev_timer_start(loop, w);
        return;
    }
    opt = 1;
    setsockopt(w->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); // ignore error
    ev_io_init(&ctx->connect.w, on_write, soc, EV_WRITE);
    ev_io_start(loop, &ctx->connect.w);
    fprintf(stderr, "Connection Established: soc=%d\n", soc);
}

void *
thread_main (void *arg) {
    struct context *ctx;
    struct ev_loop *loop;
    int soc, opt;

    ctx = (struct context *)arg;
    loop = ev_loop_new(0);
    if (!loop) {
        return NULL;
    }
    ctx->connect.w.data = ctx;
    ctx->connect.retry_w.data = ctx;
    ev_timer_init(&ctx->connect.retry_w, on_retry, 3.0, 0.0);
    soc = setup_client_socket(ctx->opts->target, DEFAULT_RLOGD_PORT, 0);
    if (soc == -1) {
        ev_timer_start(loop, &ctx->connect.retry_w);
    } else {
        opt = 1;
        setsockopt(w->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); // ignore error
        ev_io_init(&ctx->connect.w, on_write, soc, EV_WRITE);
        ev_io_start(loop, &ctx->connect.w);
        fprintf(stderr, "Connection Established: soc=%d\n", soc);
    }
    ev_run(loop, 0);
    ev_loop_destroy(loop);
    return NULL;
}

static void
usage (void) {
    printf("usage: %s [options]\n", APP_NAME);
    printf("  options:\n");
    printf("    -d, --debug         # debug mode\n");
    printf("    -l, --listen=ADDR   # listen address (default: %s)\n", DEFAULT_LISTEN_ADDR);
    printf("    -t, --target=TARGET # target address (default: %s)\n", DEFAULT_TARGET_ADDR);
    printf("    -u, --user=USER     # socket file owner\n");
    printf("    -m, --mode=MODE     # socket file permission (default: %o)\n", DEFAULT_SOCKET_MODE);
    printf("    -b, --buffer=PATH   # file buffer directory path (default: %s)\n", DEFAULT_BUFFER);
    printf("    -c, --chunk=SIZE    # maximum length of the chunk (default: %d)\n", DEFAULT_CHUNK);
    printf("    -f, --flush=TIME    # time to flush the chunk (default: %d)\n", DEFAULT_FLUSH);
    printf("        --help          # show this message\n");
    printf("        --version       # show version\n");
}

static void
version (void) {
    printf("%s %s\n", APP_NAME, PACKAGE_VERSION);
}

static int
parse_options (struct opts *opts, int argc, char *argv[]) {
    int opt;
    struct option long_options[] = {
        {"debug",   0, NULL, 'd'},
        {"listen",  1, NULL, 'l'},
        {"target",  1, NULL, 't'},
        {"user",    1, NULL, 'u'},
        {"mode",    1, NULL, 'm'},
        {"buffer",  1, NULL, 'b'},
        {"chunk",   1, NULL, 'c'},
        {"flush",   1, NULL, 'f'},
        {"help",    0, NULL,  2 },
        {"version", 0, NULL,  1 },
        { NULL,     0, NULL,  0 }
    };

    memset(opts, 0, sizeof(struct opts));
    opts->listen = DEFAULT_LISTEN_ADDR;
    opts->target = DEFAULT_TARGET_ADDR;
    opts->user = NULL;
    opts->mode = DEFAULT_SOCKET_MODE;
    opts->buffer = DEFAULT_BUFFER;
    opts->chunk = DEFAULT_CHUNK;
    opts->flush = DEFAULT_FLUSH;
    while ((opt = getopt_long_only(argc, argv, "dl:u:m:t:b:c:f:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            opts->debug = 1;
            break;
        case 'l':
            opts->listen = optarg;
            break;
        case 't':
            opts->target = optarg;
            break;
        case 'u':
            opts->user = optarg;
            break;
        case 'm':
            opts->mode = strtol(optarg, NULL, 8);
            if (opts->mode == -1) {
                usage();
                return -1;
            }
            break;
        case 'b':
            opts->buffer = optarg;
            break;
        case 'c':
            opts->chunk = strtol(optarg, NULL, 10);
            if (opts->chunk == -1) {
                usage();
                return -1;
            }
            break;
        case 'f':
            opts->flush = strtol(optarg, NULL, 10);
            if (opts->flush == -1) {
                usage();
                return -1;
            }
            break;
        case 2:
            usage();
            exit(EXIT_SUCCESS);
        case 1:
            version();
            exit(EXIT_SUCCESS);
        default:
            usage();
            return -1;
        }
    }
    if (optind != argc) {
        usage();
        return -1;
    }
    return 0;
}

static void
terminate (struct context *ctx) {
    if (ctx->buffer.len && ctx->buffer.fd != -1) {
        close(ctx->buffer.fd);
    }
    if (strncmp(ctx->opts->listen, "unix://", 7) == 0) {
        unlink(ctx->opts->listen + 7);
    }
}

int
main (int argc, char *argv[]) {
    struct opts opts;
    struct context ctx;
    int soc;
    struct ev_loop *loop;
    struct ev_timer timer_w;
    struct {
        int signum;
        struct ev_signal w;
    } signals[] = {
        {.signum = SIGINT},
        {.signum = SIGTERM},
        {.signum = SIGHUP},
        {.signum = 0}
    }, *s;
    pthread_t thread;

    sig_ignore(SIGPIPE);
    if (parse_options(&opts, argc, argv) == -1) {
        return -1;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.opts = &opts;
    if (buffer_init(&ctx.buffer, opts.buffer) == -1) {
        fprintf(stderr, "buffer_init: failure\n");
        return -1;
    }
    soc = setup_server_socket(opts.listen, DEFAULT_RLOGGERD_PORT, SOMAXCONN, 0);
    if (soc == -1) {
        terminate(&ctx);
        return -1;
    }
    if (strncmp(opts.listen, "unix://", 7) == 0) {
        if (chperm(opts.listen + 7, opts.user, opts.mode) == -1) {
            close(soc);
            terminate(&ctx);
            return -1;
        }
    }
    loop = ev_loop_new(0);
    ctx.listen.w.data = &ctx;
    ev_io_init(&ctx.listen.w, on_accept, soc, EV_READ);
    ev_io_start(loop, &ctx.listen.w);
    timer_w.data = &ctx;
    ev_timer_init(&timer_w, on_timer, 0.0, 1.0);
    ev_timer_start(loop, &timer_w);
    for (s = signals; s->signum; s++) {
        s->w.data =&ctx;
        ev_signal_init(&s->w, on_signal, s->signum);
        ev_signal_start(loop, &s->w);
    }
    pthread_create(&thread, NULL, thread_main, &ctx);
    ev_run(loop, 0);
    pthread_join(thread, NULL);
    close(soc);
    terminate(&ctx);
    ev_loop_destroy(loop);
    return 0;
}
