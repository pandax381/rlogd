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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <ev.h>
#include "config.h"
#include "common.h"
#include "protocol.h"

#define APP_NAME "rlogger"

#define DEFAULT_TARGET   DEFAULT_RLOGGERD_SOCKET
#define DEFAULT_LIMIT    DEFAULT_BUFFER_CHUNK_LIMIT
#define DEFAULT_INTERVAL DEFAULT_FLUSH_INTERVAL
#define DEFAULT_TAG      "system.notice"

#define RBUF_SIZ 65536

typedef struct {
    int debug;
    char *target;
    int timeout;
    int limit;
    int interval;
    struct string tag;
} option_t;

struct context {
    option_t option;
    int fd;
    struct buf rbuf;
    struct buf sbuf;
    struct timeval tstamp;
    int skip;
    int broken;
};

struct signal_def {
    int signum;
    struct ev_signal w;
};

static struct signal_def signals[] = {
    {.signum = SIGINT },
    {.signum = SIGTERM},
    {.signum = 0}
};

static int
on_flush (struct context *ctx) {
    size_t off;
    struct hdr hdr;
    struct iovec iov[3];

    off = sizeof(hdr) + ctx->option.tag.len;
    hdr.ver  = HDR_VERSION;
    hdr.type = HDR_TYPE_PSH;
    hdr.off  = htons(off);
    hdr.seq  = htonl(0);
    hdr.len  = htonl(off + ctx->sbuf.len);
    iov[0].iov_base = &hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = ctx->option.tag.text;
    iov[1].iov_len  = ctx->option.tag.len;
    iov[2].iov_base = ctx->sbuf.data;
    iov[2].iov_len  = ctx->sbuf.len;
    if (writevn(ctx->fd, iov, 3) == -1) {
        return -1;
    }
    ctx->sbuf.len = 0;
    return 0;
}

static int
on_message (struct context *ctx, struct timeval *tstamp, const char *data, size_t len) {
    struct entry *entry;

    if (!buf_permit(&ctx->sbuf, sizeof(struct entry) + len)) {
        if (on_flush(ctx) == -1) {
            return -1;
        }
        if (!buf_permit(&ctx->sbuf, sizeof(struct entry) + len)) {
            fprintf(stderr, "send buffer full: entry too long.\n");
            return 0; /* ignore error */
        }
    }
    entry = (struct entry *)(buf_tail(&ctx->sbuf));
    entry->timestamp = htonl((uint32_t)tstamp->tv_sec);
    entry->len = htonl(len);
    memcpy(entry->data, data, len);
    if (entry == ctx->sbuf.data) {
        ctx->tstamp = *tstamp;
    }
    ctx->sbuf.len += sizeof(struct entry) + len;
    return 0;
}

static void
on_stdin_read (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    ssize_t n;
    struct timeval tstamp;
    char *s, *e;

    ctx = (struct context *)w->data;
    if (ctx->broken) {
        return;
    }
    if (buf_full(&ctx->rbuf)) {
        fprintf(stderr, "receive buffer full: message too long.\n");
        ctx->rbuf.len = 0;
        ctx->skip = 1;
    }
    n = read(w->fd, buf_tail(&ctx->rbuf), buf_capacity(&ctx->rbuf));
    if (n <= 0) {
        if (n) {
            if (errno == EINTR) {
                return;
            }
            perror("read");
        }
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    ctx->rbuf.len += n;
    gettimeofday(&tstamp, NULL);
    s = ctx->rbuf.data;
    while ((e = memchr(s, '\n', buf_lengthat(&ctx->rbuf, s))) != NULL) {
        if (ctx->skip) {
            ctx->skip = 0;
        } else {
            if (on_message(ctx, &tstamp, s, e - s) == -1) {
                ctx->broken = 1;
                ev_break(loop, EVBREAK_ALL);
                return;
            }
        }
        s = (e + 1);
    }
    if (!ctx->option.interval && !buf_empty(&ctx->rbuf)) {
        if (on_flush(ctx) == -1) {
            ctx->broken = 1;
            ev_break(loop, EVBREAK_ALL);
            return;
        }
    }
    buf_removeat(&ctx->rbuf, s);
}

static void
on_socket_read (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    char buf[1024];
    ssize_t n;

    ctx = (struct context *)w->data;
    n = read(w->fd, buf, sizeof(buf));
    if (n <= 0) {
        if (n) {
            if (errno == EINTR) {
                return;
            }
            perror("read");
        }
        ctx->broken = 1;
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    fprintf(stderr, "unknown '%zu' bytes data receive via socket.\n", n);
}

static void
on_timer (struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct context *ctx;
    struct timeval now, diff;

    ctx = (struct context *)w->data;
    if (buf_empty(&ctx->sbuf) || ctx->broken) {
        return;
    }
    gettimeofday(&now, NULL);
    tvsub(&now, &ctx->tstamp, &diff);
    if (diff.tv_sec > (time_t)ctx->option.interval) {
        if (on_flush(ctx) == -1) {
            ctx->broken = 1;
            ev_break(loop, EVBREAK_ALL);
        }
    }
}

static void
on_signal (struct ev_loop *loop, struct ev_signal *w, int revents) {
    fprintf(stderr, "receive signal: signum=%d\n", w->signum);
    ev_break(loop, EVBREAK_ALL);
}

static void
terminate (struct context *ctx) {
    close(ctx->fd);
    free(ctx->sbuf.data);
    free(ctx->rbuf.data);
}

static void
on_timeout (struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct context *ctx;

    ctx = (struct context *)w->data;
    if (ctx->fd == -1) {
        return;
    }
    close(ctx->fd);
    ctx->fd = -1;
    ev_timer_stop(loop, w);
    ev_break(loop, EVBREAK_ALL);
    fprintf(stderr, "Connection timed out\n");
}

static void
on_connect (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    socklen_t errlen;
    int err, opt;

    ctx = (struct context *)w->data;
    if (ctx->fd == -1) {
        return;
    }
    errlen = sizeof(err);
    if (getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
        fprintf(stderr, "getsockpot: %s\n", strerror(errno));
        close(w->fd);
        ev_io_stop(loop, w);
        ctx->fd = -1;
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    if (err) {
        fprintf(stderr, "connect: %s\n", strerror(err));
        close(w->fd);
        ev_io_stop(loop, w);
        ctx->fd = -1;
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    opt = 0;
    if (ioctl(w->fd, FIONBIO, &opt) == -1) {
        perror("ioctl [FIONBIO]");
        close(w->fd);
        ev_io_stop(loop, w);
        ctx->fd = -1;
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    fprintf(stderr, "Connection Established: soc=%d\n", w->fd);
    ev_break(loop, EVBREAK_ALL);
}

static int
init (struct context *ctx) {
    struct ev_loop *loop;
    struct ev_io connect_w;
    struct ev_timer timeout_w;

    sig_ignore(SIGPIPE);
    if (buf_init(&ctx->rbuf, RBUF_SIZ) == -1) {
        return -1;
    }
    if (buf_init(&ctx->sbuf, ctx->option.limit - (sizeof(struct hdr) + ctx->option.tag.len)) == -1) {
        free(ctx->rbuf.data);
        return -1;
    }
    ctx->fd = setup_client_socket(ctx->option.target, ctx->option.timeout ? 1 : 0);
    if (ctx->fd == -1) {
        free(ctx->sbuf.data);
        free(ctx->rbuf.data);
        return -1;
    }
    if (ctx->option.timeout) {
        loop = ev_loop_new(0);
        connect_w.data = ctx;
        ev_io_init(&connect_w, on_connect, ctx->fd, EV_WRITE);
        ev_io_start(loop, &connect_w);
        timeout_w.data = ctx;
        ev_timer_init(&timeout_w, on_timeout, ctx->option.timeout, 0.0);
        ev_timer_start(loop, &timeout_w);
        ev_run(loop, 0);
        ev_loop_destroy(loop);
        if (ctx->fd == -1) {
            free(ctx->sbuf.data);
            free(ctx->rbuf.data);
            return -1;
        }
    }
    return 0;
}

static void
usage (void) {
    printf("usage: %s [options] <tag>\n", APP_NAME);
    printf("  options:\n");
    printf("    -d, --debug         # debug mode\n");
    printf("    -t, --target=TARGET # target (default: %s)\n", DEFAULT_TARGET);
    printf("    -T, --timeout=SEC   # connection timeout sec (default: system default)\n");
    printf("    -c, --chunk=SIZE    # maximum length of the chunk (default: %d)\n", DEFAULT_LIMIT);
    printf("    -f, --flush=TIME    # time to flush the chunk (default: %d)\n", DEFAULT_INTERVAL);
    printf("        --help          # show this message\n");
    printf("        --version       # show version\n");
}

static void
version (void) {
    printf("%s %s\n", APP_NAME, PACKAGE_VERSION);
}

static int
option_parse (option_t *dst, int argc, char *argv[]) {
    int opt;
    struct option long_options[] = {
        {"debug",   0, NULL, 'd'},
        {"target",  1, NULL, 't'},
        {"timeout", 1, NULL, 'T'},
        {"chunk",   1, NULL, 'c'},
        {"flush",   1, NULL, 'f'},
        {"help",    0, NULL,  2 },
        {"version", 0, NULL,  1 },
        { NULL,     0, NULL,  0 }
    };

    dst->debug = 0;
    dst->target = DEFAULT_TARGET;
    dst->timeout = 0;
    dst->limit = DEFAULT_LIMIT;
    dst->interval = DEFAULT_INTERVAL;
    dst->tag.text = DEFAULT_TAG;
    dst->tag.len = strlen(dst->tag.text);
    while ((opt = getopt_long_only(argc, argv, "dt:T:c:f:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            dst->debug = 1;
            break;
        case 't':
            dst->target = optarg;
            break;
        case 'T':
            dst->timeout = strtol(optarg, NULL, 10);
            if (dst->timeout == -1) {
                usage();
                return -1;
            }
            break;
        case 'c':
            dst->limit = strtol(optarg, NULL, 10);
            if (dst->limit == -1) {
                usage();
                return -1;
            }
            break;
        case 'f':
            dst->interval = strtol(optarg, NULL, 10);
            if (dst->interval == -1) {
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
    if (optind != argc - 1) {
        usage();
        return -1;
    }
    dst->tag.text = argv[optind++];
    dst->tag.len = strlen(dst->tag.text);
    return 0;
}

int
main (int argc, char *argv[]) {
    struct context ctx;
    struct ev_loop *loop;
    struct signal_def *s;
    struct ev_timer timer_w;
    struct ev_io stdin_w, socket_w;

    memset(&ctx, 0, sizeof(ctx));
    if (option_parse(&ctx.option, argc, argv) == -1) {
        return -1;
    }
    if (init(&ctx) == -1) {
        return -1;
    }
    loop = ev_loop_new(0);
    if (!loop) {
        terminate(&ctx);
        return -1;
    }
    stdin_w.data = &ctx;
    ev_io_init(&stdin_w, on_stdin_read, STDIN_FILENO, EV_READ);
    ev_io_start(loop, &stdin_w);
    socket_w.data = &ctx;
    ev_io_init(&socket_w, on_socket_read, ctx.fd, EV_READ);
    ev_io_start(loop, &socket_w);
    if (ctx.option.interval) {
        timer_w.data = &ctx;
        ev_timer_init(&timer_w, on_timer, 0.0, 1.0);
        ev_timer_start(loop, &timer_w);
    }
    for (s = signals; s->signum; s++) {
        ev_signal_init(&s->w, on_signal, s->signum);
        ev_signal_start(loop, &s->w);
    }
    ev_run(loop, 0);
    if (ctx.broken) {
        ev_loop_destroy(loop);
        terminate(&ctx);
        return -1;
    }
    if (!ctx.skip && !buf_empty(&ctx.rbuf)) {
        fprintf(stderr, "Incomplete data of '%zu' bytes in the receive buffer is left.\n", ctx.rbuf.len);
    }
    if (!buf_empty(&ctx.sbuf)) {
        on_flush(&ctx);
    }
    ev_loop_destroy(loop);
    terminate(&ctx);
    return 0;
}
