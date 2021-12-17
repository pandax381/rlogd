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
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <ev.h>
#include "common.h"
#include "protocol.h"
#include "buffer.h"

#define APP_NAME "rloggerd"

#define DEFAULT_BUFFER (LOCALSTATEDIR "/spool/rlogd/rloggerd")
#define DEFAULT_CHUNK DEFAULT_BUFFER_CHUNK_LIMIT
#define DEFAULT_FLUSH DEFAULT_FLUSH_INTERVAL
#define DEFAULT_TIMEOUT DEFAULT_ACK_TIMEOUT
#define DEFAULT_LISTEN_ADDR DEFAULT_RLOGGERD_SOCKET
#define DEFAULT_TARGET_ADDR DEFAULT_RLOGD_SOCKET

struct opts {
    int debug;
    char *buffer;
    int chunk;
    int flush;
    int timeout;
    char *listen;
    char *target;
    char *user;
    char *prefix;
    char *suffix;
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

ssize_t
maketag (char *buf, size_t size, const char *tag, size_t tag_len, const char *prefix, const char *suffix) {
    ssize_t n = 0, plen, slen;

    plen = prefix ? strlen(prefix) : 0;
    slen = suffix ? strlen(suffix) : 0;
    if ((plen ? plen + 1 : 0) + tag_len + (slen ? slen + 1 : 0) > size) {
        return -1;
    }
    if (plen) {
        strncpy(buf, prefix, plen);
        n += plen;
        buf[n++] = '.';
    }
    strncpy(buf + n, tag, tag_len);
    n += tag_len;
    if (slen) {
        buf[n++] = '.';
        strncpy(buf + n, suffix, slen);
        n += slen;
    }
    return n;
}

static void
on_message (struct e_context *ctx, struct hdr *hdr, size_t len) {
    char *tag, buf[1024];
    size_t tag_len;
    ssize_t buf_len;
    struct entry *s, *e;
    size_t n;

    tag = (char *)(hdr + 1);
    tag_len = ntohs(hdr->off) - sizeof(struct hdr);
    s = e = (struct entry *)(tag + tag_len);
    if (ctx->parent->opts->prefix || ctx->parent->opts->suffix) {
        buf_len = maketag(buf, sizeof(buf), tag, tag_len, ctx->parent->opts->prefix, ctx->parent->opts->suffix);
        if (buf_len == -1) {
            warning_print("tag too long");
            pthread_mutex_unlock(&ctx->parent->buffer.mutex);
            return;
        }
        tag = buf;
        tag_len = (size_t)buf_len;
    }
    pthread_mutex_lock(&ctx->parent->buffer.mutex);
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
                warning_print("entry too long");
                s = e;
            }
        }
        e = (struct entry *)((caddr_t)(e + 1) + ntohl(e->len));
    }
    if (e != s) {
        buffer_write(&ctx->parent->buffer, tag, tag_len, s, (caddr_t)e - (caddr_t)s);
    }
    pthread_mutex_unlock(&ctx->parent->buffer.mutex);
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
            error_print("recv: %s, fd=%d", strerror(errno), w->fd);
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
        error_print("accept: %s, fd=%d", strerror(errno), w->fd);
        return;
    }
    ctx = (struct e_context *)malloc(sizeof(struct e_context));
    if (!ctx) {
        error_print("malloc error");
        close(soc);
        return;
    }
    memset(ctx, 0, sizeof(struct e_context));
    ctx->parent = (struct context *)w->data;
    ctx->rbuf.alloc = ctx->parent->opts->chunk;
    ctx->rbuf.data = malloc(ctx->rbuf.alloc);
    if (!ctx->rbuf.data) {
        error_print("malloc error");
        free(ctx);
        close(soc);
        return;
    }
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
    pthread_mutex_lock(&ctx->buffer.mutex);
    if (!ctx->buffer.len || ctx->buffer.cursor->rb != ctx->buffer.cursor->wb) {
        pthread_mutex_unlock(&ctx->buffer.mutex);
        return;
    }
    gettimeofday(&now, NULL);
    tvsub(&now, &ctx->buffer.tstamp, &diff);
    if (diff.tv_sec >= (time_t)ctx->opts->flush) {
        if (buffer_flush(&ctx->buffer) == -1) {
            // TODO
        }
    }
    pthread_mutex_unlock(&ctx->buffer.mutex);
}

static void
on_signal (struct ev_loop *loop, struct ev_signal *w, int revents) {
    struct context *ctx;

    warning_print("receive signal: signum=%d", w->signum);
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
    struct timeval base, now, diff;

    pfd.fd = ctx->connect.w.fd;
    pfd.events = POLLIN;
    gettimeofday(&base, NULL);
    while (1) {
        if ((ret = poll(&pfd, 1, 1000)) <= 0) {
            if (ret == 0 || errno == EINTR) {
                gettimeofday(&now, NULL);
                tvsub(&now, &base, &diff);
                if (diff.tv_sec >= (time_t)ctx->opts->timeout) {
                    error_print("timeout: no response");
                    return -1;
                }
                continue;
            }
            error_print("poll: %s", strerror(errno));
            return -1;
        }
        n = recv(pfd.fd, (char *)&ack + done, sizeof(ack) - done, 0);
        switch (n) {
        case -1:
            if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            }
            error_print("recv: %s, fd=%d", strerror(errno), pfd.fd);
            return -1;
        case  0:
            warning_print("connection closed");
            if (n) {
                warning_print("unprocessed %zu bytes data", done);
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
                error_print("recv: %s, fd=%d", strerror(errno), in_fd);
                return -1;
            }
            break;
        }
        if (out_fd != -1) {
            writen(out_fd, buf, n);
        }
        done += n;
    }
    return done;
}

static void
on_write (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    char path[PATH_MAX];
    int fd, skip = 0;
    struct hdr hdr;
    ssize_t n, done = 0, len;
    uint32_t seq;

    ctx = (struct context *)w->data;
    if (ctx->terminate) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    snprintf(path, sizeof(path), "%s/%s.%d", ctx->opts->buffer, BUFFER_FILE_NAME, ctx->buffer.cursor->rb);
    fd = open(path, O_RDWR);
    if (fd == -1) {
        // TODO
        sleep(1);
        return;
    }
    debug_print("forward buffer: %s", path);
    while (1) {
        n = read(fd, &hdr, sizeof(hdr) - done);
        if (n <= 0) {
            if (n) {
                if (errno == EINTR) {
                    continue;
                }
                error_print("recv: %s, fd=%d", strerror(errno), fd);
                close(fd);
                return;
            }
            break;
        }
        done += n;
        if (done < (ssize_t)sizeof(hdr)) {
            continue;
        }
        seq = ntohl(hdr.seq);
        if (!seq && ctx->buffer.cursor->rc == UINT32_MAX) {
            ctx->buffer.cursor->rc = 0;
        }
        if (seq < ctx->buffer.cursor->rc) {
            skip = 1;
            debug_print("skip: %s, seq=%u, cursor->rc=%u", path, seq, ctx->buffer.cursor->rc);
        } else {
            writen(w->fd, &hdr, sizeof(hdr));
        }
        done = 0;
        len = ntohl(hdr.len) - sizeof(hdr);
        while (done < len) {
            n = _sendfile(skip ? -1 : w->fd, fd, len - done);
            if (n == -1) {
                close(fd);
                ev_io_stop(loop, w);
                close(w->fd);
                w->fd = -1;
                ev_timer_set(&ctx->connect.retry_w, 3.0, 0.0);
                ev_timer_start(loop, &ctx->connect.retry_w);
                return;
            }
            if (n != (len - done)) {
                error_print("incomplete sendfile, %zd / %zd", n, len - done);
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
        if (skip) {
            skip = 0;
            done = 0;
            continue;
        }
        if (wait_ack(ctx, seq) == -1) {
            close(fd);
            ev_io_stop(loop, w);
            close(w->fd);
            w->fd = -1;
            ev_timer_set(&ctx->connect.retry_w, 3.0, 0.0);
            ev_timer_start(loop, &ctx->connect.retry_w);
            return;
        }
        ctx->buffer.cursor->rc = seq;
        done = 0;
    }
    close(fd);
    ctx->buffer.cursor->rb++;
    debug_print("unlink buffer: %s, next=%u", path, ctx->buffer.cursor->rb);
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
    setsockopt(soc, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); // ignore error
    ev_io_init(&ctx->connect.w, on_write, soc, EV_WRITE);
    ev_io_start(loop, &ctx->connect.w);
    debug_print("connection established, fd=%d", soc);
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
        setsockopt(soc, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); // ignore error
        ev_io_init(&ctx->connect.w, on_write, soc, EV_WRITE);
        ev_io_start(loop, &ctx->connect.w);
        debug_print("connection established, fd=%d", soc);
    }
    ev_run(loop, 0);
    ev_loop_destroy(loop);
    return NULL;
}

static void
usage (void) {
    printf("usage: %s [options]\n", APP_NAME);
    printf("  options:\n");
    printf("    -d, --debug          # debug mode\n");
    printf("    -l, --listen=ADDR    # listen address (default: %s)\n", DEFAULT_LISTEN_ADDR);
    printf("    -t, --target=TARGET  # target address (default: %s)\n", DEFAULT_TARGET_ADDR);
    printf("    -u, --user=USER      # socket file owner\n");
    printf("    -m, --mode=MODE      # socket file permission (default: %o)\n", DEFAULT_SOCKET_MODE);
    printf("    -b, --buffer=PATH    # file buffer directory path (default: %s)\n", DEFAULT_BUFFER);
    printf("    -c, --chunk=SIZE     # maximum length of the chunk (default: %d)\n", DEFAULT_CHUNK);
    printf("    -f, --flush=TIME     # time to flush the chunk (default: %d)\n", DEFAULT_FLUSH);
    printf("        --timeout=TIME   # time to wait for ACK (default: %d)\n", DEFAULT_TIMEOUT);
    printf("        --add-prefix=TAG # add prefix to tag\n");
    printf("        --add-suffix=TAG # add suffix to tag\n");
    printf("        --help           # show this message\n");
    printf("        --version        # show version\n");
}

static void
version (void) {
    printf("%s %s\n", APP_NAME, PACKAGE_VERSION);
}

static int
parse_options (struct opts *opts, int argc, char *argv[]) {
    int opt;
    struct option long_options[] = {
        {"debug",      0, NULL, 'd'},
        {"listen",     1, NULL, 'l'},
        {"target",     1, NULL, 't'},
        {"user",       1, NULL, 'u'},
        {"mode",       1, NULL, 'm'},
        {"buffer",     1, NULL, 'b'},
        {"chunk",      1, NULL, 'c'},
        {"flush",      1, NULL, 'f'},
        {"timeout",    1, NULL,  5 },
        {"add-prefix", 1, NULL,  4 },
        {"add-suffix", 1, NULL,  3 },
        {"help",       0, NULL,  2 },
        {"version",    0, NULL,  1 },
        { NULL,        0, NULL,  0 }
    };

    memset(opts, 0, sizeof(struct opts));
    opts->listen = DEFAULT_LISTEN_ADDR;
    opts->target = DEFAULT_TARGET_ADDR;
    opts->user = NULL;
    opts->mode = DEFAULT_SOCKET_MODE;
    opts->buffer = DEFAULT_BUFFER;
    opts->chunk = DEFAULT_CHUNK;
    opts->flush = DEFAULT_FLUSH;
    opts->timeout = DEFAULT_TIMEOUT;
    opts->prefix = NULL;
    opts->suffix = NULL;
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
        case 5:
            opts->timeout = strtol(optarg, NULL, 10);
            if (opts->timeout == -1) {
                usage();
                return -1;
            }
            break;
        case 4:
            opts->prefix = optarg;
            break;
        case 3:
            opts->suffix = optarg;
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
    __debug  = opts->debug;
    return 0;
}

static void
terminate (struct context *ctx) {
    buffer_terminate(&ctx->buffer);
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
    notice_print("starting %s %s", APP_NAME, PACKAGE_VERSION);
    memset(&ctx, 0, sizeof(ctx));
    ctx.opts = &opts;
    if (buffer_init(&ctx.buffer, opts.buffer) == -1) {
        error_print("buffer_init: failure");
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
    notice_print("running...");
    pthread_create(&thread, NULL, thread_main, &ctx);
    ev_run(loop, 0);
    notice_print("shutting down...");
    ev_loop_destroy(loop);
    pthread_join(thread, NULL);
    close(soc);
    terminate(&ctx);
    notice_print("good bye");
    return 0;
}
