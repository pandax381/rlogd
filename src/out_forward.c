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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <ev.h>
#include <msgpack.h>
#include "rlogd.h"
#include "buffer.h"
#include "common.h"

struct env {
    char *target;
    char *buffer;
    size_t limit;
    size_t interval;
    int fluentd_compatible;
    int follow_ltsv;
};

struct context {
    struct module *module;
    struct env env;
    struct ev_loop *loop;
    struct {
        struct ev_io w;
        struct ev_timer retry_w;
    } connect;
    struct ev_timer flush_w;
    struct ev_async shutdown_w;
    struct ev_async feed_w;
    struct buffer buffer;
    struct timeval tstamp;
    int terminate;
};

static void
feed (void *arg) {
    ev_async_send(((struct context *)arg)->loop, &((struct context *)arg)->feed_w);
}

static void
_revoke (void *arg) {
    struct context *ctx;

    ctx = (struct context *)arg;
    if (ctx->connect.w.fd != -1) {
        close(ctx->connect.w.fd);
    }
    ev_loop_destroy(ctx->loop);
    buffer_terminate(&ctx->buffer);
    free(ctx);
}

static void
cancel (void *arg) {
    ev_async_send(((struct context *)arg)->loop, &((struct context *)arg)->shutdown_w);
}

static void *
run (void *arg) {
    struct context *ctx;

    ctx = (struct context *)arg;
    ev_run(ctx->loop, 0);
    if (ctx->connect.w.fd != -1) {
        close(ctx->connect.w.fd);
    }
    ev_loop_destroy(ctx->loop);
    buffer_terminate(&ctx->buffer);
    free(ctx);
    return NULL;
}

static void
on_feed (struct ev_loop *loop, struct ev_async *w, int revents) {
    struct context *ctx;

    ctx = (struct context *)w->data;
    if (!ev_is_active(&ctx->connect.retry_w) && ctx->connect.w.fd != -1 && !ev_is_active(&ctx->connect.w)) {
        ev_io_start(loop, &ctx->connect.w);
        ev_feed_event(loop, &ctx->connect.w, EV_CUSTOM);
    }
}

static void
on_shutdown (struct ev_loop *loop, struct ev_async *w, int revents) {
    ev_break(loop, EVBREAK_ALL);
}

static void
emit (void *arg, const char *tag, size_t tag_len, const struct entry *entries, size_t len) {
    struct context *ctx;
    struct entry *s, *e;
    size_t n;

    ctx = (struct context *)arg;
    pthread_mutex_lock(&ctx->buffer.mutex);
    for (s = e = (struct entry *)entries; (caddr_t)e < (caddr_t)entries + len; e = NEXT_ENTRY(e)) {
        n = sizeof(struct hdr) + tag_len + (((caddr_t)(e + 1) + ntohl(e->len)) - (caddr_t)s);
        if (ctx->env.limit < ctx->buffer.len + n) {
            if (e != s) {
                while (buffer_write(&ctx->buffer, tag, tag_len, s, (caddr_t)e - (caddr_t)s) == -1) {
                    warning_print("buffer_write: error, retry after 1 seconds...");
                    sleep(1);
                }
                s = e;
            }
            if (ctx->buffer.len) {
                if (buffer_flush(&ctx->buffer) == -1) {
                    // TODO
                }
                feed(arg);
            }
            n = sizeof(struct hdr) + tag_len + (((caddr_t)(e + 1) + ntohl(e->len)) - (caddr_t)s);
            if (ctx->env.limit < ctx->buffer.len + n) {
                warning_print("entry too long");
                s = NEXT_ENTRY(e);
            }
        }
    }
    if (e != s) {
        while (buffer_write(&ctx->buffer, tag, tag_len, s, (caddr_t)e - (caddr_t)s) == -1) {
            warning_print("buffer_write: error, retry after 1 seconds...");
            sleep(1);
        }
    }
    pthread_mutex_unlock(&ctx->buffer.mutex);
}

static int
wait_ack (struct context *ctx, uint32_t seq) {
    int ret;
    struct pollfd pfd;
    char buf[16];
    struct hdr *ack;
    size_t size, done = 0;
    ssize_t n;

    size = ctx->env.fluentd_compatible ? 10 : sizeof(*ack);
    pfd.fd = ctx->connect.w.fd;
    pfd.events = POLLIN;
    while (1) {
        if ((ret = poll(&pfd, 1, 1000)) <= 0) {
            if (ret == 0 || errno == EINTR) {
                continue;
            }
            error_print("poll: %s", strerror(errno));
            return -1;
        }
        n = recv(pfd.fd, buf + done, size - done, 0);
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
        if (done < size) {
            continue;
        }
        if (ctx->env.fluentd_compatible) {
            /* TODO */
            buf[10] = '\0';
            if (strtol(buf + 6, NULL, 16) == seq) {
              break;
            }
        } else {
            ack = (struct hdr *)buf;
            if (ntohl(ack->seq) == seq) {
                break;
            }
        }
    }
    return 0;
}

struct strvec {
    uint8_t *base;
    size_t len;
};

struct ltsv {
    struct strvec col;
    struct strvec val;
};

#define LTSV_ALLOC_SIZE (256)

static int
parse_ltsv (struct entry *entry, struct ltsv **dst) {
    struct ltsv *ltsv = NULL, *_ltsv;
    int capacity = 0, n = 0;
    uint8_t *p, *sentinel;

    sentinel = entry->data + ntohl(entry->len);
    for (p = entry->data; p < sentinel; p++) {
        struct strvec col = {};
        struct strvec val = {};

        col.base = p;
        p = memchr(p, ':', sentinel - p);
        if (!p || (p + 1) == sentinel) {
            free(ltsv);
            return 0;
        }
        col.len = p - col.base;
        val.base = ++p;
        p = memchr(p, '\t', sentinel - p);
        if (!p) {
            p = sentinel;
        }
        // p points '\t' or end of entyr->data
        val.len = p - val.base;
        if (n == capacity) {
            capacity += LTSV_ALLOC_SIZE;
            _ltsv = (struct ltsv *)realloc(ltsv, sizeof(struct ltsv) * capacity);
            if (!_ltsv) {
                error_print("malloc error");
                free(ltsv);
                return -1;
            }
            ltsv = _ltsv;
        }
        ltsv[n].col = col;
        ltsv[n].val = val;
        n++;
    }
    *dst = ltsv;
    return n;
}

static int
send_chunk_fluentd_compatible (struct context *ctx, struct hdr *hdr, int out_fd, int in_fd) {
    size_t offset, tag_len, size, remain = 0, count = 0;
    ssize_t n, done = 0;
    char buf[8+65536], tag[1024], seq[5];
    struct entry *entry;
    msgpack_packer packer;
    msgpack_sbuffer head, body;
    struct ltsv *ltsv;
    int ncols, i;

    offset = ntohs(hdr->off);
    tag_len = offset - sizeof(*hdr);
    n = readn(in_fd, tag, tag_len);
    if (n != (ssize_t)tag_len) {
        if (n == -1) {
            error_print("readn: %s, %d", strerror(errno), in_fd);
        } else {
            warning_print("readn: less than tag_len=%zd, fd=%d, n=%zd", tag_len, in_fd, n);
        }
        return -1;
    }
    size = ntohl(hdr->len) - offset;
    msgpack_sbuffer_init(&body);
    msgpack_packer_init(&packer, &body, msgpack_sbuffer_write);
    while (done < (ssize_t)size) {
        n = read(in_fd, buf + remain, MIN(sizeof(buf) - remain, (size - done)));
        if (n <= 0) {
            if (n) {
                if (errno == EINTR) {
                    continue;
                }
                // TODO
                error_print("read: %s, %d", strerror(errno), in_fd);
                msgpack_sbuffer_destroy(&body);
                return -1;
            }
            break;
        }
        entry = (struct entry *)buf;
        remain += n;
        while (remain >= sizeof(struct entry)) {
            size_t len = ntohl(entry->len);
            if (remain < sizeof(struct entry) + len) {
                break;
            }
            // record
            msgpack_pack_array(&packer, 2);
            msgpack_pack_uint32(&packer, ntohl(entry->timestamp));
            if (ctx->env.follow_ltsv) {
                ncols = parse_ltsv(entry, &ltsv);
                if (ncols == -1) {
                    return -1;
                }
            }
            if (ctx->env.follow_ltsv && ncols) {
                msgpack_pack_map(&packer, ncols);
                for (i = 0; i < ncols; i++) {
                    msgpack_pack_str(&packer, ltsv[i].col.len);
                    msgpack_pack_str_body(&packer, ltsv[i].col.base, ltsv[i].col.len);
                    msgpack_pack_str(&packer, ltsv[i].val.len);
                    msgpack_pack_str_body(&packer, ltsv[i].val.base, ltsv[i].val.len);
                }
                free(ltsv);
            } else {
                msgpack_pack_map(&packer, 1);
                msgpack_pack_str(&packer, 7);
                msgpack_pack_str_body(&packer, "message", 7);
                msgpack_pack_str(&packer, len);
                msgpack_pack_str_body(&packer, entry->data, len);
            }
            count++;
            entry = (struct entry *)((caddr_t)(entry + 1) + len);
            remain -= sizeof(struct entry) + len;
        }
        if ((caddr_t)entry != buf) {
            memmove(buf, entry, remain);
        }
        done += n;
    }
    debug_print("count: %zd", count);
    // option
    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "chunk", 5);
    msgpack_pack_str(&packer, 4);
    sprintf(seq, "%04x", ntohl(hdr->seq));
    msgpack_pack_str_body(&packer, seq, 4);
    // header
    msgpack_sbuffer_init(&head);
    msgpack_packer_init(&packer, &head, msgpack_sbuffer_write);
    msgpack_pack_array(&packer, 3);
    msgpack_pack_str(&packer, tag_len);
    msgpack_pack_str_body(&packer, tag, tag_len);
    msgpack_pack_array(&packer, count);
    writen(out_fd, head.data, head.size);
    msgpack_sbuffer_destroy(&head);
    writen(out_fd, body.data, body.size);
    msgpack_sbuffer_destroy(&body);
    return 0;
}

static int
send_chunk (struct context *ctx, struct hdr *hdr, int out_fd, int in_fd) {
    char buf[65536];
    ssize_t n, done = 0;
    size_t count;

    if (out_fd != -1) {
        if (ctx->env.fluentd_compatible) {
            return send_chunk_fluentd_compatible(ctx, hdr, out_fd, in_fd);
        }
        writen(out_fd, hdr, sizeof(*hdr));
    }
    count = ntohl(hdr->len) - sizeof(*hdr);
    while (done < (ssize_t)count) {
        n = read(in_fd, buf, MIN(sizeof(buf), (count - done)));
        if (n <= 0) {
            if (n) {
                if (errno == EINTR) {
                    continue;
                }
                // TODO
                error_print("read: %s, %d", strerror(errno), in_fd);
                return -1;
            }
            break;
        }
        if (out_fd != -1) {
            writen(out_fd, buf, n);
        }
        done += n;
    }
    return 0;
}

static void
on_write (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    char path[PATH_MAX];
    int fd, err;
    struct hdr hdr;
    ssize_t n;
    uint32_t seq;

    ctx = (struct context *)w->data;
    if (ctx->terminate) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    snprintf(path, sizeof(path), "%s/%s.%d", ctx->env.buffer, BUFFER_FILE_NAME, ctx->buffer.cursor->rb);
    fd = open(path, O_RDWR);
    if (fd == -1) {
        // TODO
        sleep(1);
        return;
    }
    debug_print("forward buffer: %s", path);
    while (1) {
        n = readn(fd, &hdr, sizeof(hdr));
        if (n != sizeof(hdr)) {
            if (n) {
                if (n == -1) {
                    error_print("read: %s, fd=%d", strerror(errno), fd);
                } else {
                    warning_print("read: less than sizeof(struct hdr), fd=%d, n=%zd", fd, n);
                }
                close(fd);
                return;
            }
            break;
        }
        seq = ntohl(hdr.seq);
        if (!seq && ctx->buffer.cursor->rc == UINT32_MAX) {
            ctx->buffer.cursor->rc = 0;
        }
        if (seq < ctx->buffer.cursor->rc) {
            debug_print("skip: %s, seq=%u, cursor->rc=%u", path, seq, ctx->buffer.cursor->rc);
            send_chunk(ctx, &hdr, -1, fd);
            continue;
        }
        err = send_chunk(ctx, &hdr, w->fd, fd);
        if (err) {
            close(fd);
            ev_io_stop(loop, w);
            close(w->fd);
            w->fd = -1;
            ev_timer_start(loop, &ctx->connect.retry_w);
            return;
        }
        if (wait_ack(ctx, seq) == -1) {
            close(fd);
            ev_io_stop(loop, w);
            close(w->fd);
            w->fd = -1;
            ev_timer_start(loop, &ctx->connect.retry_w);
            return;
        }
        ctx->buffer.cursor->rc = seq;
    }
    close(fd);
    ctx->buffer.cursor->rb++;
    debug_print("unlink buffer: %s, next=%u", path, ctx->buffer.cursor->rb);
    unlink(path);
}

static void
on_connect (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct context *ctx;
    int err, opt;
    socklen_t errlen;

    ctx = (struct context *)w->data;
    errlen = sizeof(err);
    if (getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
        error_print("getsockpot: %s, target=%s, fd=%d", strerror(errno), ctx->env.target, w->fd);
        ev_io_stop(loop, w);
        close(w->fd);
        w->fd = -1;
        ev_timer_start(ctx->loop, &ctx->connect.retry_w);
        return;
    }
    if (err) {
        error_print("connect: %s, target=%s, fd=%d", strerror(err), ctx->env.target, w->fd);
        ev_io_stop(loop, w);
        close(w->fd);
        w->fd = -1;
        ev_timer_start(ctx->loop, &ctx->connect.retry_w);
        return;
    }
    opt = 0;
    if (ioctl(w->fd, FIONBIO, &opt) == -1) {
        error_print("ioctl [FIONBIO]: %s, target=%s, fd=%d", strerror(errno), ctx->env.target, w->fd);
        ev_io_stop(loop, w);
        close(w->fd);
        w->fd = -1;
        ev_timer_start(ctx->loop, &ctx->connect.retry_w);
    }
    opt = 1;
    setsockopt(w->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); // ignore error
    ev_set_cb(w, on_write);
    debug_print("connection established, target=%s, fd=%d", ctx->env.target, w->fd);
}

static void
on_flush (struct ev_loop *loop, struct ev_timer *w, int revents) {
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
    if (diff.tv_sec >= (time_t)ctx->env.interval) {
        if (buffer_flush(&ctx->buffer) == -1) {
            // TODO
        }
    }
    pthread_mutex_unlock(&ctx->buffer.mutex);
}

static void
on_retry (struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct context *ctx;
    int soc;

    ctx = (struct context *)w->data;
    soc = setup_client_socket(ctx->env.target, DEFAULT_RLOGD_PORT, 1);
    if (soc == -1) {
        // retry at next timer tick
        return;
    }
    ev_timer_stop(loop, w);
    ev_io_init(&ctx->connect.w, on_connect, soc, EV_WRITE);
    ev_io_start(loop, &ctx->connect.w);
}

static int
parse_options (struct env *env, struct dir *dir) {
    struct param *param;
    char *endptr;
    long int val;

    TAILQ_FOREACH(param, &dir->params, lp) {
        if (strcmp(param->key, "type") == 0) {
            // ignore
        } else if (strcmp(param->key, "buffer_path") == 0) {
            env->buffer = param->value;
        } else if (strcmp(param->key, "target") == 0) {
            env->target = param->value;
        } else if (strcmp(param->key, "buffer_chunk_limit") == 0) {
            val = strtol(param->value, &endptr, 10);
            if (val < 0 || *endptr != '\0') {
                error_print("value of 'buffer_chunk_limit' is invalid, line %zu", param->line);
                return -1;
            }
            env->limit = val;
        } else if (strcmp(param->key, "flush_interval") == 0) {
            val = strtol(param->value, &endptr, 10);
            if (val < 0 || *endptr) {
                error_print("value of 'flush_interval' is invalid, line %zu", param->line);
                return -1;
            }
            env->interval = val;
        } else if (strcmp(param->key, "fluentd_compatible") == 0) {
            if (strcmp(param->value, "true") == 0) {
                env->fluentd_compatible = 1;
            } else {
                error_print("value of 'fluentd_compatible' is invalid, line %zu", param->line);
                return -1;
            }
        } else if (strcmp(param->key, "follow_ltsv") == 0) {
            if (strcmp(param->value, "true") == 0) {
                env->follow_ltsv = 1;
            } else {
                error_print("value of 'follow_ltsv' is invalid, line %zu", param->line);
                return -1;
            }
        } else {
            warning_print("unknown parameter, line %zu", param->line);
        }
    }
    if (!env->buffer) {
        error_print("'buffer' is required, line %zu", dir->line);
        return -1;
    }
    if (!env->target) {
        error_print("'target' is required, line %zu", dir->line);
        return -1;
    }
    return 0;
}

int
out_forward_setup (struct module *module, struct dir *dir) {
    struct context *ctx;
    int soc;

    ctx = (struct context *)malloc(sizeof(struct context));
    if (!ctx) {
        error_print("malloc error");
        return -1;
    }
    ctx->terminate = 0;
    ctx->module = module;
    ctx->env.limit = DEFAULT_BUFFER_CHUNK_LIMIT;
    ctx->env.interval = DEFAULT_FLUSH_INTERVAL;
    ctx->env.fluentd_compatible = 0;
    ctx->env.follow_ltsv = 0;
    if (parse_options(&ctx->env, dir) == -1) {
        free(ctx);
        return -1;
    }
    if (__dryrun) {
        ctx->buffer.fd = -1;
        ctx->buffer.cursor = NULL;
    } else {
        if (buffer_init(&ctx->buffer, ctx->env.buffer) == -1) {
            error_print("position file load error");
            free(ctx);
            return -1;
        }
    }
    ctx->loop = ev_loop_new(0);
    if (!ctx->loop) {
        if (!__dryrun) {
            buffer_terminate(&ctx->buffer);
        }
        error_print("ev_loop_new: error");
        free(ctx);
        return -1;
    }
    ctx->connect.w.data = ctx;
    ctx->connect.retry_w.data = ctx;
    ev_timer_init(&ctx->connect.retry_w, on_retry, 3.0, 3.0);
    if (__dryrun) {
        soc = open("/dev/null", O_RDWR);
    } else {
        soc = setup_client_socket(ctx->env.target, DEFAULT_RLOGD_PORT, 1);
    }
    if (soc == -1) {
        ctx->connect.w.fd = -1;
        ev_timer_start(ctx->loop, &ctx->connect.retry_w);
    } else {
        ev_io_init(&ctx->connect.w, on_connect, soc, EV_WRITE);
        ev_io_start(ctx->loop, &ctx->connect.w);
    }
    ctx->flush_w.data = ctx;
    ev_timer_init(&ctx->flush_w, on_flush, 1.0, 1.0);
    ev_timer_start(ctx->loop, &ctx->flush_w);
    ctx->shutdown_w.data = ctx;
    ev_async_init(&ctx->shutdown_w, on_shutdown);
    ev_async_start(ctx->loop, &ctx->shutdown_w);
    ctx->feed_w.data = ctx;
    ev_async_init(&ctx->feed_w, on_feed);
    ev_async_start(ctx->loop, &ctx->feed_w);
    module->arg = ctx;
    module->run = run;
    module->cancel = cancel;
    module->revoke = _revoke;
    module->emit = emit;
    return 0;
}
