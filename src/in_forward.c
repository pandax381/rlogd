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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <ev.h>
#include "rlogd.h"
#include "common.h"

struct env {
    char *bind;
    char *user;
    int mode;
    int limit;
};

struct context {
    struct module *module;
    struct env env;
    struct ev_loop *loop;
    struct ev_io w;
    struct ev_async shutdown_w;
    LIST_HEAD(/**/, e_context) head;
};

struct e_context {
    struct context *parent;
    struct ev_io w;
    struct buf rbuf;
    LIST_ENTRY(e_context) lp;
};

static void
_revoke (void *arg) {
    struct context *ctx;

    ctx = (struct context *)arg;
    close(ctx->w.fd);
    if (strncmp(ctx->env.bind, "unix://", 7) == 0) {
        unlink(ctx->env.bind + 7);
    }
    ev_loop_destroy(ctx->loop);
    free(ctx);
}

static void
cancel (void *arg) {
    ev_async_send(((struct context *)arg)->loop, &((struct context *)arg)->shutdown_w);
}

static void *
run (void *arg) {
    struct context *ctx;
    struct e_context *e;

    ctx = (struct context *)arg;
    ev_run(ctx->loop, 0);
    close(ctx->w.fd);
    while ((e = LIST_FIRST(&ctx->head)) != NULL) {
        LIST_REMOVE(e, lp);
        close(e->w.fd);
        free(e->rbuf.data);
        free(e);
    }
    if (strncmp(ctx->env.bind, "unix://", 7) == 0) {
        unlink(ctx->env.bind + 7);
    }
    ev_loop_destroy(ctx->loop);
    free(ctx);
    return NULL;
}

static void
on_shutdown (struct ev_loop *loop, struct ev_async *w, int revents) {
    ev_break(loop, EVBREAK_ALL);
}

static int
on_message (struct e_context *ctx, struct hdr *hdr) {
    struct hdr ack;
    ssize_t n;

    push_entries(ctx->parent->module, TAG_PTR(hdr), TAG_LEN(hdr), ENTRY_PTR(hdr), ENTRY_LEN(hdr));
    if (hdr->type & HDR_NEED_ACK) {
        ack.ver = HDR_VERSION;
        ack.type = HDR_TYPE_ACK;
        ack.off = 0;
        ack.seq = hdr->seq;
        ack.len = 0;
        n = writen(ctx->w.fd, &ack, sizeof(ack));
        if (n != sizeof(ack)) {
            fprintf(stderr, "send ack error\n");
            return -1;
        }
    }
    return 0;
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
        LIST_REMOVE(ctx, lp);
        close(w->fd);
        ev_io_stop(loop, w);
        free(ctx->rbuf.data);
        free(ctx);
        return;
    }
    ctx->rbuf.len += n;
    hdr = (struct hdr *)ctx->rbuf.data;
    while (ctx->rbuf.len > sizeof(*hdr)) {
        len = ntohl(hdr->len);
        if (ctx->rbuf.len < len) {
            break;
        }
        on_message(ctx, hdr);
        hdr = (struct hdr *)((caddr_t)hdr + len);
        ctx->rbuf.len -= len;
    }
    if ((caddr_t)hdr != ctx->rbuf.data) {
        memmove(ctx->rbuf.data, hdr, ctx->rbuf.len);
    }
}

static void
on_accept (struct ev_loop *loop, struct ev_io *w, int revents) {
    int soc, opt;
    struct e_context *ctx;

    soc = accept(w->fd, NULL, NULL);
    if (soc == -1) {
        perror("accept");
        return;
    }
    opt = 1;
    if (ioctl(soc, FIONBIO, &opt) == -1) {
        perror("ioctl");
        close(soc);
        return;
    }
    opt = 1;
    setsockopt(w->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); // ignore error
    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "malloc: error\n");
        close(soc);
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->parent = (struct context *)w->data;
    ctx->rbuf.alloc = ctx->parent->env.limit;
    ctx->rbuf.data = malloc(ctx->rbuf.alloc);
    if (!ctx->rbuf.data) {
        fprintf(stderr, "malloc: error\n");
        close(soc);
        free(ctx);
        return;
    }
    ctx->w.data = ctx;
    ev_io_init(&ctx->w, on_read, soc, EV_READ);
    ev_io_start(loop, &ctx->w);
    LIST_INSERT_HEAD(&ctx->parent->head, ctx, lp);
    fprintf(stderr, "in_forward: Accepted new connection, fd=%d\n", soc);
}

static int
parse_params (struct env *env, struct dir *dir) {
    struct param *param;
    char *p;

    TAILQ_FOREACH(param, &dir->params, lp) {
        if (strcmp(param->key, "type") == 0 || strcmp(param->key, "label") == 0 ) {
            // ignore
        } else if (strcmp(param->key, "bind") == 0) {
            env->bind = param->value;
        } else if (strcmp(param->key, "user") == 0) {
            env->user = param->value;
        } else if (strcmp(param->key, "mode") == 0) {
            env->mode = 0;
            for (p = param->value; *p; p++) {
                if (!isodigit(*p)) {
                    fprintf(stderr, "error: value of 'mode' is invalid, line %zu\n", param->line);
                    return -1;
                }
                env->mode = (env->mode << 3) | ctoi(*p);
            }
            if (!env->mode || env->mode > 0777) {
                fprintf(stderr, "error: value of 'mode' is invalid, line %zu\n", param->line);
                return -1;
            }
        } else {
            fprintf(stderr, "warning: unknown parameter, line %zu\n", param->line);
        }
    }
    if (!env->bind) {
        fprintf(stderr, "error: 'bind' is required, line %zu\n", dir->line);
        return -1;
    }
    return 0;
}

int
in_forward_setup (struct module *module, struct dir *dir) {
    struct context *ctx;
    int soc;

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "malloc: error\n");
        return -1;
    }
    ctx->module = module;
    ctx->env.limit = DEFAULT_BUFFER_CHUNK_LIMIT;
    ctx->env.mode  = DEFAULT_SOCKET_MODE;
    if (parse_params(&ctx->env, dir) == -1) {
        free(ctx);
        return -1;
    }
    if (__dryrun) {
        soc = open("/dev/null", O_RDWR);
    } else {
        soc = setup_server_socket(ctx->env.bind, DEFAULT_RLOGD_PORT, SOMAXCONN, 0);
        if (soc == -1) {
            fprintf(stderr, "setup_server_socket: error\n");
            free(ctx);
            return -1;
        }
        if (strncmp(ctx->env.bind, "unix://", 7) == 0) {
            if (chperm(ctx->env.bind + 7, ctx->env.user, ctx->env.mode) == -1) {
                fprintf(stderr, "chperm: error\n");
                close(soc);
                free(ctx);
                return -1;
            }
        }
    }
    ctx->loop = ev_loop_new(0);
    if (!ctx->loop) {
        fprintf(stderr, "ev_loop_new: error\n");
        close(soc);
        free(ctx);
        return -1;
    }
    ctx->w.data = ctx;
    ev_io_init(&ctx->w, on_accept, soc, EV_READ);
    ev_io_start(ctx->loop, &ctx->w);
    ctx->shutdown_w.data = ctx;
    ev_async_init(&ctx->shutdown_w, on_shutdown);
    ev_async_start(ctx->loop, &ctx->shutdown_w);
    LIST_INIT(&ctx->head);
    module->arg = ctx;
    module->run = run;
    module->cancel = cancel;
    module->revoke = _revoke;
    return 0;
}
