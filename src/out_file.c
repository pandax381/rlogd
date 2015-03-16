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
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <ev.h>
#include "rlogd.h"
#include "common.h"

#define DEFAULT_PERM_DIRS (00755)
#define DEFAULT_PERM_FILE (00644)

struct context {
    struct module *module;
    struct {
        char *path;
        char *user;
        int mode;
    } env;
    int fd;
    char current[PATH_MAX];
    time_t timestamp;
    struct ev_loop *loop;
    struct ev_async shutdown_w;
};

static ssize_t
format (char *dst, size_t size, time_t timestamp, const char *tag, size_t tag_len, const struct entry *entry) {
    int n;

    n = snprintf(dst, size, "[%.*s] %.*s\n", (int)tag_len, tag, (int)ntohl(entry->len), (char *)entry->data);
    if (n >= (int)size) {
        return -1;
    }
    return n;
}

static void
emit (void *arg, const char *tag, size_t tag_len, const struct entry *entries, size_t len) {
    struct context *ctx;
    time_t timestamp;
    struct tm tm;
    char path[PATH_MAX], *p, buf[65536];
    ssize_t n;
    const struct entry *entry;

    ctx = (struct context *)arg;
    for (entry = entries; (caddr_t)entry < (caddr_t)entries + len; entry = NEXT_ENTRY(entry)) {
        timestamp = (time_t)ntohl(entry->timestamp);
        if (ctx->timestamp != timestamp || ctx->fd == -1) {
            strftime(path, sizeof(path), ctx->env.path, localtime_r(&timestamp, &tm));
            if (strcmp(ctx->current, path) != 0) {
                if (ctx->fd != -1) {
                    close(ctx->fd);
                }
                p = strrchr(path, '/');
                if (p) {
                    setchar(p, '\0');
                    mkdir_p(path, DEFAULT_PERM_DIRS);
                    setchar(p, '/');
                }
                ctx->fd = open(path, O_WRONLY | O_CREAT | O_APPEND, DEFAULT_PERM_FILE);
                if (ctx->fd == -1) {
                    fprintf(stderr, "%s: %s\n", strerror(errno), path);
                    return;
                }
                strcpy(ctx->current, path);
                if (ctx->env.user) {
                    chperm(ctx->current, ctx->env.user, ctx->env.mode);
                }
                fprintf(stderr, "Open file, path=%s, fd=%d\n", ctx->current, ctx->fd);
            }
            ctx->timestamp = timestamp;
        }
        n = format(buf, sizeof(buf), timestamp, tag, tag_len, entry);
        if (n == -1) {
            fprintf(stderr, "entry message too long\n");
            return;
        }
        writen(ctx->fd, buf, n);
    }
}

static void
_revoke (void *arg) {
    struct context *ctx;

    ctx = (struct context *)arg;
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

    ctx = (struct context *)arg;
    ev_run(ctx->loop, 0);
    if (ctx->fd != -1) {
        close(ctx->fd);
    }
    ev_loop_destroy(ctx->loop);
    free(ctx);
    return NULL;
}

static void
on_shutdown (struct ev_loop *loop, struct ev_async *w, int revents) {
    ev_break(loop, EVBREAK_ALL);
}

int
out_file_setup (struct module *module, struct dir *dir) {
    struct context *ctx;
    char *val;

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "malloc: error\n");
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->module = module;
    ctx->env.path = config_dir_get_param_value(dir, "path");
    if (!ctx->env.path) {
        fprintf(stderr, "'path' is required\n");
        free(ctx);
        return -1;
    }
    ctx->env.user = config_dir_get_param_value(dir, "user");
    ctx->env.mode = DEFAULT_SOCKET_MODE;
    val = config_dir_get_param_value(dir, "mode");
    if (val) {
        ctx->env.mode = strtol(val, NULL, 8);
        if (ctx->env.mode == -1) {
            fprintf(stderr, "'mode' value is invalid\n");
            free(ctx);
            return -1;
        }
    }
    ctx->fd = -1;
    ctx->loop = ev_loop_new(0);
    if (!ctx->loop) {
        fprintf(stderr, "ev_loop_new: error\n");
        free(ctx);
        return -1;
    }
    ctx->shutdown_w.data = ctx;
    ev_async_init(&ctx->shutdown_w, on_shutdown);
    ev_async_start(ctx->loop, &ctx->shutdown_w);
    module->arg = ctx;
    module->run = run;
    module->cancel = cancel;
    module->revoke = _revoke;
    module->emit = emit;
    return 0;
}
