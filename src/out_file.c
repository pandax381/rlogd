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
#include <ctype.h>
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

#define DEFAULT_TIME_FORMAT "%s"
#define DEFAULT_FORMAT "[$tag] $record"
#define DEFAULT_PERM_DIRS (00755)
#define DEFAULT_PERM_FILE (00644)

struct env {
    char *time_format;
    char *format;
    char *path;
    char *user;
    int mode;
    int embed_hostname;
};

struct context {
    struct module *module;
    struct env env;
    int fd;
    time_t timestamp;
    char template[PATH_MAX];
    char path[PATH_MAX];
    char timestr[128];
    struct ev_loop *loop;
    struct ev_async shutdown_w;
};

struct kv {
    char *k;
    size_t klen;
    char *v;
    size_t vlen;
};

static ssize_t
format (char *dst, size_t size, const char *fmt, const struct kv *table) {
    char *sp, *ep, *dp, *k;
    size_t len, ncopy, klen;
    struct kv *kv;

    sp = ep = (char *)fmt;
    len = strlen(fmt);
    dp = dst;
    while (1) {
        sp = strchr(ep, '$');
        if (!sp) {
            ncopy = len - (ep - fmt);
            memcpy(dp, ep, ncopy);
            dp += ncopy;
            break;
        }
        ncopy = sp - ep;
        memcpy(dp, ep, ncopy);
        dp += ncopy;
        for (ep = sp + 1; *ep; ep++) {
            if (!(isalnum(*ep) || *ep == '_')) {
                break;
            }
        }
        k = sp + 1;
        klen = ep - (sp + 1);
        for (kv = (struct kv *)table; kv && kv->k; kv++) {
            if (klen == kv->klen && memcmp(k, kv->k, klen) == 0) {
                ncopy = kv->vlen;
                memcpy(dp, kv->v, ncopy);
                dp += ncopy;
            }
        }
        sp = ep;
    }
    *dp = '\0';
    return dp - dst;
}

static int
reopenfile (struct context *ctx) {
    char path[PATH_MAX];
    struct tm tm;
    char *p;

    strftime(path, sizeof(path), ctx->template, localtime_r(&ctx->timestamp, &tm));
    strftime(ctx->timestr, sizeof(ctx->timestr), ctx->env.time_format, localtime_r(&ctx->timestamp, &tm));
    if (strcmp(ctx->path, path) != 0 || ctx->fd == -1) {
        strcpy(ctx->path, path);
        if (ctx->fd != -1) {
            close(ctx->fd);
        }
        p = ctx->path;
        while ((p = strstr(p, "../")) != NULL) {
            p[2] = '_';
            p += 3;
        }
        p = ctx->path;
        while ((p = strstr(p, "/..")) != NULL) {
            p[0] = '_';
            p += 3;
        }
        p = strrchr(ctx->path, '/');
        if (p) {
            setchar(p, '\0');
            mkdir_p(ctx->path, ctx->env.user, DEFAULT_PERM_DIRS);
            setchar(p, '/');
        }
        ctx->fd = open(ctx->path, O_WRONLY | O_CREAT | O_APPEND, ctx->env.mode);
        if (ctx->fd == -1) {
            fprintf(stderr, "%s: %s\n", strerror(errno), ctx->path);
            return -1;
        }
        if (ctx->env.user) {
            chperm(ctx->path, ctx->env.user, ctx->env.mode);
        }
        fprintf(stderr, "Open file, path=%s, fd=%d\n", ctx->path, ctx->fd);
    }
    return 0;
}

static void
emit (void *arg, const char *tag, size_t tag_len, const struct entry *entries, size_t len) {
    struct context *ctx;
    char template[PATH_MAX], buf[65536];
    const struct entry *entry;
    time_t timestamp;
    ssize_t n;
    struct kv table[] = {
        {"tag",      3, NULL, 0},
        {"time",     4, NULL, 0},
        {"hostname", 8, NULL, 0},
        {"record",   6, NULL, 0},
        { NULL,      0, NULL, 0}
    };

    ctx = (struct context *)arg;
    if (ctx->env.embed_hostname) {
        table[2].v = memrchr(tag, '.', tag_len);
        if (table[2].v) {
            table[2].vlen = tag_len - (++table[2].v - tag);
            tag_len -= table[2].vlen + 1;
        }
    }
    table[0].v = (char *)tag;
    table[0].vlen = tag_len;
    format(template, sizeof(template), ctx->env.path, table);
    if (strcmp(ctx->template, template) != 0) {
        strcpy(ctx->template, template);
        if (ctx->fd != -1) {
            close(ctx->fd);
            ctx->fd = -1;
        }
    }
    for (entry = entries; (caddr_t)entry < (caddr_t)entries + len; entry = NEXT_ENTRY(entry)) {
        timestamp = (time_t)ntohl(entry->timestamp);
        if (ctx->timestamp != timestamp || ctx->fd == -1) {
            ctx->timestamp = timestamp;
            if (reopenfile(ctx) == -1) {
                return;
            }
            table[1].v = ctx->timestr;
            table[1].vlen = strlen(ctx->timestr);
        }
        if (!table[1].v) {
            table[1].v = ctx->timestr;
            table[1].vlen = strlen(ctx->timestr);
        }
        table[3].v = (char *)entry->data;
        table[3].vlen = ntohl(entry->len);
        n = format(buf, sizeof(buf), ctx->env.format, table);
        if (n == -1) {
            fprintf(stderr, "entry message too long\n");
            return;
        }
        buf[n++] = '\n';
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

static int
parse_options (struct env *env, struct dir *dir) {
    struct param *param;
    time_t now;
    char tmp[128], *p;

    TAILQ_FOREACH(param, &dir->params, lp) {
        if (strcmp(param->key, "type") == 0) {
            // ignore
        } else if (strcmp(param->key, "path") == 0) {
            env->path = param->value;
        } else if (strcmp(param->key, "time_format") == 0) {
            env->time_format = param->value;
            now = time(NULL);
            strftime(tmp, sizeof(tmp), env->time_format, localtime(&now));
            if (strcmp(tmp, env->time_format) == 0) {
                fprintf(stderr, "warning: string of time format could not be found in the 'time_format', line %zu\n", param->line);
            }
        } else if (strcmp(param->key, "format") == 0) {
            env->format = param->value;
            unescape(env->format, strlen(env->format));
            if (!strstr(env->format, "$record")) {
                fprintf(stderr, "warning: $record could not be found in the 'format', line %zu\n", param->line);
            }
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
        } else if (strcmp(param->key, "embed_hostname") == 0) {
            env->embed_hostname = (strcmp(param->value, "true") == 0) ? 1 : 0;
        } else {
            fprintf(stderr, "warning: unknown parameter, line %zu\n", param->line);
        }
    }
    if (!env->path) {
        fprintf(stderr, "error: 'path' is required, line %zu\n", dir->line);
        return -1;
    }
    return 0;
}

int
out_file_setup (struct module *module, struct dir *dir) {
    struct context *ctx;

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "malloc: error\n");
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->module = module;
    ctx->env.time_format = DEFAULT_TIME_FORMAT;
    ctx->env.format = DEFAULT_FORMAT;
    ctx->env.mode = DEFAULT_PERM_FILE;
    if (parse_options(&ctx->env, dir) == -1) {
        free(ctx);
        return -1;
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
