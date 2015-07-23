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
#ifndef RLOGD_H
#define RLOGD_H

#include <stdint.h>
#include <sys/queue.h>
#include "protocol.h"

struct module {
    void *arg;
    void *(*run)(void *);
    void (*cancel)(void *);
    void (*revoke)(void *);
    void (*emit)(void *, const char *, size_t, const struct entry *, size_t);
};

struct param {
    char *key;
    char *value;
    size_t line;
    TAILQ_ENTRY(param) lp;
};

struct dir {
    struct dir *parent;
    char *name;
    char *arg;
    size_t line;
    TAILQ_HEAD(/**/, param) params;
    TAILQ_HEAD(/**/, dir) dirs;
    TAILQ_ENTRY(dir) lp;
};

struct config {
    TAILQ_HEAD(/**/, dir) dirs;
};

extern int __dryrun;

extern char *
config_dir_get_param_value (struct dir *dir, const char *key);
extern void
push_entries (struct module *module, const char *tag, size_t tag_len, struct entry *entries, size_t len);

#endif
