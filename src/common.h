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
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/stat.h>

#ifndef container_of
#define container_of(ptr, type, member) ({ \
const typeof( ((type *)0)->member ) *__mptr = (ptr); \
(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef SOMAXCONN
#define SOMAXCONN 128
#endif

#define PRINTSTR(x) (x ? x : "(null)")
#define CADDR(x) ((caddr_t)x)

#define INDENT_SIZE 2
#define INDENT(x) ((x)*INDENT_SIZE)

#define setchar(x, y) (*(x) = y)

extern int __debug;

#define __print(type, fmt, ...) \
    fprintf(stderr, "%s: " fmt " (%s:%d)\n", type, ##__VA_ARGS__, __FILE__, __LINE__);
#define error_print(...) \
    __print("error", __VA_ARGS__);
#define warning_print(...) \
    __print("warning", __VA_ARGS__);
#define notice_print(...) \
    __print("notice", __VA_ARGS__);
#define debug_print(...) \
    if (__debug) \
        __print("debug", __VA_ARGS__);

struct string {
    char *text;
    size_t len;
};

struct buf {
    void *data;
    size_t alloc;
    size_t len;
};

static inline int
buf_init (struct buf *b, size_t n) {
    b->data = malloc(n);
    if (!b->data) {
        return -1;
    }
    b->alloc = n;
    b->len = 0;
    return 0;
}

static inline caddr_t
buf_addr (struct buf *b) {
    return b->data;
}

static inline caddr_t
buf_tail (struct buf *b) {
    return buf_addr(b) + b->len;
}

static inline size_t
buf_capacity (struct buf *b) {
    return b->alloc - b->len;
}

static inline int
buf_empty (struct buf *b) {
    return b->len ? 0 : 1;
}

static inline int
buf_full (struct buf *b) {
    return b->len == b->alloc;
}

static inline size_t
buf_offset (struct buf *b, void *p) {
    return (caddr_t)p - buf_addr(b);
}

static inline void
buf_remove (struct buf *b, size_t offset) {
    memmove(b->data, buf_addr(b) + offset, b->len - offset);
    b->len -= offset;
}

static inline void
buf_removeat (struct buf *b, void *p) {
    buf_remove(b, buf_offset(b, p));
}

static inline size_t
buf_lengthat (struct buf *b, void *p) {
    return b->len - buf_offset(b, p);
}

static inline int
buf_permit (struct buf *b, size_t n) {
    return buf_capacity(b) >= n;
}

extern void
hexdump (FILE *fp, void *data, size_t size);
extern void
sig_ignore (int n);
extern int
mkdir_p (const char *dir, const char *user, mode_t mode);
extern char *
strtrim (char *str);
extern struct timeval *
tvsub (struct timeval *a, struct timeval *b, struct timeval *c);
extern struct timeval *
tvadd (struct timeval *a, struct timeval *b);
extern int
setup_client_socket (const char *address, const char *default_port, int nonblock);
extern int
setup_unix_client_socket (const char *path, int nonblock);
extern int
setup_tcp_client_socket (const char *host, const char *port, int nonblock);
extern int
setup_server_socket (const char *address, const char *default_port, int backlog, int nonblock);
extern int
setup_unix_server_socket (const char *path, int backlog, int nonblock);
extern int
setup_tcp_server_socket (const char *host, const char *port, int backlog, int nonblock);
extern ssize_t
writen (int fd, const void *buf, size_t n);
extern size_t
iovlen (const struct iovec *iov, size_t n);
extern ssize_t
writevn (int fd, struct iovec *iov, size_t n);
extern int
daemonize (const char *dir, int noclose);
extern int
chperm (const char *path, const char *user, mode_t mode);
extern int
ctoi (int c);
extern int
isodigit (int c);
extern char *
unescape (char *str, size_t len);
#ifndef HAVE_MEMRCHR
extern void *
memrchr (const void *s, int c, size_t n);
#endif
#ifndef HAVE_OPENAT
extern int
openat (int dirfd, const char *file, int flags, ...);
#endif
#ifndef HAVE_RENAMEAT
extern int
renameat (int olddirfd, const char *oldfile, int newdirfd, const char *newfile);
#endif

#endif
