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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
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
#include "common.h"
#include "buffer.h"

#define DEFAULT_PERM_DIRS (00755)

static void
buffer_resume (struct buffer *buffer);

int
buffer_init (struct buffer *buffer, const char *base) {
    int posfd;
    const char c = 0;
    struct stat st;

    buffer->fd = -1;
    buffer->len = 0;
    buffer->base = (char *)base;
    buffer->dirfd = open(buffer->base, O_RDONLY);
    if (buffer->dirfd == -1) {
        mkdir_p(buffer->base, NULL, DEFAULT_PERM_DIRS);
        buffer->dirfd = open(buffer->base, O_RDONLY);
        if (buffer->dirfd == -1) {
            error_print("open: %s, path=%s", strerror(errno), buffer->base);
            return -1;
        }
    }
    posfd = openat(buffer->dirfd, POSITION_FILE_NAME, O_RDWR);
    if (posfd == -1) {
        posfd = openat(buffer->dirfd, POSITION_FILE_NAME, O_RDWR | O_CREAT | O_EXCL, 00644);
        if (posfd == -1) {
            error_print("open: %s, file=%s/%s", strerror(errno), buffer->base, POSITION_FILE_NAME);
            close(buffer->dirfd);
            return -1;
        }
        if (lseek(posfd, sizeof(struct position) - 1, SEEK_SET) == -1) {
            error_print("lseek: %s, file=%s/%s", strerror(errno), buffer->base, POSITION_FILE_NAME);
            close(posfd);
            close(buffer->dirfd);
            return -1;
        }
        if (writen(posfd, &c, sizeof(c)) == -1) {
            error_print("writen: failure, file=%s/%s", buffer->base, POSITION_FILE_NAME);
            close(posfd);
            close(buffer->dirfd);
            return -1;
        }
    }
    if (fstat(posfd, &st) == -1) {
        error_print("fstat: %s, file=%s/%s", strerror(errno), buffer->base, POSITION_FILE_NAME);
        close(posfd);
        close(buffer->dirfd);
        return -1;
    }
    if (st.st_size != sizeof(struct position)) {
        error_print("file size check error, file=%s/%s", buffer->base, POSITION_FILE_NAME);
        close(posfd);
        close(buffer->dirfd);
        return -1;
    }
    buffer->size = st.st_size;
    buffer->cursor = mmap(NULL, buffer->size, PROT_READ | PROT_WRITE, MAP_SHARED, posfd, 0);
    if (buffer->cursor == MAP_FAILED) {
        error_print("mmap: %s, file=%s/%s, size=%zd", strerror(errno), buffer->base, POSITION_FILE_NAME, buffer->size);
        close(posfd);
        close(buffer->dirfd);
        return -1;
    }
    close(posfd);
    buffer_resume(buffer);
    pthread_mutex_init(&buffer->mutex, NULL);
    notice_print("position: %s/%s, read=%u/%u, write=%u/%u", buffer->base, POSITION_FILE_NAME,
        buffer->cursor->rb, buffer->cursor->rc, buffer->cursor->wb, buffer->cursor->wc);
    return 0;
}

int
buffer_create (struct buffer *buffer) {
    char fname[NAME_MAX];

    snprintf(fname, sizeof(fname), "_%s.%u", BUFFER_FILE_NAME, buffer->cursor->wb);
    buffer->fd = openat(buffer->dirfd, fname, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (buffer->fd == -1) {
        error_print("open: %s, path=%s/%s", strerror(errno), buffer->base, fname);
        return -1;
    }
    return 0;
}

static void
buffer_resume (struct buffer *buffer) {
    char fname[NAME_MAX];
    struct stat st;

    snprintf(fname, sizeof(fname), "_%s.%u", BUFFER_FILE_NAME, buffer->cursor->wb);
    buffer->fd = openat(buffer->dirfd, fname, O_WRONLY);
    if (buffer->fd != -1) {
        fstat(buffer->fd, &st);
        buffer->tstamp.tv_sec = st.st_mtime;
        buffer->tstamp.tv_usec = 0;
        buffer->len = st.st_size;
        lseek(buffer->fd, 0, SEEK_END);
    }
}

int
buffer_flush (struct buffer *buffer) {
    char fname[NAME_MAX];

    if (buffer->fd == -1) {
        warning_print("buffer has not yet been made");
        return 0;
    }
    snprintf(fname, sizeof(fname), "_%s.%u", BUFFER_FILE_NAME, buffer->cursor->wb);
    debug_print("flush buffer: %s/%s", buffer->base, fname + 1);
    if (renameat(buffer->dirfd, fname, buffer->dirfd, fname + 1) == -1) {
        warning_print("renameat: %s, base=%s, %s -> %s", strerror(errno), buffer->base, fname, fname + 1);
    }
    close(buffer->fd);
    buffer->cursor->wb++;
    buffer->fd = -1;
    buffer->len = 0;
    return 0;
}

int
buffer_write (struct buffer *buffer, const char *tag, size_t tag_len, struct entry *entries, size_t len) {
    size_t off;
    struct hdr hdr;
    struct iovec iov[3];
    off_t cur;

    if (buffer->fd == -1) {
        if (buffer_create(buffer) == -1) {
            return -1;
        }
    }
    if (!buffer->len) {
        gettimeofday(&buffer->tstamp, NULL);
    }
    off = sizeof(hdr) + tag_len;
    hdr.ver  = HDR_VERSION;
    hdr.type = HDR_TYPE_PSH | HDR_NEED_ACK;
    hdr.off  = htons(off);
    hdr.seq  = htonl(buffer->cursor->wc + 1);
    hdr.len  = htonl(off + len);
    iov[0].iov_base = (void *)&hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = (void *)tag;
    iov[1].iov_len  = tag_len;
    iov[2].iov_base = (void *)entries;
    iov[2].iov_len  = len;
    cur = lseek(buffer->fd, 0, SEEK_CUR);
    if (writevn(buffer->fd, iov, 3) == -1) {
        warning_print("writevn: error, rewind file offset [%lld] to [%lld]", lseek(buffer->fd, 0, SEEK_CUR), cur);
        ftruncate(buffer->fd, cur);
        lseek(buffer->fd, cur, SEEK_SET);
        return -1;
    }
    buffer->len += (off + len);
    buffer->cursor->wc++;
    return 0;
}

void
buffer_terminate (struct buffer *buffer) {
    if (buffer->dirfd != -1) {
        close(buffer->dirfd);
    }
    if (buffer->fd != -1) {
        close(buffer->fd );
        buffer->fd = -1;
    }
    if (buffer->cursor) {
        if (munmap(buffer->cursor, buffer->size) == -1) {
            warning_print("munmap: %s", strerror(errno));
        }
        buffer->cursor = NULL;
        buffer->size = 0;
    }
    buffer->len = 0;
    pthread_mutex_destroy(&buffer->mutex);
}
