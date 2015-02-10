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

static void
buffer_resume (struct buffer *buffer);

int
buffer_init (struct buffer *buffer, const char *base) {
    int fd;
    const char c = 0;
    struct stat st;

    buffer->fd = -1;
    buffer->len = 0;
    buffer->base = (char *)base;
    snprintf(buffer->file, sizeof(buffer->file), "%s/%s", buffer->base, POSITION_FILE_NAME);
    fd = open(buffer->file, O_RDWR);
    if (fd == -1) {
        fd = open(buffer->file, O_RDWR | O_CREAT | O_EXCL, 00644);
        if (fd == -1) {
            fprintf(stderr, "open: %s, file=%s\n", strerror(errno), buffer->file);
            return -1;
        }
        if (lseek(fd, sizeof(struct position) - 1, SEEK_SET) == -1) {
            fprintf(stderr, "lseek: %s, file=%s\n", strerror(errno), buffer->file);
            close(fd);
            return -1;
        }
        if (writen(fd, &c, sizeof(c)) == -1) {
            fprintf(stderr, "write: %s, file=%s\n", strerror(errno), buffer->file);
            close(fd);
            return -1;
        }
    }
    if (fstat(fd, &st) == -1) {
        fprintf(stderr, "fstat: %s, file=%s\n", strerror(errno), buffer->file);
        close(fd);
        return -1;
    }
    if (st.st_size != sizeof(struct position)) {
        close(fd);
        return -1;
    }
    buffer->size = st.st_size;
    buffer->cursor = mmap(NULL, buffer->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buffer->cursor == MAP_FAILED) {
        fprintf(stderr, "mmap: %s, file=%s, size=%lld\n", strerror(errno), buffer->file, buffer->size);
        close(fd);
        return -1;
    }
    close(fd);
    buffer_resume(buffer);
    return 0;
}

int
buffer_create (struct buffer *buffer) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/_%s.%u", buffer->base, BUFFER_FILE_NAME, buffer->cursor->wb);
    buffer->fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (buffer->fd == -1) {
        fprintf(stderr, "open: %s, path=%s\n", strerror(errno), path);
        return -1;
    }
    return 0;
}

static void
buffer_resume (struct buffer *buffer) {
    char path[PATH_MAX];
    struct stat st;

    snprintf(path, sizeof(path), "%s/_%s.%u", buffer->base, BUFFER_FILE_NAME, buffer->cursor->wb);
    buffer->fd = open(path, O_WRONLY);
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
    char tmp[PATH_MAX], path[PATH_MAX];

    snprintf(tmp, sizeof(tmp), "%s/_%s.%u", buffer->base, BUFFER_FILE_NAME, buffer->cursor->wb);
    snprintf(path, sizeof(path), "%s/%s.%u", buffer->base, BUFFER_FILE_NAME, buffer->cursor->wb);
    fprintf(stderr, "flush_buffer: %s\n", path);
    rename(tmp, path);
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
    hdr.seq  = htonl(buffer->cursor->wc++);
    hdr.len  = htonl(off + len);
    iov[0].iov_base = (void *)&hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = (void *)tag;
    iov[1].iov_len  = tag_len;
    iov[2].iov_base = (void *)entries;
    iov[2].iov_len  = len;
    if (writevn(buffer->fd, iov, 3) == -1) {
        return -1;
    }
    buffer->len += (off + len);
    return 0;
}

void
buffer_terminate (struct buffer *buffer) {
    if (buffer->fd != -1) {
        close(buffer->fd );
        buffer->fd = -1;
    }
    if (buffer->cursor) {
        if (munmap(buffer->cursor, buffer->size) == -1) {
            perror("munmap");
        }
        buffer->cursor = NULL;
        buffer->size = 0;
    }
    buffer->file[0] = 0x00;
    buffer->len = 0;
}
