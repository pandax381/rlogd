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
#ifndef RLOGD_PROTOCOL_H
#define RLOGD_PROTOCOL_H

#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define HDR_VERSION  0x01
#define HDR_TYPE_PSH 0x01
#define HDR_TYPE_ACK 0x02
#define HDR_NEED_ACK 0x80

struct hdr {
    uint8_t ver;
    uint8_t type;
    uint16_t off;
    uint32_t seq;
    uint32_t len;
    uint8_t tag[0];
};

struct entry {
    uint32_t timestamp;
    uint32_t len;
    uint8_t data[0];
};

#define HDR_LEN(x) (ntohs((x)->off))
#define TAG_PTR(x) ((caddr_t)((x) + 1))
#define TAG_LEN(x) (ntohs((x)->off) - sizeof(*(x)))
#define ENTRY_PTR(x) ((struct entry *)((caddr_t)(x) + ntohs((x)->off)))
#define ENTRY_LEN(x) (ntohl((x)->len) - ntohs((x)->off))
#define NEXT_ENTRY(x) ((struct entry *)((caddr_t)((x) + 1) + ntohl((x)->len)))

#define DEFAULT_BUFFER_CHUNK_LIMIT (1024*1024*8)
#define DEFAULT_FLUSH_INTERVAL (5)

#define DEFAULT_SOCKET_MODE (0666)
#define DEFAULT_RLOGD_SOCKET "unix:///var/run/rlogd/rlogd.sock"
#define DEFAULT_RLOGGERD_SOCKET "unix:///var/run/rlogd/rloggerd.sock"

#endif
