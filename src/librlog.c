#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "librlog.h"
#include "protocol.h"
#include "common.h"

struct rlog *
rlog_open (const char *address, int timeout) {
    int soc, ret, err, opt;
    struct pollfd pfd[1];
    socklen_t errlen;
    struct rlog *rlog;

    soc = setup_client_socket(address, DEFAULT_RLOGGERD_PORT, timeout ? 1 : 0);
    if (soc == -1) {
        return NULL;
    }
    if (timeout) {
        pfd[0].fd = soc;
        pfd[0].events = POLLOUT;
        ret = poll(pfd, 1, timeout);
        switch (ret) {
        case -1:
            error_print("poll: %s", strerror(errno));
            close(soc);
            return NULL;
        case  0:
            error_print("connect: timeout");
            close(soc);
            return NULL;
        default:
            errlen = sizeof(err);
            if (getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
                error_print("getsockopt [SOL_SOCKET/SO_ERROR]: %s", strerror(errno));
                close(soc);
                return NULL;
            }
            if (err) {
                error_print("connect: timeout: %s", strerror(err));
                close(soc);
                return NULL;
            }
        }
        opt = 0;
        if (ioctl(soc, FIONBIO, &opt) == -1) {
            error_print("ioctl [FIONBIO]: %s", strerror(errno));
            close(soc);
            return NULL;
        }
    }
    rlog = malloc(sizeof(struct rlog));
    if (!rlog) {
        error_print("malloc: failure");
        close(soc);
        return NULL;
    }
    rlog->fd = soc;
    rlog->seq = 0;
    return rlog;
}

void
rlog_close (struct rlog *r) {
    close(r->fd);
    free(r);
}

int
rlog_write (struct rlog *r, const char *tag, size_t tlen, const char *str, size_t slen) {
    size_t off;
    struct hdr hdr;
    struct entry entry;
    struct iovec iov[4];

    off = sizeof(hdr) + tlen;
    hdr.ver  = HDR_VERSION;
    hdr.type = HDR_TYPE_PSH;
    hdr.off  = htons(off);
    hdr.seq  = htonl(0);
    hdr.len  = htonl(off + sizeof(entry) + slen);
    entry.timestamp = htonl((uint32_t)time(NULL));
    entry.len = htonl(slen);
    iov[0].iov_base = &hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = (void *)tag;
    iov[1].iov_len  = tlen;
    iov[2].iov_base = &entry;
    iov[2].iov_len  = sizeof(entry);
    iov[3].iov_base = (void *)str;
    iov[3].iov_len  = slen;
    if (writevn(r->fd, iov, 4) == -1) {
        return -1;
    }
    return 0;
}
