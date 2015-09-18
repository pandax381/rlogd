#ifndef LIB_RLOG_H
#define LIB_RLOG_H

#include <unistd.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

struct rlog {
    int fd;
    uint32_t seq;
};

struct rlog *
rlog_open (const char *address, int timeout);
int
rlog_write (struct rlog *r, const char *tag, size_t tlen, const char *str, size_t slen);
void
rlog_close (struct rlog *r);

#endif
