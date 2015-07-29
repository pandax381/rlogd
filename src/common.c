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
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pwd.h>
#include "common.h"

int __debug;

void
hexdump (FILE *fp, void *data, size_t size) {
    unsigned char *src;
    int offset, index;

    src = (unsigned char *)data;
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    for(offset = 0; offset < (int)size; offset += 16) {
        fprintf(fp, "| %04x | ", offset);
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "| ");
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                if(isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");
                }
            } else {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
}

void
sig_ignore (int n) {
    struct sigaction sig;

    sig.sa_handler = SIG_IGN;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags= 0;
    sigaction(n, &sig, NULL);
}

int
mkdir_p (const char *dir, const char *user, mode_t mode) {
    char *s, *e, path[PATH_MAX];
    struct stat st;

    s = (char *)dir;
    while ((e = strchr(s, '/')) != NULL) {
        snprintf(path, sizeof(path), "%.*s", (int)((e + 1) - dir), dir);
        if (stat(path, &st) == -1) {
            if (errno != ENOENT) {
                return -1;
            }
            if (mkdir(path, mode) == -1) {
                return -1;
            }
            chperm(path, user, mode);
        } else {
            if (!S_ISDIR(st.st_mode)) {
                return -1;
            }
        }
        s = e + 1;
    }
    if (mkdir(dir, mode) == -1) {
        return -1;
    }
    chperm(dir, user, mode);
    return 0;
}

char *
strtrim (char *str) {
    char *s, *e;

    if (!str) {
        return NULL;
    }
    for (s = str; *s; s++) {
        if (!isspace(*s)) {
            break;
        }
    }
    for (e = (str + (strlen(str))); e > s; e--) {
        if (!isspace(*(e - 1))) {
            break;
        }
    }
    memmove(str, s, e - s);
    str[e - s] = '\0';
    return str;
}

struct timeval *
tvsub (struct timeval *a, struct timeval *b, struct timeval *c) {
    c->tv_sec = a->tv_sec - b->tv_sec;
    c->tv_usec = a->tv_usec - b->tv_usec;
    if(c->tv_usec < 0) {
        c->tv_sec -= 1;
        c->tv_usec += 1000000;
    }
    return c;
}

struct timeval *
tvadd (struct timeval *a, struct timeval *b) {
    a->tv_sec += b->tv_sec;
    if(a->tv_usec + b->tv_usec >= 1000000) {
        a->tv_sec++;
        a->tv_usec = a->tv_usec + b->tv_usec - 1000000;
    }
    else {
        a->tv_usec = a->tv_usec + b->tv_usec;
    }
    return a;
}

int
setup_client_socket (const char *address, const char *default_port, int nonblock) {
    char *addr, *port;
    int fd;

    if (strncmp(address, "unix://", 7) == 0) {
        return setup_unix_client_socket(address + 7, nonblock);
    } else {
        addr = strdup(address);
        if (!addr) {
            return -1;
        }
        port = strrchr(addr, ':');
        if (!port) {
            if (!default_port) {
                free(addr);
                return -1;
            }
            port = (char *)default_port;
        } else {
            *port++ = '\0';
        }
        fd = setup_tcp_client_socket(addr, port, nonblock);
        free(addr);
        return fd;
    }
}

int
setup_unix_client_socket (const char *path, int nonblock) {
    int soc, opt;
    struct sockaddr_un addr;

    soc = socket(AF_UNIX, SOCK_STREAM, 0);
    if (soc == -1) {
        warning_print("socket: %s", strerror(errno));
        return -1;
    }
    if (nonblock) {
        opt = 1;
        if (ioctl(soc, FIONBIO, &opt) == -1) {
            warning_print("ioctl [FIONBIO]: %s", strerror(errno));
            close(soc);
            return -1;
        }
    }
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (connect(soc, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        if (!nonblock || errno != EINPROGRESS) {
            warning_print("connect: %s, path=%s", strerror(errno), path);
            close(soc);
            return -1;
        }
    }
    return soc;
}

int
setup_tcp_client_socket (const char *host, const char *port, int nonblock) {
    struct addrinfo hints, *ais, *ai;
    int err, soc, opt;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &ais);
    if (err) {
        warning_print("getaddrinfo: %s, host=%s, port=%s", gai_strerror(err), PRINTSTR(host), PRINTSTR(port));
        return -1;
    }
    for (ai = ais; ai; ai = ai->ai_next) {
        soc = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (soc == -1) {
            warning_print("socket: %s", strerror(errno));
            continue;
        }
        if (nonblock) {
            opt = 1;
            if (ioctl(soc, FIONBIO, &opt) == -1) {
                warning_print("ioctl [FIONBIO]: %s", strerror(errno));
                close(soc);
                continue;
            }
        }
        if (connect(soc, ai->ai_addr, ai->ai_addrlen) == -1) {
            if (!nonblock || errno != EINPROGRESS) {
                warning_print("connect: %s, host=%s, port=%s", strerror(errno), PRINTSTR(host), PRINTSTR(port));
                close(soc);
                continue;
            }
        }
        freeaddrinfo(ais);
        return soc;
    }
    freeaddrinfo(ais);
    warning_print("Can't create any client sockets");
    return -1;
}

int
setup_server_socket (const char *address, const char *default_port, int backlog, int nonblock) {
    char *addr, *port;
    int fd;

    if (strncmp(address, "unix://", 7) == 0) {
        return setup_unix_server_socket(address + 7, backlog, nonblock);
    } else {
        addr = strdup(address);
        if (!addr) {
            return -1;
        }
        port = strrchr(addr, ':');
        if (!port) {
            if (!default_port) {
                free(addr);
                return -1;
            }
            port = (char *)default_port;
        } else {
            *port++ = '\0';
        }
        fd = setup_tcp_server_socket(addr, port, backlog, nonblock);
        free(addr);
        return fd;
    }
}

int
setup_unix_server_socket (const char *path, int backlog, int nonblock) {
    int soc, opt;
    struct sockaddr_un addr;

    soc = socket(AF_UNIX, SOCK_STREAM, 0);
    if (soc == -1) {
        warning_print("socket: %s", strerror(errno));
        return -1;
    }
    if (nonblock) {
        opt = 1;
        if (ioctl(soc, FIONBIO, &opt) == -1) {
            warning_print("ioctl [FIONBIO]: %s", strerror(errno));
            close(soc);
            return -1;
        }
    }
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (bind(soc, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        warning_print("bind: %s, path=%s", strerror(errno), path);
        close(soc);
        return -1;
    }
    if (listen(soc, backlog) == -1) {
        warning_print("listen: %s, path=%s", strerror(errno), path);
        close(soc);
        return -1;
    }
    return soc;
}

int
setup_tcp_server_socket (const char *host, const char *port, int backlog, int nonblock) {
    struct addrinfo hints, *ais, *ai;
    int err, soc, opt;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE,
    err = getaddrinfo(host, port, &hints, &ais);
    if (err) {
        warning_print("getaddrinfo: %s, host=%s, port=%s", gai_strerror(err), PRINTSTR(host), PRINTSTR(port));
        return -1;
    }
    for (ai = ais; ai; ai = ai->ai_next) {
        soc = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (soc == -1) {
            warning_print("socket: %s", strerror(errno));
            continue;
        }
        if (nonblock) {
            opt = 1;
            if (ioctl(soc, FIONBIO, &opt) == -1) {
                warning_print("ioctl [FIONBIO]: %s", strerror(errno));
                close(soc);
                continue;
            }
        }
        opt = 1;
        if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            warning_print("setsockopt [SO_REUSEADDR]: %s", strerror(errno));
            close(soc);
            continue;
        }
#ifdef IPV6_V6ONLY
        if (ai->ai_family == AF_INET6) {
            opt = 1;
            if (setsockopt(soc, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1) {
                warning_print("setsockopt [IPV6_V6ONLY]: %s", strerror(errno));
                close(soc);
                continue;
            }
        }
#endif
        if (bind(soc, ai->ai_addr, ai->ai_addrlen) == -1) {
            warning_print("bind: %s", strerror(errno));
            close(soc);
            continue;
        }
        if (listen(soc, backlog) == -1) {
            warning_print("listen: %s", strerror(errno));
            close(soc);
            continue;
        }
        freeaddrinfo(ais);
        return soc;
    }
    freeaddrinfo(ais);
    warning_print("Can't create any server sockets");
    return -1;
}

ssize_t
writen (int fd, const void *buf, size_t n) {
    size_t done = 0;
    ssize_t ret;

    while (done < n) {
        ret = write(fd, (caddr_t)buf + done, n - done);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return (ssize_t)done;
            }
            warning_print("write: %s", strerror(errno));
            return -1;
        } else {
            done += ret;
        }
    }
    return (ssize_t)done;
}

size_t
iovlen (const struct iovec *iov, size_t n) {
    size_t len = 0;

    while (n) {
        len += iov[--n].iov_len;
    }
    return len;
}

ssize_t
writevn (int fd, struct iovec *iov, size_t n) {
    size_t total = 0, done = 0, i;
    ssize_t ret;

    total = iovlen(iov, n);
    while (done < total) {
        ret = writev(fd, iov, n);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return (ssize_t)done;
            }
            warning_print("writev: %s", strerror(errno));
            return -1;
        }
        done += ret;
        for (i = 0; i < n; i++) {
            if (iov[i].iov_len > (size_t)ret) {
                iov[i].iov_len -= ret;
                iov[i].iov_base = (caddr_t)iov[i].iov_base + ret;
                break;
            } 
            ret -= iov[i].iov_len;
            iov[i].iov_len = 0;
        }
    }
    return (ssize_t)done;
}

static pid_t
fork_and_exit (void) {
    pid_t pid;

    if ((pid = fork()) > 0) {
        // parent process
        _exit(EXIT_SUCCESS);
    }
    return pid;
}

int
daemonize (const char *dir, int noclose) {
    int fd;

    if (fork_and_exit() == -1) {
        warning_print("fork: %s", strerror(errno));
        return -1;
    }
    if (setsid() == -1) {
        warning_print("setsid: %s", strerror(errno));
        return -1;
    }
    if (fork_and_exit() == -1) {
        warning_print("fork: %s", strerror(errno));
        return -1;
    }
    if (dir) {
        chdir(dir);
    }
    if (!noclose) {
        if ((fd = open("/dev/null", O_RDWR)) == -1) {
            warning_print("open: %s", strerror(errno));
            return -1;
        }
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            close(fd);
        }
    }
    return 0;
}

int
chperm (const char *path, const char *user, mode_t mode) {
    struct passwd *p;

    if (chmod(path, mode) == -1) {
        warning_print("chperm: %s", strerror(errno));
        return -1;
    }
    if (user) {
        errno = 0;
        p = getpwnam(user);
        if (!p) {
            if (errno) {
                warning_print("getpwnam: %s", strerror(errno));
            } else {
                warning_print("getpwnam: not found");
            }
            return -1;
        }
        if (chown(path, p->pw_uid, p->pw_gid) == -1) {
            warning_print("chown: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

int
ctoi (int c) {
    if (c >= 'a' && c <= 'f') {
        return (c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F' ) {
        return (c - 'A') + 10;
    }
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return 0;
}

int
isodigit (int c) {
    return (c >= '0' && c <= '7') ? 1 : 0;
}

char *
unescape (char *str, size_t len) {
    char *dp, *sp, *ep;
    int esc, num, n;

    dp = ep = str;
    while (1) {
        sp = memchr(ep, '\\', len - (ep - str));
        if (!sp) {
            if (ep != str) {
                n = len - (ep - str);
                memmove(dp, ep, n);
                dp[n] = '\0';
            }
            break;
        }
        memmove(dp, ep, sp - ep);
        dp += sp - ep;
        esc = 2; /* majority of the escape sequence length */
        switch (sp[1]) {
        case '\\':
            *dp++ = '\\';
            break;
        case 'a':
            *dp++ = '\a';
            break;
        case 'b':
            *dp++ = '\b';
            break;
        case 'n':
            *dp++ = '\n';
            break;
        case 'r':
            *dp++ = '\r';
            break;
        case 't':
            *dp++ = '\t';
            break;
        case 'v':
            *dp++ = '\v';
            break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
            for (n = 0, num = 0; n < 3 && isodigit(sp[1+n]); n++) {
                num = (num << 3) | ctoi(sp[1+n]);
            }
            esc += n - 1; /* n is never 0 */
            *dp++ = num;
            break;
        case 'x':
            for (n = 0, num = 0; n < 2 && isxdigit(sp[2+n]); n++) {
                num = (num << 4) | ctoi(sp[2+n]);
            }
            if (n == 0) {
                /* error */
                break;
            }
            esc += n;
            *dp++ = num;
            break;
        default:
            warning_print("'\\%c' is unsupported escape sequence", sp[1]);
            break;
        }
        ep = sp + esc;
    }
    return str;
}

#ifndef HAVE_MEMRCHR
void *
memrchr (const void *s, int c, size_t n) {
    const unsigned char *p;

    if (n) {
        for (p = (unsigned char *)s; n; n--) {
            if (p[n-1] == (unsigned char)c) {
                return (void *)&p[n-1];
            }
        }
    }
    return NULL;
}
#endif
