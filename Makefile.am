ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = @PTHREAD_CFLAGS@
AM_CFLAGS = -W -Wall -Wno-unused-parameter -fno-strict-aliasing

bin_PROGRAMS  = rlogger rloggerd
sbin_PROGRAMS = rlogd

rlogger_SOURCES = rlogger.c common.c
rlogger_LDADD = @LIBEV_LDADD@

rloggerd_SOURCES = rloggerd.c common.c buffer.c
rloggerd_LDADD = @LIBEV_LDADD@ @PCRE_LDADD@ @PTHREAD_LIBS@

rlogd_SOURCES = rlogd.c common.c buffer.c in_forward.c out_forward.c out_file.c
rlogd_LDADD = @LIBEV_LDADD@ @PCRE_LDADD@ @PTHREAD_LIBS@

EXTRA_DIST = README.md LICENSE autogen.sh rlogd.conf.example

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 compile config.h.in config.h.in~ config.guess config.sub configure depcomp install-sh missing
