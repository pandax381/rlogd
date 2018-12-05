AM_CPPFLAGS = -DSYSCONFDIR=\"${sysconfdir}\" -DLOCALSTATEDIR=\"${localstatedir}\" 
CFLAGS += -W -Wall -Wno-unused-parameter -fno-strict-aliasing -Wno-varargs -fPIC

bin_PROGRAMS = rlogger rloggerd
sbin_PROGRAMS = rlogd
noinst_LIBRARIES = librlog.a
 
noinst_HEADERS = buffer.h common.h protocol.h rlogd.h librlog.h

librlog_a_SOURCES = librlog.c common.c

rlogger_SOURCES = rlogger.c common.c
rlogger_CFLAGS = $(EV_CPPFLAGS)
rlogger_LDADD = $(EV_LIBS)
rlogger_LDFLAGS = $(EV_LDFLAGS)

rloggerd_SOURCES = rloggerd.c common.c buffer.c
rloggerd_CFLAGS = $(EV_CPPFLAGS) $(PCRE_CPPFLAGS) $(PTHREAD_CFLAGS)
rloggerd_LDADD = $(EV_LIBS) $(PCRE_LIBS) $(PTHREAD_LIBS)
rloggerd_LDFLAGS = $(EV_LDFLAGS) $(PCRE_LDFLAGS)

rlogd_SOURCES = rlogd.c common.c buffer.c in_forward.c out_forward.c out_file.c
rlogd_CFLAGS = $(EV_CPPFLAGS) $(PCRE_CPPFLAGS) $(MSGPACKC_CPPFLAGS) $(PTHREAD_CFLAGS)
rlogd_LDADD = $(EV_LIBS) $(PCRE_LIBS) $(MSGPACKC_LIBS) $(PTHREAD_LIBS)
rlogd_LDFLAGS = $(EV_LDFLAGS) $(PCRE_LDFLAGS) $(MSGPACKC_LDFLAGS)

MAINTAINERCLEANFILES = Makefile.in
