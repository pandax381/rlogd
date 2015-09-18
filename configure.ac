#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([rlogd], [0.4.3], [https://github.com/pandax381/rlogd/issues/])
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_SRCDIR([src/rlogd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_DEFINE([_GNU_SOURCE], [], [Enable GNU extensions])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([dup2 gettimeofday isascii localtime_r memchr memmove memset mkdir regcomp socket strchr strdup strerror strndup strpbrk strrchr strtol memrchr])
AX_PTHREAD

# Checks for libev
AC_ARG_WITH([libev],[AC_HELP_STRING([--with-libev=DIR],[location of the libev installed directory])],[EV_PATH="$withval"],[])
if test "$EV_PATH"; then
    EV_LDFLAGS="-L${EV_PATH}/lib -Wl,-rpath,${EV_PATH}/lib"
    EV_CPPFLAGS="-I${EV_PATH}/include"
fi
AX_CHECK_LIBRARY([EV],[ev.h],[ev],[],[AC_MSG_ERROR([libev not found])])
AC_ARG_ENABLE([libev-static],[AC_HELP_STRING([--enable-libev-static],[libev static link])],[EV_STATIC="yes"],[])
if test "$EV_STATIC" = "yes"; then
    EV_LIBS="-lm ${EV_PATH}/lib/libev.a"
else
    EV_LIBS="-lev"
fi
AC_SUBST(EV_LDFLAGS)
AC_SUBST(EV_CPPFLAGS)
AC_SUBST(EV_LIBS)

# Checks for libpcre
AC_ARG_WITH([libpcre],[AC_HELP_STRING([--with-libpcre=DIR],[location of the libpcre installed directory])],[PCRE_PATH="$withval"],[])
if test "$PCRE_PATH"; then
    PCRE_LDFLAGS="-L${PCRE_PATH}/lib -Wl,-rpath,${PCRE_PATH}/lib"
    PCRE_CPPFLAGS="-I${PCRE_PATH}/include"
fi
AX_CHECK_LIBRARY([PCRE],[pcre.h],[pcre],[],[AC_MSG_ERROR([libpcre not found])])
AC_ARG_ENABLE([libpcre-static],[AC_HELP_STRING([--enable-libpcre-static],[libpcre static link])],[PCRE_STATIC="yes"],[])
if test "$PCRE_STATIC" = "yes"; then
    PCRE_LIBS="${PCRE_PATH}/lib/libpcre.a"
else
    PCRE_LIBS="-lpcre"
fi
AC_SUBST(PCRE_LDFLAGS)
AC_SUBST(PCRE_CPPFLAGS)
AC_SUBST(PCRE_LIBS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
