#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rlogd], [0.3.1], [https://github.com/pandax381/rlogd/issues/])
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_SRCDIR([rlogd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC

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
AC_CHECK_FUNCS([dup2 gettimeofday isascii localtime_r memchr memmove memset mkdir regcomp socket strchr strdup strerror strndup strpbrk strrchr strtol])
AX_PTHREAD

# Checks for libev
AC_ARG_WITH([libev],[AC_HELP_STRING([--with-libev=DIR],[location of the libev installed directory])],[LIBEV_PATH="$withval"])
if test "$LIBEV_PATH"; then
    LDFLAGS="-L${LIBEV_PATH}/lib -Wl,-rpath,${LIBEV_PATH}/lib ${LDFLAGS}"
    CPPFLAGS="-I${LIBEV_PATH}/include ${CPPFLAGS}"
fi
AC_CHECK_HEADER(ev.h,,[AC_MSG_ERROR([ev.h not found])])
AC_ARG_ENABLE([libev-static],[AC_HELP_STRING([--enable-libev-static],[libev static link])],[LIBEV_STATIC="yes"])
if test "$LIBEV_STATIC" = "yes"; then
    LIBEV_LDADD="-lm ${LIBEV_PATH}/lib/libev.a"
else
    LIBEV_LDADD="-lev"
fi
AC_SUBST(LIBEV_LDADD)

# Checks for libpcre
AC_ARG_WITH([libpcre],[AC_HELP_STRING([--with-libpcre=DIR],[location of the libpcre installed directory])],[LIBPCRE_PATH="$withval"])
if test "$LIBPCRE_PATH"; then
    LDFLAGS="-L${LIBPCRE_PATH}/lib -Wl,-rpath,${LIBPCRE_PATH}/lib ${LDFLAGS}"
    CPPFLAGS="-I${LIBPCRE_PATH}/include ${CPPFLAGS}"
fi
AC_CHECK_HEADER(pcre.h,,[AC_MSG_ERROR([pcre.h not found])])
AC_ARG_ENABLE([libpcre-static],[AC_HELP_STRING([--enable-libpcre-static],[libpcre static link])],[LIBPCRE_STATIC="yes"])
if test "$LIBPCRE_STATIC" = "yes"; then
    PCRE_LDADD="-lm ${LIBPCRE_PATH}/lib/libpcre.a ${LIBS}"
else
    PCRE_LDADD="-lpcre ${LIBS}"
fi
AC_SUBST(PCRE_LDADD)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
