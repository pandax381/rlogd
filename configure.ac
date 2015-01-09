#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rlogd], [0.3.0], [https://github.com/pandax381/rlogd/issues/])
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_SRCDIR([rlogd.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

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

# Checks for libev
LIBEVPATH="/usr"
AC_ARG_WITH(libev,
AC_HELP_STRING([--with-libev=PATH],[path to libev installation]),
  [
    LIBEVPATH="$withval"
    LDFLAGS="-L$LIBEVPATH/lib -Wl,-rpath -Wl,$LIBEVPATH/lib $LDFLAGS"
    CPPFLAGS="-I$LIBEVPATH/include $CPPFLAGS"
  ]
)
AC_ARG_ENABLE(libev-static,
  AC_HELP_STRING([--enable-libev-static],[libev static link]),
  [
    LIBS="$LIBS -lm $LIBEVPATH/lib/libev.a"
  ],
  [
    LIBS="$LIBS -lev"
  ]
)
AC_CHECK_HEADER(ev.h,,[AC_MSG_ERROR([not found ev.h])])

# Checks for libpcre
LIBPCREPATH="/usr"
AC_ARG_WITH(libpcre,
AC_HELP_STRING([--with-pcre=PATH],[path to pcre installation]),
  [
    LIBPCREPATH="$withval"
    LDFLAGS="-L$LIBPCREPATH/lib -Wl,-rpath -Wl,$LIBPCREPATH/lib $LDFLAGS"
    CPPFLAGS="-I$LIBPCREPATH/include $CPPFLAGS"
  ]
)
AC_ARG_ENABLE(libpcre-static,
  AC_HELP_STRING([--enable-libpcre-static],[libpcre static link]),
  [
    LIBS="$LIBS $LIBPCREPATH/lib/libpcre.a"
  ],
  [
    LIBS="$LIBS -lpcre"
  ]
)
AC_CHECK_HEADER(pcre.h,,[AC_MSG_ERROR([not found pcre.h])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
