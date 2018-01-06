# Copyright (C) 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>
#
# This file is part of SecureSkat.
#
# SecureSkat is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser general Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# SecureSkat is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SecureSkat; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Process this file with autoconf to produce a configure script.
AC_REVISION([20180106])
AC_PREREQ(2.61)

AC_INIT([SecureSkat], [2.13], [HeikoStamer@gmx.net], [SecureSkat], [https://savannah.nongnu.org/projects/secureskat])
AC_LANG(C++)
AC_CONFIG_SRCDIR([SecureSkat.cc])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])

AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME")
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION")
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

# Check commandline switches
AC_MSG_CHECKING([whether NOHUP behaviour is enabled])
AC_ARG_ENABLE(nohup, [  --enable-nohup          enable NOHUP behaviour],
	use_nohup=$enableval, use_nohup=no)
AC_MSG_RESULT($use_nohup)
if test "$use_nohup" = yes ; then
	AC_DEFINE(NOHUP, , [Define to have the NOHUP behaviour])
fi

AC_MSG_CHECKING([whether AUTOJOIN behaviour is enabled])
AC_ARG_ENABLE(autojoin, [  --enable-autojoin       enable AUTOJOIN behaviour],
	use_autojoin=$enableval, use_autojoin=no)
AC_MSG_RESULT($use_autojoin)
if test "$use_autojoin" = yes ; then
	AC_DEFINE(AUTOJOIN, , [Define to have the AUTOJOIN behaviour])
fi

# Checks for Libtool
LT_PREREQ([2.4.2])
LT_INIT
LT_LANG([C++])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

# Checks for internationalization support.
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19.8])

# Checks for libraries.
backup_LDFLAGS="$LDFLAGS"       
backup_CPPLAGS="$CPPFLAGS"
AC_ARG_WITH(gmp, [AS_HELP_STRING([--with-gmp=<path>], [prefix of libgmp installation e.g. /usr/local])],\
 [GMP_PREFIX="$with_gmp" LDFLAGS="-L${with_gmp}/lib $backup_LDFLAGS" CPPFLAGS="-I${with_gmp}/include $backup_CPPFLAGS"],\
 [AC_CHECK_LIB(gmp, __gmpz_init, [LIBS=""], AC_MSG_ERROR([libgmp is needed; maybe you want to call configure with the --with-gmp=<path> option]))])
AC_CHECK_LIB(gmp, __gmpz_import, [LIBS=""], AC_MSG_ERROR([libgmp >= 4.2 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, [LIBS=""], AC_MSG_ERROR([libgmp >= 4.2 is needed]))
AC_CHECK_HEADERS([gmp.h], , AC_MSG_ERROR([libgmp headers are missing]))
if test "x$GMP_PREFIX" != x ; then
        LIBGMP_LIBS=" -L${GMP_PREFIX}/lib"
        LIBGMP_CFLAGS=" -I${GMP_PREFIX}/include"
else
        LIBGMP_LIBS=""
        LIBGMP_CFLAGS=""
fi
LIBGMP_LIBS="${GMP_LIBS} -lgmp"
AC_SUBST(LIBGMP_LIBS)
AC_SUBST(LIBGMP_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

AM_PATH_LIBGCRYPT("1.6.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.6.0 is needed])
fi
backup_CPPLAGS="$CPPFLAGS"
CPPFLAGS="$LIBGCRYPT_CFLAGS $backup_CPPFLAGS"
AC_CHECK_HEADERS([gcrypt.h], , AC_MSG_ERROR([libgcrypt headers are missing]))
CPPFLAGS="$backup_CPPFLAGS"
AC_SUBST(LIBGCRYPT_LIBS)
AC_SUBST(LIBGCRYPT_CFLAGS)

AM_PATH_LIBTMCG("1.3.8")
if test "x$LIBTMCG_LIBS" = "x"; then
	AC_MSG_ERROR([libTMCG >= 1.3.8 is needed])
fi
AC_SUBST(LIBTMCG_LIBS)
AC_SUBST(LIBTMCG_CFLAGS)

AC_ARG_WITH(gdbm, [AS_HELP_STRING([--with-gdbm=<path>], [prefix of libgdbm installation e.g. /usr/local])],\
 [LDFLAGS="-L${with_gdbm}/lib $LDFLAGS" CPPFLAGS="-I${with_gdbm}/include $CPPFLAGS"], [])
AC_CHECK_LIB(gdbm, gdbm_open, , AC_MSG_ERROR([libgdbm is needed; maybe you want to call configure with the --with-gdbm=<path> option]))
AC_CHECK_LIB(ncurses, initscr, , AC_MSG_ERROR([libncurses is needed]))
AC_CHECK_LIB(readline, rl_callback_handler_install, , AC_MSG_ERROR([libreadline is needed]))
AC_CHECK_LIB(z, zlibVersion, , AC_MSG_ERROR([zlib is needed]))

# Solaris needs -lsocket and -lnsl. Unisys system includes
# gethostbyname in libsocket but needs libnsl for socket.
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket, ac_need_libsocket=1, ac_try_nsl=1)
if test x$ac_need_libsocket = x1; then
	LIBS="$LIBS -lsocket"
fi
if test x$ac_try_nsl = x1; then
	AC_CHECK_LIB(nsl, gethostbyname, ac_need_libnsl=1)
	if test x$ac_need_libnsl = x1
		then
			LIBS="$LIBS -lnsl"
	fi
fi

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h cassert cctype cerrno csignal cstdio cstdlib\
 cstdarg cstring ctime fcntl.h netdb.h netinet/in.h sys/socket.h sys/stat.h\
 sys/wait.h termios.h unistd.h algorithm fstream iostream list map sstream\
 string vector zlib.h gdbm.h readline/readline.h readline/history.h], ,\
 AC_MSG_ERROR([some C/C++ headers are missing]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_SYS_POSIX_TERMIOS

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_STAT
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([fork dup2 getaddrinfo memset memcpy memcmp memmove select\
 socket strchr strncasecmp strrchr strstr strtol strtoul uname clock stat\
 mkdir getuid getenv strerror snprintf pipe perror waitpid close read write\
 send recv fileno tcgetattr tcsetattr connect bind listen accept setsockopt\
 htonl], , AC_MSG_ERROR([some essential C functions are missing]))

##CXXFLAGS="$CXXFLAGS -Wall -g3 $LIBGMP_CFLAGS $LIBGCRYPT_CFLAGS $LIBTMCG_CFLAGS"
##echo ">>>>>>>>>>>>>>>>>>> DEBUG MODE <<<<<<<<<<<<<<<<<<<<<<<"

CXXFLAGS="$CXXFLAGS -Wall -D NDEBUG $LIBGMP_CFLAGS $LIBGCRYPT_CFLAGS $LIBTMCG_CFLAGS"

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT

echo "Now type 'make && make install' to build and install SecureSkat."

