# Process this file with autoconf to produce a configure script.
AC_REVISION($Revision: 1.52 $)
AC_PREREQ(2.57)

AC_INIT(SecureSkat, 2.8, stamer@gaos.org)
AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_LANG(C++)
AC_CONFIG_SRCDIR(SecureSkat.cc)
AM_CONFIG_HEADER(config.h)

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

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for internationalization support.
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14.4])
#ALL_LINGUAS="de"

# Checks for libraries.
AC_CHECK_LIB(gdbm, main, , AC_MSG_ERROR([libgdbm is needed]))
AC_CHECK_LIB(gmp, __gmpz_import, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
##AC_CHECK_LIB(gmpxx, __gmpz_set_str, , AC_MSG_ERROR([libgmpxx (C++ support) >= 4.1 is needed]))
AC_CHECK_LIB(ncurses, main, , AC_MSG_ERROR([libncurses is needed]))
AC_CHECK_LIB(readline, main, , AC_MSG_ERROR([libreadline is needed]))
AC_CHECK_LIB(z, zlibVersion, , AC_MSG_ERROR([zlib is needed]))

AM_PATH_LIBGCRYPT("1.2.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.2.0 is needed])
fi
AC_SUBST(LIBGCRYPT_CONFIG_LIBS)
AC_SUBST(LIBGCRYPT_CONFIG_CFLAGS)

AM_PATH_LIBTMCG("1.0.2")
if test "x$LIBTMCG_LIBS" = "x"; then
	AC_MSG_ERROR([libTMCG >= 1.0.2 is needed])
fi
AC_SUBST(LIBTMCG_CONFIG_LIBS)
AC_SUBST(LIBTMCG_CONFIG_CFLAGS)

AM_PATH_LIBGNUTLS("1.2.0")

# Checks for header files.
AC_PATH_X
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h arpa/inet.h stdlib.h string.h sys/socket.h sys/time.h sys/stat.h termios.h unistd.h locale.h libintl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_SYS_POSIX_TERMIOS

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([dup2 gethostbyname memset memcpy memcmp select socket strchr strncasecmp strrchr strstr strtol strtoul uname clock stat mkdir getuid getenv strerror])

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

CXXFLAGS="$CXXFLAGS -Wall -g3 -pedantic $LIBGCRYPT_CFLAGS $LIBTMCG_CFLAGS"
echo ">>>>>>>>>>>>>>>>>>> DEBUG MODE <<<<<<<<<<<<<<<<<<<<<<<"
##CXXFLAGS="$CXXFLAGS -Wall -D NDEBUG $LIBGCRYPT_CFLAGS $LIBTMCG_CFLAGS"

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT

echo "Now type 'make && make install' to build and install SecureSkat."
