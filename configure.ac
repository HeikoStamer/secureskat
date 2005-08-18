# Process this file with autoconf to produce a configure script.
AC_REVISION($Revision: 1.43 $)
AC_PREREQ(2.57)

AC_INIT(SecureSkat, 2.7, stamer@gaos.org)
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

AC_MSG_CHECKING([whether ABHEBEN behaviour is enabled])
AC_ARG_ENABLE(abheben, [  --enable-abheben        enable ABHEBEN behaviour],
	use_abheben=$enableval, use_abheben=no)
AC_MSG_RESULT($use_abheben)
if test "$use_abheben" = yes ; then
	AC_DEFINE(ABHEBEN, , [Define to have the ABHEBEN behaviour])
fi

AC_MSG_CHECKING([whether COMMON_DDH_GROUP behaviour is enabled])
AC_ARG_ENABLE(commongroup, [  --disable-commongroup   disable COMMON_DDH_GROUP behaviour],
	use_commongroup=no, use_commongroup=yes)
AC_MSG_RESULT($use_commongroup)
if test "$use_commongroup" = yes ; then
	AC_DEFINE(COMMON_DDH_GROUP, , [Define to have the COMMON_DDH_GROUP behaviour])
	AC_DEFINE(COMMON_DDH_GROUP_P,
	"1a1e4vngailcvh7j2tur8zts6fbkrcac6d3g0jdfvdggl9r7cr2v6zllf6b3z6xb6w0nix8jsjlecgt8lwx1huihghkvqnbbgviiz0vg6ntckohpeac84n0co9czkw174ic47ifwd2189x26609ce63xm5vddxvsbbevn4bxaiv2784d9335o38na680ay8apygtmnz",
	[Prime p of the common DDH-hard group G (Well-Known Group 2, RFC 2412)])
	AC_DEFINE(COMMON_DDH_GROUP_Q,
	"n0p2ftq59aofqlrjexdmhww37nsdo5636jq09opxoq8amvlodjflhsspl5jzlgnlg0brgm9w9sp68emaygiqx98q8sfvbnnqfr9hifq3bwoac8up5642bi6c4ohsg0lk9623r7y6j0m4yj3304o731yt2xooyxw5npftk5yn9fj3m26mjjku1mbn3405h45cz8etbz",
	[Prime q of the common DDH-hard group G (Well-Known Group 2, RFC 2412)])
	AC_DEFINE(COMMON_DDH_GROUP_G,
	"2",
	[Generator g of the common DDH-hard group G (Well-Known Group 2, RFC 2412)])
#
# The above numbers define the MODP Group 2 of the Oakley Protocol and IKE.
# Orman, H., "The Oakley Key Determination Protocol", RFC 2412, November 1998.
# p = 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }
# FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
# 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
# EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
# E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
# EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
# FFFFFFFF FFFFFFFF
#
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

AM_PATH_LIBTMCG("1.0.0")
if test "x$LIBTMCG_LIBS" = "x"; then
	AC_MSG_ERROR([libTMCG >= 1.0.0 is needed])
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
AC_CHECK_FUNCS([dup2 gethostbyname memset select socket strchr strncasecmp strrchr strstr strtol strtoul uname clock stat mkdir getuid getenv strerror])

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

#CXXFLAGS="$CXXFLAGS -Wall -g3 -pedantic $LIBGCRYPT_CFLAGS $LIBTMCG_CFLAGS"
CXXFLAGS="$CXXFLAGS -O2 -Wall -D NDEBUG $LIBGCRYPT_CFLAGS $LIBTMCG_CFLAGS"

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT

echo "Now type 'make && make install' to build and to install SecureSkat."
