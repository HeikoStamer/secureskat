# Process this file with autoconf to produce a configure script.
AC_INIT(SecureSkat, 2.3, stamer@gaos.org)
AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_LANG(C++)
AC_CONFIG_SRCDIR(SecureSkat.cc)
AM_CONFIG_HEADER(config.h)

AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME")
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION")
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

ALL_LINGUAS="de"
AC_DEFINE_UNQUOTED(LOCALEDIR, "${datadir}/locale", "/usr/local/share/locale")
AC_SUBST(LOCALEDIR)
#LDFLAGS="-L/usr/lib -L/usr/local/lib $LDFLAGS"


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
	AC_DEFINE(COMMON_DDH_GROUP,
	"143ftcwitk0hm5db6g2f4ltt0ln2k3khqfwy67mlw55lywuho9vlyqr4wzclztgy5d08649y20f8c24vntpupkmekxa0swsyjoppqvcc1ym3mqjwo0u498hy1kuytxxhyy2z4zq05ljdr0d27of35az8p8kjfnc1rb8wmd3t93gb64rpxiwfs8r9066ymm91kzjmk6b",
	[safe prime p (1024 bit) of the common DDH-hard group G])
fi

AC_DEFINE(TMCG_DDH_P_SIZE, 1024L, [security parameter of the DDH-hard group G])
AC_DEFINE(TMCG_KEY_SIZE, 1024L, [security parameter of the TMCG public key])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for internationalization support
AM_GNU_GETTEXT([external])
#AM_GNU_GETTEXT_VERSION(0.11.1)

# Checks for libraries.
AC_CHECK_LIB(gdbm, main, , AC_MSG_ERROR([libgdbm is needed]))
AC_CHECK_LIB(gmp, __gmpz_import, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
##AC_CHECK_LIB(gmpxx, __gmpz_set_str, , AC_MSG_ERROR([libgmpxx (C++ support) >= 4.1 is needed]))
AC_DEFINE(TMCG_MPZ_IO_BASE, 36, [Define input/ouput base encoding of iostream operators])
AC_DEFINE(TMCG_GCRY_MD_ALGO, GCRY_MD_RMD160, [Define message digest algorithm for signatures and FS-heuristic])

AM_PATH_LIBGCRYPT("1.2.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
  AC_MSG_ERROR([libgcrypt is needed])
fi
LIBS="$LIBS $LIBGCRYPT_LIBS"
AC_DEFINE(LIBGCRYPT_VERSION, "1.2.0", [Define appropriate version number of libgcrypt])

AC_CHECK_LIB(ncurses, main, , AC_MSG_ERROR([libncurses is needed]))
AC_CHECK_LIB(readline, main, , AC_MSG_ERROR([libreadline is needed]))
AC_CHECK_LIB(z, zlibVersion, , AC_MSG_ERROR([libz is needed]))

# Checks for header files.
AC_PATH_X
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h termios.h unistd.h locale.h libintl.h])

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
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero dup2 gethostbyname memset select socket strchr strncasecmp strrchr strstr strtol strtoul uname])

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

CXXFLAGS="-Wall -g3 -pedantic -O $LIBGCRYPT_CFLAGS"
##CXXFLAGS="$CXXFLAGS -O2 -Wall -D NODEBUG $LIBGCRYPT_CFLAGS"

AC_CONFIG_FILES([Makefile po/Makefile.in libTMCG/Makefile])
AC_OUTPUT

echo "Now type 'make && make install' to build and to install SecureSkat."
