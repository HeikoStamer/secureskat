EXTRA_DIST = ABOUT-NLS aclocal.m4 config.guess config.h.in config.status\
	config.sub configure configure.ac install-sh missing mkinstalldirs\
	Makefile.am AUTHORS BUGS COPYING FDL INSTALL NEWS README TODO THANKS ChangeLog

bin_PROGRAMS = SecureSkat SecureSkat_random

SecureSkat_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_misc.cc SecureSkat_pki.cc SecureSkat_rnk.cc SecureSkat_vtmf.cc\
	SecureSkat_misc.hh SecureSkat_pki.hh SecureSkat_rnk.hh SecureSkat_vtmf.hh\
	SecureSkat_ballot.inc\
	SecureSkat.cc

SecureSkat_CFLAGS = @LIBGCRYPT_CFLAGS@ @LIBTMCG_CFLAGS@
SecureSkat_LIBS = @LIBGCRYPT_LIBS@ @LIBTMCG_LIBS@

SecureSkat_random_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_vtmf.cc SecureSkat_vtmf.hh\
	SecureSkat_random.cc

SecureSkat_random_CFLAGS = @LIBGCRYPT_CFLAGS@ @LIBTMCG_CFLAGS@
SecureSkat_random_LIBS = @LIBGCRYPT_LIBS@ @LIBTMCG_LIBS@
