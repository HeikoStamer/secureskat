SUBDIRS = m4  po

DIST_SUBDIRS = m4  po

EXTRA_DIST = config.rpath m4/ChangeLog  ABOUT-NLS aclocal.m4 config.guess config.h.in config.status\
	config.sub configure configure.ac install-sh missing mkinstalldirs\
	Makefile.am AUTHORS BUGS COPYING FDL INSTALL NEWS README TODO THANKS ChangeLog

LDADD = @LIBGCRYPT_LIBS@ @LIBTMCG_LIBS@

bin_PROGRAMS = SecureSkat SecureSkat_random

SecureSkat_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_misc.cc SecureSkat_pki.cc SecureSkat_rnk.cc SecureSkat_vtmf.cc\
	SecureSkat_misc.hh SecureSkat_pki.hh SecureSkat_rnk.hh SecureSkat_vtmf.hh\
	SecureSkat.cc

SecureSkat_random_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_vtmf.cc SecureSkat_vtmf.hh\
	SecureSkat_random.cc

ACLOCAL_AMFLAGS = -I m4

datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
