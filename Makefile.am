SUBDIRS = libTMCG

DIST_SUBDIRS = libTMCG

EXTRA_DIST = ABOUT-NLS acinclude.m4 aclocal.m4 config.guess config.h.in config.status\
	config.sub configure configure.ac install-sh missing mkinstalldirs\
	Makefile.am AUTHORS BUGS COPYING FDL INSTALL NEWS README TODO THANKS ChangeLog

LDADD = libTMCG/libTMCG.la
INCLUDES = -I./libTMCG

bin_PROGRAMS = SecureSkat SecureSkat_random

SecureSkat_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_misc.cc SecureSkat_pki.cc SecureSkat_rnk.cc SecureSkat_vtmf.cc\
	SecureSkat_misc.hh SecureSkat_pki.hh SecureSkat_rnk.hh SecureSkat_vtmf.hh\
	SecureSkat_ballot.inc\
	SecureSkat.cc

SecureSkat_random_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_vtmf.cc SecureSkat_vtmf.hh\
	SecureSkat_random.cc
