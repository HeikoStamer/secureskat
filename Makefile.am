SUBDIRS = po

DIST_SUBDIRS = po

EXTRA_DIST = AUTHORS BUGS COPYING FDL INSTALL NEWS README TODO THANKS ChangeLog

LDADD = @LIBGMP_LIBS@ @LIBGCRYPT_LIBS@ @LIBTMCG_LIBS@

bin_PROGRAMS = SecureSkat SecureSkat_random

SecureSkat_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_misc.cc SecureSkat_pki.cc SecureSkat_rnk.cc SecureSkat_irc.cc\
    SecureSkat_game.cc\
	SecureSkat_misc.hh SecureSkat_pki.hh SecureSkat_rnk.hh SecureSkat_irc.hh\
    SecureSkat_game.hh\
	SecureSkat_vote.hh SecureSkat_vote.cc SecureSkat_skat.hh SecureSkat_skat.cc\
	SecureSkat_defs.hh SecureSkat.cc

SecureSkat_random_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_game.cc SecureSkat_game.hh SecureSkat_misc.cc SecureSkat_misc.hh\
	SecureSkat_defs.hh SecureSkat_random.cc

ACLOCAL_AMFLAGS = -I m4

datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
