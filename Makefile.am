SUBDIRS = intl po libTMCG

EXTRA_DIST = ABOUT-NLS acinclude.m4 aclocal.m4 config.guess config.h.in config.status\
	config.sub configure configure.ac install-sh missing mkinstalldirs\
	Makefile.am AUTHORS BUGS COPYING INSTALL NEWS README TODO THANKS ChangeLog

bin_PROGRAMS = SecureSkat SecureSkat_random

SecureSkat_SOURCES = libTMCG/mpz_srandom.c libTMCG/mpz_srandom.h\
	libTMCG/BarnettSmartVTMF_dlog.cc libTMCG/BarnettSmartVTMF_dlog.hh\
	libTMCG/mpz_primes.h libTMCG/mpz_spowm.h libTMCG/mpz_shash.h\
	libTMCG/SchindelhauerTMCG.cc libTMCG/SchindelhauerTMCG.hh\
	libTMCG/mpz_sqrtm.h libTMCG/mpz_srandom.h\
	securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_misc.cc SecureSkat_pki.cc SecureSkat_rnk.cc SecureSkat_vtmf.cc\
	SecureSkat_misc.hh SecureSkat_pki.hh SecureSkat_rnk.hh SecureSkat_vtmf.hh\
	SecureSkat_ballot.inc\
	SecureSkat.cc

SecureSkat_random_SOURCES = libTMCG/mpz_srandom.c libTMCG/mpz_srandom.h\
	libTMCG/BarnettSmartVTMF_dlog.cc libTMCG/BarnettSmartVTMF_dlog.hh\
	libTMCG/mpz_primes.h libTMCG/mpz_spowm.h libTMCG/mpz_shash.h\
	libTMCG/SchindelhauerTMCG.cc libTMCG/SchindelhauerTMCG.hh\
	libTMCG/mpz_sqrtm.h libTMCG/mpz_srandom.h\
	securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_vtmf.cc SecureSkat_vtmf.hh\
	SecureSkat_random.cc
