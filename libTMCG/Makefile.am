LIBS = -lgmp -lgcrypt -lgpg-error

lib_LTLIBRARIES = libTMCG.la

include_HEADERS = mpz_srandom.h\
	BarnettSmartVTMF_dlog.hh SchindelhauerTMCG.hh

libTMCG_la_SOURCES = mpz_srandom.c mpz_srandom.h\
	mpz_primes.h mpz_shash.h mpz_spowm.h mpz_sqrtm.h\
	BarnettSmartVTMF_dlog.cc BarnettSmartVTMF_dlog.hh\
	SchindelhauerTMCG.cc SchindelhauerTMCG.hh
