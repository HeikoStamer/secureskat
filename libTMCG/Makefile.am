LIBS = -lgmp -lgcrypt -lgpg-error

lib_LTLIBRARIES = libTMCG.la

include_HEADERS = mpz_srandom.h parse_helper.hh\
	BarnettSmartVTMF_dlog.hh SchindelhauerTMCG.hh

libTMCG_la_SOURCES = mpz_srandom.c mpz_srandom.h\
	parse_helper.cc parse_helper.hh\
	mpz_primes.h mpz_shash.h mpz_spowm.h mpz_sqrtm.h\
	BarnettSmartVTMF_dlog.cc BarnettSmartVTMF_dlog.hh\
	SchindelhauerTMCG.cc SchindelhauerTMCG.hh
