LIBS = -lgmp -lgcrypt -lgpg-error

lib_LTLIBRARIES = libTMCG.la

include_HEADERS = mpz_srandom.h parse_helper.hh\
	BarnettSmartVTMF_dlog.hh SchindelhauerTMCG.hh\
	VTMF_Card.hh VTMF_CardSecret.hh\
	TMCG_Card.hh TMCG_CardSecret.hh\
	TMCG_Stack.hh TMCG_OpenStack.hh TMCG_StackSecret.hh\
	libTMCG.hh

libTMCG_la_SOURCES = mpz_srandom.c mpz_srandom.h\
	parse_helper.cc parse_helper.hh\
	mpz_primes.h mpz_shash.h mpz_spowm.h mpz_sqrtm.h\
	BarnettSmartVTMF_dlog.cc BarnettSmartVTMF_dlog.hh\
	SchindelhauerTMCG.cc SchindelhauerTMCG.hh\
	VTMF_Card.hh VTMF_CardSecret.hh\
	TMCG_Card.hh TMCG_CardSecret.hh\
	TMCG_Stack.hh TMCG_OpenStack.hh TMCG_StackSecret.hh\
	libTMCG.hh
