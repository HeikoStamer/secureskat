LIBS = -lgmp -lgcrypt -lgpg-error

lib_LTLIBRARIES = libTMCG.la

include_HEADERS = mpz_srandom.h mpz_sqrtm.h mpz_spowm.h mpz_sprime.h\
	mpz_shash.hh parse_helper.hh mpz_helper.hh\
	BarnettSmartVTMF_dlog.hh SchindelhauerTMCG.hh\
	VTMF_Card.hh VTMF_CardSecret.hh\
	TMCG_Card.hh TMCG_CardSecret.hh\
	TMCG_Stack.hh TMCG_OpenStack.hh TMCG_StackSecret.hh\
	TMCG_SecretKey.hh TMCG_PublicKey.hh TMCG_PublicKeyRing.hh\
	libTMCG.hh libTMCG.def

libTMCG_la_SOURCES = mpz_srandom.c mpz_srandom.h\
	mpz_sqrtm.c mpz_sqrtm.h\
	mpz_spowm.c mpz_spowm.h\
	mpz_sprime.c mpz_sprime.h\
	mpz_shash.cc mpz_shash.hh\
	parse_helper.cc parse_helper.hh\
	mpz_helper.cc mpz_helper.hh\
	BarnettSmartVTMF_dlog.cc BarnettSmartVTMF_dlog.hh\
	SchindelhauerTMCG.cc SchindelhauerTMCG.hh\
	VTMF_Card.cc VTMF_Card.hh\
	VTMF_CardSecret.cc VTMF_CardSecret.hh\
	TMCG_Card.cc TMCG_Card.hh\
	TMCG_CardSecret.cc TMCG_CardSecret.hh\
	TMCG_Stack.hh\
	TMCG_OpenStack.hh\
	TMCG_StackSecret.hh\
	TMCG_SecretKey.cc TMCG_SecretKey.hh\
	TMCG_PublicKey.cc TMCG_PublicKey.hh\
	TMCG_PublicKeyRing.hh libTMCG.hh

EXTRA_DIST = libTMCG.def
