/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2004 Heiko Stamer, <stamer@gaos.org>

   SecureSkat is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   SecureSkat is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with SecureSkat; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

// autoconf header
#if HAVE_CONFIG_H
	#include "config.h"
#endif

// C++/C header
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cassert>
#include <cstring>
#include <strings.h>
#include <csignal>
#include <unistd.h>
#include <ctime>
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <zlib.h>
#include <clocale>
#include <libintl.h>

// STL classes
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>

// GNU crypto library
#include <gcrypt.h> 

// libTMCG
#include <libTMCG.hh>
#include "securesocketstream.hh"
#include "pipestream.hh"

#ifdef ENABLE_NLS
	#define _(String) gettext(String)
#else
	#define _(String) String
#endif

size_t skat_idx
	(
		size_t ft[5][18], size_t f, size_t t
	);

size_t skat_spiel2gwert
	(
		size_t spiel
	);

size_t skat_spitzen
	(
		size_t spiel, SchindelhauerTMCG *tmcg,
		const TMCG_OpenStack<VTMF_Card> &os
	);

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel, const std::vector<size_t> &cv
	);

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel,
		const TMCG_OpenStack<VTMF_Card> &os
	);

int skat_bstich
	(
		const TMCG_OpenStack<VTMF_Card> &os, size_t spiel
	);

int skat_vkarte
	(
		size_t pkr_self, size_t pkr_who, SchindelhauerTMCG *tmcg,
		BarnettSmartVTMF_dlog *vtmf, TMCG_Stack<VTMF_Card> &s,
		iosecuresocketstream *right, iosecuresocketstream *left, bool rmv
	);

void skat_okarte
	(
		SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf, const VTMF_Card &c,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

const char *skat_spiel2string
	(
		size_t spiel
	);

int skat_wort2spiel
	(
		const std::string &wort
	);

void skat_szeigen
	(
		SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const TMCG_Stack<VTMF_Card> &sk, iosecuresocketstream *rls
	);

bool skat_ssehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		TMCG_OpenStack<VTMF_Card> &os, const TMCG_Stack<VTMF_Card> &sk,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

int skat_wort2type
	(
		const std::string &wort
	);

const char *skat_type2string
	(
		size_t type
	);

void skat_blatt
	( 
		size_t p, const TMCG_OpenStack<VTMF_Card> &os
	);

bool skat_sehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		TMCG_OpenStack<VTMF_Card> &os, const TMCG_Stack<VTMF_Card> &s0,
		const TMCG_Stack<VTMF_Card> &s1, const TMCG_Stack<VTMF_Card> &s2,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

bool skat_geben
	(
		SchindelhauerTMCG *tmcg, TMCG_Stack<VTMF_Card> &d_mix,
		TMCG_Stack<VTMF_Card> &s0, TMCG_Stack<VTMF_Card> &s1,
		TMCG_Stack<VTMF_Card> &s2, TMCG_Stack<VTMF_Card> &sk
	);

bool skat_mischen_beweis
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const TMCG_Stack<VTMF_Card> &d,
		const TMCG_StackSecret<VTMF_CardSecret> &ss,
		const TMCG_Stack<VTMF_Card> &d0, const TMCG_Stack<VTMF_Card> &d1,
		const TMCG_Stack<VTMF_Card> &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

bool skat_mischen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const TMCG_Stack<VTMF_Card> &d,
		const TMCG_StackSecret<VTMF_CardSecret> &ss,
		TMCG_Stack<VTMF_Card> &d0, TMCG_Stack<VTMF_Card> &d1,
		TMCG_Stack<VTMF_Card> &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

int skat_game
	(
		std::string nr, size_t rounds, size_t pkr_self, bool master, int opipe,
		int ipipe, int ctl_o, int ctl_i, SchindelhauerTMCG *tmcg,
		const TMCG_PublicKeyRing &pkr, const TMCG_SecretKey &sec,
		iosecuresocketstream *right, iosecuresocketstream *left,
		const std::vector<std::string> &nicks, int hpipe, bool pctl,
		char *ireadbuf, int &ireaded
	);
