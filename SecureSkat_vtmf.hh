/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002-2004 Heiko Stamer, <stamer@gaos.org>

   SecureSkat is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
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
#include <list>
#include <algorithm>
#include <iostream>
#include <sstream>

// GNU crypto library
#include <gcrypt.h> 

#include <libTMCG.hh>
#include "securesocketstream.hh"
#include "pipestream.hh"

#ifdef ENABLE_NLS
	#define _(String) gettext(String)
#else
	#define _(String) String
#endif
using namespace std;

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
		size_t spiel, SchindelhauerTMCG *tmcg, const VTMF_OpenStack &os
	);

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel, const vector<size_t> &cv
	);

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel, const VTMF_OpenStack &os
	);

int skat_bstich
	(
		const VTMF_OpenStack &os, size_t spiel
	);

int skat_vkarte
	(
		size_t pkr_self, size_t pkr_who, SchindelhauerTMCG *tmcg,
		BarnettSmartVTMF_dlog *vtmf, VTMF_Stack &s,
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
		const string &wort
	);

void skat_szeigen
	(
		SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const VTMF_Stack &sk, iosecuresocketstream *rls
	);

bool skat_ssehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		VTMF_OpenStack &os, const VTMF_Stack &sk,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

int skat_wort2type
	(
		const string &wort
	);

const char *skat_type2string
	(
		size_t type
	);

void skat_blatt
	( 
		size_t p, const VTMF_OpenStack &os
	);

bool skat_sehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		VTMF_OpenStack &os,
		const VTMF_Stack &s0, const VTMF_Stack &s1, const VTMF_Stack &s2,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

bool skat_geben
	(
		SchindelhauerTMCG *tmcg, VTMF_Stack &d_mix,
		VTMF_Stack &s0, VTMF_Stack &s1, VTMF_Stack &s2, VTMF_Stack &sk
	);

bool skat_mischen_beweis
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const VTMF_Stack &d, const VTMF_StackSecret &ss,
		const VTMF_Stack &d0, const VTMF_Stack &d1, const VTMF_Stack &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

bool skat_mischen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const VTMF_Stack &d, const VTMF_StackSecret &ss,
		VTMF_Stack &d0, VTMF_Stack &d1, VTMF_Stack &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	);

int skat_game
	(
		string nr, size_t rounds, size_t pkr_self, bool master, int opipe, int ipipe,
		int ctl_o, int ctl_i, SchindelhauerTMCG *tmcg, const TMCG_PublicKeyRing &pkr,
		const TMCG_SecretKey &sec, iosecuresocketstream *right, iosecuresocketstream *left,
		const vector<string> &nicks, int hpipe, bool pctl, char *ireadbuf, int &ireaded
	);
