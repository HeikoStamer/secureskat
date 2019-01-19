/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2004, 2005, 2006, 2007,
               2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/
#ifndef INCLUDED_SecureSkat_game_HH
	#define INCLUDED_SecureSkat_game_HH
	
	#include "SecureSkat_defs.hh"
	#include "SecureSkat_misc.hh"
	#include "SecureSkat_rule.hh"
		
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
		
	bool skat_sehen
		(
			size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
			TMCG_OpenStack<VTMF_Card> &os, const TMCG_Stack<VTMF_Card> &s0,
			const TMCG_Stack<VTMF_Card> &s1, const TMCG_Stack<VTMF_Card> &s2,
			iosecuresocketstream *right, iosecuresocketstream *left
		);
	
	bool skat_geben
		(
			TMCG_Stack<VTMF_Card> &d_mix,
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
			TMCG_PublicKeyRing &pkr, const TMCG_SecretKey &sec,
			iosecuresocketstream *right, iosecuresocketstream *left,
			const std::vector<std::string> &nicks, int hpipe, bool pctl,
			char *ireadbuf, int &ireaded,
			std::string main_channel, std::string main_channel_underscore
		);
#endif
