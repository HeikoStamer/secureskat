/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
#ifndef INCLUDED_SecureSkat_rule_HH
	#define INCLUDED_SecureSkat_rule_HH
	
	#include "SecureSkat_defs.hh"

	// values for biding
	static const size_t skat_reizwert[] =
	{
		0, 18, 20, 22, 23, 24, 27, 30, 33, 35, 36, 40, 44, 45, 46, 48, 50, 54, 
		55, 59, 60, 63, 66, 70, 72, 77, 80, 81, 84, 88, 90, 96, 99, 100, 108, 
		110, 117, 120, 121, 126, 130, 132, 135, 140, 143, 144, 150, 153, 154, 
		156, 160, 162, 165, 168, 170, 176, 180, 187, 192, 198, 204, 216, 240
	};

	// values of the cards (Augen)
	static const size_t skat_pktwert[] =
	{
		2, 2, 2, 2, 
		11, 10, 4, 3, 0, 0, 0, 11, 10, 4, 3, 0, 0, 0, 
		11, 10, 4, 3, 0, 0, 0, 11, 10, 4, 3, 0, 0, 0
	};

	size_t skat_spiel2gwert
		(
			const size_t spiel
		);
	
	size_t skat_spitzen
		(
			const size_t spiel, const TMCG_OpenStack<VTMF_Card> &os
		);
	
	bool skat_rulectl
		(
			const size_t t, const size_t tt, const size_t spiel,
			const std::vector<size_t> &cv
		);
	
	bool skat_rulectl
		(
			const size_t t, const size_t tt, const size_t spiel,
			const TMCG_OpenStack<VTMF_Card> &os
		);
	
	int skat_bstich
		(
			const TMCG_OpenStack<VTMF_Card> &os, const size_t spiel
		);
	
	std::string skat_spiel2string
		(
			const size_t spiel
		);
	
	int skat_wort2spiel
		(
			const std::string &wort
		);
	
	int skat_wort2type
		(
			const std::string &wort
		);
	
	std::string skat_type2string
		(
			const size_t type
		);
	
	void skat_blatt
		(
			const size_t p, const TMCG_OpenStack<VTMF_Card> &os
		);

#endif
