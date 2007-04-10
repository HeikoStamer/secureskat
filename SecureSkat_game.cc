/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#include "SecureSkat_game.hh"

#define MFD_SET(fd, where) { FD_SET(fd, where); mfds = (fd > mfds) ? fd : mfds; }

// global return string
std::string wstr;

// values for biding
size_t reiz_wert[] =
	{
		0, 18, 20, 22, 23, 24, 27, 30, 33, 35, 36, 40, 44, 45, 46, 48, 50, 54, 
		55, 59, 60, 63, 66, 70, 72, 77, 80, 81, 84, 88, 90, 96, 99, 100, 108, 
		110, 117, 120, 121, 126, 130, 132, 135, 140, 143, 144, 150, 153, 154, 
		156, 160, 162, 165, 168, 170, 176, 180, 187, 192, 198, 204, 216, 240
	};

// values of the cards (Augen)
size_t pkt_wert[] =
	{
		2, 2, 2, 2, 
		11, 10, 4, 3, 0, 0, 0, 11, 10, 4, 3, 0, 0, 0, 
		11, 10, 4, 3, 0, 0, 0, 11, 10, 4, 3, 0, 0, 0
	};

// order of the cards in several games (99 is a marker for an invalid card)
size_t card_order[][5][18] =
	{
		// Sc
		{
			{
				0,  1,  2,  3, 25, 26, 27, 28, 29, 30, 31,  4,  5,  6,  7,  8,  9, 10
			},
			{
				0,  1,  2,  3, 25, 26, 27, 28, 29, 30, 31, 11, 12, 13, 14, 15, 16, 17
			},
			{
				0,  1,  2,  3, 25, 26, 27, 28, 29, 30, 31, 18, 19, 20, 21, 22, 23, 24, 
			},
			{
				0,  1,  2,  3, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99, 99, 99,
			},
			{
				0,  1,  2,  3, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99, 99, 99
			}
		},
		// Ro
		{
			{
				0,  1,  2,  3, 18, 19, 20, 21, 22, 23, 24,  4,  5,  6,  7,  8,  9, 10
			},
			{
				0,  1,  2,  3, 18, 19, 20, 21, 22, 23, 24, 11, 12, 13, 14, 15, 16, 17
			},
			{
				0,  1,  2,  3, 18, 19, 20, 21, 22, 23, 24, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
			},
			{
				0,  1,  2,  3, 18, 19, 20, 21, 22, 23, 24, 99, 99, 99, 99, 99, 99, 99
			}
		},
		// Gr
		{
			{
				0,  1,  2,  3, 11, 12, 13, 14, 15, 16, 17,  4,  5,  6,  7,  8,  9, 10
			},
			{
				0,  1,  2,  3, 11, 12, 13, 14, 15, 16, 17, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24
			},
			{
				0,  1,  2,  3, 11, 12, 13, 14, 15, 16, 17, 25, 26, 27, 28, 29, 30, 31
			},
			{
				0,  1,  2,  3, 11, 12, 13, 14, 15, 16, 17, 99, 99, 99, 99, 99, 99, 99
			}
		},
		// Ei
		{
			{
				0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17
			},
			{
				0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 18, 19, 20, 21, 22, 23, 24
			},
			{
				0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 25, 26, 27, 28, 29, 30, 31
			},
			{
				0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 99, 99, 99, 99, 99, 99, 99
			}
		},
		// Nu
		{
			{
				4,  6,  7,  0,  5,  8,  9, 10, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99
			},
			{
				11, 13, 14,  1, 12, 15, 16, 17, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99
			},
			{
				18, 20, 21,  2, 19, 22, 23, 24, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99
			},
			{
				25, 27, 28,  3, 26, 29, 30, 31, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99
			},
			{
				99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99
			}
		},
		// Gd
		{
			{
				0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3, 11, 12, 13, 14, 15, 16, 17, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3, 18, 19, 20, 21, 22, 23, 24, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99, 99, 99
			},
			{
				0,  1,  2,  3, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99
			}
		}
	};

size_t skat_idx
	(
		size_t ft[5][18], size_t f, size_t t, size_t s
	)
{
	assert (s < 18);
	assert (f < 5);
	for (size_t i = s; i < 18; i++)
		if (t == ft[f][i])
			return i;
	return 99;
}

size_t skat_spiel2gwert
	(
		size_t spiel
	)
{
	return (spiel % 100);
}

size_t skat_spiel2twert
	(
		size_t spiel
	)
{
	if (skat_spiel2gwert(spiel) == 9)
		return 0;
	else if (skat_spiel2gwert(spiel) == 10)
		return 1;
	else if (skat_spiel2gwert(spiel) == 11)
		return 2;
	else if (skat_spiel2gwert(spiel) == 12)
		return 3;
	else if (skat_spiel2gwert(spiel) == 23)
		return 4;
	else if (skat_spiel2gwert(spiel) == 24)
		return 5;
	else
		return 99;
}

void init_co
	(
		size_t spiel, size_t co[5][18]
	)
{
	for (size_t i = 0; i < 5; i++)
		for (size_t j = 0; j < 18; j++)
			co[i][j] = card_order[skat_spiel2twert(spiel)][i][j];
}

size_t skat_spitzen
	(
		size_t spiel, SchindelhauerTMCG *tmcg,
		const TMCG_OpenStack<VTMF_Card> &os
	)
{
	size_t co[5][18], sz_cnt = 0;
	init_co(spiel, co);
	
	// Null Spiel? Keine Spitzen!
	if (skat_spiel2gwert(spiel) == 23)
		return 0;
	
	// mit oder ohne Spitzen zaehlen
	if (os.find(0))
	{
		for (size_t sz = 0; sz < 11; sz++)
		{
			if (os.find(co[4][sz]))
					sz_cnt++;
			else
				break;
		}
	}
	else
	{
		for (size_t sz = 0; sz < 11; sz++)
		{
			if (!os.find(co[4][sz]))
				sz_cnt++;
			else
				break;
		}
	}
	return sz_cnt;
}

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel, const std::vector<size_t> &cv
	)
{
	TMCG_OpenStack<VTMF_Card> os;
	for (size_t j = 0; j < cv.size(); j++)
		os.push(cv[j], VTMF_Card());
	return skat_rulectl(t, tt, spiel, os);
}

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel,
		const TMCG_OpenStack<VTMF_Card> &os
	)
{
	size_t co[5][18], to = 0;
	init_co(spiel, co);
	
	if (skat_spiel2gwert(spiel) == 23)
		to = 0;	// Null: kein Trumpf
	else if (skat_spiel2gwert(spiel) == 24)
		to = 4;	// Grand: 4 Truempfe
	else
		to = 11;	// Farbspiele: 11 Truempfe

	if (skat_idx(co, 4, t, 0) != 99)
	{
		// Trumpf angespielt, aber nicht bedient
		if (skat_idx(co, 4, tt, 0) == 99)
		{
			for (size_t i = 0; i < os.size(); i++)
				if (skat_idx(co, 4, os[i].first, 0) < 99)
						return false;
			return true;
		}
		return true;
	}
	else
	{
		// Farbe i angespielt ...
		for (size_t i = 0; i < 4; i++)
		{
			if (skat_idx(co, i, t, 0) != 99)
			{
				// ... aber nicht bedient
				if (skat_idx(co, i, tt, to) == 99)
				{
					for (size_t j = 0; j < os.size(); j++)
						if (skat_idx(co, i, os[j].first, to) < 99)
							return false;
					return true;
				}
				return true;
			}
		}
	}
	return false;
}
	
int skat_bstich
	(
		const TMCG_OpenStack<VTMF_Card> &os, size_t spiel
	)
{
	size_t co[5][18];
	assert (os.size() == 3);
	init_co(spiel, co);

	if (skat_idx(co, 4, os[0].first, 0) != 99)
	{
		// Trumpf angespielt
		if (skat_idx(co, 4, os[1].first, 0) < skat_idx(co, 4, os[0].first, 0))
		{
			if (skat_idx(co, 4, os[2].first, 0) < skat_idx(co, 4, os[1].first, 0))
				return 2;
			else
				return 1;
		}
		else
		{
			if (skat_idx(co, 4, os[2].first, 0) < skat_idx(co, 4, os[0].first, 0))
				return 2;
			else
				return 0;
		}
	}
	else
	{
		// Farbe i angespielt
		for (size_t i = 0; i < 4; i++)
		{
			if (skat_idx(co, i, os[0].first, 0) != 99)
			{
				if (skat_idx(co, i, os[1].first, 0) < skat_idx(co, i, os[0].first, 0))
				{
					if (skat_idx(co, i, os[2].first, 0) < skat_idx(co, i, os[1].first, 0))
						return 2;
					else
						return 1;
				}
				else
				{
					if (skat_idx(co, i, os[2].first, 0) < skat_idx(co, i, os[0].first, 0))
						return 2;
					else
						return 0;
				}
			}
		}
	}
	return -1;
}

int skat_vkarte
	(
		size_t pkr_self, size_t pkr_who, SchindelhauerTMCG *tmcg,
		BarnettSmartVTMF_dlog *vtmf, TMCG_Stack<VTMF_Card> &s,
		iosecuresocketstream *right, iosecuresocketstream *left, bool rmv
	)
{
	assert(pkr_self != pkr_who);
	
#ifndef NDEBUG
	start_clock();
#endif
	
	int type = -1;
	VTMF_Card c;
	
	try
	{
		if (((pkr_self == 0) && (pkr_who == 1)) || 
			((pkr_self == 1) && (pkr_who == 2)) || 
			((pkr_self == 2) && (pkr_who == 0)))
		{
			*left >> c;
			if (!left->good())
				throw -1;
			if (!s.find(c))
				throw -1;
			tmcg->TMCG_SelfCardSecret(c, vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *left, *left))
				throw -1;
			
			if ((pkr_self == 0) && (pkr_who == 1))
				tmcg->TMCG_ProveCardSecret(c, vtmf, *right, *right);
			if ((pkr_self == 1) && (pkr_who == 2))
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *right, *right))
					throw -1;
			if ((pkr_self == 2) && (pkr_who == 0))
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *right, *right))
					throw -1;
			if ((pkr_self == 0) && (pkr_who == 1))
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *right, *right))
					throw -1;
			if ((pkr_self == 1) && (pkr_who == 2))
				tmcg->TMCG_ProveCardSecret(c, vtmf, *right, *right);
			if ((pkr_self == 2) && (pkr_who == 0))
				tmcg->TMCG_ProveCardSecret(c, vtmf, *right, *right);
			
			type = tmcg->TMCG_TypeOfCard(c, vtmf);
			if (rmv)
				s.remove(c);
			throw type;
		}
		if (((pkr_self == 0) && (pkr_who == 2)) || 
			((pkr_self == 1) && (pkr_who == 0)) || 
			((pkr_self == 2) && (pkr_who == 1)))
		{
			*right >> c;
			if (!right->good())
				throw -1;
			if (!s.find(c))
				throw -1;
			tmcg->TMCG_SelfCardSecret(c, vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *right, *right))
				throw -1;
			
			if ((pkr_self == 0) && (pkr_who == 2))
				tmcg->TMCG_ProveCardSecret(c, vtmf, *left, *left);
			if ((pkr_self == 1) && (pkr_who == 0))
				tmcg->TMCG_ProveCardSecret(c, vtmf, *left, *left);
			if ((pkr_self == 2) && (pkr_who == 1))
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *left, *left))
					throw -1;
			if ((pkr_self == 0) && (pkr_who == 2))
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *left, *left))
					throw -1;
			if ((pkr_self == 1) && (pkr_who == 0))
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *left, *left))
					throw -1;
			if ((pkr_self == 2) && (pkr_who == 1))
				tmcg->TMCG_ProveCardSecret(c, vtmf, *left, *left);
			
			type = tmcg->TMCG_TypeOfCard(c, vtmf);
			if (rmv)
				s.remove(c);
			throw type;
		}
		throw -1;
	}
	catch (int return_value)
	{
#ifndef NDEBUG
		stop_clock();
		std::cerr << elapsed_time() << std::flush;
#endif
		return return_value;
	}
}

void skat_okarte
	(
		SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf, const VTMF_Card &c,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
#ifndef NDEBUG
	start_clock();
#endif
	
	// use the non-interactiveness of the proof (only VTMF!)
	std::stringstream proof;
	tmcg->TMCG_ProveCardSecret(c, vtmf, proof, proof);
	*right << c << std::endl << std::flush;
	*right << proof.str() << std::flush;
	*left << c << std::endl << std::flush;
	*left << proof.str() << std::flush;
	
#ifndef NDEBUG
	stop_clock();
	std::cerr << elapsed_time() << std::flush;
#endif
}

const char *skat_spiel2string
	(
		size_t spiel
	)
{
	wstr = "";
	if (skat_spiel2gwert(spiel) == 9)
		wstr += "Schellen (Sc)";
	else if (skat_spiel2gwert(spiel) == 10)
		wstr += "Rot (Ro)";
	else if (skat_spiel2gwert(spiel) == 11)
		wstr += "Gruen (Gr)";
	else if (skat_spiel2gwert(spiel) == 12)
		wstr += "Eicheln (Ei)";
	else if (skat_spiel2gwert(spiel) == 23)
		wstr += "Null (Nu)";
	else if (skat_spiel2gwert(spiel) == 24)
		wstr += "Grand (Gd)";
	else
		wstr += _("unknown");
	if (spiel > 1000)
	{
		wstr += " Hand";
		if (((spiel % 1000) > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schneider";
		if (((spiel % 1000) > 200) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schwarz";
		if (((spiel % 1000) > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += _(" announced");
		if ((spiel % 1000) > 300)
			wstr += " Ouvert";
	}
	else
	{
		if ((spiel > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schneider";
		if ((spiel > 200) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schwarz";
		if ((spiel > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += _(" announced");
		if (spiel > 300)
			wstr += " Ouvert";
	}
	return wstr.c_str();
}

int skat_wort2spiel
	(
		const std::string &wort
	)
{
	if (wort == "")
		return 0;
	else if (wort == "Sc")
		return 9;
	else if (wort == "Ro")
		return 10;
	else if (wort == "Gr")
		return 11;
	else if (wort == "Nu")
		return 23;
	else if (wort == "Ei")
		return 12;
	else if (wort == "Gd")
		return 24;
	else if (wort == "Sn")
		return 100;
	else if (wort == "Sw")
		return 200;
	else if (wort == "Ov")
		return 300;
	else
		return -1;
}

void skat_szeigen
	(
		SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const TMCG_Stack<VTMF_Card> &sk, iosecuresocketstream *rls
	)
{
	for (size_t i = 0; i < sk.size(); i++)
		tmcg->TMCG_ProveCardSecret(sk[i], vtmf, *rls, *rls);
}

bool skat_ssehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		TMCG_OpenStack<VTMF_Card> &os, const TMCG_Stack<VTMF_Card> &sk,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	for (size_t i = 0; i < sk.size(); i++)
	{
		tmcg->TMCG_SelfCardSecret(sk[i], vtmf);
		if (pkr_self == 0)
		{
			if (!tmcg->TMCG_VerifyCardSecret(sk[i], vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(sk[i], vtmf, *right, *right))
				return false;
		}
		else if (pkr_self == 1)
		{
			if (!tmcg->TMCG_VerifyCardSecret(sk[i], vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(sk[i], vtmf, *right, *right))
				return false;
		}
		else if (pkr_self == 2)
		{
			if (!tmcg->TMCG_VerifyCardSecret(sk[i], vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(sk[i], vtmf, *right, *right))
				return false;
		}
		os.push(tmcg->TMCG_TypeOfCard(sk[i], vtmf), sk[i]);
	}
	return true;
}

int skat_wort2type
	(
		const std::string &wort
	)
{
	// Wenzel
	if (wort == "EiU")
		return 0;
	else if (wort == "GrU")
		return 1;
	else if (wort == "RoU")
		return 2;
	else if (wort == "ScU")
		return 3;
	else
	{
		if (wort.length() < 3)
			return -1;
		std::string wert = wort.substr(2, wort.length() - 2);
		int ww = -1;
		// Figuren und Luschen
		if (wert == "A")
			ww = 4;
		else if (wert == "10")
			ww = 5;
		else if (wert == "K")
			ww = 6;
		else if (wert == "O")
			ww = 7;
		else if (wert == "9")
			ww = 8;
		else if (wert == "8")
			ww = 9;
		else if (wert == "7")
			ww = 10;
		else
			return -1;
		if (wort.find("Ei", 0) == 0)
			return ww;
		else if (wort.find("Gr", 0) == 0)
			return ww + 7;
		else if (wort.find("Ro", 0) == 0)
			return ww + 14;
		else if (wort.find("Sc", 0) == 0)
			return ww + 21;
		else
			return -1;
	}
}

const char *skat_type2string
	(
		size_t type
	)
{
	wstr = "";
	// Wenzel
	if (type == 0)
		wstr += "EiU ";
	else if (type == 1)
		wstr += "GrU ";
	else if (type == 2)
		wstr += "RoU ";
	else if (type == 3)
		wstr += "ScU ";
	else
	{
		// Farben
		int ww = type - 4;
		if (ww < 7)
			wstr += "Ei";
		else if (ww < 14)
			wstr += "Gr", ww -= 7;
		else if (ww < 21)
			wstr += "Ro", ww -= 14;
		else if (ww < 28)
			wstr += "Sc", ww -= 21;
		// Figuren und Luschen
		if (ww == 0)
			wstr += "A ";
		else if (ww == 1)
			wstr += "10 ";
		else if (ww == 2)
			wstr += "K ";
		else if (ww == 3)
			wstr += "O ";
		else if (ww == 4)
			wstr += "9 ";
		else if (ww == 5)
			wstr += "8 ";
		else if (ww == 6)
			wstr += "7 ";
	}
	return wstr.c_str();
}

void skat_blatt
	(
		size_t p, const TMCG_OpenStack<VTMF_Card> &os
	)
{
	std::vector<int> w;
	for (size_t i = 0; i < os.size(); i++)
		w.push_back(os[i].first);
	if (p != 99)
		std::sort(w.begin(), w.end());
	if (p != 99)
		std::cout << "><><>< ";
	if (p == 0)
		std::cout << "VH: ";
	if (p == 1)
		std::cout << "MH: ";
	if (p == 2)
		std::cout << "HH: ";
	if (p == 10)
		std::cout << _("revealed cards") << ": ";
	for (std::vector<int>::const_iterator wi = w.begin(); wi != w.end(); wi++)
		std::cout << skat_type2string(*wi);
	if (p != 99)
		std::cout << std::endl;
}

bool skat_sehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		TMCG_OpenStack<VTMF_Card> &os, const TMCG_Stack<VTMF_Card> &s0,
		const TMCG_Stack<VTMF_Card> &s1, const TMCG_Stack<VTMF_Card> &s2,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	if (pkr_self == 0)
	{
		for (size_t i = 0; i < s0.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(s0[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(s0[i], vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(s0[i], vtmf, *right, *right))
				return false;
			os.push(tmcg->TMCG_TypeOfCard(s0[i], vtmf), s0[i]);
		}
		for (size_t i = 0; i < s1.size(); i++)
			tmcg->TMCG_ProveCardSecret(s1[i], vtmf, *left, *left);
		for (size_t i = 0; i < s2.size(); i++)
			tmcg->TMCG_ProveCardSecret(s2[i], vtmf, *right, *right);
	}
	if (pkr_self == 1)
	{
		for (size_t i = 0; i < s0.size(); i++)
			tmcg->TMCG_ProveCardSecret(s0[i], vtmf, *right, *right);
		for (size_t i = 0; i < s1.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(s1[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(s1[i], vtmf, *right, *right))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(s1[i], vtmf, *left, *left))
				return false;
			os.push(tmcg->TMCG_TypeOfCard(s1[i], vtmf), s1[i]);
		}
		for (size_t i = 0; i < s2.size(); i++)
			tmcg->TMCG_ProveCardSecret(s2[i], vtmf, *left, *left);
	}
	if (pkr_self == 2)
	{
		for (size_t i = 0; i < s0.size(); i++)
			tmcg->TMCG_ProveCardSecret(s0[i], vtmf, *left, *left);
		for (size_t i = 0; i < s1.size(); i++)
			tmcg->TMCG_ProveCardSecret(s1[i], vtmf, *right, *right);
		for (size_t i = 0; i < s2.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(s2[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(s2[i], vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(s2[i], vtmf, *right, *right))
				return false;
			os.push(tmcg->TMCG_TypeOfCard(s2[i], vtmf), s2[i]);
		}
	}
	return true;
}

bool skat_geben
	(
		SchindelhauerTMCG *tmcg, TMCG_Stack<VTMF_Card> &d_mix,
		TMCG_Stack<VTMF_Card> &s0, TMCG_Stack<VTMF_Card> &s1,
		TMCG_Stack<VTMF_Card> &s2, TMCG_Stack<VTMF_Card> &sk
	)
{
	VTMF_Card c;
	for (size_t i = 0; i < 3; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s0.push(c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s1.push(c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s2.push(c);
	}
	for (size_t i = 0; i < 2; i++)
	{
		if (!d_mix.pop(c))
			return false;
		sk.push(c);
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s0.push(c);
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s1.push(c);
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s2.push(c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s0.push(c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s1.push(c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!d_mix.pop(c))
			return false;
		s2.push(c);
	}
	assert(d_mix.size() == 0);
	return true;
}

bool skat_mischen_beweis
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		GrothVSSHE *vsshe, const TMCG_Stack<VTMF_Card> &d,
		const TMCG_StackSecret<VTMF_CardSecret> &ss,
		const TMCG_Stack<VTMF_Card> &d0, const TMCG_Stack<VTMF_Card> &d1,
		const TMCG_Stack<VTMF_Card> &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	if (pkr_self == 0)
	{
		tmcg->TMCG_ProveStackEquality_Groth(d, d0, ss, vtmf, vsshe, *left, *left);
		tmcg->TMCG_ProveStackEquality_Groth(d, d0, ss, vtmf, vsshe, *right, *right);
		if (!tmcg->TMCG_VerifyStackEquality_Groth(d0, d1, vtmf, vsshe, *left, *left))
			return false;
		if (!tmcg->TMCG_VerifyStackEquality_Groth(d1, d2, vtmf, vsshe, *right, *right))
			return false;
	}
	if (pkr_self == 1)
	{
		if (!tmcg->TMCG_VerifyStackEquality_Groth(d, d0, vtmf, vsshe, *right, *right))
			return false;
		tmcg->TMCG_ProveStackEquality_Groth(d0, d1, ss, vtmf, vsshe, *right, *right);
		tmcg->TMCG_ProveStackEquality_Groth(d0, d1, ss, vtmf, vsshe, *left, *left);
		if (!tmcg->TMCG_VerifyStackEquality_Groth(d1, d2, vtmf, vsshe, *left, *left))
			return false;
	}
	if (pkr_self == 2)
	{
		if (!tmcg->TMCG_VerifyStackEquality_Groth(d, d0, vtmf, vsshe, *left, *left))
			return false;
		if (!tmcg->TMCG_VerifyStackEquality_Groth(d0, d1, vtmf, vsshe, *right, *right))
			return false;
		tmcg->TMCG_ProveStackEquality_Groth(d1, d2, ss, vtmf, vsshe, *left, *left);
		tmcg->TMCG_ProveStackEquality_Groth(d1, d2, ss, vtmf, vsshe, *right, *right);
	}
	return true;
}

bool skat_mischen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const TMCG_Stack<VTMF_Card> &d, const TMCG_StackSecret<VTMF_CardSecret> &ss,
		TMCG_Stack<VTMF_Card> &d0, TMCG_Stack<VTMF_Card> &d1,
		TMCG_Stack<VTMF_Card> &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	if (pkr_self == 0)
	{
		tmcg->TMCG_MixStack(d, d0, ss, vtmf);
		*right << d0 << std::endl << std::flush;
		*left << d0 << std::endl << std::flush;
		*left >> d1;
		if (!left->good())
			return false;
		*right >> d2;
		if (!right->good())
			return false;
	}
	else if (pkr_self == 1)
	{
		*right >> d0;
		if (!right->good())
			return false;
		tmcg->TMCG_MixStack(d0, d1, ss, vtmf);
		*right << d1 << std::endl << std::flush;
		*left << d1 << std::endl << std::flush;
		*left >> d2;
		if (!left->good())
			return false;
	}
	else if (pkr_self == 2)
	{
		*left >> d0;
		if (!left->good())
			return false;
		*right >> d1;
		if (!right->good())
			return false;
		tmcg->TMCG_MixStack(d1, d2, ss, vtmf);
		*right << d2 << std::endl << std::flush;
		*left << d2 << std::endl << std::flush;
	}
	else
		return false;
	
	return true;
}

bool game_helper_1
	(size_t &reiz_status, size_t &spiel_allein, size_t vh, size_t mh, size_t hh,
	size_t reiz_counter, size_t pkr_self, const std::vector<std::string> &nicks,
	const TMCG_PublicKeyRing &pkr, bool pctl, opipestream *out_ctl)
{
	switch (reiz_status)
	{
		case 11:
			reiz_status += 100;
			std::cout << "><><>< " << _("Nobody is biding.") <<
				" " << _("Deal again!") << std::endl;
			if (pctl)
			{
				std::ostringstream ost;
				ost << nicks[pkr_self] << " RAMSCH" << std::endl;
				*out_ctl << ost.str() << std::flush;
			}
			return false;
		case 12:
			reiz_status += 100;
			std::cout << "><><>< VH aka \"" << pkr.keys[vh].name << 
				"\" " << _("gets the game at") << " " << 
				reiz_wert[reiz_counter] << std::endl;
			spiel_allein = vh;
			if (pctl)
				*out_ctl << nicks[spiel_allein] << " SPIELT" << std::endl << 
					std::flush;
			return true;
		case 13:
			reiz_status += 100;
			std::cout << "><><>< MH aka \"" << pkr.keys[mh].name << 
				"\" " << _("gets the game at") << " " << 
				reiz_wert[reiz_counter] << std::endl;
			spiel_allein = mh;
			if (pctl)
				*out_ctl << nicks[spiel_allein] << " SPIELT" << std::endl << 
					std::flush;
			return true;
		case 14:
			reiz_status += 100;
			std::cout << "><><>< HH aka \"" << pkr.keys[hh].name << 
				"\" " << _("gets the game at") << " " << 
				reiz_wert[reiz_counter] << std::endl;
			spiel_allein = hh;
			if (pctl)
				*out_ctl << nicks[spiel_allein] << " SPIELT" << std::endl << 
					std::flush;
			return true;
		default:
			return true;
	}
}

int skat_game
	(
		std::string nr, size_t rounds, size_t pkr_self, bool master, int opipe,
		int ipipe, int ctl_o, int ctl_i, SchindelhauerTMCG *tmcg,
		const TMCG_PublicKeyRing &pkr, const TMCG_SecretKey &sec,
		iosecuresocketstream *right, iosecuresocketstream *left,
		const std::vector<std::string> &nicks, int hpipe, bool pctl,
		char *ireadbuf, int &ireaded,
		std::string main_channel, std::string main_channel_underscore
	)
{
	opipestream *out_pipe = new opipestream(opipe), *out_ctl = NULL;
	if (pctl)
		out_ctl = new opipestream(ctl_o);
	
	int pkt_sum[3] = { 0, 0, 0 };
	for (size_t i = 0; pctl && (i < 3); i++)
	{
		std::ostringstream ost;
		ost << nicks[pkr_self] << " INIT " << nicks[i] << " " << 
			pkr.keys[i].name << std::endl;
		*out_ctl << ost.str() << std::flush;
	}
	
	// VTMF initialization
	BarnettSmartVTMF_dlog *vtmf;
	
	if (pkr_self == 2)
	{
#ifndef NDEBUG
		start_clock();
#endif
		
#ifdef COMMON_DDH_GROUP
		std::stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP_P << std::endl;
		ddh_group << COMMON_DDH_GROUP_Q << std::endl;
		ddh_group << COMMON_DDH_GROUP_G << std::endl;
		ddh_group << "2" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog_GroupQR(ddh_group);
#else
		vtmf = new BarnettSmartVTMF_dlog();
		vtmf->PublishGroup(*left), vtmf->PublishGroup(*right);
#endif
		
		if (!vtmf->CheckGroup())
		{
			std::cout << ">< " << _("VTMF ERROR") << ": " <<
				_("function CheckGroup() failed") << std::endl;
			return 2;
		}
		
		vtmf->KeyGenerationProtocol_GenerateKey();
		
		vtmf->KeyGenerationProtocol_PublishKey(*left);
		vtmf->KeyGenerationProtocol_PublishKey(*right);
		
		if (!vtmf->KeyGenerationProtocol_UpdateKey(*left))
		{
			std::cout << ">< " << _("VTMF ERROR") << ": " <<
				_("function KeyGenerationProtocol_UpdateKey() failed") << std::endl;
			return 2;
		}
		if (!vtmf->KeyGenerationProtocol_UpdateKey(*right))
		{
			std::cout << ">< " << _("VTMF ERROR") << ": " <<
				_("function KeyGenerationProtocol_UpdateKey() failed") << std::endl;
			return 2;
		}
		
		vtmf->KeyGenerationProtocol_Finalize();
		
#ifndef NDEBUG
		stop_clock();
		std::cerr << "KeyGenerationProtocol: " << elapsed_time() << std::endl;
#endif
	}
	else
	{
#ifndef NDEBUG
		start_clock();
#endif
		
#ifdef COMMON_DDH_GROUP
		std::stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP_P << std::endl;
		ddh_group << COMMON_DDH_GROUP_Q << std::endl;
		ddh_group << COMMON_DDH_GROUP_G << std::endl;
		ddh_group << "2" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog_GroupQR(ddh_group);
#else
		if (pkr_self == 0)
			vtmf = new BarnettSmartVTMF_dlog(*right);
		else
			vtmf = new BarnettSmartVTMF_dlog(*left);
#endif
		
		if (!vtmf->CheckGroup())
		{
			std::cout << ">< " << _("VTMF ERROR") << ": " <<
				_("function CheckGroup() failed") << std::endl;
			return 2;
		}
		
		vtmf->KeyGenerationProtocol_GenerateKey();
		
		if (pkr_self == 0)
		{
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*right))
			{
				std::cout << ">< " << _("VTMF ERROR") << ": " <<
					_("function KeyGenerationProtocol_UpdateKey() failed") << std::endl;
				return 2;
			}
			vtmf->KeyGenerationProtocol_PublishKey(*left);
			vtmf->KeyGenerationProtocol_PublishKey(*right);
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*left))
			{
				std::cout << ">< " << _("VTMF ERROR") << ": " <<
					_("function KeyGenerationProtocol_UpdateKey() failed") << std::endl;
				return 2;
			}
		}
		else
		{
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*left))
			{
				std::cout << ">< " << _("VTMF ERROR") << ": " <<
					_("function KeyGenerationProtocol_UpdateKey() failed") << std::endl;
				return 2;
			}
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*right))
			{
				std::cout << ">< " << _("VTMF ERROR") << ": " <<
					_("function KeyGenerationProtocol_UpdateKey() failed") << std::endl;
				return 2;
			}
			vtmf->KeyGenerationProtocol_PublishKey(*left);
			vtmf->KeyGenerationProtocol_PublishKey(*right);
		}
		
		vtmf->KeyGenerationProtocol_Finalize();
		
#ifndef NDEBUG
		stop_clock();
		std::cerr << "KeyGenerationProtocol: " << elapsed_time() << std::endl;
#endif
	}
	
	// initialization for Groth's shuffle
	GrothVSSHE *vsshe;
	
	if (pkr_self == 2)
	{
#ifndef NDEBUG
		start_clock();
#endif
		
		vsshe = new GrothVSSHE(32, vtmf->p, vtmf->q, vtmf->k, 
			vtmf->g, vtmf->h);
		vsshe->PublishGroup(*left), vsshe->PublishGroup(*right);
		if (!vsshe->CheckGroup())
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("function CheckGroup() failed") << std::endl;
			return 2;
		}
		if (mpz_cmp(vtmf->h, vsshe->com->h))
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("common public key does not match") << std::endl;
			return 2;
		}
		if (mpz_cmp(vtmf->q, vsshe->com->q))
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("subgroup order does not match") << std::endl;
			return 2;
		}
		if (mpz_cmp(vtmf->p, vsshe->p) || mpz_cmp(vtmf->q, vsshe->q) || 
			mpz_cmp(vtmf->g, vsshe->g) || mpz_cmp(vtmf->h, vsshe->h))
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("encryption scheme does not match") << std::endl;
			return 2;
		}
		
#ifndef NDEBUG
		stop_clock();
		std::cerr << "KeyGenerationProtocol2: " << elapsed_time() << std::endl;
#endif
	}
	else
	{
#ifndef NDEBUG
		start_clock();
#endif
		
		if (pkr_self == 0)
			vsshe = new GrothVSSHE(32, *right);
		else
			vsshe = new GrothVSSHE(32, *left);
		if (!vsshe->CheckGroup())
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("function CheckGroup() failed") << std::endl;
			return 2;
		}
		if (mpz_cmp(vtmf->h, vsshe->com->h))
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("common public key does not match") << std::endl;
			return 2;
		}
		if (mpz_cmp(vtmf->q, vsshe->com->q))
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("subgroup order does not match") << std::endl;
			return 2;
		}
		if (mpz_cmp(vtmf->p, vsshe->p) || mpz_cmp(vtmf->q, vsshe->q) || 
			mpz_cmp(vtmf->g, vsshe->g) || mpz_cmp(vtmf->h, vsshe->h))
		{
			std::cout << ">< " << _("VSSHE ERROR") << ": " <<
				_("encryption scheme does not match") << std::endl;
			return 2;
		}
		
#ifndef NDEBUG
		stop_clock();
		std::cerr << "KeyGenerationProtocol2: " << elapsed_time() << std::endl;
#endif
	}
	
	// loop the given number of rounds
	for (size_t r = 0; r < rounds; r++)
	{
		std::ostringstream spiel_protokoll;
		spiel_protokoll << "prt#" << nr << "#";
		for (size_t p = 0; p < 3; p++)
			spiel_protokoll << nicks[p] << "#";
		
		// play three games in each round
		for (size_t p = 0; p < 3; p++)
		{
			// create the deck (32 different cards)
			TMCG_OpenStack<VTMF_Card> d;
			for (int i = 0; i < 32; i++)
			{
				VTMF_Card c;
				tmcg->TMCG_CreateOpenCard(c, vtmf, i);
				d.push(i, c);
			}
			// shuffle the deck
			TMCG_Stack<VTMF_Card> d2, d_mix[3], d_end;
			TMCG_StackSecret<VTMF_CardSecret> ss, ab;
			d2.push(d);
			tmcg->TMCG_CreateStackSecret(ss, false, d2.size(), vtmf);
			std::cout << "><>< " << _("Shuffle the cards.") << " " <<
				_("Please wait") << "." << std::flush;
			if (pctl)
			{
				std::ostringstream ost;
				ost << nicks[pkr_self] << " MISCHEN" << std::endl;
				*out_ctl << ost.str() << std::flush;
			}
#ifndef NDEBUG
			start_clock();
#endif
			if (!skat_mischen(pkr_self, tmcg, vtmf, d2, ss,
				d_mix[0], d_mix[1], d_mix[2], right, left))
			{
				std::cout << ">< " << _("shuffling error") << ": " <<
					_("bad stack format") << std::endl;
				return 1;
			}
#ifndef NDEBUG
			stop_clock();
			std::cerr << elapsed_time() << std::flush;
#endif
			std::cout << "." << std::flush;
#ifndef NDEBUG
			start_clock();
#endif
			if (!skat_mischen_beweis(pkr_self, tmcg, vtmf, vsshe, d2, ss,
				d_mix[0], d_mix[1], d_mix[2], right, left))
			{
				std::cout << ">< " << _("shuffling error") << ": " <<
					_("wrong ZK proof") << std::endl;
				return 2;
			}
#ifndef NDEBUG
			stop_clock();
			std::cerr << elapsed_time() << std::flush;
#endif
			std::cout << "." << _("finished!") << std::endl;
			d_end = d_mix[2];

			
			// compute unique game ID (aka hex_game_digest)
			std::ostringstream game_stream;
			game_stream << d_end << std::endl << std::flush;
			std::string osttmp = game_stream.str();
			assert(gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO));
			char *game_digest = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
			gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, game_digest,
				osttmp.c_str(), osttmp.length());
			char *hex_game_digest =
				new char[2 * gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO) + 1];
			for (size_t i = 0; i < gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO); i++)
				snprintf(hex_game_digest + (2 * i), 3, "%02x",
					(unsigned char)game_digest[i]);
			
			// dealing the cards
			std::cout << "><>< " << _("Dealing the cards.") << " " <<
				_("Please wait") << "." << std::flush;
			if (pctl)
			{
				std::ostringstream ost;
				ost << nicks[pkr_self] << " GEBEN" << std::endl;
				*out_ctl << ost.str() << std::flush;
			}
#ifndef NDEBUG
			start_clock();
#endif
			TMCG_Stack<VTMF_Card> s[3], sk;
			if (!skat_geben(tmcg, d_end, s[0], s[1], s[2], sk))
			{
				std::cout << ">< " << _("dealing error") << ": " <<
					_("not enough cards") << std::endl;
				return 3;
			}
			std::cout << "." << std::flush;
			TMCG_OpenStack<VTMF_Card> os, os_ov, os_sp, os_st, os_pkt[3], os_rc[3];
			if (!skat_sehen(pkr_self, tmcg, vtmf, os,
				s[0], s[1], s[2], right, left))
			{
				std::cout << ">< " << _("dealing error") << ": " <<
					_("wrong ZK proof") << std::endl;
				return 4;
			}
#ifndef NDEBUG
			stop_clock();
			std::cerr << elapsed_time() << std::flush;
#endif
			std::cout << "." << _("finished!") << std::endl;
			for (size_t i = 0; pctl && (i < os.size()); i++)
			{
				std::ostringstream ost;
				ost << nicks[pkr_self] << " KARTE " << os[i].first << std::endl;
				*out_ctl << ost.str() << std::flush;
			}
			if (pctl)
			{
				std::ostringstream ost;
				ost << nicks[pkr_self] << " START " << ((pkr_self + p) % 3) << std::endl;
				*out_ctl << ost.str() << std::flush;
			}
			
			size_t reiz_status = 0, reiz_counter = 0, vh = 0, mh = 0, hh = 0;
			size_t spiel_status = 0, spiel_allein = 0, spiel_dran = 0, spiel_who[3];
			bool hand_spiel = false, started = false;
			if (p == 0)
				vh = 0, mh = 1, hh = 2;
			if (p == 1)
				vh = 2, mh = 0, hh = 1;
			if (p == 2)
				vh = 1, mh = 2, hh = 0;
			skat_blatt((pkr_self + p) % 3, os);
			fd_set rfds;		// set of read descriptors
			int mfds = 0;		// highest-numbered descriptor
			while ((s[0].size() > 0) || (s[1].size() > 0) || (s[2].size() > 0))
			{
				if (!left->good() || !right->good())
				{
					std::cout << ">< " <<
						_("connection with participating player(s) collapsed") << std::endl;
					return 5;
				}
				
				if (!game_helper_1(reiz_status, spiel_allein, vh, mh, hh,
					reiz_counter, pkr_self, nicks, pkr, pctl, out_ctl))
						break;
				
				// select(2) -- initialize file descriptors
				FD_ZERO(&rfds);
				MFD_SET(ipipe, &rfds);
				if (pctl)
					MFD_SET(ctl_i, &rfds);
				
				// select(2)
				int ret = select(mfds + 1, &rfds, NULL, NULL, NULL);
				
				// error occured
				if (ret < 0)
				{
					if (errno != EINTR)
						perror("SecureSkat_vtmf::skat_game (select)");
				}
				if (ret <= 0)
					continue;
				
				ssize_t num = 0;
				// pipe request
				if (FD_ISSET(ipipe, &rfds))
				{
					num = read(ipipe, ireadbuf + ireaded, 65536 - ireaded);
//FIXME: Was passiert, wenn der Buffer von ipipe und ctl_i gefuellt wird?
//std::cerr << "ipipe " << num << std::endl;
				}
				else if (pctl && FD_ISSET(ctl_i, &rfds))
				{
					num = read(ctl_i, ireadbuf + ireaded, 65536 - ireaded);
//std::cerr << "ctl_i " << num << std::endl;
				}
				ireaded += num;
				
				if (ireaded > 0)
				{
					bool got_break = false;
					std::vector<int> pos_delim;
					int cnt_delim = 0, cnt_pos = 0, pos = 0;
					for (int i = 0; i < ireaded; i++)
						if (ireadbuf[i] == '\n')
							cnt_delim++, pos_delim.push_back(i);
					while (cnt_delim >= 1)
					{
						char xtmp[65536];
						memset(xtmp, 0, sizeof(xtmp));
						memcpy(xtmp, ireadbuf + cnt_pos, pos_delim[pos] - cnt_pos);
						--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
						std::string cmd = xtmp;
						// do operation
						// ---------------------------------------------------------------
				
				if (!left->good() || !right->good())
				{
					std::cout << ">< " <<
					_("connection with participating player(s) collapsed") << std::endl;
					return 5;
				}
				
				if (!game_helper_1(reiz_status, spiel_allein, vh, mh, hh,
					reiz_counter, pkr_self, nicks, pkr, pctl, out_ctl))
				{
					got_break = true;
					break;
				}
				
				if ((cmd.find("!KICK", 0) == 0) || (cmd.find("!QUIT", 0) == 0))
					return 6;
				if ((cmd.find("PART ", 0) == 0) 
					|| (cmd.find("QUIT ", 0) == 0)
					|| (cmd.find("KICK ", 0) == 0))
				{
					std::string nick = cmd.substr(5, cmd.length() - 5);
					if (std::find(nicks.begin(), nicks.end(), nick) != nicks.end())
						return 7;
				}
				if (master && started && (cmd.find("!ANNOUNCE", 0) == 0))
				{
					*out_pipe << "PRIVMSG " << main_channel << " :" << nr << "|3~" <<
						(rounds - r) << "!" << std::endl << std::flush;
				}	
				if (cmd.find("IRC ", 0) == 0)
				{
					*out_pipe << "PRIVMSG " << main_channel << " :" << 
						cmd.substr(4, cmd.length() - 4) << std::endl << std::flush;
				}
				if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
				{
					std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
					std::string msg = cmd.substr(cmd.find(" ", 4) + 1, 
						cmd.length() - cmd.find(" ", 4) - 1);
					
					size_t who_biding = 100;
					switch (reiz_status)
					{
						case 1:
						case 4:
						case 7:
						case 10:
							who_biding = vh;
							break;
						case 0:
						case 2:
						case 9:
							who_biding = mh;
							break;
						case 3:
						case 5:
						case 6:
						case 8:
							who_biding = hh;
							break;
					}
					
					if ((msg.find("PASSE", 0) == 0) || (msg.find("passe", 0) == 0) ||
						(msg.find("PASS", 0) == 0) || (msg.find("pass", 0) == 0))
					{
						if ((who_biding != 100) && (nick == nicks[who_biding]))
						{
							switch (reiz_status)
							{
								case 0: // MH passt (sofort)
									reiz_status = 3;
									break;
								case 1: // VH passt (nach Reizen MH)
									reiz_status = 8;
									break;
								case 2: // MH passt (nach dem Reizen)
									reiz_status = 6;
									break;
								case 3: // HH passt (sofort)
									reiz_status = 10;
									break;
								case 4: // VH passt (nach Reizen HH)
									reiz_status = 14;
									break;
								case 5: // HH passt (nach dem Reizen)
								case 6: // HH passt (nach dem Reizen)
									reiz_status = 12;
									break;
								case 7: // VH passt (nach Passen MH)
									reiz_status = 14;
									break;
								case 8: // HH passt (nach dem Passen VH)
									reiz_status = 13;
									break;
								case 9: // MH passt (nach dem Passen VH)
									reiz_status = 14;
									break;
								case 10: // VH passt (am Schluss)
									reiz_status = 11;
									break;
							}
							std::cout << "><><>< " << _("player") << " \"" << 
								pkr.keys[who_biding].name << "\" " << _("passes at") << " " << 
								reiz_wert[reiz_counter] << std::endl;
							if (pctl)
								*out_ctl << nicks[who_biding] << " PASSE" << std::endl << 
									std::flush;
						}
						else
							std::cout << ">< " << _("biding error") << ": " <<
								_("pass action incorrect") << std::endl;
					}
					else if ((msg.find("REIZE", 0) == 0) || (msg.find("reize", 0) == 0) ||
						(msg.find("BID", 0) == 0) || (msg.find("bid", 0) == 0))
					{
						size_t rei = msg.find(" ", 6);
						std::string srw = msg.substr(6, rei - 6);
						size_t irw = atoi(srw.c_str());
						
						if ((who_biding != 100) && (nick == nicks[who_biding]))
						{
							switch (reiz_status)
							{
								case 0: // MH reizt (zu Beginn)
									if (irw != reiz_wert[++reiz_counter])
										return 22;
									reiz_status = 1;
									break;
								case 1: // VH sagt ja (nach Reizen MH)
									if (irw != reiz_wert[reiz_counter])
										return 22;
									reiz_status = 2;
									break;
								case 2: // MH reizt (weiter)
									if (irw != reiz_wert[++reiz_counter])
										return 22;
									reiz_status = 1;
									break;
								case 3: // HH reizt (nach sofort Passen MH, oder Reizen VH)
								case 5: // HH reizt (nach sofort Passen MH, oder Reizen VH)
									if (irw != reiz_wert[++reiz_counter])
										return 22;
									reiz_status = 4;
									break;
								case 4: // VH sagt ja (nach Passen MH, Reizen HH)
									if (irw != reiz_wert[reiz_counter])
										return 22;
									reiz_status = 5;
									break;
								case 6: // HH reizt (nach Passen MH)
									if (irw != reiz_wert[++reiz_counter])
										return 22;
									reiz_status = 7;
									break;
								case 7: // VH sagt ja (nach Passen MH, Reizen HH)
									if (irw != reiz_wert[reiz_counter])
										return 22;
									reiz_status = 6;
									break;
								case 8: // HH reizt (nach Passen VH)
									if (irw != reiz_wert[++reiz_counter])
										return 22;
									reiz_status = 9;
									break;
								case 9: // MH sagt ja (nach Passen VH)
									if (irw != reiz_wert[reiz_counter])
										return 22;
									reiz_status = 8;
									break;
								case 10: // VH reizt (nach sofort Passen MH, sofort Passen HH)
									if (irw != reiz_wert[++reiz_counter])
										return 22;
									reiz_status = 12;
									break;
								
							}
							std::cout << "><><>< " << _("player") << " \"" << 
								pkr.keys[who_biding].name << "\" " << _("bids") << " " << 
								reiz_wert[reiz_counter] << std::endl;
							if (pctl)
							{
								std::ostringstream ost;
								ost << nicks[who_biding] << " REIZE " << 
									reiz_wert[reiz_counter] << std::endl;
								*out_ctl << ost.str() << std::flush;
							}
						}
						else
							std::cout << ">< " << _("biding error") << ": " <<
								_("bid action incorrect") << std::endl;
					}
					else if ((msg.find("HAND", 0) == 0) || (msg.find("hand", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if ((nick == nicks[spiel_allein]) && (pkr_self != spiel_allein))
							{
								hand_spiel = true, reiz_status += 100;
								std::cout << "><><>< " << _("player") << " \"" <<
									pkr.keys[spiel_allein].name << 
									"\" " << _("doesn't take the Skat") << std::endl;
								if (pctl)
									*out_ctl << nicks[spiel_allein] << " HAND" << std::endl << 
										std::flush;
							}
						}
					}
					else if ((msg.find("SKAT", 0) == 0) || (msg.find("skat", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if ((nick == nicks[spiel_allein]) && (pkr_self != spiel_allein))
							{
								hand_spiel = false, reiz_status += 100;
								std::cout << "><><>< " << _("player") << " \"" << 
									pkr.keys[spiel_allein].name << 
									"\" " << _("takes the Skat") << std::endl;
								assert(sk.size() == 2);
								s[spiel_allein].push(sk);
								if (pkr_self == 0)
								{
									if (spiel_allein == 1)
										skat_szeigen(tmcg, vtmf, sk, left);
									if (spiel_allein == 2)
										skat_szeigen(tmcg, vtmf, sk, right);
								}
								else if (pkr_self == 1)
								{
									if (spiel_allein == 2)
										skat_szeigen(tmcg, vtmf, sk, left);
									if (spiel_allein == 0)
										skat_szeigen(tmcg, vtmf, sk, right);
								}
								else if (pkr_self == 2)
								{
									if (spiel_allein == 0)
										skat_szeigen(tmcg, vtmf, sk, left);
									if (spiel_allein == 1)
										skat_szeigen(tmcg, vtmf, sk, right);
								}
								if (pctl)
									*out_ctl << nicks[spiel_allein] << " SKAT" << std::endl << 
										std::flush;
							}
						}
					}
					else if ((msg.find("DRUECKE", 0) == 0) || 
						(msg.find("druecke", 0) == 0) || (msg.find("PUSH", 0) == 0) || 
						(msg.find("push", 0) == 0))
					{
						if ((reiz_status > 200) && (reiz_status < 300))
						{
							if (!hand_spiel)
							{
								if ((nick == nicks[spiel_allein]) && 
									(pkr_self != spiel_allein))
								{
									VTMF_Card c1, c2;
									reiz_status += 100;
									std::cout << "><><>< " << _("player") << " \"" << 
										pkr.keys[spiel_allein].name << 
										"\" " << _("pushes the Skat") << std::endl;
									if (pctl)
										*out_ctl << nicks[spiel_allein] << " DRUECKE" << 
											std::endl << std::flush;
									if (((pkr_self == 0) && (spiel_allein == 1)) || 
										((pkr_self == 1) && (spiel_allein == 2)) || 
										((pkr_self == 2) && (spiel_allein == 0)))
									{
										*left >> c1 >> c2;
										if (!left->good())
											return 9;
									}
									else if (((pkr_self == 0) && (spiel_allein == 2)) || 
										((pkr_self == 1) && (spiel_allein == 0)) || 
										((pkr_self == 2) && (spiel_allein == 1)))
									{
										*right >> c1 >> c2;
										if (!right->good())
											return 9;
									}
									else
										return 9;
									
									// check and store pushed cards
									if ((!s[spiel_allein].find(c1)) || 
										(!s[spiel_allein].find(c2)))
											return 10;
									sk.clear();
									s[spiel_allein].remove(c1);
									sk.push(c1);
									s[spiel_allein].remove(c2);
									sk.push(c2);
								}
							}
						}
					}
					else if ((msg.find("SAGEAN", 0) == 0) || 
						(msg.find("sagean", 0) == 0) || (msg.find("ANNOUNCE", 0) == 0) || 
						(msg.find("announce", 0) == 0))
					{
						if ((!hand_spiel && (reiz_status > 300) && (reiz_status < 400))
							|| (hand_spiel && (reiz_status > 200) && (reiz_status < 300)))
						{
							char ltmp[100];
							if (((pkr_self == 0) && (spiel_allein == 1)) ||
								((pkr_self == 1) && (spiel_allein == 2)) ||
								((pkr_self == 2) && (spiel_allein == 0)))
							{
								left->getline(ltmp, sizeof(ltmp));
							}
							else if (((pkr_self == 0) && (spiel_allein == 2)) ||
								((pkr_self == 1) && (spiel_allein == 0)) ||
								((pkr_self == 2) && (spiel_allein == 1)))
							{
								right->getline(ltmp, sizeof(ltmp));
							}
							else
							{
								ltmp[0] = '0', ltmp[1] = '\000';
							}
							int sz2 = atoi(ltmp);
							if ((nick == nicks[spiel_allein]) && (pkr_self != spiel_allein)
								&& (sz2 > 0) && (sz2 != 1123) && (sz2 != 1223) 
								&& ((sz2 < 100) || (sz2 > 1000) || (sz2 == 323)))
							{
								reiz_status += (hand_spiel ? 200 : 100);
								spiel_status = sz2;
								// Ouvert Spiele
								if ((spiel_status - (hand_spiel ? 1000 : 0)) > 300)
								{
									for (size_t i = 0; i < 10; i++)
									{
										int type = skat_vkarte(pkr_self, spiel_allein, tmcg,
											vtmf, s[spiel_allein], right, left, false);
										if (type < 0)
										{
											std::cout << ">< " << _("card decryption error") << 
												": " << _("wrong ZK proof") << std::endl;
											return 11;
										}
										os_ov.push(type, VTMF_Card());
										if (pctl)
										{
											std::ostringstream ost;
											ost << nicks[spiel_allein] << " OUVERT " << type << 
												std::endl;
											*out_ctl << ost.str() << std::flush;
										}
									}
									skat_blatt(10, os_ov);
								}
								std::cout << "><><>< " << _("player") << " \"" << 
									pkr.keys[spiel_allein].name << "\" " << _("announces") << 
									": " << skat_spiel2string(spiel_status) << std::endl;
								if (pctl)
								{
									std::ostringstream ost;
									ost << nicks[spiel_allein] << " SAGEAN " << spiel_status <<
										std::endl;
									*out_ctl << ost.str() << std::flush;
								}
								spiel_dran = 0;
								spiel_who[0] = vh, spiel_who[1] = mh, spiel_who[2] = hh;
								started = true;
							}
						}
					}	
					else if ((msg.find("LEGE", 0) == 0) || 
						(msg.find("lege", 0) == 0) || (msg.find("PLAY", 0) == 0) || 
						(msg.find("play", 0) == 0))
					{
						if (nick == nicks[spiel_who[spiel_dran]])
						{
							int type = skat_vkarte(pkr_self, spiel_who[spiel_dran], tmcg,
								vtmf, s[spiel_who[spiel_dran]], right, left, true);
							if (type < 0)
							{
								std::cout << ">< " << _("card decryption error") << 
									": " << _("wrong ZK proof") << std::endl;
								return 12;
							}
							std::cout << "><><>< " << _("player") << " \"" << 
								pkr.keys[spiel_who[spiel_dran]].name << "\" " << 
								_("plays the card") << ": " <<
								skat_type2string(type) << std::endl;
							if (pctl)
							{
								std::ostringstream ost;
								ost << nicks[spiel_who[spiel_dran]] << " LEGE " << type << 
									std::endl;
								*out_ctl << ost.str() << std::flush;
							}	
							VTMF_Card c;
							tmcg->TMCG_CreateOpenCard(c, vtmf, type);
							os_sp.push(type, c);
							// Ouvert Spiele -- Karte vom Sichtstapel entfernen
							if ((spiel_status - (hand_spiel ? 1000 : 0)) > 300)
								os_ov.remove(type);
							if (os_sp.size() == 3)
							{
								int bk = skat_bstich(os_sp, spiel_status);
								assert (bk != -1);
								std::cout << "><><>< " << _("player") << " \"" << 
									pkr.keys[spiel_who[bk]].name << "\" " << 
									_("gets the trick") << ": ";
								for (size_t i = 0; i < os_sp.size(); i++)
									std::cout << skat_type2string(os_sp[i].first);
								std::cout << std::endl;
								if (os.size() > 0)
									skat_blatt((pkr_self + p) % 3, os);
								if (pctl)
									*out_ctl << nicks[spiel_who[bk]] << " BSTICH" << 
										std::endl << std::flush;
								// Stichstapel erste Karte (Regelkontrolle)
								os_st.push(os_sp[0].first, os_sp[0].second);
								// Stichstapel jedes Spielers
								os_pkt[spiel_who[bk]].push(os_sp);
								// Kartenstapel jedes Spielers (Regelkontrolle)
								for (size_t i = 0; i < os_sp.size(); i++)
									os_rc[spiel_who[i]].push(os_sp[i].first, os_sp[i].second);
								os_sp.clear();
								spiel_who[0] = spiel_who[bk];
								spiel_who[1] = (spiel_who[0] + 1) % 3;
								spiel_who[2] = (spiel_who[0] + 2) % 3;
								spiel_dran = 0;
								// Null-Spiele ggf. sofort abbrechen
								if ((skat_spiel2gwert(spiel_status) == 23)
									&& (os_pkt[spiel_allein].size() != 0))
								{
									s[0].clear(), s[1].clear(), s[2].clear();
								}
							}
							else
								spiel_dran += 1;
						}
					}
				}
				if (cmd.find("CMD ", 0) == 0)
				{
					std::string msg = cmd.substr(4, cmd.length() - 4);
//std::cerr << "parse: CMD = " << msg << std::endl;
					
					// trim spaces at end of std::string
					while (msg.find(" ", msg.length() - 1) == (msg.length() - 1))
						msg = msg.substr(0, (msg.length() - 1));
					
					if ((msg.find("BLATT", 0) == 0) || (msg.find("blatt", 0) == 0) || 
						(msg.find("VIEW", 0) == 0) || (msg.find("view", 0) == 0))
					{
						skat_blatt((pkr_self + p) % 3, os);
						if (os_ov.size() > 0)
							skat_blatt(10, os_ov);
						if (spiel_status > 0)
						{
							std::cout << "><><>< " << _("player") << " \"" << 
								pkr.keys[spiel_allein].name << "\" (";
							if ((reiz_status - 412) == 0)
								std::cout << "VH";
							if ((reiz_status - 412) == 1)
								std::cout << "MH";
							if ((reiz_status - 412) == 2)
								std::cout << "HH";
							std::cout << ") " << _("announced") << " \"" << 
								skat_spiel2string(spiel_status) << "\"" << std::endl;
							std::cout << "><><>< " << _("played cards") << ": ";
							for (size_t i = 0; i < os_sp.size(); i++)
							{
								TMCG_OpenStack<VTMF_Card> os_sp2;
								os_sp2.push(os_sp[i].first, os_sp[i].second);
								skat_blatt(99, os_sp2);
								std::cout << "(" << pkr.keys[spiel_who[i]].name << ") ";
							}
							if (os_sp.size() < 3)
							{
								std::cout << " [" << pkr.keys[spiel_who[spiel_dran]].name << 
									" " << _("has to play") << "]" << std::endl;
							}
						}
					}
					else if ((msg.find("PASSE", 0) == 0) ||
						(msg.find("passe", 0) == 0) || (msg.find("PASS", 0) == 0) || 
						(msg.find("pass", 0) == 0))
					{
						bool pass_ok = true;
						switch ((pkr_self + p) % 3)
						{
							case 0: // VH beim Passen
								switch (reiz_status)
								{
									case 1:
										reiz_status = 8;
										break;
									case 4:
									case 7:
										reiz_status = 14;
										break;
									case 10:
										reiz_status = 11;
										break;
									default:
										pass_ok = false;
								}
								break;
							case 1: // MH beim Passen
								switch (reiz_status)
								{
									case 0:
										reiz_status = 3;
										break;
									case 2:
										reiz_status = 6;
										break;
									case 9:
										reiz_status = 14;
										break;
									default:
										pass_ok = false;
								}
								break;
							case 2: // HH beim Passen
								switch (reiz_status)
								{
									case 3:
										reiz_status = 10;
										break;
									case 5:
									case 6:
										reiz_status = 12;
										break;
									case 8:
										reiz_status = 13;
										break;
									default:
										pass_ok = false;
								}
								break;
						}
						
						if (pass_ok)
						{
							std::cout << "><><>< " << _("player") << " \"" << 
								pkr.keys[pkr_self].name << "\" " << _("passes at") << " " << 
								reiz_wert[reiz_counter] << std::endl;
							*out_pipe << "PRIVMSG " << main_channel_underscore << nr << 
								" :PASSE " << hex_game_digest << std::endl << std::flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << std::endl << 
									std::flush;
						}
						else
							std::cout << ">< " << _("biding error") << ": " << 
								_("passing is currently not allowed") << std::endl;
					}
					else if ((msg.find("REIZE", 0) == 0) || 
						(msg.find("reize", 0) == 0) || (msg.find("BID", 0) == 0) || 
						(msg.find("bid", 0) == 0))
					{
					bool bid_ok = true;
						switch ((pkr_self + p) % 3)
						{
							case 0: // VH beim Reizen
								switch (reiz_status)
								{
									case 1:
										reiz_status = 2;
										break;
									case 4:
										reiz_status = 5;
										break;
									case 7:
										reiz_status = 6;
										break;
									case 10:
										reiz_status = 12;
										reiz_counter++;
										break;
									default:
										bid_ok = false;
								}
								break;
							case 1: // MH beim Reizen
								switch (reiz_status)
								{
									case 0:
									case 2:
										reiz_status = 1;
										reiz_counter++;
										break;
									case 9:
										reiz_status = 8;
										break;
									default:
										bid_ok = false;
								}
								break;
							case 2: // HH beim Reizen
								switch (reiz_status)
								{
									case 3:
									case 5:
										reiz_status = 4;
										reiz_counter++;
										break;
									case 6:
										reiz_status = 7;
										reiz_counter++;
										break;
									case 8:
										reiz_status = 9;
										reiz_counter++;
										break;
									default:
										bid_ok = false;
								}
								break;
						}
						
						if (bid_ok)
						{
							std::cout << "><><>< " << _("player") << " \"" << 
								pkr.keys[pkr_self].name << "\" " << _("bids") << " " << 
								reiz_wert[reiz_counter] << std::endl;
							*out_pipe << "PRIVMSG " << main_channel_underscore << nr << 
								" :REIZE " << reiz_wert[reiz_counter] << " " << 
								hex_game_digest << std::endl << std::flush;
							if (pctl)
							{
								std::ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << std::endl;
								*out_ctl << ost.str() << std::flush;
							}
						}
						else
							std::cout << ">< " << _("biding error") << ": " << 
								_("biding is currently not allowed") << std::endl;
					}
					else if ((msg.find("HAND", 0) == 0) || (msg.find("hand", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if ((reiz_status - 112) == ((pkr_self + p) % 3))
							{
								std::cout << "><><>< " << _("player") << " \"" << 
									pkr.keys[pkr_self].name << "\" " <<
									_("doesn't take the Skat") << std::endl;
								*out_pipe << "PRIVMSG " << main_channel_underscore << nr << 
									" :HAND " << hex_game_digest << std::endl << std::flush;
								hand_spiel = true, reiz_status += 100;
								if (pctl)
									*out_ctl << nicks[pkr_self] << " HAND" << std::endl << 
										std::flush;
							}
							else
								std::cout << ">< " << _("It's not your game.") << std::endl;
						}
						else
							std::cout << ">< " <<
								_("taking the Skat is currently not allowed") << std::endl;
					}
					else if ((msg.find("SKAT", 0) == 0) || (msg.find("skat", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if (pkr_self == spiel_allein)
							{
								std::cout << "><><>< " << _("player") << " \"" << 
									pkr.keys[pkr_self].name << "\" " << 
									_("takes the Skat") << std::endl;
								*out_pipe << "PRIVMSG " << main_channel_underscore << nr << 
									" :SKAT " << hex_game_digest << std::endl << std::flush;
								hand_spiel = false, reiz_status += 100;
								if (!skat_ssehen(pkr_self, tmcg, vtmf, os, sk,
									right, left))
								{
									std::cout << ">< " << _("card decryption error") << 
										": " << _("wrong ZK proof") << std::endl;
									return 8;
								}
								for (size_t i = 10; (pctl && (i < os.size())); i++)
								{
									std::ostringstream ost;
									ost << nicks[pkr_self] << " KARTE " << os[i].first << 
										std::endl;
									*out_ctl << ost.str() << std::flush;
								}
								if (pctl)
									*out_ctl << nicks[pkr_self] << " SKAT" << std::endl << 
										std::flush;
								skat_blatt((pkr_self + p) % 3, os);
							}
							else
								std::cout << ">< " << _("It's not your game.") << std::endl;
						}
						else
							std::cout << ">< " << 
								_("taking the Skat is currently not allowed") << std::endl;
					}
					else if ((msg.find("DRUECKE", 0) == 0) || 
						(msg.find("druecke", 0) == 0) || (msg.find("PUSH", 0) == 0) || 
						(msg.find("push", 0) == 0))
					{
						if ((reiz_status > 200) && (reiz_status < 300))
						{
							if (pkr_self == spiel_allein)
							{
								if (!hand_spiel)
								{
									std::string par = "";
									size_t ei = par.npos, mi = msg.find(" ", 0);
									
									if ((mi != msg.npos) && (msg.length() > mi))
									{
										par = msg.substr(mi + 1, msg.length() - (mi + 1));
										ei = par.find(" ", 0);
									}
									if ((ei != par.npos) && (par.length() > ei))
									{
										std::string cc1 = par.substr(0, ei);
										std::string cc2 = par.substr(ei + 1,
											par.length() - (ei + 1));
										
										int tt1 = skat_wort2type(cc1), tt2 = skat_wort2type(cc2);
										if ((tt1 != -1) && (tt2 != -1))
										{
											if (os.find(tt1) && os.find(tt2))
											{
												sk.clear();
												os.move(tt1, sk), os.move(tt2, sk);
												assert(sk.size() == 2);
												s[pkr_self].clear();
												s[pkr_self].push(os);
												std::cout << "><><>< " << _("player") << " \"" << 
													pkr.keys[pkr_self].name << 
													"\" " << _("pushes") << ": " << 
													skat_type2string(tt1) << skat_type2string(tt2) << 
													std::endl;
												*out_pipe << "PRIVMSG " << main_channel_underscore << 
													nr << " :DRUECKE " << hex_game_digest << 
													std::endl << std::flush;
												reiz_status += 100;
												*right << sk[0] << std::endl << std::flush;
												*right << sk[1] << std::endl << std::flush;
												*left << sk[0] << std::endl << std::flush;
												*left << sk[1] << std::endl << std::flush;
												if (pctl)
													*out_ctl << nicks[pkr_self] << " DRUECKE" << 
														std::endl << std::flush;
												skat_blatt((pkr_self + p) % 3, os);
											}
											else
												std::cout << ">< " << _("card") << " \"" << 
													cc1 << "\" " << _("resp.") << " \"" <<
													cc2 << "\" " << _("is not in your hands") << 
													std::endl;
										}
										else
											std::cout << ">< " << _("wrong card name") << ": \"" << 
												cc1 << "\" " << _("resp.") << " \"" << cc2 << "\"" << 
												std::endl;
									}
									else
										std::cout << ">< " << _("not enough parameter") << 
											std::endl;
								}
								else
									std::cout << ">< " << _("You must play without the Skat.") << 
										std::endl;
							}
							else
								std::cout << ">< " << _("It's not your game.") << std::endl;
						}
						else
							std::cout << ">< " << 
								_("pushing the Skat is currently not allowed") << std::endl;
					}
					else if ((msg.find("SAGEAN", 0) == 0) || 
						(msg.find("sagean", 0) == 0) || (msg.find("ANNOUNCE", 0) == 0) || 
						(msg.find("announce", 0) == 0))
					{
						if ((!hand_spiel && (reiz_status > 300) && (reiz_status < 400))
							|| (hand_spiel && (reiz_status > 200) && (reiz_status < 300)))
						{
							if (pkr_self == spiel_allein)
							{
								std::string par = "";
								size_t ei = par.npos, mi = msg.find(" ", 0);
								
								if ((mi != msg.npos) && (msg.length() > mi))
								{
									par = msg.substr(mi + 1, msg.length() - (mi + 1));
									ei = par.find(" ", 0);
								}
								if ((mi != msg.npos) && (par != ""))
								{
									std::string spiel = "", zusatz = "";
									if (ei != par.npos)
									{
										spiel = par.substr(0, ei);
										zusatz = par.substr(ei + 1, par.length() - (ei + 1));
									}
									else
										spiel = par;
									
									int s1 = skat_wort2spiel(spiel);
									int s2 = skat_wort2spiel(zusatz);
									int sz = s1 + s2 + (hand_spiel ? 1000 : 0);
									if ((s1 != -1) && (s2 != -1) && (s1 > 0) && (sz > 0))
									{
										if (((sz < 100) || (sz > 1000) || (sz == 323)) &&
											(sz != 1123) && (sz != 1223))
										{
											reiz_status += (hand_spiel ? 200 : 100);
											spiel_status = sz;
											*out_pipe << "PRIVMSG " << main_channel_underscore << 
												nr << " :SAGEAN " << skat_spiel2string(spiel_status) << 
												" " << hex_game_digest << std::endl << std::flush;
											std::ostringstream ost;
											ost << spiel_status << std::endl;
											*left << ost.str() << std::flush;
											*right << ost.str() << std::flush;
											// Ouvert Spiele -- Karten oeffnen
											if ((spiel_status - (hand_spiel ? 1000 : 0)) > 300)
											{
												for (size_t i = 0; i < os.size(); i++)
												{
													*out_pipe << "PRIVMSG " << main_channel_underscore << 
														nr << " :OUVERT " << 
														skat_type2string(os[i].first) << " " << 
														hex_game_digest << std::endl << std::flush;
													skat_okarte(tmcg, vtmf, os[i].second, right, left);
													// sleep to prevent "Excess Flood" error
													sleep(3);
												}
											}
											std::cout << "><><>< " << _("player") << " \"" << 
												pkr.keys[pkr_self].name << "\" " << _("announces") << 
												": " << skat_spiel2string(spiel_status) << std::endl;
											if (pctl)
												*out_ctl << nicks[pkr_self] << " SAGEAN " <<
													ost.str() << std::endl << std::flush;
											spiel_dran = 0;
											spiel_who[0] = vh, spiel_who[1] = mh, spiel_who[2] = hh;
											started = true;
										}
										else
											std::cout << ">< " << _("invalid announcement") << 
												": " << sz << std::endl;
									}
									else
										std::cout << ">< " << _("wrong name of announcement") << 
											": \"" << spiel << "\" " << _("resp.") << " \"" << 
											zusatz << "\"" << std::endl;
								}
								else
									std::cout << ">< " << _("not enough parameters") << std::endl;
							}
							else
								std::cout << ">< " << _("It's not your game.") << std::endl;
						}
						else
							std::cout << ">< " << 
								_("announcing the game is currently not allowed") << std::endl;
					}
					else if ((msg.find("LEGE", 0) == 0) || (msg.find("lege", 0) == 0) || 
						(msg.find("PLAY", 0) == 0) || (msg.find("play", 0) == 0))
					{
						if ((spiel_status > 0) && (pkr_self == spiel_who[spiel_dran]))
						{
							std::string par = "";
							size_t mi = msg.find(" ", 0);
							
							if ((mi != msg.npos) && (msg.length() > mi))
								par = msg.substr(mi + 1, msg.length() - (mi + 1));
							
							if (par.length() > 0)
							{
								int tt = skat_wort2type(par);
								if (tt != -1)
								{
									if (os.find(tt))
									{
										// Regelkontrolle, falls schon Karten gespielt sind
										if ((os_sp.size() > 0) &&
											(!skat_rulectl(os_sp[0].first, tt, spiel_status, os)))
										{
											std::cout << ">< " << _("playing the card") << " \"" << 
												par << "\" " << _("is not conform with the rules") << 
												std::endl;
											continue;
										}
										std::cout << "><><>< " << _("player") << " \"" << 
											pkr.keys[pkr_self].name << "\" " << _("plays the card") <<
											": " << skat_type2string(tt) << std::endl;
										*out_pipe << "PRIVMSG " << main_channel_underscore << nr << 
											" :LEGE " << skat_type2string(tt) << " " << 
											hex_game_digest << std::endl << std::flush;
										if (pctl)
										{
											std::ostringstream ost;
											ost << nicks[pkr_self] << " LEGE " << tt << std::endl;
											*out_ctl << ost.str() << std::flush;
										}
										TMCG_Stack<VTMF_Card> st;
										VTMF_Card c;
										os.move(tt, st);
										assert(st.size() == 1);
										skat_okarte(tmcg, vtmf, st[0], right, left);
										s[pkr_self].remove(st[0]);
										tmcg->TMCG_CreateOpenCard(c, vtmf, tt);
										os_sp.push(tt, c);
										st.clear();
										if (os_sp.size() == 3)
										{
											int bk = skat_bstich(os_sp, spiel_status);
											assert(bk != -1);
											std::cout << "><><>< " << _("player") << " \"" << 
												pkr.keys[spiel_who[bk]].name << 
												"\" " << _("gets the trick") << ": ";
											for (size_t i = 0; i < os_sp.size(); i++)
												std::cout << skat_type2string(os_sp[i].first);
											std::cout << std::endl;
											if (os.size() > 0)
												skat_blatt((pkr_self + p) % 3, os);
											if (pctl)
												*out_ctl << nicks[spiel_who[bk]] << " BSTICH" <<
													std::endl << std::flush;
											// Stichstapel erste Karte (Regelkontrolle)
											os_st.push(os_sp[0].first, os_sp[0].second);
											// Stichstapel jedes Spielers
											os_pkt[spiel_who[bk]].push(os_sp);
											// Kartenstapel jedes Spielers (Regelkontrolle)
											for (size_t i = 0; i < os_sp.size(); i++)
												os_rc[spiel_who[i]].push(os_sp[i].first,
													os_sp[i].second);
											os_sp.clear();
											spiel_who[0] = spiel_who[bk];
											spiel_who[1] = (spiel_who[0] + 1) % 3;
											spiel_who[2] = (spiel_who[0] + 2) % 3;
											spiel_dran = 0;
											// Null-Spiele ggf. sofort abbrechen
											if ((skat_spiel2gwert(spiel_status) == 23)
												&& (os_pkt[spiel_allein].size() != 0))
											{
												s[0].clear(), s[1].clear(), s[2].clear();
											}
										}
										else
											spiel_dran += 1;
									}
									else
										std::cout << ">< " << _("card") << " \"" << par << "\" " << 
											_("is not in your hands") << std::endl;
								}
								else
									std::cout << ">< " << _("wrong card name") << ": \"" <<
										par << "\"" << std::endl;
							}
							else
								std::cout << ">< " << _("not enough parameter") << std::endl;
						}
						else
							std::cout << ">< " << 
								_("playing of cards is currently not allowed") << std::endl;
					}
					else
					{
						std::cout << ">< " << _("unknown table command") << " \"/" << nr << 
							" " << msg << "\"" << std::endl;
					}
				}
							// ----------------------------------------------------------------
					}
					char ytmp[65536];
					memset(ytmp, 0, sizeof(ytmp));
					ireaded -= cnt_pos;
					memcpy(ytmp, ireadbuf + cnt_pos, ireaded);
					memcpy(ireadbuf, ytmp, ireaded);
					if (got_break)
						break;
				}
				if (num == 0)
				{
					std::cout << "><>< " << 
						_("connection to program modules collapsed") << std::endl;
					return 5;
				}
			}
			
			if (pctl)
				*out_ctl << nicks[pkr_self] << " STOP" << std::endl << std::flush;
			
			if (spiel_status > 0)
			{
				bool spiel_gewonnen = false;
				
				// Augen der Gegenpartei zaehlen
				size_t pkt_allein = 0, pkt_gegner = 0; 
				for (size_t i = 0; i < 3; i++)
					for (size_t j = 0; (i != spiel_allein) && (j < os_pkt[i].size()); j++)
						pkt_gegner += pkt_wert[os_pkt[i][j].first];
				pkt_allein = 120 - pkt_gegner;
				std::cout << "><><>< " << _("card points") << " " <<
					_("playing party") << " (" << pkr.keys[spiel_allein].name << "): " << 
					pkt_allein << ", " << _("card points") << " " << 
					_("opponent party") << ": " << pkt_gegner << std::endl;
				
				if (pkt_allein > 60)
					spiel_gewonnen = true;
				else
					spiel_gewonnen = false;
				
				// nachtraegliche Regelkontrolle
				bool rules_ok[3];
				assert((os_st.size() == 10) ||
					((skat_spiel2gwert(spiel_status) == 23)
						&& (os_pkt[spiel_allein].size() != 0)));
				for (size_t i = 0; i < 3; i++)
				{
					TMCG_OpenStack<VTMF_Card> gps;
					assert((os_rc[i].size() == 10) ||
						((skat_spiel2gwert(spiel_status) == 23)
							&& (os_pkt[spiel_allein].size() != 0)));
					gps.push(os_rc[i]);
					rules_ok[i] = true;
					for (size_t j = 0; j < os_st.size(); j++)
					{
						if (!skat_rulectl(os_st[j].first,
							os_rc[i][j].first, spiel_status, gps))
								rules_ok[i] = false;
						gps.remove(os_rc[i][j].first);
					}
				}
				
				// Stapel des Alleinspielers um Skat vervollstaendigen
				for (size_t t = 0; t < 32; t++)
				{
					if (!os_rc[0].find(t) && !os_rc[1].find(t) && !os_rc[2].find(t))
					{
						VTMF_Card c;
						tmcg->TMCG_CreateOpenCard(c, vtmf, t);
						os_rc[spiel_allein].push(t, c);
					}
				}
				
				// Spielwert ermitteln
				int spiel_wert = 0;
				
				// Null Spiel?
				if (skat_spiel2gwert(spiel_status) == 23)
				{
					if (os_pkt[spiel_allein].size() == 0)
						spiel_gewonnen = true;
					else
						spiel_gewonnen = false;
					if (hand_spiel && (spiel_status > 1300))
						spiel_wert = 59;
					if (!hand_spiel && (spiel_status > 300))
						spiel_wert = 46;
					if (hand_spiel && !(spiel_status > 1300))
						spiel_wert = 35;
					if (!hand_spiel && !(spiel_status > 300))
						spiel_wert = 23;
				}
				else
				{
					size_t spitzen = 
						skat_spitzen(spiel_status, tmcg, os_rc[spiel_allein]);
					size_t gs = spiel_status, gstufen = 1;
					
					// Hand (2)
					if (gs > 1000)
						gstufen++, gs -= 1000;
					// Offen (3)
					if (gs > 300)
						gstufen++, gs -= 100;
					// Schwarz angesagt (4)
					if (gs > 200)
					{
						if (os_pkt[spiel_allein].size() == 30)
							gstufen++, gs -= 100;
						else
							gstufen++, gs -= 100, spiel_gewonnen = false;
					}
					// Schneider angesagt (5)
					if (gs > 100)
					{
						if (pkt_gegner < 31)
							gstufen++, gs -= 100;
						else
							gstufen++, gs -= 100, spiel_gewonnen = false;
					}
					// Schwarz gespielt (6)
					if (os_pkt[spiel_allein].size() == 30)
					{
						std::cout << "><>< " << _("opponent party") << " " << 
							_("is") << " " << "Schwarz" << "!" << std::endl;
						gstufen++;
					}
					// Schneider gespielt (7)
					if (pkt_gegner < 31)
					{
						std::cout << "><>< " << _("opponent party") << " " << 
							_("is") << " " << "Schneider" << "!" << std::endl;
						gstufen++;
					}
					// (selbst) Schwarz gespielt (6)
					if (os_pkt[spiel_allein].size() == 0)
					{
						std::cout << "><>< " << _("playing party") << " " << _("is") << 
							" " << "Schwarz" << ". " << _("Loosing the game!") << std::endl;
						gstufen++, spiel_gewonnen = false;
					}
					// (selbst) Schneider gespielt (7)
					if (pkt_allein < 31)
					{
						std::cout << "><>< " << _("playing party") << " " << _("is") << 
							" " << "Schneider" << ". " << _("Loosing the game!") << std::endl;
						gstufen++, spiel_gewonnen = false;
					}
					
					spiel_wert = (spitzen + gstufen) * skat_spiel2gwert(spiel_status);
				}
				if (reiz_wert[reiz_counter] > (size_t)spiel_wert)
				{
					std::cout << "><>< " << _("playing party") << " " << 
						_("has bet to much") << ". " << _("Loosing the game!") << std::endl;
					spiel_wert = 0;
					while ((size_t)spiel_wert < reiz_wert[reiz_counter])
						spiel_wert += skat_spiel2gwert(spiel_status);
					spiel_wert = -spiel_wert;
					spiel_gewonnen = false;
				}
				else
				{
					// verlorene Spiele werden immer bestraft!
					if (!spiel_gewonnen)
						spiel_wert = -2 * spiel_wert;
				}
				for (size_t i = 0; i < 3; i++)
				{
					if (!rules_ok[i])
					{
						std::cout << "><>< " << _("player") << " \"" << pkr.keys[i].name << 
							"\" " << _("has violated the rules.") << std::endl;
						return 20;
					}
				}
				std::cout << "><><>< " << _("game points") << ": " << spiel_wert << 
					", " << _("biding value") << ": " <<
					reiz_wert[reiz_counter] << ", " << _("game outcome") << ": " <<
					(spiel_gewonnen ? _("win") : _("loose")) << std::endl;
				if (pctl)
				{
					std::string ctlt = "";
					if (spiel_gewonnen)
						*out_ctl << nicks[spiel_allein] << " GEWONNEN" << std::endl << std::flush;
					else
						*out_ctl << nicks[spiel_allein] << " VERLOREN" << std::endl << std::flush;
				}
				pkt_sum[spiel_allein] += spiel_wert;
				
				std::ostringstream einzel_protokoll;
				einzel_protokoll << nicks[spiel_allein] << "~" << spiel_wert <<
					"~" << spiel_status << "~" << pkt_allein << "~" <<
					reiz_wert[reiz_counter] << "~" << hex_game_digest << "~";
				spiel_protokoll << einzel_protokoll.str() << "#";
				if (pctl)
					*out_ctl << nicks[spiel_allein] << " PROTO " <<
						einzel_protokoll.str() << std::endl << std::flush;
			}
			else
			{	
				if (pctl)
					*out_ctl << nicks[pkr_self] << " NONE" << std::endl << std::flush;
				spiel_protokoll << "NONE~0~0~0~0~" << hex_game_digest << "~#";
			}
			
			delete [] game_digest, delete [] hex_game_digest;
			os.clear();
			os_ov.clear();
			os_sp.clear();
			os_st.clear();
			for (size_t i = 0; i < 3; i++)
			{
				os_pkt[i].clear();
				os_rc[i].clear();
				s[i].clear();
				d_mix[i].clear();
			}
			sk.clear();
			d_end.clear();
			ab.clear();
			ss.clear();
			d2.clear();
			d.clear();
			
			std::cout << "><><>< " << _("game result") << " <><><> ";
			for (size_t i = 0; i < 3; i++)
				std::cout << pkr.keys[i].name << ": " << pkt_sum[i] << " ";
			std::cout << std::endl;
		}
		
		std::string sig;
		std::string sig_data = spiel_protokoll.str();
		std::ostringstream sig_protokoll;
		char stmp[10000];
		if (pkr_self == 0)
		{
			sig = sec.sign(sig_data);
			sig_protokoll << sig << "#";
			*left << sig << std::endl << std::flush;
			*right << sig << std::endl << std::flush;
			left->getline(stmp, sizeof(stmp));
			if (!pkr.keys[1].verify(sig_data, stmp))
			{
				std::cout << "><>< " << _("Signature of") << " " << _("player") <<
					" \"" << pkr.keys[1].name << "\" " << _("is invalid") << std::endl;
				return 30;
			}
			sig_protokoll << stmp << "#";
			right->getline(stmp, sizeof(stmp));
			if (!pkr.keys[2].verify(sig_data, stmp))
			{
				std::cout << "><>< " << _("Signature of") << " " << _("player") <<
					" \"" << pkr.keys[2].name << "\" " << _("is invalid") << std::endl;
				return 30;
			}
			sig_protokoll << stmp << "#";
		}
		else if (pkr_self == 1)
		{
			right->getline(stmp, sizeof(stmp));
			if (!pkr.keys[0].verify(sig_data, stmp))
			{
				std::cout << "><>< " << _("Signature of") << " " << _("player") <<
					" \"" << pkr.keys[0].name << "\" " << _("is invalid") << std::endl;
				return 30;
			}
			sig_protokoll << stmp << "#";
			sig = sec.sign(sig_data);
			sig_protokoll << sig << "#";
			*left << sig << std::endl << std::flush;
			*right << sig << std::endl << std::flush;
			left->getline(stmp, sizeof(stmp));
			if (!pkr.keys[2].verify(sig_data, stmp))
			{
				std::cout << "><>< " << _("Signature of") << " " << _("player") <<
					" \"" << pkr.keys[2].name << "\" " << _("is invalid") << std::endl;
				return 30;
			}
			sig_protokoll << stmp << "#";
		}
		else if (pkr_self == 2)
		{
			left->getline(stmp, sizeof(stmp));
			if (!pkr.keys[0].verify(sig_data, stmp))
			{
				std::cout << "><>< " << _("Signature of") << " " << _("player") <<
					" \"" << pkr.keys[0].name << "\" " << _("is invalid") << std::endl;
				return 30;
			}
			sig_protokoll << stmp << "#";
			right->getline(stmp, sizeof(stmp));
			if (!pkr.keys[1].verify(sig_data, stmp))
			{
				std::cout << "><>< " << _("Signature of") << " " << _("player") <<
					" \"" << pkr.keys[1].name << "\" " << _("is invalid") << std::endl;
				return 30;
			}
			sig_protokoll << stmp << "#";
			sig = sec.sign(sig_data);
			sig_protokoll << sig << "#";
			*left << sig << std::endl << std::flush;
			*right << sig << std::endl << std::flush;
		}
		spiel_protokoll << sig_protokoll.str();
		
		// compute rnk_id aka hex_rnk_digest
		std::string osttmp = spiel_protokoll.str();
		assert(gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO));
		char *rnk_digest = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
		gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, rnk_digest,
			osttmp.c_str(), osttmp.length());
		char *hex_rnk_digest = 
			new char[2 * gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO) + 1];
		for (size_t i = 0; i < gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO); i++)
			snprintf(hex_rnk_digest + (2 * i), 3, "%02x", 
				(unsigned char)rnk_digest[i]);
		opipestream *npipe = new opipestream(hpipe);
		*npipe << hex_rnk_digest << std::endl << std::flush;
		*npipe << spiel_protokoll.str() << std::endl << std::flush;
		delete [] rnk_digest;
		delete [] hex_rnk_digest;
		delete npipe;
	}
	delete vsshe,	delete vtmf;
	if (pctl)
		*out_ctl << nicks[pkr_self] << " DONE" << std::endl << std::flush;
	delete out_pipe;
	if (pctl)
		delete out_ctl;
	return 0;
}
