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

#include "SecureSkat_vtmf.hh"

#define MFD_SET(fd, where) { FD_SET(fd, where); mfds = (fd > mfds) ? fd : mfds; }

// global variable for return strings
string wstr;

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

// order of the cards in several games
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
		size_t spiel, SchindelhauerTMCG *tmcg, const VTMF_OpenStack &os
	)
{
	size_t co[5][18], sz_cnt = 0;
	init_co(spiel, co);
	
	// Null Spiel? Keine Spitzen!
	if (skat_spiel2gwert(spiel) == 23)
		return 0;

	// mit oder ohne Spitzen z?len
	if (tmcg->TMCG_IsInOpenStack(os, 0))
	{
		for (size_t sz = 0; sz < 11; sz++)
		{
			if (tmcg->TMCG_IsInOpenStack(os, co[4][sz]))
					sz_cnt++;
			else
				break;
		}
	}
	else
	{
		for (size_t sz = 0; sz < 11; sz++)
		{
			if (!tmcg->TMCG_IsInOpenStack(os, co[4][sz]))
				sz_cnt++;
			else
				break;
		}
	}
	return sz_cnt;
}

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel, const vector<size_t> &cv
	)
{
	VTMF_OpenStack os;
	pair<short int, VTMF_Card*> os_p;
	for (size_t j = 0; j < cv.size(); j++)
	{
		os_p.first = cv[j], os_p.second = NULL;
		os.push_back(os_p);
	}	
	return skat_rulectl(t, tt, spiel, os);
}

bool skat_rulectl
	(
		size_t t, size_t tt, size_t spiel, const VTMF_OpenStack &os
	)
{
	size_t co[5][18], to = 0;
	init_co(spiel, co);

	if (skat_spiel2gwert(spiel) == 23)
		to = 0;	// Null: kein Trumpf
	else if (skat_spiel2gwert(spiel) == 24)
		to = 4;	// Grand: 4 Tr?pfe
	else
		to = 11;	// Farbspiele: 11 Tr?pfe

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
		const VTMF_OpenStack &os, size_t spiel
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
		BarnettSmartVTMF_dlog *vtmf, VTMF_Stack &s,
		iosecuresocketstream *right, iosecuresocketstream *left, bool rmv
	)
{
	char *tmp = new char[TMCG_MAX_CARD_CHARS];
	int type = -1;
	VTMF_Card c;
	assert(pkr_self != pkr_who);
	
	try
	{
		if (((pkr_self == 0) && (pkr_who == 1)) || 
			((pkr_self == 1) && (pkr_who == 2)) || 
			((pkr_self == 2) && (pkr_who == 0)))
		{
			left->getline(tmp, TMCG_MAX_CARD_CHARS);
			if (!tmcg->TMCG_ImportCard(c, tmp))
				throw -1;
			if (!tmcg->TMCG_IsInStack(s, c))
				throw -1;
			tmcg->TMCG_SelfCardSecret(c, vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *left, *left))
				throw -1;
			
			if ((pkr_self == 0) && (pkr_who == 1))
				tmcg->TMCG_ProofCardSecret(c, vtmf, *right, *right);
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
				tmcg->TMCG_ProofCardSecret(c, vtmf, *right, *right);
			if ((pkr_self == 2) && (pkr_who == 0))
				tmcg->TMCG_ProofCardSecret(c, vtmf, *right, *right);
			
			type = tmcg->TMCG_TypeOfCard(c, vtmf);
			if (rmv)
				tmcg->TMCG_RemoveFirstFromStack(s, c);
			throw type;
		}
		if (((pkr_self == 0) && (pkr_who == 2)) || 
			((pkr_self == 1) && (pkr_who == 0)) || 
			((pkr_self == 2) && (pkr_who == 1)))
		{
			right->getline(tmp, TMCG_MAX_CARD_CHARS);
			if (!tmcg->TMCG_ImportCard(c, tmp))
				throw -1;
			if (!tmcg->TMCG_IsInStack(s, c))
				throw -1;
			tmcg->TMCG_SelfCardSecret(c, vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, *right, *right))
				throw -1;
			
			if ((pkr_self == 0) && (pkr_who == 2))
				tmcg->TMCG_ProofCardSecret(c, vtmf, *left, *left);
			if ((pkr_self == 1) && (pkr_who == 0))
				tmcg->TMCG_ProofCardSecret(c, vtmf, *left, *left);
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
				tmcg->TMCG_ProofCardSecret(c, vtmf, *left, *left);
			
			type = tmcg->TMCG_TypeOfCard(c, vtmf);
			if (rmv)
				tmcg->TMCG_RemoveFirstFromStack(s, c);
			throw type;
		}
		throw -1;
	}
	catch (int return_value)
	{
		delete [] tmp;
		return return_value;
	}
}

void skat_okarte
	(
		SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf, const VTMF_Card &c,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	*right << c << endl << flush;
	tmcg->TMCG_ProofCardSecret(c, vtmf, *right, *right);
	*left << c << endl << flush;
	tmcg->TMCG_ProofCardSecret(c, vtmf, *left, *left);
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
		wstr += "Gr? (Gr)";
	else if (skat_spiel2gwert(spiel) == 12)
		wstr += "Eicheln (Ei)";
	else if (skat_spiel2gwert(spiel) == 23)
		wstr += "Null (Nu)";
	else if (skat_spiel2gwert(spiel) == 24)
		wstr += "Grand (Gd)";
	else
		wstr += "Unbekannt";
	if (spiel > 1000)
	{
		wstr += " Hand";
		if (((spiel % 1000) > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schneider";
		if (((spiel % 1000) > 200) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schwarz";
		if (((spiel % 1000) > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " angesagt";
		if ((spiel % 1000) > 300)
			wstr += " Ouvert (Offen)";
	}
	else
	{
		if ((spiel > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schneider";
		if ((spiel > 200) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " Schwarz";
		if ((spiel > 100) && !(skat_spiel2gwert(spiel) == 23))
			wstr += " angesagt";
		if (spiel > 300)
			wstr += " Ouvert (Offen)";
	}
	return wstr.c_str();
}

int skat_wort2spiel
	(
		const string &wort
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
		const VTMF_Stack &sk, iosecuresocketstream *rls
	)
{
	for (size_t i = 0; i < sk.size(); i++)
		tmcg->TMCG_ProofCardSecret(*(sk[i]), vtmf, *rls, *rls);
}

bool skat_ssehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		VTMF_OpenStack &os, const VTMF_Stack &sk,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	for (size_t i = 0; i < sk.size(); i++)
	{
		tmcg->TMCG_SelfCardSecret(*(sk[i]), vtmf);
		if (pkr_self == 0)
		{
			if (!tmcg->TMCG_VerifyCardSecret(*(sk[i]), vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(*(sk[i]), vtmf, *right, *right))
				return false;
		}
		else if (pkr_self == 1)
		{
			if (!tmcg->TMCG_VerifyCardSecret(*(sk[i]), vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(*(sk[i]), vtmf, *right, *right))
				return false;
		}
		else if (pkr_self == 2)
		{
			if (!tmcg->TMCG_VerifyCardSecret(*(sk[i]), vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(*(sk[i]), vtmf, *right, *right))
				return false;
		}
		tmcg->TMCG_PushToOpenStack(os, *(sk[i]),
			tmcg->TMCG_TypeOfCard(*(sk[i]), vtmf));
	}
	return true;
}

int skat_wort2type
	(
		const string &wort
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
		string wert = wort.substr(2, wort.length() - 2);
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
		size_t p, const VTMF_OpenStack &os
	)
{
	list<int> w;
	for (size_t i = 0; i < os.size(); i++)
		w.push_back(os[i].first);
	if (p != 99)
		w.sort();
	if (p != 99)
		cout << "><><>< ";
	if (p == 0)
		cout << "VH: ";
	if (p == 1)
		cout << "MH: ";
	if (p == 2)
		cout << "HH: ";
	if (p == 10)
		cout << "offengelegte Karten: ";
	for (list<int>::const_iterator wi = w.begin(); wi != w.end(); wi++)
		cout << skat_type2string(*wi);
	if (p != 99)
		cout << endl;
}

bool skat_sehen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		VTMF_OpenStack &os,
		const VTMF_Stack &s0, const VTMF_Stack &s1, const VTMF_Stack &s2,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	if (pkr_self == 0)
	{
		for (size_t i = 0; i < s0.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(*(s0[i]), vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(*(s0[i]), vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(*(s0[i]), vtmf, *right, *right))
				return false;
			tmcg->TMCG_PushToOpenStack(os, *(s0[i]), 
				tmcg->TMCG_TypeOfCard(*(s0[i]), vtmf));
		}
		for (size_t i = 0; i < s1.size(); i++)
			tmcg->TMCG_ProofCardSecret(*(s1[i]), vtmf, *left, *left);
		for (size_t i = 0; i < s2.size(); i++)
			tmcg->TMCG_ProofCardSecret(*(s2[i]), vtmf, *right, *right);
	}
	if (pkr_self == 1)
	{
		for (size_t i = 0; i < s0.size(); i++)
			tmcg->TMCG_ProofCardSecret(*(s0[i]), vtmf, *right, *right);
		for (size_t i = 0; i < s1.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(*(s1[i]), vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(*(s1[i]), vtmf, *right, *right))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(*(s1[i]), vtmf, *left, *left))
				return false;
			tmcg->TMCG_PushToOpenStack(os, *(s1[i]),
				tmcg->TMCG_TypeOfCard(*(s1[i]), vtmf));
		}
		for (size_t i = 0; i < s2.size(); i++)
			tmcg->TMCG_ProofCardSecret(*(s2[i]), vtmf, *left, *left);
	}
	if (pkr_self == 2)
	{
		for (size_t i = 0; i < s0.size(); i++)
			tmcg->TMCG_ProofCardSecret(*(s0[i]), vtmf, *left, *left);
		for (size_t i = 0; i < s1.size(); i++)
			tmcg->TMCG_ProofCardSecret(*(s1[i]), vtmf, *right, *right);
		for (size_t i = 0; i < s2.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(*(s2[i]), vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(*(s2[i]), vtmf, *left, *left))
				return false;
			if (!tmcg->TMCG_VerifyCardSecret(*(s2[i]), vtmf, *right, *right))
				return false;
			tmcg->TMCG_PushToOpenStack(os, *(s2[i]),
				tmcg->TMCG_TypeOfCard(*(s2[i]), vtmf));
		}
	}
	return true;
}

bool skat_geben
	(
		SchindelhauerTMCG *tmcg, VTMF_Stack &d_mix,
		VTMF_Stack &s0, VTMF_Stack &s1, VTMF_Stack &s2, VTMF_Stack &sk
	)
{
	VTMF_Card c;
	for (size_t i = 0; i < 3; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s0, c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s1, c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s2, c);
	}
	for (size_t i = 0; i < 2; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(sk, c);
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s0, c);
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s1, c);
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s2, c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s0, c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s1, c);
	}
	for (size_t i = 0; i < 3; i++)
	{
		if (!tmcg->TMCG_PopFromStack(d_mix, c))
			return false;
		tmcg->TMCG_PushToStack(s2, c);
	}
	if (d_mix.size() != 0)
		return false;
	else
		return true;
}

bool skat_mischen_beweis
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const VTMF_Stack &d, const VTMF_StackSecret &ss,
		const VTMF_Stack &d0, const VTMF_Stack &d1, const VTMF_Stack &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	if (pkr_self == 0)
	{
		tmcg->TMCG_ProofStackEquality(d, d0, ss, false, vtmf, *left, *left);
		tmcg->TMCG_ProofStackEquality(d, d0, ss, false, vtmf, *right, *right);
		if (!tmcg->TMCG_VerifyStackEquality(d0, d1, false, vtmf, *left, *left))
			return false;
		if (!tmcg->TMCG_VerifyStackEquality(d1, d2, false, vtmf, *right, *right))
			return false;
	}
	if (pkr_self == 1)
	{
		if (!tmcg->TMCG_VerifyStackEquality(d, d0, false, vtmf, *right, *right))
			return false;
		tmcg->TMCG_ProofStackEquality(d0, d1, ss, false, vtmf, *right, *right);
		tmcg->TMCG_ProofStackEquality(d0, d1, ss, false, vtmf, *left, *left);
		if (!tmcg->TMCG_VerifyStackEquality(d1, d2, false, vtmf, *left, *left))
			return false;
	}
	if (pkr_self == 2)
	{
		if (!tmcg->TMCG_VerifyStackEquality(d, d0, false, vtmf, *left, *left))
			return false;
		if (!tmcg->TMCG_VerifyStackEquality(d0, d1, false, vtmf, *right, *right))
			return false;
		tmcg->TMCG_ProofStackEquality(d1, d2, ss, false, vtmf, *left, *left);
		tmcg->TMCG_ProofStackEquality(d1, d2, ss, false, vtmf, *right, *right);
	}
	return true;
}

bool skat_mischen
	(
		size_t pkr_self, SchindelhauerTMCG *tmcg, BarnettSmartVTMF_dlog *vtmf,
		const VTMF_Stack &d, const VTMF_StackSecret &ss,
		VTMF_Stack &d0, VTMF_Stack &d1, VTMF_Stack &d2,
		iosecuresocketstream *right, iosecuresocketstream *left
	)
{
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	
	try
	{
		if (pkr_self == 0)
		{
			tmcg->TMCG_MixStack(d, d0, ss, vtmf);
			*right << d0 << endl << flush;
			*left << d0 << endl << flush;
			left->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!tmcg->TMCG_ImportStack(d1, tmp))
				throw false;
			right->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!tmcg->TMCG_ImportStack(d2, tmp))
				throw false;
		}
		if (pkr_self == 1)
		{
			right->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!tmcg->TMCG_ImportStack(d0, tmp))
				throw false;
			tmcg->TMCG_MixStack(d0, d1, ss, vtmf);
			*right << d1 << endl << flush;
			*left << d1 << endl << flush;
			left->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!tmcg->TMCG_ImportStack(d2, tmp))
				throw false;
		}
		if (pkr_self == 2)
		{
			left->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!tmcg->TMCG_ImportStack(d0, tmp))
				throw false;
			right->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!tmcg->TMCG_ImportStack(d1, tmp))
				throw false;
			tmcg->TMCG_MixStack(d1, d2, ss, vtmf);
			*right << d2 << endl << flush;
			*left << d2 << endl << flush;
		}
		throw true;
	}
	catch (bool return_value)
	{
		delete [] tmp;
		return return_value;
	}
}

int skat_game
	(
		string nr, size_t rounds, size_t pkr_self, bool master, int opipe, int ipipe, 
		int ctl_o, int ctl_i, SchindelhauerTMCG *tmcg, const TMCG_PublicKeyRing &pkr,
		const TMCG_SecretKey &sec, iosecuresocketstream *right, iosecuresocketstream *left,
		const vector<string> &nicks, int hpipe, bool pctl, char *ireadbuf, int &ireaded
	)
{
	opipestream *out_pipe = new opipestream(opipe), *out_ctl = NULL;
	if (pctl)
		out_ctl = new opipestream(ctl_o);
	
	int pkt_sum[3] = { 0, 0, 0 };
	for (size_t i = 0; pctl && (i < 3); i++)
	{
		ostringstream ost;
		ost << nicks[pkr_self] << " INIT " << nicks[i] << " " << 
			pkr.key[i].name << endl;
		*out_ctl << ost.str() << flush;
	}
	
	// VTMF initalization
	BarnettSmartVTMF_dlog *vtmf;
	if (pkr_self == 2)
	{
#ifdef COMMON_DDH_GROUP
		stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP << endl;
		vtmf = new BarnettSmartVTMF_dlog(ddh_group);
#else
		vtmf = new BarnettSmartVTMF_dlog();
		vtmf->PublishGroup(*left), vtmf->PublishGroup(*right);
#endif
		
		if (!vtmf->CheckGroup())
		{
			cout << ">< Fehler in VTMF: CheckGroup() failed" << endl;
			return 2;
		}
		
		vtmf->KeyGenerationProtocol_GenerateKey();
		
		vtmf->KeyGenerationProtocol_PublishKey(*left);
		vtmf->KeyGenerationProtocol_PublishKey(*right);
		
		if (!vtmf->KeyGenerationProtocol_UpdateKey(*left))
		{
			cout << ">< Fehler in VTMF: UpdateKey() failed" << endl;
			return 2;
		}
		if (!vtmf->KeyGenerationProtocol_UpdateKey(*right))
		{
			cout << ">< Fehler in VTMF: UpdateKey() failed" << endl;
			return 2;
		}
	}
	else
	{
#ifdef COMMON_DDH_GROUP
		stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP << endl;
		vtmf = new BarnettSmartVTMF_dlog(ddh_group);
#else
		if (pkr_self == 0)
			vtmf = new BarnettSmartVTMF_dlog(*right);
		else
			vtmf = new BarnettSmartVTMF_dlog(*left);
#endif
		
		if (!vtmf->CheckGroup())
		{
			cout << ">< Fehler in VTMF: CheckGroup() failed" << endl;
			return 2;
		}
		
		vtmf->KeyGenerationProtocol_GenerateKey();
		
		if (pkr_self == 0)
		{
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*right))
			{
				cout << ">< Fehler in VTMF: UpdateKey() failed" << endl;
				return 2;
			}
			vtmf->KeyGenerationProtocol_PublishKey(*left);
			vtmf->KeyGenerationProtocol_PublishKey(*right);
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*left))
			{
				cout << ">< Fehler in VTMF: UpdateKey() failed" << endl;
				return 2;
			}
		}
		else
		{
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*left))
			{
				cout << ">< Fehler in VTMF: UpdateKey() failed" << endl;
				return 2;
			}
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*right))
			{
				cout << ">< Fehler in VTMF: UpdateKey() failed" << endl;
				return 2;
			}
			vtmf->KeyGenerationProtocol_PublishKey(*left);
			vtmf->KeyGenerationProtocol_PublishKey(*right);
		}
	}
	
	for (size_t r = 0; r < rounds; r++)
	{
		ostringstream spiel_protokoll;
		spiel_protokoll << "prt#" << nr << "#";
		for (size_t p = 0; p < 3; p++)
			spiel_protokoll << nicks[p] << "#";
		
		// play three games in each round
		for (size_t p = 0; p < 3; p++)
		{
			// Skatblatt mit 32 (verschiedenen) Karten erstellen
			VTMF_OpenStack d;
			for (int i = 0; i < 32; i++)
			{
				VTMF_Card c;
				tmcg->TMCG_CreateOpenCard(c, vtmf, i);
				tmcg->TMCG_PushToOpenStack(d, c, i);
			}
			// Mischen
			VTMF_Stack d2, d_mix[3], d_end;
			VTMF_StackSecret ss, ab;
			tmcg->TMCG_ExtractStack(d, d2);
			tmcg->TMCG_CreateStackSecret(ss, false, d2.size(), vtmf);
			cout << "><>< Mische Karten. Bitte warten ..." << flush;
			if (pctl)
			{
				ostringstream ost;
				ost << nicks[pkr_self] << " MISCHEN" << endl;
				*out_ctl << ost.str() << flush;
			}
			if (!skat_mischen(pkr_self, tmcg, vtmf, d2, ss,
				d_mix[0], d_mix[1], d_mix[2], right, left))
			{
				cout << ">< Fehler beim Mischen: falsches Stapelformat" << endl;
				return 1;
			}
			if (!skat_mischen_beweis(pkr_self, tmcg, vtmf, d2, ss,
				d_mix[0], d_mix[1], d_mix[2], right, left))
			{
				cout << ">< Fehler beim Mischen: Betrugsversuch im ZNP" << endl;
				return 2;
			}
			cout << "Fertig!" << endl;
			
#ifdef ABHEBEN
			// Abheben (cyclic shift of stack) von HH
			cout << "><>< HH hebt Karten ab. Bitte warten ..." << flush;
			if (((pkr_self + p) % 3) == 2)
			{
				size_t cyc = 0;
				do
				{
					tmcg->TMCG_ReleaseStackSecret(ab);
					cyc = tmcg->TMCG_CreateStackSecret(ab, true, vtmf, d_mix[2].size());
				}
				while ((cyc <= 3) || (cyc >= 29));
				cout << "[" << cyc << " Karten abgehoben]..." << flush;
				tmcg->TMCG_MixStack(d_mix[2], d_end, ab, vtmf);
				*left << tmcg->TMCG_ExportStack(d_end) << endl << flush;
				*right << tmcg->TMCG_ExportStack(d_end) << endl << flush;
				tmcg->TMCG_ProofStackEquality(d_mix[2], d_end, ab, true, vtmf,
					*left, *left);
				tmcg->TMCG_ProofStackEquality(d_mix[2], d_end, ab, true, vtmf,
					*right, *right);
			}
			else
			{	
				char *tmp = new char[TMCG_MAX_STACK_CHARS];
				iosecuresocketstream *hhs;
				if ((pkr_self == 0) && (p == 0))
					hhs = right;
				else if ((pkr_self == 0) && (p == 1))
					hhs = left;
				else if ((pkr_self == 1) && (p == 0))
					hhs = left;
				else if ((pkr_self == 1) && (p == 2))
					hhs = right;
				else if ((pkr_self == 2) && (p == 1))
					hhs = right;
				else if ((pkr_self == 2) && (p == 2))
					hhs = left;
				else
					hhs = NULL;
				hhs->getline(tmp, TMCG_MAX_STACK_CHARS);
				if (!tmcg->TMCG_ImportStack(d_end, tmp))
				{
					cout << ">< Fehler beim Abheben: falsches Stapelformat" << endl;
					delete [] tmp, return 1;
				}
				if (!tmcg->TMCG_VerifyStackEquality(d_mix[2], d_end, 
					true, vtmf, *hhs, *hhs))
				{
					cout << ">< Fehler beim Abheben: Betrugsversuch im ZNP" << endl;
					delete [] tmp, return 2;
				}
				delete [] tmp;
			}
			cout << "Fertig!" << endl;
#else
			tmcg->TMCG_CopyStack(d_mix[2], d_end);
#endif
			
			// compute unique game ID (aka hex_game_digest)
			ostringstream game_stream;
			game_stream << d_end << endl << flush;
			string osttmp = game_stream.str();
			assert(gcry_md_get_algo_dlen(GCRY_MD_RMD160));
			char *game_digest = new char[gcry_md_get_algo_dlen(GCRY_MD_RMD160)];
			gcry_md_hash_buffer(GCRY_MD_RMD160, game_digest,
				osttmp.c_str(), osttmp.length());
			char *hex_game_digest =
				new char[2 * gcry_md_get_algo_dlen(GCRY_MD_RMD160) + 1];
			for (size_t i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_RMD160); i++)
				snprintf(hex_game_digest + (2 * i), 3, "%02x",
					(unsigned char)game_digest[i]);
			
			// Geben
			cout << "><>< Gebe Karten. Bitte warten ..." << flush;
			if (pctl)
			{
				ostringstream ost;
				ost << nicks[pkr_self] << " GEBEN" << endl;
				*out_ctl << ost.str() << flush;
			}
			VTMF_Stack s[3], sk;
			if (!skat_geben(tmcg, d_end, s[0], s[1], s[2], sk))
			{
				cout << ">< Fehler beim Geben: zu wenig Spielkarten" << endl;
				return 3;
			}
			VTMF_OpenStack os, os_ov, os_sp, os_st, os_pkt[3], os_rc[3];
			if (!skat_sehen(pkr_self, tmcg, vtmf, os,
				s[0], s[1], s[2], right, left))
			{
				cout << ">< Fehler beim Geben: Betrugsversuch im ZNP" << endl;
				return 4;
			}
			cout << "Fertig!" << endl;
			for (size_t i = 0; pctl && (i < os.size()); i++)
			{
				ostringstream ost;
				ost << nicks[pkr_self] << " KARTE " << os[i].first << endl;
				*out_ctl << ost.str() << flush;
			}
			if (pctl)
			{
				ostringstream ost;
				ost << nicks[pkr_self] << " START " << ((pkr_self + p) % 3) << endl;
				*out_ctl << ost.str() << flush;
			}
			
			size_t reiz_status = 0, reiz_counter = 0, vh = 0, mh = 0, hh = 0;
			size_t spiel_status = 0, spiel_allein = 0, spiel_dran = 0, spiel_who[3];
			bool hand_spiel = false;
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
					cout << ">< Verbindung mit Spielpartner(n) zusammengebrochen" << endl;
					return 5;
				}
				if (reiz_status == 11)
				{
					reiz_status += 100;
					cout << "><><>< Keiner reizt das Spiel. Neu geben!" << endl;
					if (pctl)
					{
						ostringstream ost;
						ost << nicks[pkr_self] << " RAMSCH" << endl;
						*out_ctl << ost.str() << flush;
					}
					break;
				}
				if (reiz_status == 12)
				{
					reiz_status += 100;
					cout << "><><>< VH aka \"" << pkr.key[vh].name << 
						"\" bekommt das Spiel bei " << reiz_wert[reiz_counter] << endl;
					spiel_allein = vh;
					if (pctl)
						*out_ctl << nicks[spiel_allein] << " SPIELT" << endl << flush;
				}
				if (reiz_status == 13)
				{
					reiz_status += 100;
					cout << "><><>< MH aka \"" << pkr.key[mh].name << 
						"\" bekommt das Spiel bei " << reiz_wert[reiz_counter] << endl;
					spiel_allein = mh;
					if (pctl)
						*out_ctl << nicks[spiel_allein] << " SPIELT" << endl << flush;
				}
				if (reiz_status == 14)
				{
					reiz_status += 100;
					cout << "><><>< HH aka \"" << pkr.key[hh].name << 
						"\" bekommt das Spiel bei " << reiz_wert[reiz_counter] << endl;
					spiel_allein = hh;
					if (pctl)
						*out_ctl << nicks[spiel_allein] << " SPIELT" << endl << flush;
				}
				
				// select(2) -- initalize file descriptors
				FD_ZERO(&rfds);
				MFD_SET(ipipe, &rfds);
				if (pctl)
					MFD_SET(ctl_i, &rfds);
				
				// select(2)
				int ret = select(mfds + 1, &rfds, NULL, NULL, NULL);
				
				// error occured
				if (ret < 0)
					if (errno != EINTR)
						perror("SecureSkat_vtmf::skat_game (select)");
				if (!(ret > 0))
					continue;
				else
				{
					ssize_t num = 0;
					// pipe request
					if (FD_ISSET(ipipe, &rfds))
						num = read(ipipe, ireadbuf + ireaded, 65536 - ireaded);
					else if (pctl && FD_ISSET(ctl_i, &rfds))
						num = read(ctl_i, ireadbuf + ireaded, 65536 - ireaded);
					ireaded += num;
					
					if (ireaded > 0)
					{
						bool got_break = false;
						vector<int> pos_delim;
						int cnt_delim = 0, cnt_pos = 0, pos = 0;
						for (int i = 0; i < ireaded; i++)
							if (ireadbuf[i] == '\n')
								cnt_delim++, pos_delim.push_back(i);
						while (cnt_delim >= 1)
						{
							char xtmp[65536];
							bzero(xtmp, sizeof(xtmp));
							memcpy(xtmp, ireadbuf + cnt_pos, pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							string cmd = xtmp;
							// do operation
							// ---------------------------------------------------------------
				
				if (!left->good() || !right->good())
				{
					cout << ">< Verbindung mit Spielpartner(n) zusammengebrochen" << endl;
					return 5;
				}
				if (reiz_status == 11)
				{
					reiz_status += 100;
					cout << "><><>< Keiner reizt das Spiel. Neu geben!" << endl;
					if (pctl)
						*out_ctl << nicks[pkr_self] << " RAMSCH" << endl << flush;
					got_break = true;
					break;
				}
				if (reiz_status == 12)
				{
					reiz_status += 100;
					cout << "><><>< VH aka \"" << pkr.key[vh].name << 
						"\" bekommt das Spiel bei " << reiz_wert[reiz_counter] << endl;
					spiel_allein = vh;
					if (pctl)
						*out_ctl << nicks[spiel_allein] << " SPIELT" << endl << flush;
				}
				if (reiz_status == 13)
				{
					reiz_status += 100;
					cout << "><><>< MH aka \"" << pkr.key[mh].name << 
						"\" bekommt das Spiel bei " << reiz_wert[reiz_counter] << endl;
					spiel_allein = mh;
					if (pctl)
						*out_ctl << nicks[spiel_allein] << " SPIELT" << endl << flush;
				}
				if (reiz_status == 14)
				{
					reiz_status += 100;
					cout << "><><>< HH aka \"" << pkr.key[hh].name << 
						"\" bekommt das Spiel bei " << reiz_wert[reiz_counter] << endl;
					spiel_allein = hh;
					if (pctl)
						*out_ctl << nicks[spiel_allein] << " SPIELT" << endl << flush;
				}
				
				if ((cmd.find("!KICK", 0) == 0) || (cmd.find("!QUIT", 0) == 0))
					return 6;
				if ((cmd.find("PART ", 0) == 0) 
					|| (cmd.find("QUIT ", 0) == 0)
					|| (cmd.find("KICK ", 0) == 0))
				{
					string nick = cmd.substr(5, cmd.length() - 5);
					if (std::find(nicks.begin(), nicks.end(), nick) != nicks.end())
						return 7;
				}
				if (master && (cmd.find("!ANNOUNCE", 0) == 0))
				{
					*out_pipe << "PRIVMSG #openSkat :" << nr << "|3~" << (rounds - r) 
						<< "!" << endl << flush;
				}	
				if (cmd.find("IRC ", 0) == 0)
				{
					*out_pipe << "PRIVMSG #openSkat :" << 
						cmd.substr(4, cmd.length() - 4) << endl << flush;
				}
				if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
				{
					string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
					string msg = cmd.substr(cmd.find(" ", 4) + 1, 
						cmd.length() - cmd.find(" ", 4) - 1);
					if ((msg.find("PASSE", 0) == 0) || (msg.find("passe", 0) == 0))
					{
						// VH passt (am Schlu?
						if (reiz_status == 10)
						{
							if (nick == nicks[vh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 11;
								if (pctl)
									*out_ctl << nicks[vh] << " PASSE" << endl << flush;
							}
						}
						// VH passt (nach Reizen HH)
						else if (reiz_status == 4)
						{
							if (nick == nicks[vh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 14;
								if (pctl)
									*out_ctl << nicks[vh] << " PASSE" << endl << flush;
							}
						}
						// VH passt (nach Reizen MH)
						else if (reiz_status == 1)
						{
							if (nick == nicks[vh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 8;
								if (pctl)
									*out_ctl << nicks[vh] << " PASSE" << endl << flush;
							}
						}
						// VH passt (nach Passen MH)
						else if (reiz_status == 7)
						{
							if (nick == nicks[vh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 14;
								if (pctl)
									*out_ctl << nicks[vh] << " PASSE" << endl << flush;
							}
						}
						// MH passt (sofort)
						else if (reiz_status == 0)
						{
							if (nick == nicks[mh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[mh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 3;
								if (pctl)
									*out_ctl << nicks[mh] << " PASSE" << endl << flush;
							}
						}
						// MH passt (nach dem Reizen)
						else if (reiz_status == 2)
						{
							if (nick == nicks[mh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[mh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 6;
								if (pctl)
									*out_ctl << nicks[mh] << " PASSE" << endl << flush;
							}
						}
						// MH passt (nach dem Passen VH)
						else if (reiz_status == 9)
						{
							if (nick == nicks[mh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[mh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 14;
								if (pctl)
									*out_ctl << nicks[mh] << " PASSE" << endl << flush;
							}
						}
						// HH passt (sofort)
						else if (reiz_status == 3)
						{
							if (nick == nicks[hh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[hh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 10;
								if (pctl)
									*out_ctl << nicks[hh] << " PASSE" << endl << flush;
							}
						}
						// HH passt (nach dem Reizen)
						else if ((reiz_status == 5) || (reiz_status == 6))
						{
							if (nick == nicks[hh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[hh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 12;
								if (pctl)
									*out_ctl << nicks[hh] << " PASSE" << endl << flush;
							}
						}
						// HH passt (nach dem Passen VH)
						else if (reiz_status == 8)
						{
							if (nick == nicks[hh])
							{
								cout << "><><>< Skatfreund \"" << pkr.key[hh].name << 
									"\" passt bei " << reiz_wert[reiz_counter] << endl;
								reiz_status = 13;
								if (pctl)
									*out_ctl << nicks[hh] << " PASSE" << endl << flush;
							}
						}
						else
							cout << ">< Reizvorgang inkorrekt (Passe-Aktion)" << endl;
					}
					else if ((msg.find("REIZE", 0) == 0) || (msg.find("reize", 0) == 0))
					{
						size_t rei = msg.find(" ", 6);
						string srw = msg.substr(6, rei - 6);
						size_t irw = atoi(srw.c_str());
						
						// VH sagt ja (nach Passen MH, Reizen HH)
						if (reiz_status == 4)
						{
							if (nick == nicks[vh])
							{
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
								reiz_status = 5;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[vh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// VH sagt ja (nach Reizen MH)
						else if (reiz_status == 1)
						{
							if (nick == nicks[vh])
							{
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
								reiz_status = 2;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[vh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// VH sagt ja (nach Passen MH, Reizen HH)
						else if (reiz_status == 7)
						{
							if (nick == nicks[vh])
							{
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
								reiz_status = 6;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[vh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// VH reizt (nach sofort Passen MH, sofort Passen HH)
						else if (reiz_status == 10)
						{
							if (nick == nicks[vh])
							{
								reiz_counter++;
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[vh].name << 
									"\" reizt " << reiz_wert[reiz_counter] << endl;
								reiz_status = 12;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[vh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// MH reizt (zu Beginn)
						else if (reiz_status == 0)
						{
							if (nick == nicks[mh])
							{
								reiz_counter++;
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[mh].name << 
									"\" reizt " << reiz_wert[reiz_counter] << endl;
								reiz_status = 1;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[mh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// MH reizt (weiter)
						else if (reiz_status == 2)
						{
							if (nick == nicks[mh])
							{
								reiz_counter++;
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[mh].name << 
									"\" reizt " << reiz_wert[reiz_counter] << endl;
								reiz_status = 1;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[mh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// MH sagt ja (nach Passen VH)
						else if (reiz_status == 9)
						{
							if (nick == nicks[mh])
							{
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[mh].name << 
									"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
								reiz_status = 8;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[mh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// HH reizt (nach Passen MH)
						else if (reiz_status == 6)
						{
							if (nick == nicks[hh])
							{
								reiz_counter++;
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[hh].name << 
									"\" reizt " << reiz_wert[reiz_counter] << endl;
								reiz_status = 7;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[hh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// HH erhoeht (nach Passen VH)
						else if (reiz_status == 8)
						{
							if (nick == nicks[hh])
							{
								reiz_counter++;
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[hh].name << 
									"\" reizt " << reiz_wert[reiz_counter] << endl;
								reiz_status = 9;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[hh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						// HH reizt (nach sofort Passen MH, oder Reizen VH)
						else if ((reiz_status == 3) || (reiz_status == 5))
						{
							if (nick == nicks[hh])
							{
								reiz_counter++;
								if (irw != reiz_wert[reiz_counter])
									return 22;
								cout << "><><>< Skatfreund \"" << pkr.key[hh].name << 
									"\" reizt " << reiz_wert[reiz_counter] << endl;
								reiz_status = 4;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[hh] << " REIZE " << 
										reiz_wert[reiz_counter] << endl;
									*out_ctl << ost.str() << flush;
								}
							}
						}
						else
							cout << ">< Reizvorgang inkorrekt (Reize-Aktion)" << endl;
					}
					else if ((msg.find("HAND", 0) == 0) || (msg.find("hand", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if ((nick == nicks[spiel_allein]) && (pkr_self != spiel_allein))
							{
								hand_spiel = true, reiz_status += 100;
								cout << "><><>< Skatfreund \"" <<
									pkr.key[spiel_allein].name << 
									"\" spielt aus der Hand" << endl;
								if (pctl)
									*out_ctl << nicks[spiel_allein] << " HAND" << endl << flush;
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
								cout << "><><>< Skatfreund \"" << 
									pkr.key[spiel_allein].name << 
									"\" nimmt den Skat auf" << endl;
								assert (sk.size() == 2);
								tmcg->TMCG_PushToStack(s[spiel_allein], *(sk[0]));
								tmcg->TMCG_PushToStack(s[spiel_allein], *(sk[1]));
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
									*out_ctl << nicks[spiel_allein] << " SKAT" << endl << flush;
							}
						}
					}
					else if ((msg.find("DRUECKE", 0) == 0) || 
						(msg.find("druecke", 0) == 0))
					{
						if ((reiz_status > 200) && (reiz_status < 300))
						{
							if (!hand_spiel)
							{
								if ((nick == nicks[spiel_allein]) && 
									(pkr_self != spiel_allein))
								{
									char *tmp1 = new char[TMCG_MAX_CARD_CHARS];
									char *tmp2 = new char[TMCG_MAX_CARD_CHARS];
									VTMF_Card c1, c2;
									reiz_status += 100;
									cout << "><><>< Skatfreund \"" << 
										pkr.key[spiel_allein].name << 
										"\" drueckt den Skat" << endl;
									if (pctl)
										*out_ctl << nicks[spiel_allein] << " DRUECKE" <<
											endl << flush;
									if (((pkr_self == 0) && (spiel_allein == 1)) ||
										((pkr_self == 1) && (spiel_allein == 2)) ||
										((pkr_self == 2) && (spiel_allein == 0)))
									{
										left->getline(tmp1, TMCG_MAX_CARD_CHARS);
										left->getline(tmp2, TMCG_MAX_CARD_CHARS);
									}
									else if (((pkr_self == 0) && (spiel_allein == 2)) ||
										((pkr_self == 1) && (spiel_allein == 0)) ||
										((pkr_self == 2) && (spiel_allein == 1)))
									{
										right->getline(tmp1, TMCG_MAX_CARD_CHARS);
										right->getline(tmp2, TMCG_MAX_CARD_CHARS);
									}
									else
									{
										delete [] tmp1, delete [] tmp2;
										return 9;
									}
									
									// check and store pushed cards
									if (!tmcg->TMCG_ImportCard(c1, tmp1))
									{
										delete [] tmp1, delete [] tmp2;
										return 9;
									}
									if (!tmcg->TMCG_ImportCard(c2, tmp2))
									{
										delete [] tmp1, delete [] tmp2;
										return 9;
									}
									if ((!tmcg->TMCG_IsInStack(s[spiel_allein], c1)) ||
										(!tmcg->TMCG_IsInStack(s[spiel_allein], c2)))
									{
										delete [] tmp1, delete [] tmp2;
										return 10;
									}
									tmcg->TMCG_ReleaseStack(sk);
									tmcg->TMCG_RemoveFirstFromStack(s[spiel_allein], c1);
									tmcg->TMCG_PushToStack(sk, c1);
									tmcg->TMCG_RemoveFirstFromStack(s[spiel_allein], c2);
									tmcg->TMCG_PushToStack(sk, c2);
									delete [] tmp1, delete [] tmp2;
								}
							}
						}
					}
					else if ((msg.find("SAGEAN", 0) == 0) || 
						(msg.find("sagean", 0) == 0))
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
											cout << ">< Fehler beim Aufdecken: " <<
												"Betrugsversuch im ZNP" << endl;
											return 11;
										}
										VTMF_Card c;
										tmcg->TMCG_CreateOpenCard(c, vtmf, 0);
										tmcg->TMCG_PushToOpenStack(os_ov, c, type);
										if (pctl)
										{
											ostringstream ost;
											ost << nicks[spiel_allein] << " OUVERT " << type << endl;
											*out_ctl << ost.str() << flush;
										}
									}
									skat_blatt(10, os_ov);
								}
								cout << "><><>< Skatfreund \"" << 
									pkr.key[spiel_allein].name << "\" spielt: " <<
									skat_spiel2string(spiel_status) << endl;
								if (pctl)
								{
									ostringstream ost;
									ost << nicks[spiel_allein] << " SAGEAN " << spiel_status <<
										endl;
									*out_ctl << ost.str() << flush;
								}
								spiel_dran = 0;
								spiel_who[0] = vh, spiel_who[1] = mh, spiel_who[2] = hh;
							}
						}
					}	
					else if ((msg.find("LEGE", 0) == 0) || 
						(msg.find("lege", 0) == 0))
					{
						if (nick == nicks[spiel_who[spiel_dran]])
						{
							int type = skat_vkarte(pkr_self, spiel_who[spiel_dran], tmcg,
								vtmf, s[spiel_who[spiel_dran]], right, left, true);
							if (type < 0)
							{
								cout << ">< Fehler beim Aufdecken: " <<
									"Betrugsversuch im ZNP" << endl;
								return 12;
							}
							cout << "><><>< Skatfreund \"" << 
								pkr.key[spiel_who[spiel_dran]].name << 
								"\" legt die Karte: " << skat_type2string(type) << endl;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[spiel_who[spiel_dran]] << " LEGE " << type << endl;
								*out_ctl << ost.str() << flush;
							}	
							VTMF_Card c;
							tmcg->TMCG_CreateOpenCard(c, vtmf, type);
							tmcg->TMCG_PushToOpenStack(os_sp, c, type);
							// Ouvert Spiele -- Karte vom Sichtstapel entfernen
							if ((spiel_status - (hand_spiel ? 1000 : 0)) > 300)
							{
								VTMF_Stack st;
								tmcg->TMCG_MoveFromOpenStackToStack(os_ov, st, type);
								tmcg->TMCG_ReleaseStack(st);
							}
							if (os_sp.size() == 3)
							{
								int bk = skat_bstich(os_sp, spiel_status);
								assert (bk != -1);
								cout << "><><>< Skatfreund \"" << 
									pkr.key[spiel_who[bk]].name << "\" bekommt den Stich: ";
								for (size_t i = 0; i < os_sp.size(); i++)
									cout << skat_type2string(os_sp[i].first);
								cout << endl;
								if (os.size() > 0)
									skat_blatt((pkr_self + p) % 3, os);
								if (pctl)
									*out_ctl << nicks[spiel_who[bk]] << " BSTICH" << 
										endl << flush;
								// Stichstapel erste Karte (Regelkontrolle)
								tmcg->TMCG_PushToOpenStack(os_st, 
									*(os_sp[0].second), os_sp[0].first);
								// Stichstapel jedes Spielers
								tmcg->TMCG_PushOpenStackToOpenStack(
									os_pkt[spiel_who[bk]], os_sp);
								// Kartenstapel jedes Spielers (Regelkontrolle)
								for (size_t i = 0; i < os_sp.size(); i++)
									tmcg->TMCG_PushToOpenStack(os_rc[spiel_who[i]], 
									*(os_sp[i].second), os_sp[i].first);
								tmcg->TMCG_ReleaseOpenStack(os_sp);
								spiel_who[0] = spiel_who[bk];
								spiel_who[1] = (spiel_who[0] + 1) % 3;
								spiel_who[2] = (spiel_who[0] + 2) % 3;
								spiel_dran = 0;
							}
							else
								spiel_dran += 1;
						}
					}
				}
				if (cmd.find("CMD ", 0) == 0)
				{
					string msg = cmd.substr(4, cmd.length() - 4);
					
					// trim spaces at end of string
					while (msg.find(" ", msg.length() - 1) == (msg.length() - 1))
						msg = msg.substr(0, (msg.length() - 1));
					
					if ((msg.find("BLATT", 0) == 0) || (msg.find("blatt", 0) == 0))
					{
						skat_blatt((pkr_self + p) % 3, os);
						if (os_ov.size() > 0)
							skat_blatt(10, os_ov);
						if (spiel_status > 0)
						{
							cout << "><><>< Skatfreund \"" << pkr.key[spiel_allein].name <<
								"\" (";
							if ((reiz_status - 412) == 0)
								cout << "VH";
							if ((reiz_status - 412) == 1)
								cout << "MH";
							if ((reiz_status - 412) == 2)
								cout << "HH";
							cout << ") spielt \"" << skat_spiel2string(spiel_status) <<
								"\"" << endl;
							cout << "><><>< gelegt wurde: ";
							for (size_t i = 0; i < os_sp.size(); i++)
							{
								VTMF_OpenStack os_sp2;
								tmcg->TMCG_PushToOpenStack(os_sp2, 
									*(os_sp[i].second), os_sp[i].first);
								skat_blatt(99, os_sp2);
								cout << "(" << pkr.key[spiel_who[i]].name << ") ";
							}
							if (os_sp.size() < 3)
							{
								cout << " [" << pkr.key[spiel_who[spiel_dran]].name << 
									" ist dran]" << endl;
							}
						}
					}
					else if ((msg.find("PASSE", 0) == 0) || (msg.find("passe", 0) == 0))
					{
						// VH beim Passen
						if ((reiz_status == 4) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 14;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 10) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 11;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 1) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 8;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 7) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 14;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						// MH beim Passen
						else if ((reiz_status == 0) && (((pkr_self + p) % 3) == 1))
						{
							reiz_status = 3;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 2) && (((pkr_self + p) % 3) == 1))
						{
							reiz_status = 6;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 9) && (((pkr_self + p) % 3) == 1))
						{
							reiz_status = 14;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						// HH beim Passen
						else if ((reiz_status == 3) && (((pkr_self + p) % 3) == 2))
						{
							reiz_status = 10;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 5) && (((pkr_self + p) % 3) == 2))
						{
							reiz_status = 12;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 6) && (((pkr_self + p) % 3) == 2))
						{
							reiz_status = 12;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else if ((reiz_status == 8) && (((pkr_self + p) % 3) == 2))
						{
							reiz_status = 13;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
								"\" passt bei " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :PASSE " << 
								hex_game_digest << endl << flush;
							if (pctl)
								*out_ctl << nicks[pkr_self] << " PASSE" << endl << flush;
						}
						else
							cout << ">< Passen z.Z. nicht erlaubt" << endl;
					}
					else if ((msg.find("REIZE", 0) == 0) || (msg.find("reize", 0) == 0))
					{
						// VH beim Reizen
						if ((reiz_status == 1) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 2;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 4) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 5;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 7) && (((pkr_self + p) % 3) == 0))
						{
							reiz_status = 6;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 10) && (((pkr_self + p) % 3) == 0))
						{
							reiz_counter++;
							reiz_status = 12;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						// MH beim Reizen
						else if ((reiz_status == 0) && (((pkr_self + p) % 3) == 1))
						{
							reiz_counter++;
							reiz_status = 1;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 2) && (((pkr_self + p) % 3) == 1))
						{
							reiz_counter++;
							reiz_status = 1;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 9) && (((pkr_self + p) % 3) == 1))
						{
							reiz_status = 8;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" sagt ja zu " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						// HH beim Reizen
						else if ((reiz_status == 3) && (((pkr_self + p) % 3) == 2))
						{
							reiz_counter++;
							reiz_status = 4;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 5) && (((pkr_self + p) % 3) == 2))
						{
							reiz_counter++;
							reiz_status = 4;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 6) && (((pkr_self + p) % 3) == 2))
						{
							reiz_counter++;
							reiz_status = 7;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else if ((reiz_status == 8) && (((pkr_self + p) % 3) == 2))
						{
							reiz_counter++;
							reiz_status = 9;
							cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name <<
								"\" reizt " << reiz_wert[reiz_counter] << endl;
							*out_pipe << "PRIVMSG #openSkat_" << nr << " :REIZE " << 
								reiz_wert[reiz_counter] << " " << hex_game_digest << 
								endl << flush;
							if (pctl)
							{
								ostringstream ost;
								ost << nicks[pkr_self] << " REIZE " << 
									reiz_wert[reiz_counter] << endl;
								*out_ctl << ost.str() << flush;
							}
						}
						else
							cout << ">< Reizen z.Z. nicht erlaubt" << endl;
					}
					else if ((msg.find("HAND", 0) == 0) || (msg.find("hand", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if ((reiz_status - 112) == ((pkr_self + p) % 3))
							{
								cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
									"\" spielt aus der Hand" << endl;
								*out_pipe << "PRIVMSG #openSkat_" << nr << " :HAND " << 
									hex_game_digest << endl << flush;
								hand_spiel = true, reiz_status += 100;
								if (pctl)
									*out_ctl << nicks[pkr_self] << " HAND" << endl << flush;
							}
							else
								cout << ">< es spielt eine andere Partei" << endl;
						}
						else
							cout << ">< Skataufnahme z.Z. nicht erlaubt" << endl;
					}
					else if ((msg.find("SKAT", 0) == 0) || (msg.find("skat", 0) == 0))
					{
						if ((reiz_status > 100) && (reiz_status < 200))
						{
							if (pkr_self == spiel_allein)
							{
								cout << "><><>< Skatfreund \"" << pkr.key[pkr_self].name << 
									"\" nimmt den Skat auf" << endl;
								*out_pipe << "PRIVMSG #openSkat_" << nr << " :SKAT " << 
									hex_game_digest << endl << flush;
								hand_spiel = false, reiz_status += 100;
								if (!skat_ssehen(pkr_self, tmcg, vtmf, os, sk,
									right, left))
								{
									cout << ">< Fehler beim Aufdecken: " <<
										"Betrugsversuch im ZNP" << endl;
									return 8;
								}
								for (size_t i = 10; (pctl && (i < os.size())); i++)
								{
									ostringstream ost;
									ost << nicks[pkr_self] << " KARTE " << os[i].first << endl;
									*out_ctl << ost.str() << flush;
								}
								if (pctl)
									*out_ctl << nicks[pkr_self] << " SKAT" << endl << flush;
								skat_blatt((pkr_self + p) % 3, os);
							}
							else
								cout << ">< es spielt eine andere Partei" << endl;
						}
						else
							cout << ">< Skataufnahme z.Z. nicht erlaubt" << endl;
					}
					else if ((msg.find("DRUECKE", 0) == 0) || 
						(msg.find("druecke", 0) == 0))
					{
						if ((reiz_status > 200) && (reiz_status < 300))
						{
							if (pkr_self == spiel_allein)
							{
								if (!hand_spiel)
								{
									string par = ""; 
									size_t ei = par.npos;
									if ((msg.find(" ", 0) == 7) && (msg.length() > 8))
									{
										par = msg.substr(8, msg.length() - 8);
										ei = par.find(" ", 0);
									}
									if ((ei != par.npos) && (par.length() > ei))
									{
										string cc1 = par.substr(0, ei);
										string cc2 = par.substr(ei + 1, par.length() - ei - 1);
										
										int tt1 = skat_wort2type(cc1), tt2 = skat_wort2type(cc2);
										if ((tt1 != -1) && (tt2 != -1))
										{
											if (tmcg->TMCG_IsInOpenStack(os, tt1) &&
												tmcg->TMCG_IsInOpenStack(os, tt2))
											{
												tmcg->TMCG_ReleaseStack(sk);
												tmcg->TMCG_MoveFromOpenStackToStack(os, sk, tt1);
												tmcg->TMCG_MoveFromOpenStackToStack(os, sk, tt2);
												assert(sk.size() == 2);
												tmcg->TMCG_ReleaseStack(s[pkr_self]);
												tmcg->TMCG_ExtractStack(os, s[pkr_self]);
												cout << "><><>< Skatfreund \"" << 
													pkr.key[pkr_self].name << 
													"\" drueckt: " << skat_type2string(tt1) <<
													skat_type2string(tt2) << endl;
												*out_pipe << "PRIVMSG #openSkat_" << nr << 
													" :DRUECKE " << hex_game_digest << endl << flush;
												reiz_status += 100;
												*right << *(sk[0]) << endl << flush;
												*right << *(sk[1]) << endl << flush;
												*left << *(sk[0]) << endl << flush;
												*left << *(sk[1]) << endl << flush;
												if (pctl)
													*out_ctl << nicks[pkr_self] << " DRUECKE" << 
														endl << flush;
												skat_blatt((pkr_self + p) % 3, os);
											}
											else
												cout << ">< Karten \"" << cc1 << "\" oder \"" << 
													cc2 << "\" nicht im Blatt" << endl;
										}
										else
											cout << ">< falsche Kartenbezeichnung: \"" <<
												cc1 << "\" oder \"" << cc2 << "\"" << endl;
									}
									else
										cout << ">< unzureichende Parameteranzahl" << endl;
								}
								else
									cout << ">< es wird aus der Hand gespielt" << endl;
							}
							else
								cout << ">< es spielt eine andere Partei" << endl;
						}
						else
							cout << ">< Skatablage z.Z. nicht erlaubt" << endl;
					}
					else if ((msg.find("SAGEAN", 0) == 0) || 
						(msg.find("sagean", 0) == 0))
					{
						if ((!hand_spiel && (reiz_status > 300) && (reiz_status < 400))
							|| (hand_spiel && (reiz_status > 200) && (reiz_status < 300)))
						{
							if (pkr_self == spiel_allein)
							{
								string par = ""; 
								size_t ei = msg.find(" ", 0), zi = par.npos;
								if ((ei == 6) && (msg.length() > 7))
								{
									par = msg.substr(7, msg.length() - 7);
									zi = par.find(" ", 0);
								}
								if ((ei != par.npos) && (par != ""))
								{
									string spiel = "", zusatz = "";
									if (zi != par.npos)
									{
										spiel = par.substr(0, zi);
										zusatz = par.substr(zi + 1, par.length() - zi - 1);
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
											*out_pipe << "PRIVMSG #openSkat_" << nr <<
												" :SAGEAN " << skat_spiel2string(spiel_status) <<
												" " << hex_game_digest << endl << flush;
											ostringstream ost;
											ost << spiel_status << endl;
											*left << ost.str() << flush;
											*right << ost.str() << flush;
											// Ouvert Spiele -- Karten oeffnen
											if ((spiel_status - (hand_spiel ? 1000 : 0)) > 300)
											{
												for (size_t i = 0; i < os.size(); i++)
												{
													*out_pipe << "PRIVMSG #openSkat_" << nr <<
														" :OUVERT " << skat_type2string(os[i].first) <<
														" " << hex_game_digest << endl << flush;
													skat_okarte(tmcg, vtmf, *(os[i].second), right, left);
												}
											}
											cout << "><><>< Skatfreund \"" << 
												pkr.key[pkr_self].name << "\" spielt: " <<
												skat_spiel2string(spiel_status) << endl;
											if (pctl)
												*out_ctl << nicks[pkr_self] << " SAGEAN " <<
													ost.str() << endl << flush;
											spiel_dran = 0;
											spiel_who[0] = vh, spiel_who[1] = mh, spiel_who[2] = hh;
										}
										else
											cout << ">< ungueltige Spielansage: " << sz << endl;
									}
									else
										cout << ">< falsche Spiel- oder Zusatzbezeichnung: \"" <<
												spiel << "\" oder \"" << zusatz << "\"" << endl;
								}
								else
									cout << ">< unzureichende Parameteranzahl" << endl;
							}
							else
								cout << ">< es spielt eine andere Partei" << endl;
						}
						else
							cout << ">< Spielansage z.Z. nicht erlaubt" << endl;
					}
					else if ((msg.find("LEGE", 0) == 0) || 
						(msg.find("lege", 0) == 0))
					{
						if ((spiel_status > 0) && (pkr_self == spiel_who[spiel_dran]))
						{
							string par = 
								(msg.length() > 5) ? msg.substr(5, msg.length() - 5) : "";
							if (par.length() > 0)
							{
								int tt = skat_wort2type(par);
								if (tt != -1)
								{
									if (tmcg->TMCG_IsInOpenStack(os, tt))
									{
										// Regelkontrolle, falls schon Karten gespielt sind
										if ((os_sp.size() > 0) &&
											(!skat_rulectl(os_sp[0].first, tt, spiel_status, os)))
										{
											cout << ">< Ausspiel von Karte \"" << par << 
												"\" ist nicht regelkonform" << endl;
											continue;
										}
										cout << "><><>< Skatfreund \"" << 
											pkr.key[pkr_self].name << "\" legt die Karte: " <<
											skat_type2string(tt) << endl;
										*out_pipe << "PRIVMSG #openSkat_" << nr << " :LEGE " <<
											skat_type2string(tt) << " " << hex_game_digest << 
											endl << flush;
										if (pctl)
										{
											ostringstream ost;
											ost << nicks[pkr_self] << " LEGE " << tt << endl;
											*out_ctl << ost.str() << flush;
										}
										VTMF_Stack st;
										VTMF_Card c;
										tmcg->TMCG_MoveFromOpenStackToStack(os, st, tt);
										skat_okarte(tmcg, vtmf, *(st[0]), right, left);
										tmcg->TMCG_RemoveFirstFromStack(s[pkr_self], *(st[0]));
										tmcg->TMCG_CreateOpenCard(c, vtmf, tt);
										tmcg->TMCG_PushToOpenStack(os_sp, c, tt);
										tmcg->TMCG_ReleaseStack(st);
										if (os_sp.size() == 3)
										{
											int bk = skat_bstich(os_sp, spiel_status);
											assert (bk != -1);
											cout << "><><>< Skatfreund \"" << 
												pkr.key[spiel_who[bk]].name << 
												"\" bekommt den Stich: ";
											for (size_t i = 0; i < os_sp.size(); i++)
												cout << skat_type2string(os_sp[i].first);
											cout << endl;
											if (os.size() > 0)
												skat_blatt((pkr_self + p) % 3, os);
											if (pctl)
												*out_ctl << nicks[spiel_who[bk]] << " BSTICH" <<
													endl << flush;
											// Stichstapel erste Karte (Regelkontrolle)
											tmcg->TMCG_PushToOpenStack(os_st, 
												*(os_sp[0].second), os_sp[0].first);
											// Stichstapel jedes Spielers
											tmcg->TMCG_PushOpenStackToOpenStack(
												os_pkt[spiel_who[bk]], os_sp);
											// Kartenstapel jedes Spielers (Regelkontrolle)
											for (size_t i = 0; i < os_sp.size(); i++)
												tmcg->TMCG_PushToOpenStack(os_rc[spiel_who[i]], 
													*(os_sp[i].second), os_sp[i].first);
											tmcg->TMCG_ReleaseOpenStack(os_sp);
											spiel_who[0] = spiel_who[bk];
											spiel_who[1] = (spiel_who[0] + 1) % 3;
											spiel_who[2] = (spiel_who[0] + 2) % 3;
											spiel_dran = 0;
										}
										else
											spiel_dran += 1;
									}
									else
										cout << ">< Karte \"" << par << "\" nicht im Blatt" << 
											endl;
								}
								else
									cout << ">< falsche Kartenbezeichnung: \"" <<
										par << "\"" << endl;
							}
							else
								cout << ">< unzureichende Parameteranzahl" << endl;
						}
						else
							cout << ">< Ausspielen z.Z. nicht erlaubt" << endl;
					}
					else
					{
						cout << ">< unbekanntes Tischkommando \"/" << nr << 
							" " << msg << "\"" << endl;
					}
				}
							// ----------------------------------------------------------------
						}
						char ytmp[65536];
						bzero(ytmp, sizeof(ytmp));
						ireaded -= cnt_pos;
						memcpy(ytmp, ireadbuf + cnt_pos, ireaded);
						memcpy(ireadbuf, ytmp, ireaded);
						if (got_break)
							break;
					}
					if (num == 0)
					{
						cout << ">< Verbindung zu Programmteilen zusammengebrochen" << endl;
						return 5;
					}
				}
			}
			
			if (pctl)
				*out_ctl << nicks[pkr_self] << " STOP" << endl << flush;
			
			if (spiel_status > 0)
			{
				bool spiel_gewonnen = false;
				
				// Augen der Gegenpartei zaehlen
				size_t pkt_allein = 0, pkt_gegner = 0; 
				for (size_t i = 0; i < 3; i++)
					for (size_t j = 0; (i != spiel_allein) && (j < os_pkt[i].size()); j++)
						pkt_gegner += pkt_wert[os_pkt[i][j].first];
				pkt_allein = 120 - pkt_gegner;
				cout << "><><>< Augen Alleinspieler (" << 
					pkr.key[spiel_allein].name << "): " << pkt_allein <<
					", Augen Gegenpartei: " << pkt_gegner << endl;
				
				if (pkt_allein > 60)
					spiel_gewonnen = true;
				else
					spiel_gewonnen = false;
				
				// nachtr?liche Regelkontrolle
				bool rules_ok[3];
				assert (os_st.size() == 10);
				for (size_t i = 0; i < 3; i++)
				{
					VTMF_OpenStack gps;
					assert (os_rc[i].size() == 10);
					tmcg->TMCG_PushOpenStackToOpenStack(gps, os_rc[i]);
					rules_ok[i] = true;
					for (size_t j = 0; j < os_st.size(); j++)
					{
						if (!skat_rulectl(os_st[j].first, os_rc[i][j].first, 
							spiel_status, gps))
								rules_ok[i] = false;
						VTMF_Stack tst;
						tmcg->TMCG_MoveFromOpenStackToStack(gps, tst, os_rc[i][j].first);
						tmcg->TMCG_ReleaseStack(tst);
					}
				}
				
				// Stapel des Alleinspielers um Skat vervollst?digen
				for (size_t t = 0; t < 32; t++)
				{
					if (!tmcg->TMCG_IsInOpenStack(os_rc[0], t)
						&& !tmcg->TMCG_IsInOpenStack(os_rc[1], t)
						&& !tmcg->TMCG_IsInOpenStack(os_rc[2], t))
					{
						VTMF_Card c;
						tmcg->TMCG_CreateOpenCard(c, vtmf, t);
						tmcg->TMCG_PushToOpenStack(os_rc[spiel_allein], c, t);
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
						cout << "><>< Gegenpartei ist Schwarz!" << endl;
						gstufen++;
					}
					// Schneider gespielt (7)
					if (pkt_gegner < 31)
					{
						cout << "><>< Gegenpartei ist Schneider!" << endl;
						gstufen++;
					}
					// (selbst) Schwarz gespielt (6)
					if (os_pkt[spiel_allein].size() == 0)
					{
						cout << "><>< Alleinspieler ist Schwarz. Verloren!" << endl;
						gstufen++, spiel_gewonnen = false;
					}
					// (selbst) Schneider gespielt (7)
					if (pkt_allein < 31)
					{
						cout << "><>< Alleinspieler ist Schneider. Verloren!" << endl;
						gstufen++, spiel_gewonnen = false;
					}
					
					spiel_wert = (spitzen + gstufen) * skat_spiel2gwert(spiel_status);
				}
				if (reiz_wert[reiz_counter] > (size_t)spiel_wert)
				{
					cout << "><>< Alleinspieler hat sich uebereizt. Verloren!" << endl;
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
						cout << "><>< Skatfreund \"" << pkr.key[i].name << "\" hat " <<
							"nicht regelkonform gespielt." << endl;
						return 20;
					}
				}
				cout << "><><>< Spielwert: " << spiel_wert << ", Reizwert: " <<
					reiz_wert[reiz_counter] << ", Gewonnen: " <<
					(spiel_gewonnen ? "JA" : "NEIN") << endl;
				if (pctl)
				{
					string ctlt = "";
					if (spiel_gewonnen)
						*out_ctl << nicks[spiel_allein] << " GEWONNEN" << endl << flush;
					else
						*out_ctl << nicks[spiel_allein] << " VERLOREN" << endl << flush;
				}
				pkt_sum[spiel_allein] += spiel_wert;
				
				ostringstream einzel_protokoll;
				einzel_protokoll << nicks[spiel_allein] << "~" << spiel_wert <<
					"~" << spiel_status << "~" << pkt_allein << "~" <<
					reiz_wert[reiz_counter] << "~" << hex_game_digest << "~";
				spiel_protokoll << einzel_protokoll.str() << "#";
				if (pctl)
					*out_ctl << nicks[spiel_allein] << " PROTO " << 
						einzel_protokoll.str() << endl << flush;
			}
			else
			{	
				if (pctl)
					*out_ctl << nicks[pkr_self] << " NONE" << endl << flush;
				spiel_protokoll << "NONE~0~0~0~0~" << hex_game_digest << "~#";
			}
			
			delete [] game_digest, delete [] hex_game_digest;
			tmcg->TMCG_ReleaseOpenStack(os);
			tmcg->TMCG_ReleaseOpenStack(os_ov);
			tmcg->TMCG_ReleaseOpenStack(os_sp);
			tmcg->TMCG_ReleaseOpenStack(os_st);
			for (size_t i = 0; i < 3; i++)
				tmcg->TMCG_ReleaseOpenStack(os_pkt[i]);
			for (size_t i = 0; i < 3; i++)
				tmcg->TMCG_ReleaseOpenStack(os_rc[i]);
			for (size_t i = 0; i < 3; i++)
				tmcg->TMCG_ReleaseStack(s[i]);
			tmcg->TMCG_ReleaseStack(sk);
			tmcg->TMCG_ReleaseStack(d_end);
			tmcg->TMCG_ReleaseStackSecret(ab);
			tmcg->TMCG_ReleaseStackSecret(ss);
			for (size_t i = 0; i < 3; i++)
				tmcg->TMCG_ReleaseStack(d_mix[i]);
			tmcg->TMCG_ReleaseStack(d2);
			tmcg->TMCG_ReleaseOpenStack(d);
			
			cout << "><><>< Spielstand <><><> ";
			for (size_t i = 0; i < 3; i++)
				cout << pkr.key[i].name << ": " << pkt_sum[i] << " ";
			cout << endl;
		}
		
		TMCG_Signature sig;
		TMCG_DataString sig_data = spiel_protokoll.str();
		ostringstream sig_protokoll;
		char stmp[10000];
		if (pkr_self == 0)
		{
			sig = tmcg->TMCG_SignData(sec, sig_data);
			sig_protokoll << sig << "#";
			*left << sig << endl << flush;
			*right << sig << endl << flush;
			left->getline(stmp, sizeof(stmp));
			sig = stmp;
			if (!tmcg->TMCG_VerifyData(pkr.key[1], sig_data, sig))
			{
				cout << "><>< Unterschrift von Skatfreund \"" << 
					pkr.key[1].name << "\" ungueltig" << endl;
				return 30;
			}
			sig_protokoll << sig << "#";
			right->getline(stmp, sizeof(stmp));
			sig = stmp;
			if (!tmcg->TMCG_VerifyData(pkr.key[2], sig_data, sig))
			{
				cout << "><>< Unterschrift von Skatfreund \"" << 
					pkr.key[2].name << "\" ungueltig" << endl;
				return 30;
			}
			sig_protokoll << sig << "#";
		}
		else if (pkr_self == 1)
		{
			right->getline(stmp, sizeof(stmp));
			sig = stmp;
			if (!tmcg->TMCG_VerifyData(pkr.key[0], sig_data, sig))
			{
				cout << "><>< Unterschrift von Skatfreund \"" << 
					pkr.key[0].name << "\" ungueltig" << endl;
				return 30;
			}
			sig_protokoll << sig << "#";
			sig = tmcg->TMCG_SignData(sec, sig_data);
			sig_protokoll << sig << "#";
			*left << sig << endl << flush;
			*right << sig << endl << flush;
			left->getline(stmp, sizeof(stmp));
			sig = stmp;
			if (!tmcg->TMCG_VerifyData(pkr.key[2], sig_data, sig))
			{
				cout << "><>< Unterschrift von Skatfreund \"" << 
					pkr.key[2].name << "\" ungueltig" << endl;
				return 30;
			}
			sig_protokoll << sig << "#";
		}
		else if (pkr_self == 2)
		{
			left->getline(stmp, sizeof(stmp));
			sig = stmp;
			if (!tmcg->TMCG_VerifyData(pkr.key[0], sig_data, sig))
			{
				cout << "><>< Unterschrift von Skatfreund \"" << 
					pkr.key[0].name << "\" ungueltig" << endl;
				return 30;
			}
			sig_protokoll << sig << "#";
			right->getline(stmp, sizeof(stmp));
			sig = stmp;
			if (!tmcg->TMCG_VerifyData(pkr.key[1], sig_data, sig))
			{
				cout << "><>< Unterschrift von Skatfreund \"" << 
					pkr.key[1].name << "\" ungueltig" << endl;
				return 30;
			}
			sig_protokoll << sig << "#";
			sig = tmcg->TMCG_SignData(sec, sig_data);
			sig_protokoll << sig << "#";
			*left << sig << endl << flush;
			*right << sig << endl << flush;
		}
		spiel_protokoll << sig_protokoll.str();
		
		// compute rnk_id aka hex_rnk_digest
		string osttmp = spiel_protokoll.str();
		assert(gcry_md_get_algo_dlen(GCRY_MD_RMD160));
		char *rnk_digest = new char[gcry_md_get_algo_dlen(GCRY_MD_RMD160)];
		gcry_md_hash_buffer(GCRY_MD_RMD160, rnk_digest,
			osttmp.c_str(), osttmp.length());
		char *hex_rnk_digest = 
			new char[2 * gcry_md_get_algo_dlen(GCRY_MD_RMD160) + 1];
		for (size_t i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_RMD160); i++)
			snprintf(hex_rnk_digest + (2 * i), 3, "%02x", 
				(unsigned char)rnk_digest[i]);
		opipestream *npipe = new opipestream(hpipe);
		*npipe << hex_rnk_digest << endl << flush;
		*npipe << spiel_protokoll.str() << endl << flush;
		delete [] rnk_digest, delete [] hex_rnk_digest;
		delete npipe;
	}
	delete vtmf;
	if (pctl)
		*out_ctl << nicks[pkr_self] << " DONE" << endl << flush;
	delete out_pipe;
	if (pctl)
		delete out_ctl;
	return 0;
}
