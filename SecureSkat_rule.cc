/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#include "SecureSkat_rule.hh"

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
		size_t ft[5][18], const size_t f, const size_t t, const size_t s
	)
{
	assert (s < 18);
	assert (f < 5);
	for (size_t i = s; i < 18; i++)
	{
		if (t == ft[f][i])
			return i;
	}
	return 99;
}

size_t skat_spiel2gwert
	(
		const size_t spiel
	)
{
	return (spiel % 100);
}

size_t skat_spiel2twert
	(
		const size_t spiel
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
		const size_t spiel, size_t co[5][18]
	)
{
	for (size_t i = 0; i < 5; i++)
		for (size_t j = 0; j < 18; j++)
			co[i][j] = card_order[skat_spiel2twert(spiel)][i][j];
}

size_t skat_spitzen
	(
		const size_t spiel, const std::vector<size_t> &cv
	)
{
	TMCG_OpenStack<VTMF_Card> os;
	for (size_t j = 0; j < cv.size(); j++)
		os.push(cv[j], VTMF_Card());
	return skat_spitzen(spiel, os);
}

size_t skat_spitzen
	(
		const size_t spiel, const TMCG_OpenStack<VTMF_Card> &os
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
			if (!os.find(co[4][sz]) && (co[4][sz] != 99))
				sz_cnt++;
			else
				break;
		}
	}
	return sz_cnt;
}

bool skat_rulectl
	(
		const size_t t, const size_t tt, const size_t spiel,
		const std::vector<size_t> &cv
	)
{
	TMCG_OpenStack<VTMF_Card> os;
	for (size_t j = 0; j < cv.size(); j++)
		os.push(cv[j], VTMF_Card());
	return skat_rulectl(t, tt, spiel, os);
}

bool skat_rulectl
	(
		const size_t t, const size_t tt, const size_t spiel,
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
		to = 11; // Farbspiele: 11 Truempfe

	if (skat_idx(co, 4, t, 0) != 99)
	{
		// Trumpf angespielt, aber nicht bedient
		if (skat_idx(co, 4, tt, 0) == 99)
		{
			for (size_t i = 0; i < os.size(); i++)
			{
				if (skat_idx(co, 4, os[i].first, 0) < 99)
					return false;
			}
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
					{
						if (skat_idx(co, i, os[j].first, to) < 99)
							return false;
					}
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
		const TMCG_OpenStack<VTMF_Card> &os, const size_t spiel
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

std::string skat_spiel2string
	(
		const size_t spiel
	)
{
	std::string wstr = "";
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
	return std::string(wstr);
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

std::string skat_type2string
	(
		const size_t type
	)
{
	std::string wstr = "";
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
	return std::string(wstr);
}

void skat_blatt
	(
		const size_t p, const TMCG_OpenStack<VTMF_Card> &os
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

