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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include "SecureSkat_defs.hh"
#include "SecureSkat_rule.hh"

void announce (const size_t spiel)
{
	switch (spiel % 100)
	{
		case 9:
			std::cout << "CMD sagean Sc" << std::endl;
			break;
		case 10:
			std::cout << "CMD sagean Ro" << std::endl;
			break;
		case 11:
			std::cout << "CMD sagean Gr" << std::endl;
			break;
		case 12:
			std::cout << "CMD sagean Ei" << std::endl;
			break;
		case 23:
			std::cout << "CMD sagean Nu" << std::endl;
			break;
		case 24:
			std::cout << "CMD sagean Gd" << std::endl;
			break;
	}
}

size_t jacks (const std::vector<size_t> &cards, std::vector<size_t> &jack_cards)
{
	jack_cards.clear();
	for (size_t i = 0; i < 4; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			jack_cards.push_back(i);
	}
	return jack_cards.size();
}

size_t num_jacks (const std::vector<size_t> &cards)
{
	std::vector<size_t> jc;
	return jacks(cards, jc);
}

bool high_jacks (const std::vector<size_t> &cards)
{
	if (std::count(cards.begin(), cards.end(), 0) &&
		std::count(cards.begin(), cards.end(), 1))
		return true;
	return false;
}

bool ace (size_t card)
{
	if ((card == 4) || (card == 11) || (card == 18) || (card == 25))
		return true;
	return false;
}

size_t aces (const std::vector<size_t> &cards, std::vector<size_t> &ace_cards)
{
	ace_cards.clear();
	if (std::count(cards.begin(), cards.end(), 4))
		ace_cards.push_back(4);
	if (std::count(cards.begin(), cards.end(), 11))
		ace_cards.push_back(11);
	if (std::count(cards.begin(), cards.end(), 18))
		ace_cards.push_back(18);
	if (std::count(cards.begin(), cards.end(), 25))
		ace_cards.push_back(25);
	return ace_cards.size();
}

size_t num_aces (const std::vector<size_t> &cards)
{
	std::vector<size_t> ac;
	return aces(cards, ac);
}

size_t tens (const std::vector<size_t> &cards, std::vector<size_t> &ten_cards)
{
	ten_cards.clear();
	if (std::count(cards.begin(), cards.end(), 5))
		ten_cards.push_back(5);
	if (std::count(cards.begin(), cards.end(), 12))
		ten_cards.push_back(12);
	if (std::count(cards.begin(), cards.end(), 19))
		ten_cards.push_back(19);
	if (std::count(cards.begin(), cards.end(), 26))
		ten_cards.push_back(26);
	return ten_cards.size();
}

size_t num_tens (const std::vector<size_t> &cards)
{
	std::vector<size_t> tc;
	return tens(cards, tc);
}

size_t suit (const size_t spiel, const std::vector<size_t> &cards,
	std::vector<size_t> &suit_cards)
{
	suit_cards.clear();
	switch (spiel % 100)
	{
		case 9:
			for (size_t i = 25; i < 32; i++)
			{
				if (std::count(cards.begin(), cards.end(), i))
					suit_cards.push_back(i);
			}
			break;
		case 10:
			for (size_t i = 18; i < 25; i++)
			{
				if (std::count(cards.begin(), cards.end(), i))
					suit_cards.push_back(i);
			}
			break;
		case 11:
			for (size_t i = 11; i < 18; i++)
			{
				if (std::count(cards.begin(), cards.end(), i))
					suit_cards.push_back(i);
			}
			break;
		case 12:
			for (size_t i = 4; i < 11; i++)
			{
				if (std::count(cards.begin(), cards.end(), i))
					suit_cards.push_back(i);
			}
			break;
	}
	return suit_cards.size();
}

size_t num_suit (const size_t spiel, const std::vector<size_t> &cards)
{
	std::vector<size_t> sc;
	return suit(spiel, cards, sc);
}

size_t trump (const size_t spiel, const std::vector<size_t> &cards,
	std::vector<size_t> &trump_cards)
{
	std::vector<size_t> sc, jc;
	trump_cards.clear();
	if ((spiel % 100) == 23)
		return 0;
	if (jacks(cards, jc) > 0)
		trump_cards.insert(trump_cards.end(), jc.begin(), jc.end());
	if (suit(spiel, cards, sc) > 0)
		trump_cards.insert(trump_cards.end(), sc.begin(), sc.end());
	return trump_cards.size();
}

size_t num_trump (const size_t spiel, const std::vector<size_t> &cards)
{
	std::vector<size_t> tc;
	return trump(spiel, cards, tc);
}

size_t high_suit (const size_t spiel, const std::vector<size_t> &cards,
	std::vector<size_t> &high_cards)
{
	high_cards.clear();
	if (std::count(cards.begin(), cards.end(), 4) &&
		std::count(cards.begin(), cards.end(), 5) &&
		std::count(cards.begin(), cards.end(), 6) && ((spiel % 100) != 12))
	{
		high_cards.push_back(4);
		high_cards.push_back(5);
	}
	if (std::count(cards.begin(), cards.end(), 11) &&
		std::count(cards.begin(), cards.end(), 12) &&
		std::count(cards.begin(), cards.end(), 13) && ((spiel % 100) != 11))
	{
		high_cards.push_back(11);
		high_cards.push_back(12);
	}
	if (std::count(cards.begin(), cards.end(), 18) &&
		std::count(cards.begin(), cards.end(), 19) &&
		std::count(cards.begin(), cards.end(), 20) && ((spiel % 100) != 10))
	{
		high_cards.push_back(18);
		high_cards.push_back(19);
	}
	if (std::count(cards.begin(), cards.end(), 25) &&
		std::count(cards.begin(), cards.end(), 26) &&
		std::count(cards.begin(), cards.end(), 27) && ((spiel % 100) != 9))
	{
		high_cards.push_back(25);
		high_cards.push_back(26);
	}
	return high_cards.size();
}

size_t good_suit (const std::vector<size_t> &cards)
{
	size_t gs = 0;
	if (std::count(cards.begin(), cards.end(), 4) &&
		std::count(cards.begin(), cards.end(), 5) &&
		std::count(cards.begin(), cards.end(), 6))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 4) &&
		std::count(cards.begin(), cards.end(), 6) &&
		(num_suit(12, cards) > 3))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 5) &&
		std::count(cards.begin(), cards.end(), 6) &&
		(num_suit(12, cards) > 4))
		gs++;
	if (std::count(cards.begin(), cards.end(), 11) &&
		std::count(cards.begin(), cards.end(), 12) &&
		std::count(cards.begin(), cards.end(), 13))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 11) &&
		std::count(cards.begin(), cards.end(), 13) &&
		(num_suit(11, cards) > 3))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 12) &&
		std::count(cards.begin(), cards.end(), 13) &&
		(num_suit(11, cards) > 4))
		gs++;
	if (std::count(cards.begin(), cards.end(), 18) &&
		std::count(cards.begin(), cards.end(), 19) &&
		std::count(cards.begin(), cards.end(), 20))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 18) &&
		std::count(cards.begin(), cards.end(), 20) &&
		(num_suit(10, cards) > 3))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 19) &&
		std::count(cards.begin(), cards.end(), 20) &&
		(num_suit(10, cards) > 4))
		gs++;
	if (std::count(cards.begin(), cards.end(), 25) &&
		std::count(cards.begin(), cards.end(), 26) &&
		std::count(cards.begin(), cards.end(), 27))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 25) &&
		std::count(cards.begin(), cards.end(), 27) &&
		(num_suit(9, cards) > 3))
		gs++;
	else if (std::count(cards.begin(), cards.end(), 26) &&
		std::count(cards.begin(), cards.end(), 27) &&
		(num_suit(9, cards) > 4))
		gs++;
	return gs;
}

size_t lows (const std::vector<size_t> &cards, std::vector<size_t> &low_cards)
{
	low_cards.clear();
	for (size_t i = 29; i < 32; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			low_cards.push_back(i);
	}
	for (size_t i = 22; i < 25; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			low_cards.push_back(i);
	}
	for (size_t i = 15; i < 18; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			low_cards.push_back(i);
	}
	for (size_t i = 8; i < 11; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			low_cards.push_back(i);
	}
	return low_cards.size();
}

size_t num_lows (const std::vector<size_t> &cards)
{
	std::vector<size_t> lc;
	return lows(cards, lc);
}

size_t highs (const std::vector<size_t> &cards, std::vector<size_t> &high_cards)
{
	high_cards.clear();
	for (size_t i = 25; i < 28; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			high_cards.push_back(i);
	}
	for (size_t i = 18; i < 21; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			high_cards.push_back(i);
	}
	for (size_t i = 11; i < 14; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			high_cards.push_back(i);
	}
	for (size_t i = 4; i < 7; i++)
	{
		if (std::count(cards.begin(), cards.end(), i))
			high_cards.push_back(i);
	}
	return high_cards.size();
}

bool trump (const size_t spiel, size_t card)
{
	switch (spiel % 100)
	{
		case 9:
			if (card < 4)
				return true;
			if ((card >= 25) && (card <= 31))
				return true;
			break;
		case 10:
			if (card < 4)
				return true;
			if ((card >= 18) && (card <= 24))
				return true;
			break;
		case 11:
			if (card < 4)
				return true;
			if ((card >= 11) && (card <= 27))
				return true;
			break;
		case 12:
			if (card < 4)
				return true;
			if ((card >= 4) && (card <= 10))
				return true;
			break;
		case 23:
			return false;
		case 24:
			if (card < 4)
				return true;
			break;
	}
	return false;
}

size_t eval (const std::vector<size_t> &cards, const bool starts)
{
	size_t nj = num_jacks(cards);
	bool hj = high_jacks(cards);
	size_t na = num_aces(cards);
	size_t nt = num_tens(cards);
	size_t gs = good_suit(cards);
	size_t nl = num_lows(cards);
	// evaluate games based on a simple heuristic
	if (starts)
	{
		// Grand
		if (hj && (na > 2) && (nt > 2))
			return 24;
		if (hj && (gs > 1))
			return 24;
		if ((nj > 2) && (gs > 1))
			return 24;
		if ((nj > 3) && (gs > 0))
			return 24;
		// Null
		if (nl > 8)
			return 23;
	}
	else
	{
		// Grand
		if ((nj > 2) && (na > 2) && (nt > 2))
			return 24;
		if ((nj > 2) && (gs > 1))
			return 24;
		if ((nj > 3) && (gs > 0))
			return 24;
		// Null
		if (nl > 7)
			return 23;
	}
	// Suit
	if ((num_trump(12, cards) > 6) ||
		((num_trump(12, cards) > 5) && (na > 1)) ||
		((num_trump(12, cards) > 4) && (na > 2)))
		return 12;
	if ((num_trump(11, cards) > 6) ||
		((num_trump(11, cards) > 5) && (na > 1)) ||
		((num_trump(11, cards) > 4) && (na > 2)))
		return 11;
	if ((num_trump(10, cards) > 6) ||
		((num_trump(10, cards) > 5) && (na > 1)) ||
		((num_trump(10, cards) > 4) && (na > 2)))
		return 10;
	if ((num_trump(9, cards) > 6) ||
		((num_trump(9, cards) > 5) && (na > 1)) ||
		((num_trump(9, cards) > 4) && (na > 2)))
		return 9;
	return 0;
}

size_t blank (const size_t spiel, const std::vector<size_t> &cards,
	std::vector<size_t> &blank_cards)
{
	std::vector<size_t> sc;
	blank_cards.clear();
	switch (spiel % 100)
	{
		case 9:
			if ((suit(10, cards, sc) == 1) && (sc[0] != 18))
				blank_cards.push_back(sc[0]);
			if ((suit(11, cards, sc) == 1) && (sc[0] != 11))
				blank_cards.push_back(sc[0]);
			if ((suit(12, cards, sc) == 1) && (sc[0] != 4))
				blank_cards.push_back(sc[0]);
			break;
		case 10:
			if ((suit(9, cards, sc) == 1) && (sc[0] != 25))
				blank_cards.push_back(sc[0]);
			if ((suit(11, cards, sc) == 1) && (sc[0] != 11))
				blank_cards.push_back(sc[0]);
			if ((suit(12, cards, sc) == 1) && (sc[0] != 4))
				blank_cards.push_back(sc[0]);
			break;
		case 11:
			if ((suit(9, cards, sc) == 1) && (sc[0] != 25))
				blank_cards.push_back(sc[0]);
			if ((suit(10, cards, sc) == 1) && (sc[0] != 18))
				blank_cards.push_back(sc[0]);
			if ((suit(12, cards, sc) == 1) && (sc[0] != 4))
				blank_cards.push_back(sc[0]);
			break;
		case 12:
			if ((suit(9, cards, sc) == 1) && (sc[0] != 25))
				blank_cards.push_back(sc[0]);
			if ((suit(10, cards, sc) == 1) && (sc[0] != 18))
				blank_cards.push_back(sc[0]);
			if ((suit(11, cards, sc) == 1) && (sc[0] != 11))
				blank_cards.push_back(sc[0]);
			break;
		case 24:
			if ((suit(9, cards, sc) == 1) && (sc[0] != 25))
				blank_cards.push_back(sc[0]);
			if ((suit(10, cards, sc) == 1) && (sc[0] != 18))
				blank_cards.push_back(sc[0]);
			if ((suit(11, cards, sc) == 1) && (sc[0] != 11))
				blank_cards.push_back(sc[0]);
			if ((suit(12, cards, sc) == 1) && (sc[0] != 4))
				blank_cards.push_back(sc[0]);
			break;
	}
	return blank_cards.size();
}

size_t rare (const size_t spiel, const std::vector<size_t> &cards,
	std::vector<size_t> &rare_cards)
{
	std::vector<size_t> sc;
	rare_cards.clear();
	switch (spiel % 100)
	{
		case 9:
			if ((suit(10, cards, sc) == 2) && (sc[0] != 18))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(11, cards, sc) == 2) && (sc[0] != 11))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(12, cards, sc) == 2) && (sc[0] != 4))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			break;
		case 10:
			if ((suit(9, cards, sc) == 2) && (sc[0] != 25))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(11, cards, sc) == 2) && (sc[0] != 11))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(12, cards, sc) == 2) && (sc[0] != 4))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			break;
		case 11:
			if ((suit(9, cards, sc) == 2) && (sc[0] != 25))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(10, cards, sc) == 2) && (sc[0] != 18))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(12, cards, sc) == 2) && (sc[0] != 4))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			break;
		case 12:
			if ((suit(9, cards, sc) == 2) && (sc[0] != 25))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(10, cards, sc) == 2) && (sc[0] != 18))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(11, cards, sc) == 2) && (sc[0] != 11))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			break;
		case 24:
			if ((suit(9, cards, sc) == 2) && (sc[0] != 25))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(10, cards, sc) == 2) && (sc[0] != 18))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(11, cards, sc) == 2) && (sc[0] != 11))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			if ((suit(12, cards, sc) == 2) && (sc[0] != 4))
				rare_cards.push_back(sc[0]), rare_cards.push_back(sc[1]);
			break;
	}
	return rare_cards.size();
}

size_t not_null (const std::vector<size_t> &cards,
	std::vector<size_t> &bad_cards)
{
	bad_cards.clear();
// TODO
	return bad_cards.size();
}

size_t pkr_self = 100, pkr_pos = 100, pkr_spielt = 100;
size_t spiel = 0, reiz_counter = 0, biete = 0;
size_t pkt = 0, opp_pkt = 0, trumps = 0, opp_trumps = 0;
bool reize_dran = false, lege_dran = false, gepasst = false, handspiel = false;
std::vector<std::string> nicks, names;
std::vector<size_t> cards, ocards, stich;

void process_command (size_t &readed, char *buffer)
{
	const size_t BUFFER_SIZE = 65536;
	if ((readed <= 0) || (readed > BUFFER_SIZE))
		return;
	// detect line endings
	std::vector<size_t> pos_delim;
	size_t cnt_delim = 0, cnt_pos = 0, pos = 0;
	for (size_t i = 0; i < readed; i++)
	{
	    if (buffer[i] == '\n')
			cnt_delim++, pos_delim.push_back(i);
	}
	// process each line
	while (cnt_delim >= 1)
	{
	    char xtmp[BUFFER_SIZE];
	    memset(xtmp, 0, sizeof(xtmp));
	    memcpy(xtmp, buffer + cnt_pos, pos_delim[pos] - cnt_pos);
	    --cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
	    std::string cmd = xtmp;
	    size_t ei;
	    std::vector<std::string> par;
	    // parse params
	    while ((ei = cmd.find(" ", 0)) != cmd.npos)
	    {
			par.push_back(cmd.substr(0, ei));
			cmd = cmd.substr(ei + 1, cmd.length() - ei - 1);
	    }
	    par.push_back(cmd);
	    if (par.size() >= 2)
	    {
			size_t from = 100;
			for (size_t j = 0; j < nicks.size(); j++)
			    if (par[0] == nicks[j])
					from = j;
						
			if ((par[1] == "INIT") && (par.size() >= 4) && 
			    (nicks.size() < 3))
			{
			    if (par[2] == par[0])
					pkr_self = nicks.size();
			    nicks.push_back(par[2]);
			    std::string name;
			    for (size_t j = 0; j < (par.size() - 3); j++)
			    {
					name += par[3 + j];
					if (j < (par.size() - 4))
					    name += " ";
			    }
			    names.push_back(name);
			}
			if ((par[1] == "DONE") && (par.size() == 2) && (from == pkr_self))
			{
				// nothing to do
			}
			if ((par[1] == "MISCHEN") && (par.size() == 2) && (from == pkr_self))
			{
				// nothing to do
			}
			if ((par[1] == "GEBEN") && (par.size() == 2) && (from == pkr_self))
			{
				// nothing to do
			}
			if ((par[1] == "KARTE") && (par.size() == 3) && (from == pkr_self))
			{
				cards.push_back(atoi(par[2].c_str()));
			}
			if ((par[1] == "START") && (par.size() == 3) && (from == pkr_self))
			{
			    pkr_pos = atoi(par[2].c_str());
			    reize_dran = (pkr_pos == 1) ? true : false;
				reiz_counter = 0, spiel = 0;
				pkt = 0, opp_pkt = 0, trumps = 0, opp_trumps = 0;
				handspiel = false;
				spiel = eval(cards, !pkr_pos);
				if (spiel)
				{
					size_t sp = skat_spitzen(24, cards); // nur Buben als Spitze
					biete = ((sp + 1) * (spiel % 100));
				}
			}
			if ((par[1] == "RAMSCH") && (par.size() == 2) && (from == pkr_self))
			{
				// nothing to do
			}
			if ((par[1] == "SPIELT") && (par.size() == 2) && (pkr_self != 100))
			{
				if (par[0] == nicks[0])
					pkr_spielt = 0;
				else if (par[0] == nicks[1])
					pkr_spielt = 1;
				else if (par[0] == nicks[2])
					pkr_spielt = 2;
				if (pkr_spielt == pkr_self)
				{
					if ((spiel % 100) == 23)
					{
						// TODO: Nullspiel
						if (tmcg_mpz_wrandom_ui() % 2)
							std::cout << "CMD skat" << std::endl << std::flush;
						else
							std::cout << "CMD hand" << std::endl << std::flush;
					}
					else
					{
						std::vector<size_t> bc, tc, bt(4), rc;
						std::vector<size_t>::iterator it;
						blank(spiel, cards, bc);
						std::sort(bc.begin(), bc.end());
						tens(cards, tc);
						std::sort(tc.begin(), tc.end());
						it = std::set_intersection(bc.begin(), bc.end(),
							tc.begin(), tc.end(), bt.begin());
						bt.resize(it - bt.begin());
						rare(spiel, cards, rc);
std::cerr << "///// hand? bt = " << bt.size() << " bc = " << bc.size() << " rc = " << rc.size() << std::endl;
						if ((bt.size() > 0) || (bc.size() > 1) || (rc.size() == 2))
							std::cout << "CMD skat" << std::endl << std::flush;
						else
							std::cout << "CMD hand" << std::endl << std::flush;
					}
				}
			}
			if ((par[1] == "PASSE") && (par.size() == 2))
			{
				if (from == pkr_self)
					gepasst = true;
				reize_dran = (!gepasst) ? true : false;
			}
			if ((par[1] == "REIZE") && (par.size() == 3))
			{
				reiz_counter++;
				if (from == pkr_self)
					reize_dran = false;
				else 
					reize_dran = (!gepasst) ? true : false;
			}
			if ((par[1] == "HAND") && (par.size() == 2) && (from == pkr_spielt))
			{
				reize_dran = false;
				handspiel = true;
				if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
				{
					announce(spiel);
				}
			}
			if ((par[1] == "SKAT") && (par.size() == 2) && (from == pkr_spielt))
			{
				reize_dran = false;
				if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
				{
					size_t c0 = cards[0], c1 = cards[1]; // fallback: first two
					if (eval(cards, !pkr_pos) > spiel)
						spiel = eval(cards, !pkr_pos);
					if ((spiel % 100) == 23)
					{
						std::vector<size_t> nn;
						not_null(cards, nn);
						// TODO: Nullspiel
					}
					else
					{
						std::vector<size_t> hs, bc, tc, bt(4), rc;
						std::vector<size_t>::iterator it;
						high_suit(spiel, cards, hs);
						blank(spiel, cards, bc);
						std::sort(bc.begin(), bc.end());
						tens(cards, tc);
						std::sort(tc.begin(), tc.end());
						it = std::set_intersection(bc.begin(), bc.end(),
							tc.begin(), tc.end(), bt.begin());
						bt.resize(it - bt.begin());
						rare(spiel, cards, rc);
std::cerr << "///// bt = " << bt.size() << " bc = " << bc.size() << " hs = " << hs.size() << " rc = " << rc.size() << std::endl;
						if (bt.size() >= 2)
						{
							size_t idx1 = tmcg_mpz_wrandom_ui() % bt.size();
							c0 = bt[idx1];
							bt.erase(std::remove(bt.begin(), bt.end(), c0),
								bt.end());
							size_t idx2 = tmcg_mpz_wrandom_ui() % bt.size();
							c1 = bt[idx2];
						}
						else if ((bt.size() == 1) && (bc.size() > 0))
						{
							c0 = bt[0];
							size_t idx2 = tmcg_mpz_wrandom_ui() % bc.size();
							c1 = bc[idx2];
						}
						else if ((bt.size() == 0) && (bc.size() >= 2))
						{
							size_t idx1 = tmcg_mpz_wrandom_ui() % bc.size();
							c0 = bc[idx1];
							bc.erase(std::remove(bc.begin(), bc.end(), c0),
								bc.end());
							size_t idx2 = tmcg_mpz_wrandom_ui() % bc.size();
							c1 = bc[idx2];
						}
						else if (rc.size() >= 2)
						{
							// Farbe entfernen (TODO: random, if rc > 2)
							c0 = rc[0], c1 = rc[1];
						}
						else if (hs.size() > 3)
						{
							// Bunker
							size_t idx1 = tmcg_mpz_wrandom_ui() % hs.size();
							c0 = hs[idx1];
							hs.erase(std::remove(hs.begin(), hs.end(), c0),
								hs.end());
							size_t idx2 = tmcg_mpz_wrandom_ui() % hs.size();
							c1 = hs[idx2];
						}
						else
						{
							while (trump(spiel, c0) || ace(c0) ||
								trump(spiel, c1) || ace(c1) || (c0 == c1))
							{
								size_t i = tmcg_mpz_wrandom_ui() % cards.size();
								size_t j = tmcg_mpz_wrandom_ui() % cards.size();
								c0 = cards[i], c1 = cards[j];
							}
						}
					}
					pkt += skat_pktwert[c0];
					pkt += skat_pktwert[c1];
					std::string card0 = skat_type2string(c0);
					std::string card1 = skat_type2string(c1);
					cards.erase(std::remove(cards.begin(), cards.end(), c0),
						cards.end());
					cards.erase(std::remove(cards.begin(), cards.end(), c1),
						cards.end());
					std::cout << "CMD druecke " << 
						card0.substr(0, card0.length() - 1) << " " << 
						card1.substr(0, card1.length() - 1) << std::endl <<
						std::flush;
				}
			}
			if ((par[1] == "DRUECKE") && (par.size() == 2) &&
				(from == pkr_spielt))
			{
				if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
				{
					announce(spiel);
				}
			}
			if ((par[1] == "SAGEAN") && (par.size() == 3) && 
				(from == pkr_spielt))
			{
				spiel = atoi(par[2].c_str());
				trumps = num_trump(spiel, cards);
				switch (spiel % 100)
				{
					// calculate maximum opponent trumps
					case 9:
					case 10:
					case 11:
					case 12:
						opp_trumps = 11 - trumps;
						break;
					case 23:
						opp_trumps = 0;
						break;
					case 24:
						opp_trumps = 4 - trumps;
						break;
				}
				lege_dran = (pkr_pos == 0) ? true : false;
			}
			if ((par[1] == "OUVERT") && (par.size() == 3) && 
				(from == pkr_spielt))
			{
				ocards.push_back(atoi(par[2].c_str()));
				if (pkr_self != pkr_spielt)
					opp_trumps = num_trump(spiel, ocards);
			}
			if ((par[1] == "LEGE") && (par.size() == 3))
			{
				size_t card = atoi(par[2].c_str());
				stich.push_back(card);
				lege_dran = ((stich.size() < 3) && 
					(((from + 1) % 3) == pkr_self)) ? true : false;
				// remove played card from my hand
				if (par[0] == nicks[pkr_self])
				{
					cards.erase(std::remove(cards.begin(), cards.end(), card),
						cards.end());
    			}
				// remove played ouvert card from stack
				if ((par[0] == nicks[pkr_spielt]) && (ocards.size() > 0))
				{
					ocards.erase(std::remove(ocards.begin(), ocards.end(),
						card), ocards.end());
				}
				// update trump statistics
				if (par[0] == nicks[pkr_self])
					trumps = num_trump(spiel, cards);
				if ((pkr_self != pkr_spielt) && (ocards.size() > 0))
					opp_trumps = num_trump(spiel, ocards);
				else if (par[0] != nicks[pkr_self])
				{
					if (trump(spiel, card) && (opp_trumps > 0))
						opp_trumps--;
				}
			}
			if ((par[1] == "BSTICH") && (par.size() == 2))
			{
				// update trump statistics
				if (trump(spiel, stich[0]) && (par[0] == nicks[pkr_self]))
				{
					if (!trump(spiel, stich[1]) && !trump(spiel, stich[2]))
						opp_trumps = 0;
				}
				// update point statistics
				if (par[0] == nicks[pkr_self])
				{
					lege_dran = true;
					for (size_t i = 0; i < stich.size(); i++)
						pkt += skat_pktwert[stich[i]];
				}
				else
				{
					lege_dran = false;
					if (pkr_spielt == pkr_self)
					{
						for (size_t i = 0; i < stich.size(); i++)
							opp_pkt += skat_pktwert[stich[i]];
					}
					else if (par[0] == nicks[pkr_spielt])
					{
						for (size_t i = 0; i < stich.size(); i++)
							opp_pkt += skat_pktwert[stich[i]];
					}
					else
					{
						for (size_t i = 0; i < stich.size(); i++)
							pkt += skat_pktwert[stich[i]];
					}
				}
				stich.clear();
			}
			if ((par[1] == "STOP") && (par.size() == 2) && (from == pkr_self))
			{
				cards.clear(), ocards.clear(), stich.clear();
				pkr_pos = 100, pkr_spielt = 100, biete = 0, spiel = 0;
				reize_dran = false, lege_dran = false, gepasst = false;
			}
			if ((par[1] == "GEWONNEN") && (par.size() == 2))
			{
				// nothing to do
			}
			if ((par[1] == "VERLOREN") && (par.size() == 2))
			{
				// nothing to do
			}
			if ((par[1] == "PROTO") && (par.size() == 3))
			{
				// nothing to do
			}
		}
	} // end 2nd while
	char ytmp[BUFFER_SIZE];
	memset(ytmp, 0, sizeof(ytmp));
	readed -= cnt_pos;
	memcpy(ytmp, buffer + cnt_pos, readed);
	memcpy(buffer, ytmp, readed);
}

void act()
{
	if (reize_dran)
	{
std::cerr << "///// spiel = " << spiel << " biete = " << biete << std::endl;
		if (spiel && (biete > skat_reizwert[reiz_counter]))
			std::cout << "CMD reize" << std::endl << std::flush;
		else
			std::cout << "CMD passe" << std::endl << std::flush;
	}
	else if (lege_dran)
	{
std::cerr << "///// spiel = " << spiel << " trumps = " << trumps << " opp_trumps = " << opp_trumps << " pkt = " << pkt << " opp_pkt = " << opp_pkt << std::endl;
		assert((cards.size() > 0));
		lege_dran = false;
		if (stich.size() == 0)
		{
			// Anspiel einer Karte
			if ((spiel % 100) == 23)
			{
				// TODO: Nullspiel: Lusche aus Reihe spielen
			}
			else if ((opp_trumps > 0) && (trumps > opp_trumps))
			{
				if (high_jacks(cards))
				{
					std::cout << "CMD lege GrU" << std::endl << std::flush;
					return;
				}
				else
				{
					if (std::count(cards.begin(), cards.end(), 1))
					{
						std::cout << "CMD lege GrU" <<
							std::endl << std::flush;
						return;
					}
					else if (std::count(cards.begin(), cards.end(), 3))
					{
						std::cout << "CMD lege ScU" <<
							std::endl << std::flush;
						return;
					}
					else if (std::count(cards.begin(), cards.end(), 2))
					{
						std::cout << "CMD lege RoU" <<
							std::endl << std::flush;
						return;
					}
				}					
			}

			size_t idx = tmcg_mpz_wrandom_ui() % cards.size();
			std::string card = skat_type2string(cards[idx]);
			std::cout << "CMD lege " << 
				card.substr(0, card.length() - 1) << std::endl << std::flush;
		}
		else if (stich.size() == 1)
		{
			std::vector<size_t> allowed_cards;
			for (size_t i = 0; i < cards.size(); i++)
			{
				if (skat_rulectl(stich[0], cards[i], spiel, cards))
					allowed_cards.push_back(cards[i]);
			}
			assert((allowed_cards.size() > 0));
			if ((spiel % 100) == 23)
			{
				// TODO: wenn möglich drunter bleiben, sonst wenig höher
			}
			// TODO: Stechen, Übernehmen oder Buttern

			// fallback: per Zufall spielen
			size_t idx = tmcg_mpz_wrandom_ui() % allowed_cards.size();
			std::string card = skat_type2string(allowed_cards[idx]);
			std::cout << "CMD lege " << 
				card.substr(0, card.length() - 1) << std::endl << std::flush;
		}
		else
		{
			std::vector<size_t> allowed_cards;
			for (size_t i = 0; i < cards.size(); i++)
			{
				if (skat_rulectl(stich[0], cards[i], spiel, cards))
					allowed_cards.push_back(cards[i]);
			}
			assert((allowed_cards.size() > 0));
			if ((spiel % 100) == 23)
			{
				// TODO: höchste Karte kleiner als bereits im Stich; Abwerfen
			}
			// TODO: Stechen, Übernehmen oder Buttern

			// fallback: per Zufall spielen
			size_t idx = tmcg_mpz_wrandom_ui() % allowed_cards.size();
			std::string card = skat_type2string(allowed_cards[idx]);
			std::cout << "CMD lege " << 
				card.substr(0, card.length() - 1) << std::endl << std::flush;
		}
	}
}

int main (int argc, char **argv)
{
	int fd = fileno(stdin); // file descriptor of STDIN
	fd_set rfds; // set of read descriptors
	int mfds = 0; // highest-numbered descriptor
	struct timeval tv; // timeout structure for select(2)
	char buffer[1024];
	size_t readed = 0;

	std::cout << argv[0] << " (c) 2018 <HeikoStamer@gmx.net> " << std::endl;
	while (1)
	{
		// select(2) -- initialize file descriptors
		FD_ZERO(&rfds);
		MFD_SET(fd, &rfds);

		// select(2) -- initialize timeout
		tv.tv_sec = 1L; // seconds
		tv.tv_usec = 0L; // microseconds

		// select(2)
		int ret = select(mfds + 1, &rfds, NULL, NULL, &tv);
		
		// error occured
		if ((ret < 0) && (errno != EINTR))
		{
			perror("SecureSkat_ai::main (select)");
			return -1;
		}
		
		if ((ret > 0) && FD_ISSET(fd, &rfds))
		{
			ssize_t num = read(fd, buffer + readed, sizeof(buffer) - readed);
			if (num < 0)
			{
				perror("SecureSkat_ai::main (read)");
				return -1;
			}
			readed += num;
			process_command(readed, buffer);
			if (num == 0)
			{
				// if parent process is dead, block child in this loop
				while (1)
					sleep(100);
			}
		}
		
		if (ret == 0)
			act();
	}
	return 0;
}

