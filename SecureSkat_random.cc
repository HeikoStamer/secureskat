/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2005, 2007,
               2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

void random_announce (const std::vector<size_t> &cards)
{
	switch (tmcg_mpz_wrandom_ui() % 6)
	{
		case 0:
			std::cout << "CMD sagean Ei" << std::endl;
			break;
		case 1:
			std::cout << "CMD sagean Gr" << std::endl;
			break;
		case 2:
			std::cout << "CMD sagean Ro" << std::endl;
			break;
		case 3:
			std::cout << "CMD sagean Sc" << std::endl;
			break;
		case 4:
			std::cout << "CMD sagean Gd" << std::endl;
			break;
		case 5:
			std::cout << "CMD sagean Nu" << std::endl;
			break;
	}
}

size_t pkr_self = 100, pkr_pos = 100, pkr_spielt = 100, spiel_status = 0;
bool reize_dran = false, lege_dran = false, gepasst = false;
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
//std::cerr << "parse_random: CMD = " << cmd << std::endl;
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
					if (tmcg_mpz_wrandom_ui() & 1L)
						std::cout << "CMD skat" << std::endl << std::flush;
					else
						std::cout << "CMD hand" << std::endl << std::flush;
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
				if (from == pkr_self)
					reize_dran = false;
				else 
					reize_dran = (!gepasst) ? true : false;
			}
			if ((par[1] == "HAND") && (par.size() == 2) && (from == pkr_spielt))
			{
				reize_dran = false;
				if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
					random_announce(cards);
			}
			if ((par[1] == "SKAT") && (par.size() == 2) && (from == pkr_spielt))
			{
				reize_dran = false;
				if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
				{
					std::string card0 = skat_type2string(cards[0]);
					std::string card1 = skat_type2string(cards[1]);
					cards.erase(cards.begin());
					cards.erase(cards.begin());
					std::cout << "CMD druecke " << 
						card0.substr(0, card0.length() - 1) << 
							" " << 
						card1.substr(0, card1.length() - 1) << 
						std::endl << std::flush;
				}
			}
			if ((par[1] == "DRUECKE") && (par.size() == 2) && (from == pkr_spielt))
			{
				if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
					random_announce(cards);
			}
			if ((par[1] == "SAGEAN") && (par.size() == 3) && 
				(from == pkr_spielt))
			{
				spiel_status = atoi(par[2].c_str());
				lege_dran = (pkr_pos == 0) ? true : false;
			}
			if ((par[1] == "OUVERT") && (par.size() == 3) && 
				(from == pkr_spielt))
			{
				ocards.push_back(atoi(par[2].c_str()));
			}
			if ((par[1] == "LEGE") && (par.size() == 3))
			{
				size_t card = atoi(par[2].c_str());
				stich.push_back(card);
				lege_dran = ((stich.size() < 3) && 
					(((from + 1) % 3) == pkr_self)) ? true : false;
				// remove played card from stack
				if (par[0] == nicks[pkr_self])
				{
					for (std::vector<size_t>::iterator ci = 
						cards.begin(); ci != cards.end(); ci++)
					{
						if (card == *ci)
						{
							cards.erase(ci);
							break;
						}
					}
    			}
				// remove played ouvert card from stack
				if ((par[0] == nicks[pkr_spielt]) && (ocards.size() > 0))
				{
					for (std::vector<size_t>::iterator oci = 
						ocards.begin(); oci != ocards.end(); oci++)
					{
						if (card == *oci)
						{
							ocards.erase(oci);
							break;
	    				}
					}
				}
			}
			if ((par[1] == "BSTICH") && (par.size() == 2))
			{
				stich.clear();
				lege_dran = (par[0] == nicks[pkr_self]) ? true : false;
			}
			if ((par[1] == "STOP") && (par.size() == 2) && (from == pkr_self))
			{
				cards.clear(), ocards.clear(), stich.clear();
				pkr_pos = 100, pkr_spielt = 100;
				reize_dran = false, lege_dran = false, 
				gepasst = false;
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
		if (tmcg_mpz_wrandom_ui() & 1L)
			std::cout << "CMD passe" << std::endl << std::flush;
		else
			std::cout << "CMD reize" << std::endl << std::flush;
	}
	else if (lege_dran)
	{
		if ((stich.size() == 0) && (cards.size() > 0))
		{
			size_t idx = tmcg_mpz_wrandom_ui() % cards.size();
			std::string card = skat_type2string(cards[idx]);
			std::cout << "CMD lege " << 
				card.substr(0, card.length() - 1) << std::endl << std::flush;
		}
		else
		{
			std::vector<size_t> allowed_cards;
			for (std::vector<size_t>::iterator ci = cards.begin();
				ci != cards.end(); ci++)
			{
				if (skat_rulectl(stich[0], *ci, spiel_status, cards))
				{
					allowed_cards.push_back(*ci);
				}
			}
			assert((allowed_cards.size() > 0));
			size_t idx = tmcg_mpz_wrandom_ui() % allowed_cards.size();
			std::string card = skat_type2string(allowed_cards[idx]);
			std::cout << "CMD lege " << 
				card.substr(0, card.length() - 1) << std::endl << std::flush;
		}
		lege_dran = false;
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

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "Initialization of LibTMCG failed!" << std::endl;
		return EXIT_FAILURE;
	}
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
			perror("SecureSkat_random::main (select)");
			return -1;
		}
		
		if ((ret > 0) && FD_ISSET(fd, &rfds))
		{
			ssize_t num = read(fd, buffer + readed, sizeof(buffer) - readed);
			if (num < 0)
			{
				perror("SecureSkat_random::main (read)");
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

