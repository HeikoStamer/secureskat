/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2005  Heiko Stamer <stamer@gaos.org>

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
#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

// C++/C header
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cassert>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <ctime>
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>

// STL classes
#include <string>
#include <vector>
#include <iostream>

#include "SecureSkat_vtmf.hh"

// old ANSI C++ namespace style (2.7/2.95)
using namespace std;
#define MFD_SET(fd, where) { FD_SET(fd, where); mfds = (fd > mfds) ? fd : mfds; }

void random_announce(const vector<size_t> &cards)
{
	if (random() & 1L)
	{
		if (random() & 1L)
		{
			if (random() & 1L)
				cout << "CMD sagean Ei" << endl;
			else
				cout << "CMD sagean Gr" << endl;
		}
		else
		{
			if (random() & 1L)
				cout << "CMD sagean Ro" << endl;
			else
				cout << "CMD sagean Sc" << endl;
		}
	}
	else
	{
		if (random() & 1L)
			cout << "CMD sagean Gd" << endl;
		else
			cout << "CMD sagean Nu" << endl;
	}
}

int main (int argc, char **argv)
{
	cout << argv[0] << " (c) 2005 <stamer@gaos.org> " << endl;
	
	fd_set rfds;									// set of read descriptors
	int mfds = 0;									// highest-numbered descriptor
	struct timeval tv;						// timeout structure for select(2)
	char buffer[1024];
	int readed = 0;
	
	size_t pkr_self = 100, pkr_pos = 100, pkr_spielt = 100, spiel_status = 0;
	bool reize_dran = false, lege_dran = false, gepasst = false;
	vector<string>			nicks, names;
	vector<size_t>			cards, ocards, stich;
	
	srandom(time(NULL) + getpid() + getppid());
	while (1)
	{
		// select(2) -- initalize file descriptors
		FD_ZERO(&rfds);
		MFD_SET(fileno(stdin), &rfds);
		
		// select(2) -- initalize timeout
		tv.tv_sec = 1L;							// seconds
		tv.tv_usec = 0L;						// microseconds

		// select(2)
		int ret = select(mfds + 1, &rfds, NULL, NULL, &tv);
		
		// error occured
		if (ret < 0)
			if (errno != EINTR)
				perror("SecureSkat_*::main (select)");
		
		if ((ret > 0) && FD_ISSET(fileno(stdin), &rfds))
		{
			ssize_t num = read(fileno(stdin), buffer + readed,
				sizeof(buffer) - readed);
			readed += num;
				
			if (readed > 0)
			{
				vector<int> pos_delim;
				int cnt_delim = 0, cnt_pos = 0, pos = 0;
				for (int i = 0; i < readed; i++)
					if (buffer[i] == '\n')
						cnt_delim++, pos_delim.push_back(i);
				while (cnt_delim >= 1)
				{
					char xtmp[65536];
					memset(xtmp, 0, sizeof(xtmp));
					memcpy(xtmp, buffer + cnt_pos, pos_delim[pos] - cnt_pos);
					--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
					string cmd = xtmp;
					size_t ei;
					vector<string> par;
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
						
						if ((par[1] == "INIT") && (par.size() >= 4) && (nicks.size() < 3))
						{
							if (par[2] == par[0])
								pkr_self = nicks.size();
							nicks.push_back(par[2]);
							string name;
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
						}
						if ((par[1] == "MISCHEN") && (par.size() == 2) && (from == pkr_self))
						{
						}
						if ((par[1] == "GEBEN") && (par.size() == 2) && (from == pkr_self))
						{
						}
						if ((par[1] == "KARTE") && (par.size() == 3) && (from == pkr_self))
						{
							cards.push_back(atoi(par[2].c_str()));
						}
						if ((par[1] == "START") && (par.size() == 3) && (from == pkr_self))
						{
							pkr_pos = atoi(par[2].c_str());
							if (pkr_pos == 1)
								reize_dran = true;
							else
								reize_dran = false;
						}
						if ((par[1] == "RAMSCH") && (par.size() == 2) && (from == pkr_self))
						{
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
								if (random() & 1L)
									cout << "CMD skat" << endl << flush;
								else
									cout << "CMD hand" << endl << flush;
							}
						}
						if ((par[1] == "PASSE") && (par.size() == 2))
						{
							if (from == pkr_self)
								gepasst = true;
							if (!gepasst)
								reize_dran = true;
							else
								reize_dran = false;
						}
						if ((par[1] == "REIZE") && (par.size() == 3))
						{
							if (from == pkr_self)
								reize_dran = false;
							else if (!gepasst)
								reize_dran = true;
							else
								reize_dran = false;
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
								string card0 = skat_type2string(cards[0]);
								string card1 = skat_type2string(cards[1]);
								cards.erase(cards.begin());
								cards.erase(cards.begin());
								cout << "CMD druecke " << 
									card0.substr(0, card0.length() - 1) << " " << 
									card1.substr(0, card1.length() - 1) << endl << flush;
							}
						}
						if ((par[1] == "DRUECKE") && (par.size() == 2) && (from == pkr_spielt))
						{
							if ((from == pkr_spielt) && (pkr_spielt == pkr_self))
								random_announce(cards);
						}
						if ((par[1] == "SAGEAN") && (par.size() == 3) && (from == pkr_spielt))
						{
							spiel_status = atoi(par[2].c_str());
							if (pkr_pos == 0)
								lege_dran = true;
							else
								lege_dran = false;
						}
						if ((par[1] == "OUVERT") && (par.size() == 3) && (from == pkr_spielt))
						{
							ocards.push_back(atoi(par[2].c_str()));
						}
						if ((par[1] == "LEGE") && (par.size() == 3))
						{
							size_t card = atoi(par[2].c_str());
							stich.push_back(card);
							
							if ((stich.size() < 3) && (((from + 1) % 3) == pkr_self))
								lege_dran = true;
							else
								lege_dran = false;
								
							// remove played card from stack
							if (par[0] == nicks[pkr_self])
							{
								for (vector<size_t>::iterator ci = cards.begin(); 
									ci != cards.end(); ci++)
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
								for (vector<size_t>::iterator oci = ocards.begin(); 
									oci != ocards.end(); oci++)
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
							if (par[0] == nicks[pkr_self])
								lege_dran = true;
							else
								lege_dran = false;
						}
						if ((par[1] == "STOP") && (par.size() == 2) && (from == pkr_self))
						{
							cards.clear(), ocards.clear(), stich.clear();
							pkr_pos = 100, pkr_spielt = 100;
							reize_dran = false, lege_dran = false, gepasst = false;
						}
						if ((par[1] == "GEWONNEN") && (par.size() == 2))
						{
						}
						if ((par[1] == "VERLOREN") && (par.size() == 2))
						{
						}
						if ((par[1] == "PROTO") && (par.size() == 3))
						{
						}
					}
				}
				char ytmp[65536];
				memset(ytmp, 0, sizeof(ytmp));
				readed -= cnt_pos;
				memcpy(ytmp, buffer + cnt_pos, readed);
				memcpy(buffer, ytmp, readed);
			}
			if (num == 0)
			{
				// parent process dead, block child in this loop
				while (1)
					sleep(100);
			}
		}
		
		if (ret == 0)
		{
			if (reize_dran)
			{
				if (random() & 1L)
					cout << "CMD passe" << endl << flush;
				else
					cout << "CMD reize" << endl << flush;
			}
			else if (lege_dran)
			{
				if ((stich.size() == 0) && (cards.size() > 0))
				{
					string card = skat_type2string(cards[0]);
					cout << "CMD lege " << card.substr(0, card.length() - 1) <<
						endl << flush;
				}
				else
				{
					for (vector<size_t>::iterator ci = cards.begin();
						ci != cards.end(); ci++)
					{
						if (skat_rulectl(stich[0], *ci, spiel_status, cards))
						{
							string card = skat_type2string(*ci);
							cout << "CMD lege " << card.substr(0, card.length() - 1) <<
								endl << flush;
							break;
						}
					}
				}
				lege_dran = false;
			}
		}
	}
	return 0;
}
