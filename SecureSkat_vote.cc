/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2007, 2009, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#include "SecureSkat_vote.hh"

RETSIGTYPE sig_handler_ballot_quit(int sig)
{
#ifndef NDEBUG
	std::cerr << "signal_handler_ballot_quit: got signal " << sig << std::endl;
#endif
	exit(-100);
}

extern TMCG_SecretKey sec;
extern TMCG_PublicKey pub;
extern std::map<std::string, TMCG_PublicKey> nick_key;
extern std::map<std::string, std::string> nick_players;
extern std::string X, XX, XXX;

int ballot_child
	(const std::string &nr, int b, bool neu, int ipipe, int opipe,
	const std::string &master)
{
	// install old signal handlers
	signal(SIGINT, sig_handler_ballot_quit);
	signal(SIGQUIT, sig_handler_ballot_quit);
	signal(SIGTERM, sig_handler_ballot_quit);
	signal(SIGSEGV, sig_handler_ballot_quit);
	signal(SIGILL, sig_handler_ballot_quit);
	signal(SIGFPE, sig_handler_ballot_quit);
	signal(SIGPIPE, sig_handler_ballot_quit);
	signal(SIGCHLD, SIG_DFL);
#ifdef NOHUP
	signal(SIGHUP, SIG_IGN);
#endif
	signal(SIGUSR1, SIG_DFL);
	
	// variables
	std::list<std::string> gp_nick;
	std::map<std::string, std::string> gp_name;
	opipestream *out_pipe = new opipestream(opipe);
	ipipestream *in_pipe = new ipipestream(ipipe);
	
	// compute 2^b
	size_t b_pow = 1;
	for (int bb = 0; bb < b; bb++)
		b_pow *= 2;
	
	// announce table construction
	gp_nick.push_back(pub.keyid(5));
	gp_name[pub.keyid(5)] = pub.name;
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|1~" << -b << "!" << std::endl << std::flush;
	
	// wait for voters
	while (1)
	{
		char tmp[10001];
		memset(tmp, 0, sizeof(tmp));
		in_pipe->getline(tmp, (sizeof(tmp) - 1));
		std::string cmd = tmp;
		
		if ((cmd == "") || (cmd.find("!KICK", 0) == 0) || (b <= 0))
		{
			delete in_pipe, delete out_pipe;
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << -b << "!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
				{
					if (gp_nick.size() < TMCG_MAX_PLAYERS)
					{
						gp_nick.push_back(nick), gp_name[nick] = nick_key[nick].name;
						*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
							gp_nick.size() << "~" << b << "!" << std::endl << std::flush;
					}
					else
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
							nick << " :" << _("room completely occupied") << 
							std::endl << std::flush;
				}
				else
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
						nick << " :" << _("voter was at room creation not present") << 
						std::endl << std::flush;
			}
			else
				*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << " :" << _("key exchange with owner is incomplete") << 
					std::endl << std::flush;
		}
		if (!neu && ((cmd.find("JOIN ", 0) == 0) || (cmd.find("WHO ", 0) == 0)))
		{
			std::string nick = (cmd.find("JOIN ", 0) == 0) ? cmd.substr(5, cmd.length() - 5) : cmd.substr(4, cmd.length() - 4);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
					gp_nick.push_back(nick), gp_name[nick] = nick_key[nick].name;
				else
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << " :" << _("voter was at room creation not present") << 
						std::endl << std::flush;
			}
			else
			{
				std::cout << X << _("key exchange with") << " " << nick << " " << _("is incomplete") << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete in_pipe, delete out_pipe;
				return -1;
			}
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(gp_nick.begin(), gp_nick.end(), nick) != gp_nick.end())
			{
				gp_nick.remove(nick), gp_name.erase(nick);
			}
		}
		
		// control messages
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string msg = cmd.substr(cmd.find(" ", 4) + 1, cmd.length() - cmd.find(" ", 4) - 1);
			if ((msg == "!READY") && (nick == master))
				break;
		}
		
		// stdin messages
		if ((cmd.find("CMD ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string msg = cmd.substr(4, cmd.find(" ", 4) - 4);

			if (neu && ((msg.find("OPEN", 0) == 0) || (msg.find("open", 0) == 0)))
			{
				*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << b << "!" << std::endl << std::flush;
				*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :!READY" << std::endl << std::flush;
				break;
			}
		}
	}
	std::cout << X << _("Room") << " " << nr << " " << _("preparing the ballot") << " ..." << std::endl;
	// prepare ballot (create PKR, bind port for secure connections)
	if (gp_nick.size() > TMCG_MAX_PLAYERS)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete in_pipe, delete out_pipe;
		return -33;
	}
	if (b > TMCG_MAX_TYPEBITS)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete in_pipe, delete out_pipe;
		return -33;
	}
	SchindelhauerTMCG *ballot_tmcg = new SchindelhauerTMCG(80, gp_nick.size(), b); // n players, 2^b cards, security level = 80
	TMCG_PublicKeyRing pkr(gp_nick.size());
	std::vector<std::string> vnicks;
	size_t pkr_i = 0, pkr_self = 0;
	gp_nick.sort();
	for (std::list<std::string>::const_iterator pi = gp_nick.begin(); pi != gp_nick.end(); pi++, pkr_i++)
	{
		vnicks.push_back(*pi);
		if (*pi == pub.keyid(5))
		{
			pkr_self = pkr_i;
			pkr.keys[pkr_i] = pub;
		}
		else
			pkr.keys[pkr_i] = nick_key[*pi];
	}
	int gp_handle, gp_port = BindEmptyPort(7900);
	if ((gp_handle = ListenToPort(gp_port)) < 0)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete in_pipe, delete out_pipe;
		delete ballot_tmcg;
		return -4;
	}
	std::ostringstream ost;
	ost << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :PORT " << gp_port << std::endl;
	*out_pipe << ost.str() << std::flush;
	std::cout << X << _("Room") << " " << nr << " " << _("with");
	for (size_t i = 0; i < gp_nick.size(); i++)
		std::cout << " '" << pkr.keys[i].name << "'";
	std::cout << " " << _("ready") << "." << std::endl;
	std::cout << XX << _("BALLOT: please make your vote with command") << " /<nr> vote <r>" << std::endl;
	
	std::list<std::string> gp_rdport, gp_voters;
	std::map<std::string, int> gp_ports;
	size_t vote = 0;
	bool has_voted = false;
	while ((gp_rdport.size() < (gp_nick.size() - 1)) || (gp_voters.size() < gp_nick.size()))
	{
		char tmp[10001];
		memset(tmp, 0, sizeof(tmp));
		in_pipe->getline(tmp, (sizeof(tmp) - 1));
		std::string cmd = tmp;
		
		if (cmd.find("!KICK", 0) == 0)
		{
			delete in_pipe, delete out_pipe;
			delete ballot_tmcg;
			CloseHandle(gp_handle);
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" <<	gp_nick.size() << "~" << -b << "!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick <<	" :" << _("room completely occupied") << std::endl << std::flush;
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
			{
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete in_pipe, delete out_pipe;
				delete ballot_tmcg;
				CloseHandle(gp_handle);
				return -5;
			}
		}
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string msg = cmd.substr(cmd.find(" ", 4) + 1, cmd.length() - cmd.find(" ", 4) - 1);
			if (msg.find("PORT ", 0) == 0)
			{
				std::string port = msg.substr(5, msg.length() - 5);
				if (std::find(gp_rdport.begin(), gp_rdport.end(), nick)	== gp_rdport.end())
				{
					gp_rdport.push_back(nick);
					gp_ports[nick] = atoi(port.c_str());
				}
			}
			if (msg.find("VOTE", 0) == 0)
			{
				if (std::find(gp_voters.begin(), gp_voters.end(), nick)
					== gp_voters.end())
				{
					gp_voters.push_back(nick);
					if (nick_key.find(nick) != nick_key.end())
						nick = nick_key[nick].name;
					std::cout << XX << _("BALLOT") << ": " << nick << " " << _("has voted") << std::endl;
				}
			}
		}
		if ((cmd.find("CMD ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string msg = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string vstr = cmd.substr(cmd.find(" ", 4) + 1, cmd.length() - cmd.find(" ", 4) - 1);
			
			if ((msg.find("VOTE", 0) == 0) || (msg.find("vote", 0) == 0))
			{
				vote = atoi(vstr.c_str());
				if (vote < b_pow)
				{
					if  (!has_voted)
					{
						std::cout << XX << _("BALLOT: you voted for value r = ") << vote << std::endl;
						*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :VOTE" << std::endl << std::flush;
						gp_voters.push_back(vnicks[pkr_self]);
						has_voted = true;
					}
					else
						std::cout << XX << _("BALLOT: changed your vote to r = ") << vote << std::endl;
				}
				else
					std::cout << XX << _("BALLOT ERROR: value of your vote is out of range ") << "(0 <= r < " << b_pow << ") " << 
						_("try again") << std::endl;
			}
		}
	}
	std::cout << X << _("Room") << " " << nr << " " << _("establishing secure channels") << " ..." << std::endl;
	
	// FIXME: the following part still contains some race conditions
	
	fd_set rfds;				// set of read descriptors
	int mfds = 0;				// highest-numbered descriptor
	struct timeval tv;			// timeout structure
	char *ireadbuf = new char[65536];
	int ireaded = 0;
	size_t pkr_idx = 0;
	std::map<std::string, iosecuresocketstream*> ios_in, ios_out;
	while (pkr_idx < gp_nick.size())
	{
		// select(2) -- initialize file descriptors
		FD_ZERO(&rfds);
		MFD_SET(gp_handle, &rfds);
		MFD_SET(ipipe, &rfds);
		
		// select(2) -- initialize timeout
		tv.tv_sec = 1L;	// seconds
		tv.tv_usec = 0L; // microseconds
		
		// select(2)
		int ret = select(mfds + 1, &rfds, NULL, NULL, &tv);
		
		// error occured
		if (ret < 0)
		{
			if (errno != EINTR)
				perror("ballot_child (select)");
		}
		else if ((ret > 0) && FD_ISSET(gp_handle, &rfds) && (pkr_idx != pkr_self))
		{
			// connection request
			struct sockaddr_in client_in;
			socklen_t client_len = sizeof(client_in);
			int handle = accept(gp_handle, (struct sockaddr*) &client_in, &client_len);
			if (handle < 0)
			{
				perror("ballot_child (accept)");
			}
			else
			{
				// establish and authenticate the connection
				iosocketstream *neighbor = new iosocketstream(handle);
				TMCG_CardSecret cs(gp_nick.size(), b);
				ballot_tmcg->TMCG_CreateCardSecret(cs, pkr, pkr_self);
				*neighbor << cs << std::endl << std::flush;
				char challenge_sig[TMCG_MAX_CARD_CHARS];
				neighbor->getline(challenge_sig, sizeof(challenge_sig));
				std::ostringstream challenge;
				challenge << cs << vnicks[pkr_self];
				if (!neighbor->good())
				{
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
					delete in_pipe, delete out_pipe;
					delete ballot_tmcg;
					CloseHandle(gp_handle);
					delete [] ireadbuf;
					CloseHandle(handle);
					delete neighbor;
					return -72;
				}
				else if (!pkr.keys[pkr_idx].verify(challenge.str(), challenge_sig))
				{
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
					delete in_pipe, delete out_pipe;
					delete ballot_tmcg;
					CloseHandle(gp_handle);
					delete [] ireadbuf;
					CloseHandle(handle);
					delete neighbor;
					return -73;
				}
				else
				{
					neighbor->getline(challenge_sig, sizeof(challenge_sig));
					if (cs.import(challenge_sig))
					{
						std::ostringstream response;
						response << challenge_sig << vnicks[pkr_idx];
						*neighbor << sec.sign(response.str()) << std::endl << std::flush;
						
						// exchange secret keys for securesocketstreams
						unsigned char *key1 = new unsigned char[TMCG_SAEP_S0];
						unsigned char *key2 = new unsigned char[TMCG_SAEP_S0];
						unsigned char *dv = new unsigned char[TMCG_SAEP_S0];
						neighbor->getline(challenge_sig, sizeof(challenge_sig));
						if (!sec.decrypt(dv, challenge_sig))
						{
							std::cerr << _("TMCG: decrypt() failed") << std::endl;
							delete [] key1;
							delete [] key2;
							delete [] dv;
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
							delete in_pipe, delete out_pipe;
							delete ballot_tmcg;
							CloseHandle(gp_handle);
							delete [] ireadbuf;
							CloseHandle(handle);
							delete neighbor;
							return -74;
						}
						memcpy(key2, dv, TMCG_SAEP_S0);
						gcry_randomize(key1, TMCG_SAEP_S0, GCRY_STRONG_RANDOM);
						*neighbor << pkr.keys[pkr_idx].encrypt(key1) << std::endl << std::flush;
						ios_in[vnicks[pkr_idx]] = new iosecuresocketstream(handle, key1, 16, key2, 16);
#ifndef NDEBUG
						std::cerr << "ios_in[" << vnicks[pkr_idx] << "]" << std::endl;
#endif
						delete neighbor;
						delete [] key1;
						delete [] key2;
						delete [] dv;						
						pkr_idx++;
					}
					else
					{
						*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
						delete in_pipe, delete out_pipe;
						delete ballot_tmcg;
						CloseHandle(gp_handle);
						delete [] ireadbuf;
						CloseHandle(handle);
						delete neighbor;
						return -76;
					}
				}
			}
			CloseHandle(handle);
		}
		else if ((ret > 0) && FD_ISSET(ipipe, &rfds))
		{
			// pipe request
			ssize_t num = read(ipipe, ireadbuf + ireaded, 65536 - ireaded);
			ireaded += num;
			if (ireaded > 0)
			{
				std::vector<int> pos_delim;
				int cnt_delim = 0, cnt_pos = 0, pos = 0;
				for (int i = 0; i < ireaded; i++)
					if (ireadbuf[i] == '\n')
						cnt_delim++, pos_delim.push_back(i);
				while (cnt_delim >= 1)
				{
					char tmp[65536];
					memset(tmp, 0, sizeof(tmp));
					memcpy(tmp, ireadbuf + cnt_pos, pos_delim[pos] - cnt_pos);
					--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
					std::string cmd = tmp;
					// do operation
					if ((cmd == "") || (cmd.find("!KICK", 0) == 0))
					{
						delete in_pipe, delete out_pipe;
						delete ballot_tmcg;
						CloseHandle(gp_handle);
						delete [] ireadbuf;
						return -1;
					}
					if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
					{
						*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << -b << "!" << std::endl << std::flush;
					}
					if (neu && (cmd.find("JOIN ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " <<  nick << " :" << _("room completely occupied") <<
							std::endl << std::flush;
					}
					if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
						{
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
							delete in_pipe, delete out_pipe;
							delete ballot_tmcg;
							CloseHandle(gp_handle);
							delete [] ireadbuf;
							return -77;
						}
					}
					if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
					{
						std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
						std::string msg = cmd.substr(cmd.find(" ", 4) + 1, cmd.length() - cmd.find(" ", 4) - 1);
					}
				}
				char tmp[65536];
				memset(tmp, 0, sizeof(tmp));
				ireaded -= cnt_pos;
				memcpy(tmp, ireadbuf + cnt_pos, ireaded);
				memcpy(ireadbuf, tmp, ireaded);
			}
			if (num == 0)
			{
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete in_pipe, delete out_pipe;
				delete ballot_tmcg;
				CloseHandle(gp_handle);
				delete [] ireadbuf;
				return -78;
			}
			else if (num < 0)
				perror("SecureSkat_vote::ballot_child (read)");
		}
		
		if (ret == 0)
		{
			// timeout occured
			if (pkr_self == pkr_idx)
			{
				// establish connections
				for (size_t i = 0; i < vnicks.size(); i++)
				{
					if (i != pkr_self)
					{
						// create TCP/IP connection
						int handle = ConnectToHost(nick_players[vnicks[i]].c_str(), gp_ports[vnicks[i]]);
						if (handle < 0)
						{
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
							delete in_pipe, delete out_pipe;
							delete ballot_tmcg;
							CloseHandle(gp_handle);
							delete [] ireadbuf;
							return -79;
						}
						iosocketstream *neighbor = new iosocketstream(handle);
						
						// authenticate connection
						char tmp[TMCG_MAX_CARD_CHARS];
						TMCG_CardSecret cs(gp_nick.size(), b);
						// receive challenge
						neighbor->getline(tmp, sizeof(tmp));
						if (cs.import(tmp))
						{
							std::ostringstream challenge, response;
							challenge << tmp << vnicks[i];
							// send signature
							*neighbor << sec.sign(challenge.str()) << std::endl << std::flush;
							// create new challenge
							ballot_tmcg->TMCG_CreateCardSecret(cs, pkr, pkr_self);
							// send challenge
							*neighbor << cs << std::endl << std::flush;
							// receive signature
							neighbor->getline(tmp, sizeof(tmp));
							// verify signature
							response << cs << vnicks[pkr_self];
							if (!neighbor->good())
							{
								*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
								delete in_pipe, delete out_pipe;
								delete ballot_tmcg;
								CloseHandle(gp_handle);
								delete [] ireadbuf;
								CloseHandle(handle);
								delete neighbor;
								return -80;
							}
							else if (!pkr.keys[i].verify(response.str(), tmp))
							{
								*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
								delete in_pipe, delete out_pipe;
								delete ballot_tmcg;
								CloseHandle(gp_handle);
								delete [] ireadbuf;
								CloseHandle(handle);
								delete neighbor;
								return -81;
							}
						}
						else
						{
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
							delete in_pipe, delete out_pipe;
							delete ballot_tmcg;
							CloseHandle(gp_handle);
							delete [] ireadbuf;
							CloseHandle(handle);
							delete neighbor;
							return -82;
						}
						
						// exchange secret keys for securesocketstreams
						unsigned char *key1 = new unsigned char[TMCG_SAEP_S0];
						unsigned char *key2 = new unsigned char[TMCG_SAEP_S0];
						unsigned char *dv = new unsigned char[TMCG_SAEP_S0];
						gcry_randomize(key1, TMCG_SAEP_S0, GCRY_STRONG_RANDOM);
						*neighbor << pkr.keys[i].encrypt(key1) << std::endl << std::flush;
						
						neighbor->getline(tmp, sizeof(tmp));
						if (!sec.decrypt(dv, tmp))
						{
							std::cerr << _("TMCG: decrypt() failed") << std::endl;
							delete [] key1, delete [] key2, delete [] dv;
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
							delete in_pipe, delete out_pipe;
							delete ballot_tmcg;
							CloseHandle(gp_handle);
							delete [] ireadbuf;
							CloseHandle(handle);
							delete neighbor;
							return -84;
						}
						memcpy(key2, dv, TMCG_SAEP_S0);
						ios_out[vnicks[i]] = 
							new iosecuresocketstream(handle, key1, 16, key2, 16);
#ifndef NDEBUG
						std::cerr << "ios_out[" << vnicks[i] << "]" << std::endl;
#endif
						delete neighbor, delete [] key1, delete [] key2, delete [] dv;
						CloseHandle(handle);
					}
				}
				pkr_idx++;
			}
		}
	} // while
	delete [] ireadbuf;
	
	// VTMF initialization
	BarnettSmartVTMF_dlog *vtmf;
	if (pkr_self == 0)
	{
		vtmf = new BarnettSmartVTMF_dlog();
		for (size_t i = 1; i < vnicks.size(); i++)
			vtmf->PublishGroup(*ios_out[vnicks[i]]);
	}
	else
	{
		vtmf = new BarnettSmartVTMF_dlog(*ios_in[vnicks[0]]);
		if (!ios_in[vnicks[0]]->good())
		{
std::cerr << "BAD!" << std::endl;
		}
	}
	if (!vtmf->CheckGroup())
	{
		std::cerr << ">< " << _("VTMF ERROR") << ": " << _("function CheckGroup() failed") << std::endl;
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete vtmf;
		for (size_t ii = 0; ii < vnicks.size(); ii++)
			delete ios_out[vnicks[ii]];
		delete in_pipe, delete out_pipe;
		delete ballot_tmcg;
		CloseHandle(gp_handle);
		return -90;
	}
	vtmf->KeyGenerationProtocol_GenerateKey();
	for (size_t i = 0; i < vnicks.size(); i++)
	{
		if (i != pkr_self)
		{
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*ios_in[vnicks[i]]))
			{
				std::cerr << ">< " << _("VTMF ERROR") << ": " << _("function KeyGenerationProtocol_UpdateKey() failed") << 
					" " << _("for") << " " << vnicks[i] << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete vtmf;
				for (size_t ii = 0; ii < vnicks.size(); ii++)
					delete ios_out[vnicks[ii]];
				delete in_pipe, delete out_pipe;
				delete ballot_tmcg;
				CloseHandle(gp_handle);
				return -90;
			}
		}
		else
		{
			for (size_t j = 0; j < vnicks.size(); j++)
			{
				if (j != pkr_self)
					vtmf->KeyGenerationProtocol_PublishKey(*ios_out[vnicks[j]]);
			}
		}
	}
	vtmf->KeyGenerationProtocol_Finalize();
	
	// create private card for ballot
	VTMF_Card vote_c;
	VTMF_CardSecret vote_cs;
	ballot_tmcg->TMCG_CreatePrivateCard(vote_c, vote_cs, vtmf, vote);
	TMCG_Stack<VTMF_Card> s;
	
	// send and receive private cards for ballot
	for (size_t i = 0; i < vnicks.size(); i++)
	{
		if (i != pkr_self)
		{
			VTMF_Card c;
			*ios_in[vnicks[i]] >> c;
			
			if (ios_in[vnicks[i]]->good())
			{
				s.push(c);
			}
			else
			{
				std::cerr << XX << _("BALLOT ERROR: bad card from ") << vnicks[i] << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete vtmf;
				for (size_t ii = 0; ii < vnicks.size(); ii++)
					delete ios_out[vnicks[ii]];
				delete in_pipe, delete out_pipe;
				delete ballot_tmcg;
				CloseHandle(gp_handle);
				return -85;
			}
		}
		else
		{
			s.push(vote_c);
			for (size_t j = 0; j < vnicks.size(); j++)
			{
				if (j != pkr_self)
					*ios_out[vnicks[j]] << vote_c << std::endl << std::flush;
			}
		}
	}
	
	// create stack secret
	TMCG_Stack<VTMF_Card> s2;
	TMCG_StackSecret<VTMF_CardSecret> ss;
	ballot_tmcg->TMCG_CreateStackSecret(ss, false, s.size(), vtmf);
	
	// mix the ballot stack
	for (size_t i = 0; i < vnicks.size(); i++)
	{
		if (i != pkr_self)
		{
			*ios_in[vnicks[i]] >> s2;
			if (ios_in[vnicks[i]]->good())
			{
				if (ballot_tmcg->TMCG_VerifyStackEquality(s, s2, false, vtmf, *ios_in[vnicks[i]], *ios_in[vnicks[i]]))
				{
					s.clear();
					s = s2;
					s2.clear();
				}
				else
				{
					std::cerr << XX << _("BALLOT ERROR: bad ZNP from ") << vnicks[i] << std::endl;
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
					delete vtmf;
					for (size_t ii = 0; ii < vnicks.size(); ii++)
						delete ios_out[vnicks[ii]];
					delete in_pipe, delete out_pipe;
					delete ballot_tmcg;
					CloseHandle(gp_handle);
					return -85;
				}
			}
			else
			{
				std::cerr << XX << _("BALLOT ERROR: bad stack from ") << vnicks[i] << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete vtmf;
				for (size_t ii = 0; ii < vnicks.size(); ii++)
					delete ios_out[vnicks[ii]];
				delete in_pipe, delete out_pipe;
				delete ballot_tmcg;
				CloseHandle(gp_handle);
				return -85;
			}
		}
		else
		{
			ballot_tmcg->TMCG_MixStack(s, s2, ss, vtmf);
			for (size_t j = 0; j < vnicks.size(); j++)
			{
				if (j != pkr_self)
				{
					*ios_out[vnicks[j]] << s2 << std::endl << std::flush;
					ballot_tmcg->TMCG_ProveStackEquality(s, s2, ss, false, vtmf, *ios_out[vnicks[j]], *ios_out[vnicks[j]]);
				}
			}
			s.clear();
			s = s2;
			s2.clear();
		}
	}
	
	std::vector<size_t> br;
	for (size_t k = 0; k < s.size(); k++)
	{
		ballot_tmcg->TMCG_SelfCardSecret(s[k], vtmf);
		
		// open cards to get result of the voting
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
			{
				if (!ballot_tmcg->TMCG_VerifyCardSecret(s[k], vtmf, *ios_in[vnicks[i]], *ios_in[vnicks[i]]))
				{
					std::cerr << XX << _("BALLOT ERROR: bad ZNP from ") << vnicks[i] << std::endl;
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
					delete vtmf;
					for (size_t ii = 0; ii < vnicks.size(); ii++)
						delete ios_out[vnicks[ii]];
					delete in_pipe, delete out_pipe;
					delete ballot_tmcg;
					CloseHandle(gp_handle);
					return -85;
				}
			}
			else
			{
				std::stringstream proof;
				ballot_tmcg->TMCG_ProveCardSecret(s[k], vtmf, proof, proof);
				for (size_t j = 0; j < vnicks.size(); j++)
				{
					if (j != pkr_self)
						*ios_out[vnicks[j]] << proof.str() << std::flush;
				}
			}
		}
		br.push_back(ballot_tmcg->TMCG_TypeOfCard(s[k], vtmf));
	}
	
	// output votes
	std::cout << XXX << _("BALLOT RESULT:") << " ";
	for (size_t k = 0; k < br.size(); k++)
	{
		std::cout << br[k] << " ";
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :RESULT " << br[k] << std::endl << std::flush;
	}
	std::cout << std::endl;
	sleep(1);
	
	// announce table destruction
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|0~" << -b << "!" << std::endl << std::flush;
	
	// exit from room
	for (size_t ii = 0; ii < vnicks.size(); ii++)
		delete ios_out[vnicks[ii]];
	CloseHandle(gp_handle);
	delete vtmf;
	delete ballot_tmcg;
	*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
	delete in_pipe;
	delete out_pipe;
	
	return 0;
}
