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

int ballot_child
	(const std::string &nr, int b, bool neu, int ipipe, int opipe, const std::string &master)
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
	gp_nick.push_back(pub.keyid());
	gp_name[pub.keyid()] = pub.name;
	if (neu)
		*out_pipe << "PRIVMSG #openSkat :" << nr << "|1~" << -b << "!" << 
			std::endl << std::flush;
	
	// wait for voters
	while (1)
	{
		char tmp[10000];
		in_pipe->getline(tmp, sizeof(tmp));
		std::string cmd = tmp;
		
		if ((cmd == "") || (cmd.find("!KICK", 0) == 0) || (b <= 0))
		{
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << gp_nick.size() <<
				"~" << -b << "!" << std::endl << std::flush;
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
						*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << 
							gp_nick.size() << "~" << b << "!" << std::endl << std::flush;
					}
					else
						*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
							_("room completely occupied") << std::endl << std::flush;
				}
				else
					*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
						_("voter was at room creation not present") << std::endl << std::flush;
			}
			else
				*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
					_("key exchange with owner is incomplete") << std::endl << std::flush;
		}
		if (!neu && ((cmd.find("JOIN ", 0) == 0) || (cmd.find("WHO ", 0) == 0)))
		{
			std::string nick = (cmd.find("JOIN ", 0) == 0) ?
				cmd.substr(5, cmd.length() - 5) : cmd.substr(4, cmd.length() - 4);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
					gp_nick.push_back(nick), gp_name[nick] = nick_key[nick].name;
				else
					*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
						_("voter was at room creation not present") << std::endl << std::flush;
			}
			else
			{
				std::cout << X << _("key exchange with") << " " << nick << " " << 
					_("is incomplete") << std::endl;
				*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
				return -1;
			}
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(gp_nick.begin(), gp_nick.end(), nick)	!= gp_nick.end())
			{
				gp_nick.remove(nick),	gp_name.erase(nick);
			}
		}
		
		// control messages
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string msg = cmd.substr(cmd.find(" ", 4) + 1, 
				cmd.length() - cmd.find(" ", 4) - 1);
			
			if ((msg == "!READY") && (nick == master))
				break;
		}
		
		// stdin messages
		if ((cmd.find("CMD ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string msg = cmd.substr(4, cmd.find(" ", 4) - 4);
			
			if (neu && ((msg.find("OPEN", 0) == 0) || (msg.find("open", 0) == 0)))
			{
				*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << gp_nick.size() <<
					"~" << b << "!" << std::endl << std::flush;
				*out_pipe << "PRIVMSG #openSkat_" << nr << " :!READY" << std::endl << std::flush;
				break;
			}
		}
	}
	std::cout << X << _("Room") << " " << nr << " " << _("preparing the ballot") << 
		" ..." << std::endl;
	// prepare ballot (create PKR, bind port for secure connection)
	assert(gp_nick.size() <= TMCG_MAX_PLAYERS);
	assert(b <= TMCG_MAX_TYPEBITS);
	SchindelhauerTMCG *ballot_tmcg = 							// n players, 2^b cards
		new SchindelhauerTMCG(security_level, gp_nick.size(), b);
	TMCG_PublicKeyRing pkr;
	std::vector<std::string> vnicks;
	size_t pkr_i = 0, pkr_self = 0;
	gp_nick.sort();
	for (std::list<std::string>::const_iterator pi = gp_nick.begin(); 
		pi != gp_nick.end(); pi++, pkr_i++)
	{
		vnicks.push_back(*pi);
		if (*pi == pub.keyid())
		{
			pkr_self = pkr_i;
			pkr.key[pkr_i] = pub;
		}
		else
			pkr.key[pkr_i] = nick_key[*pi];
	}
	int gp_handle, gp_port = BindEmptyPort(7900);
	if ((gp_handle = ListenToPort(gp_port)) < 0)
	{
		*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
		return -4;
	}
	std::ostringstream ost;
	ost << "PRIVMSG #openSkat_" << nr << " :PORT " << gp_port << std::endl;
	*out_pipe << ost.str() << std::flush;
	std::cout << X << _("Room") << " " << nr << " " << _("with");
	for (size_t i = 0; i < gp_nick.size(); i++)
		std::cout << " '" << pkr.key[i].name << "'";
	std::cout << " " << _("ready") << "." << std::endl;
	std::cout << XX << _("BALLOT: please make your vote with command") << 
		" /<nr> vote <r>" << std::endl;
	
	std::list<std::string> gp_rdport, gp_voters;
	std::map<std::string, int> gp_ports;
	size_t vote = 0;
	bool has_voted = false;
	while ((gp_rdport.size() < (gp_nick.size() - 1)) || 
		(gp_voters.size() < gp_nick.size()))
	{
		char tmp[10000];
		in_pipe->getline(tmp, sizeof(tmp));
		std::string cmd = tmp;
		
		if (cmd.find("!KICK", 0) == 0)
		{
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << gp_nick.size() << 
				"~" << -b << "!" << std::endl << std::flush;
		}		
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
				_("room completely occupied") << std::endl << std::flush;
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
			{
				*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
				return -5;
			}
		}
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string msg = cmd.substr(cmd.find(" ", 4) + 1, 
				cmd.length() - cmd.find(" ", 4) - 1);
			if (msg.find("PORT ", 0) == 0)
			{
				std::string port = msg.substr(5, msg.length() - 5);
				if (std::find(gp_rdport.begin(), gp_rdport.end(), nick) 
					== gp_rdport.end())
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
					std::cout << XX << _("BALLOT") << ": " << nick << " " << 
						_("has voted") << std::endl;
				}
			}
		}
		if ((cmd.find("CMD ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string msg = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string vstr = cmd.substr(cmd.find(" ", 4) + 1, 
				cmd.length() - cmd.find(" ", 4) - 1);
			
			if ((msg.find("VOTE", 0) == 0) || (msg.find("vote", 0) == 0))
			{
				vote = atoi(vstr.c_str());
				if  (!has_voted && (vote < b_pow))
				{
					std::cout << XX << _("BALLOT: you voted for value r = ") << vote << std::endl;
					*out_pipe << "PRIVMSG #openSkat_" << nr << " :VOTE" << std::endl << std::flush;
					gp_voters.push_back(vnicks[pkr_self]);
					has_voted = true;
				}
				else
					std::cout << XX << _("BALLOT ERROR: already voted or bad value <r> ") <<
						"(0 <= r < " << b_pow << ")" << std::endl;
			}
		}
	}
	std::cout << X << _("Room") << " " << nr << " " <<
		_("establishing secure channels") << " ..." << std::endl;

	// FIXME: the following part contains race conditions
	
	fd_set rfds;									// set of read descriptors
	int mfds = 0;									// highest-numbered descriptor
	struct timeval tv;						// timeout structure
	char *ireadbuf = (char*)malloc(65536);
	int ireaded = 0;
	size_t pkr_idx = 0;
	std::map<std::string, iosecuresocketstream*>	ios_in, ios_out;
	while (pkr_idx < gp_nick.size())
	{
		// select(2) -- initalize file descriptors
		FD_ZERO(&rfds);
		MFD_SET(gp_handle, &rfds);
		MFD_SET(ipipe, &rfds);
		
		// select(2) -- initalize timeout
		tv.tv_sec = 1L;			// seconds
		tv.tv_usec = 0L;		// microseconds
		
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
			int handle = accept(gp_handle, 
				(struct sockaddr*) &client_in, &client_len);
			if (handle < 0)
			{
				perror("ballot_child (accept)");
			}
			else
			{
				// check host address
				struct sockaddr_in sin;
				struct hostent *hostinf = 
					gethostbyname(nick_players[vnicks[pkr_idx]].c_str());
				if (hostinf != NULL)
				{ 
					memcpy((char*)&sin.sin_addr, hostinf->h_addr, hostinf->h_length);
				}
				else
				{
					perror("ballot_child (gethostbyname)");
					*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
					return -70;
				}
				if (client_in.sin_addr.s_addr != sin.sin_addr.s_addr)
				{
					*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
					return -71;
				}
				// establish connection
				iosocketstream *neighbor = new iosocketstream(handle);
				TMCG_CardSecret cs;
				ballot_tmcg->TMCG_CreateCardSecret(cs, pkr, pkr_self);
				*neighbor << cs << std::endl << std::flush;
				char challenge_sig[TMCG_MAX_CARD_CHARS];
				neighbor->getline(challenge_sig, sizeof(challenge_sig));
				std::ostringstream challenge;
				challenge << cs << vnicks[pkr_self];
				if (!neighbor->good())
				{
					delete neighbor, close(handle);
					*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
					return -72;
				}
				else if (!pkr.key[pkr_idx].verify(challenge.str(), challenge_sig))
				{
					delete neighbor, close(handle);
					*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
					return -73;
				}
				else
				{
					neighbor->getline(challenge_sig, sizeof(challenge_sig));
					if (cs.import(challenge_sig))
					{
						std::ostringstream response;
						response << challenge_sig << vnicks[pkr_idx];
						*neighbor << sec.sign(response.str()) <<
							std::endl << std::flush;
						
						// exchange secret keys for securesocketstreams
						assert (gcry_md_test_algo(TMCG_GCRY_MD_ALGO) == 0);
						char *key1 = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
						char *key2 = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
						neighbor->getline(challenge_sig, sizeof(challenge_sig));
						const char *dv = sec.decrypt(challenge_sig);
						if (dv == NULL)
						{
							std::cerr << _("TMCG: DecryptValue() failed") << std::endl;
							delete neighbor, close(handle);
							*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
							return -74;
						}
						memcpy(key2, dv, gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO));
						
						gcry_randomize((unsigned char*)key1,
							gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO), GCRY_STRONG_RANDOM);
						*neighbor << pkr.key[pkr_idx].encrypt(key1) << std::endl
							<< std::flush;
						delete neighbor;
						iosecuresocketstream *secure =
							new iosecuresocketstream(handle, key1, 16, key2, 16);
						ios_in[vnicks[pkr_idx]] = secure;
						delete [] key1, delete [] key2;
						
						pkr_idx++;
					}
					else
					{
						delete neighbor, close(handle);
						*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
						return -76;
					}
				}
			}
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
					bzero(tmp, sizeof(tmp));
					memcpy(tmp, ireadbuf + cnt_pos, pos_delim[pos] - cnt_pos);
					--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
					std::string cmd = tmp;
					// do operation
					if ((cmd == "") || (cmd.find("!KICK", 0) == 0))
					{
						return -1;
					}
					if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
					{
						*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << 
							gp_nick.size() << "~" << -b << "!" << std::endl << std::flush;
					}
					if (neu && (cmd.find("JOIN ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
							_("room completely occupied") << std::endl << std::flush;
					}
					if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
						{
							*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
							return -77;
						}
					}
					if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
					{
						std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
						std::string msg = cmd.substr(cmd.find(" ", 4) + 1, 
							cmd.length() - cmd.find(" ", 4) - 1);
					}
				}
				char tmp[65536];
				bzero(tmp, sizeof(tmp));
				ireaded -= cnt_pos;
				memcpy(tmp, ireadbuf + cnt_pos, ireaded);
				memcpy(ireadbuf, tmp, ireaded);
			}
			if (num == 0)
			{
				*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
				return -78;
			}
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
						int handle = ConnectToHost(
							nick_players[vnicks[i]].c_str(), gp_ports[vnicks[i]]
						);
						if (handle < 0)
						{
							*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
							return -79;
						}
						iosocketstream *neighbor = new iosocketstream(handle);
						
						// authenticate connection
						char tmp[TMCG_MAX_CARD_CHARS];
						TMCG_CardSecret cs;
						// receive challenge
						neighbor->getline(tmp, sizeof(tmp));
						if (cs.import(tmp))
						{
							std::ostringstream challenge, response;
							challenge << tmp << vnicks[i];
							// send signature
							*neighbor << sec.sign(challenge.str()) << std::endl
								<< std::flush;
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
								delete neighbor, close(handle);
								*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
								return -80;
							}
							else if (!pkr.key[i].verify(response.str(), tmp))
							{
								delete neighbor, close(handle);
								*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
								return -81;
							}
						}
						else
						{
							delete neighbor, close(handle);
							*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
							return -82;
						}
						
						// exchange secret keys for securesocketstreams
						assert(gcry_md_test_algo(TMCG_GCRY_MD_ALGO) == 0);
						char *key1 = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
						char *key2 = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
						gcry_randomize((unsigned char*)key1,
							gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO), GCRY_STRONG_RANDOM);
						*neighbor << pkr.key[i].encrypt(key1) << std::endl << std::flush;
						
						neighbor->getline(tmp, sizeof(tmp));
						const char *dv = sec.decrypt(tmp);
						if (dv == NULL)
						{
							std::cerr << _("TMCG: DecryptValue() failed") << std::endl;
							delete neighbor, close(handle);
							*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
							return -84;
						}
						memcpy(key2, dv, gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)); 
						delete neighbor;
						iosecuresocketstream *secure = 
							new iosecuresocketstream(handle, key1, 16, key2, 16);
						ios_out[vnicks[i]] = secure;
						delete [] key1, delete [] key2;
					}
				}
				
				pkr_idx++;
			}
		}
	} // while
	
	// VTMF initalization
	BarnettSmartVTMF_dlog *vtmf;
	if (pkr_self == 0)
	{
#ifdef COMMON_DDH_GROUP
		std::stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP << std::endl;
		vtmf = new BarnettSmartVTMF_dlog(ddh_group);
#else
		vtmf = new BarnettSmartVTMF_dlog();
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
				vtmf->PublishGroup(*ios_out[vnicks[i]]);
		}
#endif
		if (!vtmf->CheckGroup())
		{
			std::cout << ">< Fehler in VTMF: CheckGroup() failed" << std::endl;
			return -90;
		}
		vtmf->KeyGenerationProtocol_GenerateKey();
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
			{
				if (!vtmf->KeyGenerationProtocol_UpdateKey(*ios_in[vnicks[i]]))
				{
					std::cout << ">< Fehler in VTMF: UpdateKey(" << vnicks[i] <<
						") failed" << std::endl;
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
	}
	else
	{
#ifdef COMMON_DDH_GROUP
		std::stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP << std::endl;
		vtmf = new BarnettSmartVTMF_dlog(ddh_group);
#else
		vtmf = new BarnettSmartVTMF_dlog(*ios_in[vnicks[0]]);
#endif
		if (!vtmf->CheckGroup())
		{
			std::cout << ">< Fehler in VTMF: CheckGroup() failed" << std::endl;
			return -90;
		}
		vtmf->KeyGenerationProtocol_GenerateKey();
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
			{
				if (!vtmf->KeyGenerationProtocol_UpdateKey(*ios_in[vnicks[i]]))
				{
					std::cout << ">< Fehler in VTMF: UpdateKey(" << vnicks[i] <<
						") failed" << std::endl;
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
	}
	
	// create private card for ballot
	VTMF_Card vote_c;
	VTMF_CardSecret vote_cs;
	ballot_tmcg->TMCG_CreatePrivateCard(vote_c, vote_cs, vtmf, vote);
	TMCG_Stack<VTMF_Card> s;
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	
	// send and receive private cards for ballot
	for (size_t i = 0; i < vnicks.size(); i++)
	{
		if (i != pkr_self)
		{
			VTMF_Card c;
			ios_in[vnicks[i]]->getline(tmp, TMCG_MAX_STACK_CHARS);
			
			if (c.import(tmp))
			{
				s.push(c);
			}
			else
			{
				std::cerr << XX << _("BALLOT ERROR: bad card from ") << vnicks[i] << std::endl;
				*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
				return -85;
			}
		}
		else
		{
			s.push(vote_c);
			for (size_t j = 0; j < vnicks.size(); j++)
			{
				if (j != pkr_self)
					*(ios_out[vnicks[j]]) << vote_c << std::endl << std::flush;
			}
		}
	}
	
	// create stack secret
	TMCG_Stack<VTMF_Card> s2;
	TMCG_StackSecret<VTMF_CardSecret> ss;
	ballot_tmcg->TMCG_CreateStackSecret(ss, false, s.size(), vtmf);
	
	// mix ballot stack
	for (size_t i = 0; i < vnicks.size(); i++)
	{
		if (i != pkr_self)
		{
			ios_in[vnicks[i]]->getline(tmp, TMCG_MAX_STACK_CHARS);
			if (s2.import(tmp))
			{
				if (ballot_tmcg->TMCG_VerifyStackEquality(s, s2, false, vtmf,
					*(ios_in[vnicks[i]]), *(ios_in[vnicks[i]])))
				{
					s.clear();
					s = s2;
					s2.clear();
				}
				else
				{
					std::cerr << XX << _("BALLOT ERROR: bad ZNP from ") << vnicks[i] << std::endl;
					*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
					return -85;
				}
			}
			else
			{
				std::cerr << XX << _("BALLOT ERROR: bad stack from ") << vnicks[i] << std::endl;
				*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
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
					*(ios_out[vnicks[j]]) << s2 << std::endl << std::flush;
					ballot_tmcg->TMCG_ProofStackEquality(s, s2, ss, false, vtmf,
						*(ios_out[vnicks[j]]), *(ios_out[vnicks[j]]));
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
		
		// open cards to get result of the ballot
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
			{
				if (!ballot_tmcg->TMCG_VerifyCardSecret(s[k], vtmf,
					*(ios_in[vnicks[i]]), *(ios_in[vnicks[i]])))
				{
					std::cerr << XX << _("BALLOT ERROR: bad ZNP from ") << vnicks[i] << std::endl;
					*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
					return -85;
				}
			}
			else
			{
				for (size_t j = 0; j < vnicks.size(); j++)
				{
					if (j != pkr_self)
					{
						ballot_tmcg->TMCG_ProofCardSecret(s[k], vtmf,
							*(ios_out[vnicks[j]]), *(ios_out[vnicks[j]]));
					}
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
		*out_pipe << "PRIVMSG #openSkat_" << nr << " :RESULT " <<
			br[k] << std::endl << std::flush;
	}
	std::cout << std::endl;
	sleep(1);
	
	delete [] tmp;
	
	// announce table destruction
	if (neu)
		*out_pipe << "PRIVMSG #openSkat :" << nr << "|0~" << -b << "!" <<
			std::endl << std::flush;
	
	// exit from game
	delete vtmf;
	delete ballot_tmcg;
	*out_pipe << "PART #openSkat_" << nr << std::endl << std::flush;
	delete in_pipe;
	delete out_pipe;
	
	return 0;
}
