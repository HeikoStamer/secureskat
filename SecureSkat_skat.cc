/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2007, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#include "SecureSkat_skat.hh"

int ctl_pid = 0; // PID of the running control program

RETSIGTYPE sig_handler_skat_quit(int sig)
{
	// two lines of dummy code follow to avoid compiler warnings
	if (sig == 0)
		sig = 0;
#ifndef NDEBUG
	std::cerr << "sig_handler_skat_quit: got signal " << sig << std::endl;
#endif
	if (ctl_pid > 0)
	{
		// send SIGQUIT to running control program
		if (kill(ctl_pid, SIGQUIT) < 0)
			perror("sig_handler_skat_quit (kill)");
		waitpid(ctl_pid, NULL, 0);
	}
	exit(-100);
}

extern TMCG_SecretKey sec;
extern TMCG_PublicKey pub;
extern std::map<std::string, TMCG_PublicKey> nick_key;
extern std::map<std::string, std::string> nick_players;
extern std::string game_ctl;
extern char **game_env;

int skat_connect
	(size_t pkr_self, size_t pkr_idx, iosecuresocketstream *&secure, int &handle,
	std::map<std::string, int> gp_ports, const std::vector<std::string> &vnicks,
	TMCG_PublicKeyRing &pkr)
{
	// create TCP/IP connection
	handle = ConnectToHost(nick_players[vnicks[pkr_idx]].c_str(), gp_ports[vnicks[pkr_idx]]);
	if (handle < 0)
		return -4;
	iosocketstream *neighbor = new iosocketstream(handle);
	std::string tmp = "";
	
	// authenticate connection: receive the nonce
	unsigned long int nonce_A = 0;
	*neighbor >> nonce_A;
	neighbor->ignore(1, '\n');
	if (neighbor->good())
	{
		std::ostringstream ost, ost2;
		ost << nonce_A << "<req>" << vnicks[pkr_idx];
		// send the signature
		*neighbor << sec.sign(ost.str()) << std::endl << std::flush;
		// create a fresh nonce
		unsigned long int nonce_B = tmcg_mpz_srandom_ui();
		// send challenge
		*neighbor << nonce_B << std::endl << std::flush;
		// receive the signature
		std::getline(*neighbor, tmp);
		// verify the signature
		ost2 << nonce_A << "<rpl>" << vnicks[pkr_idx] << "<|>" << nonce_B << "<rpl>" << vnicks[pkr_self];
		if (!pkr.keys[pkr_idx].verify(ost2.str(), tmp) || !neighbor->good())
		{
			delete neighbor;
			CloseHandle(handle);
			return -6;
		}
	}
	else
	{
		delete neighbor;
		CloseHandle(handle);
		return -6;
	}
	
	// exchange secret keys for securesocketstreams
	unsigned char *key1 = new unsigned char[TMCG_SAEP_S0];
	unsigned char *key2 = new unsigned char[TMCG_SAEP_S0];
	unsigned char *dv = new unsigned char[TMCG_SAEP_S0];
	gcry_randomize(key1, TMCG_SAEP_S0, GCRY_STRONG_RANDOM);
	*neighbor << pkr.keys[pkr_idx].encrypt(key1) << std::endl << std::flush;
	
	std::getline(*neighbor, tmp);
	if (!sec.decrypt(dv, tmp))
	{
		std::cerr << _("TMCG: decrypt() failed") << std::endl;
		delete neighbor;
		delete [] key1;
		delete [] key2;
		delete [] dv;
		CloseHandle(handle);
		return -6;
	}
	memcpy(key2, dv, TMCG_SAEP_S0);
	delete neighbor;

	// create encrypted stream and release keys
	secure = new iosecuresocketstream(handle, key1, 16, key2, 16);
	delete [] key1;
	delete [] key2;
	delete [] dv;
	return 0;
}

int skat_accept
	(opipestream *out_pipe, int ipipe, const std::string &nr, int r,
	int pkr_self, int pkr_idx, iosecuresocketstream *&secure, int &handle,
	const std::vector<std::string> &vnicks, TMCG_PublicKeyRing &pkr,
	int gp_handle, bool neu, char *ireadbuf, size_t &ireaded)
{
	fd_set rfds;	// set of read descriptors
	int mfds = 0;	// highest-numbered descriptor
	while (1)
	{
		// select(2) -- initialize file descriptors
		FD_ZERO(&rfds);
		if (gp_handle < FD_SETSIZE)
			MFD_SET(gp_handle, &rfds);
		if (ipipe < FD_SETSIZE)
			MFD_SET(ipipe, &rfds);
		// select(2)
		int ret = select(mfds + 1, &rfds, NULL, NULL, NULL);
		// error occured
		if (ret < 0)
		{
			if (errno != EINTR)
				perror("skat_accept (select)");
		}
		
		// connection request
		if ((ret > 0) && FD_ISSET(gp_handle, &rfds))
		{
			struct sockaddr_in client_in;
			socklen_t client_len = sizeof(client_in);
			handle = accept(gp_handle, (struct sockaddr*) &client_in, &client_len);
			if (handle < 0)
			{
				perror("skat_accept (accept)");
				return -4;
			}
			else
			{
				iosocketstream *neighbor = new iosocketstream(handle);
				// create a fresh nonce
				unsigned long int nonce_A = tmcg_mpz_srandom_ui();
				std::ostringstream ost, ost2;
				std::string tmp;
				*neighbor << nonce_A << std::endl << std::flush;
				// receive the signature
				std::getline(*neighbor, tmp);
				// verify the signature
				ost << nonce_A << "<req>" << vnicks[pkr_self];
				if (!pkr.keys[pkr_idx].verify(ost.str(), tmp) || !neighbor->good())
				{
					delete neighbor;
					if (close(handle) < 0)
						perror("skat_accept (close)");
					return -6;
				}
				else
				{
					unsigned long int nonce_B = 0;
					// receive the nonce and reply
					*neighbor >> nonce_B;
					neighbor->ignore(1, '\n');
					if (neighbor->good())
					{
						ost2 << nonce_A << "<rpl>" << vnicks[pkr_self] << "<|>" << nonce_B << "<rpl>" << vnicks[pkr_idx];
						*neighbor << sec.sign(ost2.str()) << std::endl << std::flush;
						// exchange the secret keys for securesocketstream
						unsigned char *key1 = new unsigned char[TMCG_SAEP_S0];
						unsigned char *key2 = new unsigned char[TMCG_SAEP_S0];
						unsigned char *dv = new unsigned char[TMCG_SAEP_S0];
						std::getline(*neighbor, tmp);
						if (!sec.decrypt(dv, tmp))
						{
							std::cerr << _("TMCG: decrypt() failed") << std::endl;
							delete neighbor;
							delete [] key1;
							delete [] key2;
							delete [] dv;
							if (close(handle) < 0)
								perror("skat_accept (close)");
							return -6;
						}
						memcpy(key2, dv, TMCG_SAEP_S0);
						gcry_randomize(key1, TMCG_SAEP_S0, GCRY_STRONG_RANDOM);
						*neighbor << pkr.keys[pkr_idx].encrypt(key1) << std::endl << std::flush;
						delete neighbor;
						// create encrypted stream and release keys
						secure = new iosecuresocketstream(handle, key1, 16, key2, 16);
						delete [] key1;
						delete [] key2;
						delete [] dv;
						break; // exit while-loop
					}
					else
					{
						delete neighbor;
						if (close(handle) < 0)
							perror("skat_accept (close)");
						return -6;
					}
				}
			}
		}
		
		// pipe request
		if ((ret > 0) && FD_ISSET(ipipe, &rfds))
		{
			ssize_t num = read(ipipe, ireadbuf + ireaded, 65536 - ireaded);
			if (num <= 0)
			{
				std::cerr << _("read error in skat_accept() encountered") <<
					" [errno=" << errno << "]" << std::endl;
				break;
			}
			else
				ireaded += num;
			if (ireaded > 0)
			{
				std::vector<size_t> pos_delim;
				size_t cnt_delim = 0, cnt_pos = 0, pos = 0;
				for (size_t i = 0; i < ireaded; i++)
				{
					if (ireadbuf[i] == '\n')
						cnt_delim++, pos_delim.push_back(i);
				}
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
						return -1;
					}
					if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
					{
						*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|3~" << r << "!" << std::endl << std::flush;
					}
					if (neu && (cmd.find("KIEBITZ ", 0) == 0))
					{
						std::string nick = cmd.substr(8, cmd.length() - 8);
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " <<	nick << " :" << _("observers currently not permitted") << 
							std::endl << std::flush;
					}
					if (neu && (cmd.find("JOIN ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " <<	nick << " :" << _("table completely occupied") << 
							std::endl << std::flush;
					}
					if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
							return -5;
					}
				}
				char tmp[65536];
				memset(tmp, 0, sizeof(tmp));
				ireaded -= cnt_pos;
				memcpy(tmp, ireadbuf + cnt_pos, ireaded);
				memcpy(ireadbuf, tmp, ireaded);
			}
			if (num == 0)
				return -50;
			else if (num < 0)
				perror("SecureSkat_skat::skat_accept (read)");
		}
	}
	return 0;
}

int skat_alive
	(iosecuresocketstream *r, iosecuresocketstream *l)
{
	if ((r == NULL) || (l == NULL))
		return -55;
	if (!r->good() || !l->good())
		return -5;
	return 0;
}

void skat_error
	(int error, opipestream *out_pipe, const std::string &nr)
{
	if (error)
	{
		if (error < -1)
		{
			*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
			sleep(1);	// The child has to sleep a second before quitting, because
					// the parent must process the sended PART message first.
		}
		exit(error);
	}
}

int skat_child
	(const std::string &nr, int r, bool neu, int ipipe, int opipe, int hpipe,
	const std::string &master)
{
	SchindelhauerTMCG *gp_tmcg = new SchindelhauerTMCG(80, 3, 5); // 3 players, 2^5 = 32 cards, security level = 80
	std::list<std::string> gp_nick;
	std::map<std::string, std::string> gp_name;
	char *ipipe_readbuf = new char[65536];
	size_t ipipe_readed = 0;
	gp_nick.push_back(pub.keyid(5));
	gp_name[pub.keyid(5)] = pub.name;
	
	// install old signal handlers
	signal(SIGINT, sig_handler_skat_quit);
	signal(SIGQUIT, sig_handler_skat_quit);
	signal(SIGTERM, sig_handler_skat_quit);
	signal(SIGSEGV, sig_handler_skat_quit);
	signal(SIGILL, sig_handler_skat_quit);
	signal(SIGFPE, sig_handler_skat_quit);
	signal(SIGPIPE, sig_handler_skat_quit);
	signal(SIGCHLD, SIG_DFL);
#ifdef NOHUP
	signal(SIGHUP, SIG_IGN);
#endif
	signal(SIGUSR1, SIG_DFL);
	
	opipestream *out_pipe = new opipestream(opipe);
	ipipestream *in_pipe = new ipipestream(ipipe);
	
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
	
	// wait for players
	while (1)
	{
		char tmp[10001];
		memset(tmp, 0, sizeof(tmp));
		in_pipe->getline(tmp, (sizeof(tmp) - 1));
		std::string cmd = tmp;
		
		if ((cmd == "") || (cmd.find("!KICK", 0) == 0))
		{
			delete gp_tmcg;
			delete [] ipipe_readbuf;
			delete in_pipe, delete out_pipe;
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("KIEBITZ ", 0) == 0))
		{
			std::string nick = cmd.substr(8, cmd.length() - 8);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << " :" << _("observers currently not permitted") << std::endl << std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
				{
					gp_nick.push_back(nick);
					gp_name[nick] = nick_key[nick].name;
					*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
				}
				else
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << " :" << _("player was at table creation not present") << 
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
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " <<	nick << " :" << _("player was at table creation not present") << 
						std::endl << std::flush;
			}
			else
			{
				std::cerr << X << _("key exchange with") << " " << nick << " " << _("is incomplete") << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				delete gp_tmcg;
				delete [] ipipe_readbuf;
				delete in_pipe, delete out_pipe;
				return -1;
			}
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(gp_nick.begin(), gp_nick.end(), nick) != gp_nick.end())
			{
				gp_nick.remove(nick);
				gp_name.erase(nick);
			}
		}
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string msg = cmd.substr(cmd.find(" ", 4) + 1, cmd.length() - cmd.find(" ", 4) - 1);
			if ((msg == "!READY") && (nick == master))
				break;
		}
		if (neu && (gp_nick.size() == 3))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :!READY" <<  std::endl << std::flush;
			break;
		}
	}
	std::cout << X << _("Table") << " " << nr << " " << _("preparing the game") << " ..." << std::endl;
	// prepare game (check number of players, create PKR, create connections)
	if ((gp_nick.size() != 3) || (std::find(gp_nick.begin(), gp_nick.end(),	pub.keyid(5)) == gp_nick.end()))
	{
		std::cerr << X << _("wrong number of players") << ": " << gp_nick.size() << std::endl;
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete gp_tmcg;
		delete [] ipipe_readbuf;
		delete in_pipe, delete out_pipe;
		return -2;
	}
	TMCG_PublicKeyRing pkr(gp_nick.size());
	std::vector<std::string> vnicks;
	size_t pkr_i = 0, pkr_self = 0;
	gp_nick.sort();
	for (std::list<std::string>::const_iterator pi = gp_nick.begin(); pi != gp_nick.end(); ++pi)
	{
		vnicks.push_back(*pi);
		if (*pi == pub.keyid(5))
		{
			pkr_self = pkr_i;
			pkr.keys[pkr_i++] = pub;
		}
		else
			pkr.keys[pkr_i++] = nick_key[*pi];
	}
	int gp_handle, gp_port = BindEmptyPort(7800); // use free TCP ports up from 7800
	if (gp_port < 0)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete gp_tmcg;
		delete [] ipipe_readbuf;
		delete in_pipe, delete out_pipe;
		return -4;
	}
	if ((gp_handle = ListenToPort(gp_port)) < 0)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
		delete gp_tmcg;
		delete [] ipipe_readbuf;
		delete in_pipe, delete out_pipe;
		return -4;
	}
	
	std::ostringstream ost;
	ost << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :PORT " << gp_port << std::endl;
	*out_pipe << ost.str() << std::flush;
	std::cout << X << _("Table") << " " << nr << " " << _("with") << " '" <<
		pkr.keys[0].name << "', '" <<
		pkr.keys[1].name << "', '" <<
		pkr.keys[2].name << "' " << _("ready") << "." << std::endl;
	std::list<std::string> gp_rdport;
	std::map<std::string, int> gp_ports;
	while (gp_rdport.size() < 2)
	{
		char tmp[10001];
		memset(tmp, 0, sizeof(tmp));
		in_pipe->getline(tmp, (sizeof(tmp) - 1));
		std::string cmd = tmp;
		
		if (cmd.find("!KICK", 0) == 0)
		{
			CloseHandle(gp_handle);
			delete gp_tmcg;
			delete [] ipipe_readbuf;
			delete in_pipe, delete out_pipe;
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|3~" << r << "!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("KIEBITZ ", 0) == 0))
		{
			std::string nick = cmd.substr(8, cmd.length() - 8);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << " :" << _("observers currently not permitted") << std::endl << std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << " :" << _("table completely occupied") << std::endl << std::flush;
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
			{
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
				CloseHandle(gp_handle);
				delete gp_tmcg;
				delete [] ipipe_readbuf;
				delete in_pipe, delete out_pipe;
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
				if ((std::find(gp_rdport.begin(), gp_rdport.end(), nick) == gp_rdport.end()))
				{
					gp_rdport.push_back(nick);
					gp_ports[nick] = atoi(port.c_str());
				}
			}
		}
	}
	std::cout << X << _("Table") << " " << nr << " " << _("establishing secure channels") << " ..." << std::endl;
	int connect_handle = -1, accept_handle = -1, error = 0;
	iosecuresocketstream *left_neighbor = NULL, *right_neighbor = NULL;
	switch (pkr_self)
	{
		case 0:
			error = skat_connect(pkr_self, 1, left_neighbor, connect_handle, gp_ports, vnicks, pkr);
			skat_error(error, out_pipe, nr);
			error = skat_accept(out_pipe, ipipe, nr, r, pkr_self, 2, right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu, ipipe_readbuf, ipipe_readed);
			skat_error(error, out_pipe, nr);
			break;
		case 1:
			error = skat_accept(out_pipe, ipipe, nr, r, pkr_self, 0, right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu, ipipe_readbuf, ipipe_readed);
			skat_error(error, out_pipe, nr);
			error = skat_connect(pkr_self, 2, left_neighbor, connect_handle, gp_ports, vnicks, pkr);
			skat_error(error, out_pipe, nr);
			break;
		case 2:
			error = skat_accept(out_pipe, ipipe, nr, r, pkr_self, 1, right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu, ipipe_readbuf, ipipe_readed);
			skat_error(error, out_pipe, nr);
			error = skat_connect(pkr_self, 0, left_neighbor, connect_handle, gp_ports, vnicks, pkr);
			skat_error(error, out_pipe, nr);
			break;
	}
	skat_error(skat_alive(right_neighbor, left_neighbor), out_pipe, nr);
	
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|3~" << vnicks[0] << ", " << vnicks[1] << ", " << vnicks[2] << "!" <<	std::endl << std::flush;
	
	// start gui or ai (control program)
	int ctl_i = 0, ctl_o = 0;
	bool pctl = false;
	if (game_ctl != "")
	{
		int pipe1fd[2], pipe2fd[2];
		if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
			perror("skat_child (pipe)");
		else if ((ctl_pid = fork()) < 0)
			perror("skat_child (fork)");
		else
		{
			if (ctl_pid == 0)
			{
				/* BEGIN child code (control program) */
				if (dup2(pipe2fd[0], fileno(stdin)) < 0 || dup2(pipe1fd[1], fileno(stdout)) < 0)
					perror("skat_child (dup2)");
				if ((close(pipe1fd[0]) < 0) || (close(pipe1fd[1]) < 0) || (close(pipe2fd[0]) < 0) || (close(pipe2fd[1]) < 0))
					perror("skat_child (close)");
				char *game_arg[] = { NULL, NULL, NULL };
				game_arg[0] = (char*)game_ctl.c_str();
				if (execve(game_ctl.c_str(), game_arg, game_env) < 0)
					perror("skat_child (execve)");
				// block child in this loop
				while (1) 
					sleep(100);
				/* END child code (control program) */
			}
			else
			{
				pctl = true;
				if ((close(pipe1fd[1]) < 0) || (close(pipe2fd[0]) < 0))
					perror("skat_child (close)");
				ctl_i = pipe1fd[0], ctl_o = pipe2fd[1];
				std::cout << X << _("Execute control process") << " (" << ctl_pid << "): " << std::flush;
				char buffer[1025];
				memset(buffer, 0, sizeof(buffer));
				ssize_t num = read(ctl_i, buffer, (sizeof(buffer) - 1));
				if (num > 0)
				{
					buffer[num] = 0; // null-terminate string
					std::cout << buffer << std::flush;
				}
				else
					std::cout << "... " << _("failed!") << std::endl;
			}
		}
	}
	
	// start the game
	std::cout << X << _("Table") << " " << nr << " " << _("start the game.") << std::endl;
	if (neu)
	{
		// set topic
		*out_pipe << "TOPIC " << MAIN_CHANNEL_UNDERSCORE << nr <<
			" :" << PACKAGE_STRING << std::endl << std::flush;
	}
	int exit_code = skat_game(nr, r, pkr_self, neu, opipe, ipipe, ctl_o, ctl_i,
		gp_tmcg, pkr, sec, right_neighbor, left_neighbor, vnicks, hpipe, pctl,
		ipipe_readbuf, ipipe_readed, MAIN_CHANNEL, MAIN_CHANNEL_UNDERSCORE);
	
	// stop gui or ai (control program)
	if (ctl_pid > 0)
	{
		if (kill(ctl_pid, SIGQUIT) < 0)
			perror("skat_child (kill)");
		waitpid(ctl_pid, NULL, 0);
	}
	
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|0~" << r << "!" << std::endl << std::flush;
	
	// release the game
	delete left_neighbor, delete right_neighbor;
	if (connect_handle > 0)
		CloseHandle(connect_handle);
	if (accept_handle > 0)
		CloseHandle(accept_handle);
	if (exit_code != 6)
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << std::endl << std::flush;
	CloseHandle(gp_handle);
	delete in_pipe, delete out_pipe;
	delete [] ipipe_readbuf;
	delete gp_tmcg;
	return exit_code;
}

