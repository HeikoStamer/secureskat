/*******************************************************************************
   SecureSkat.cc, Secure Peer-to-Peer Implementation of the Card Game "Skat"

 Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007
               Heiko Stamer <stamer@gaos.org>

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

// autoconf header
#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

// C and C++ header
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cassert>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <ctime>
#include <cerrno>
#include <clocale>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <termios.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <libintl.h>

// STL classes
#include <string>
#include <map>
#include <vector>
#include <list>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>

// LibTMCG
#include <libTMCG.hh>

// zlib
#include <zlib.h>

// GNU TLS
#include <gnutls/gnutls.h>

#include "socketstream.hh"
#include "securesocketstream.hh"
#include "pipestream.hh"
#include "SecureSkat_misc.hh"
#include "SecureSkat_pki.hh"
#include "SecureSkat_rnk.hh"
#include "SecureSkat_vtmf.hh"

#define MFD_SET(fd, where) { FD_SET(fd, where); mfds = (fd > mfds) ? fd : mfds; }
#ifdef ENABLE_NLS
	#ifndef _
		#define _(Foo) gettext(Foo)
	#endif
#else
	#ifndef _
		#define _(Bar) Bar
	#endif
#endif

// define SIZES (in characters)
#define KEY_SIZE								1000000L
#define RNK_SIZE								1000000L

// define TIMEOUT (in seconds)
#define PKI_TIMEOUT							1500
#define RNK_TIMEOUT							500
#define ANNOUNCE_TIMEOUT				5
#define CLEAR_TIMEOUT						30
#define AUTOJOIN_TIMEOUT				75

// define CHILDS (bound the number of child processes)
#define PKI_CHILDS							10
#define RNK_CHILDS							5

#define MAIN_CHANNEL						"#openSkat"
#define MAIN_CHANNEL_UNDERSCORE	"#openSkat_"

unsigned long int							security_level = 16;
std::string										game_ctl;
char													**game_env;
TMCG_SecretKey								sec;
TMCG_PublicKey								pub;
std::map<int, char*>					readbuf;
std::map<int, ssize_t>				readed;

std::string										secret_key, public_key, public_prefix;
std::list< std::pair<pid_t, int> >			usr1_stat;
std::map<std::string, std::string>			nick_players, nick_package;
std::map<std::string, int>							nick_p7771, nick_p7772,
																				nick_p7773, nick_p7774, nick_sl;
std::map<std::string, TMCG_PublicKey>		nick_key;
std::list<std::string>						tables;
std::map<std::string, int>					tables_r, tables_p;
std::map<std::string, std::string>			tables_u, tables_o;
pid_t										game_pid, ballot_pid;
std::map<std::string, pid_t>				games_tnr2pid;
std::map<pid_t, std::string>				games_pid2tnr;
std::map<pid_t, int>						games_rnkpipe, games_opipe, games_ipipe;

pid_t										nick_pid;
std::list<pid_t>							nick_pids;
std::list<std::string>						nick_ninf;
std::map<std::string, int>					nick_ncnt;
std::map<pid_t, std::string>				nick_nick, nick_host;
std::map<pid_t, int>						nick_pipe;

std::list<pid_t>							rnk_pids, rnkrpl_pid;
pid_t										rnk_pid;
std::map<std::string, std::string>			rnk;
std::map<std::string, int>					nick_rnkcnt, nick_rcnt;
std::map<std::string, pid_t>				nick_rnkpid;
std::map<pid_t, std::string>				rnk_nick;
std::map<pid_t, int>						rnk_pipe;

int											pki7771_port, pki7772_port, 
											rnk7773_port, rnk7774_port;
int											pki7771_handle, pki7772_handle,
											rnk7773_handle, rnk7774_handle;
std::list<pid_t>							pkiprf_pid;

std::map<std::string, int>					bad_nick;

std::string									irc_reply, irc_pfx, irc_cmd, irc_par;
int											irc_port, irc_handle, ctl_pid = 0;
std::vector<std::string>					irc_parvec;
bool										irc_stat = true;
iosocketstream								*irc;

std::string									X = ">< ", XX = "><>< ", XXX = "><><>< ";
struct termios									old_term, new_term;

sig_atomic_t								irc_quit = 0, sigchld_critical = 0;

#ifndef RETSIGTYPE
	#define RETSIGTYPE void
#endif

RETSIGTYPE sig_handler_quit(int sig)
{
#ifndef NDEBUG
	std::cerr << "... SIGNAL " << sig << " RECEIVED ..." << std::endl;
#endif
	irc_quit = 1;
}

RETSIGTYPE sig_handler_skat_quit(int sig)
{
#ifndef NDEBUG
	std::cerr << "!!! SIGNAL " << sig << " RECEIVED !!!" << std::endl;
#endif
	if (ctl_pid > 0)
	{
		if (kill(ctl_pid, SIGQUIT) < 0)
			perror("sig_handler_skat_quit (kill)");
		waitpid(ctl_pid, NULL, 0);
	}
	exit(-100);
}

RETSIGTYPE sig_handler_ballot_quit(int sig)
{
#ifndef NDEBUG
	std::cerr << "??? SIGNAL " << sig << " RECEIVED ???" << std::endl;
#endif
	exit(-100);
}

RETSIGTYPE sig_handler_pipe(int sig)
{
}

RETSIGTYPE sig_handler_usr1(int sig)
{
	sigset_t sigset;
	
	// block SIGCHLD temporarily
	if (sigemptyset(&sigset) < 0)
		perror("sig_handler_usr1 (sigemptyset)");
	if (sigaddset(&sigset, SIGCHLD) < 0)
		perror("sig_handler_usr1 (sigaddset)");
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) < 0)
		perror("sig_handler_usr1 (sigprocmask)");
	
	// wait until the critical section of the SIGCHLD handler is safe
	while (sigchld_critical)
		usleep(100);
	
	while (!usr1_stat.empty())
	{
		std::pair <pid_t, int> chld_stat = usr1_stat.front();
		usr1_stat.pop_front();
		pid_t chld_pid = chld_stat.first;
		int status = chld_stat.second;
		
		if (games_pid2tnr.find(chld_pid) != games_pid2tnr.end())
		{
			std::string tnr = games_pid2tnr[chld_pid];
			if (WIFEXITED(status))
			{
				if (WEXITSTATUS(status) == 0)
					std::cerr << X << _("Session") << " \"" << tnr << "\" " << 
						_("succeeded properly") << std::endl;
				else
					std::cerr << X << _("Session") << " \"" << tnr << "\" " << 
						_("failed. Error code") << ": WEXITSTATUS " << 
						WEXITSTATUS(status) << std::endl;
			}
			if (WIFSIGNALED(status))
			{
				std::cerr << X << _("Session") << " \"" << tnr << "\" " << 
					_("failed. Error code") << ": WTERMSIG " <<
					WTERMSIG(status) << std::endl;
			}
			games_tnr2pid.erase(games_pid2tnr[chld_pid]);
			games_pid2tnr.erase(chld_pid);
		}
		else if (std::find(pkiprf_pid.begin(), pkiprf_pid.end(), chld_pid) !=
			pkiprf_pid.end())
		{
			std::cerr << X << "PKI (pid = " << chld_pid << ") " << 
				_("succeeded properly") << std::endl;
			pkiprf_pid.remove(chld_pid);
		}
		else if (std::find(rnkrpl_pid.begin(), rnkrpl_pid.end(), chld_pid) !=
			rnkrpl_pid.end())
		{
			std::cerr << X << "RNK (pid = " << chld_pid << ") " << 
				_("succeeded properly") << std::endl;
			rnkrpl_pid.remove(chld_pid);
		}
		else if (std::find(rnk_pids.begin(), rnk_pids.end(), chld_pid) !=
			rnk_pids.end())
		{
			if (WIFEXITED(status))
			{
				if (WEXITSTATUS(status) != 0)
				{
					std::cerr << X << "RNK (pid = " << chld_pid << ") " <<
						_("failed. Error code") << ": WEXITSTATUS " << 
						WEXITSTATUS(status) << std::endl;
				}
			}
			if (WIFSIGNALED(status))
			{
				std::cerr << X << "RNK (pid = " << chld_pid << ") " << 
					_("failed. Error code") << ": WTERMSIG " << 
					WTERMSIG(status) << std::endl;
			}
			rnk_pids.remove(chld_pid);
			nick_rnkcnt.erase(rnk_nick[chld_pid]);
			nick_rnkpid.erase(rnk_nick[chld_pid]);
			rnk_nick.erase(chld_pid);
		}
		else
		{
			if (WIFEXITED(status))
			{
				if (WEXITSTATUS(status) != 0)
				{
					std::cerr << X << "PKI " << chld_pid << "/" << nick_nick[chld_pid] << 
						" " << _("failed. Error code") << ": WEXITSTATUS " << 
						WEXITSTATUS(status) << std::endl;
				}
			}
			if (WIFSIGNALED(status))
			{
				std::cerr << X << "PKI " << chld_pid << "/" << nick_nick[chld_pid] <<
					" " << _("failed. Error code") << ": WTERMSIG " << 
					WTERMSIG(status) << std::endl;
			}
			
			// remove bad nick from the players list
			if (bad_nick.find(nick_nick[chld_pid]) == bad_nick.end())
				bad_nick[nick_nick[chld_pid]] = 1;
			else if (bad_nick[nick_nick[chld_pid]] <= 3)
				bad_nick[nick_nick[chld_pid]] += 1;
			else if (bad_nick[nick_nick[chld_pid]] > 3)
			{
				if (nick_players.find(nick_nick[chld_pid]) != nick_players.end())
				{
					nick_players.erase(nick_nick[chld_pid]);
					nick_p7771.erase(nick_nick[chld_pid]);
					nick_p7772.erase(nick_nick[chld_pid]);
					nick_p7773.erase(nick_nick[chld_pid]);
					nick_p7774.erase(nick_nick[chld_pid]);
					nick_sl.erase(nick_nick[chld_pid]);
				}
			}
			
			nick_ncnt.erase(nick_nick[chld_pid]);
			nick_ninf.remove(nick_nick[chld_pid]);
			nick_pids.remove(chld_pid);
			nick_nick.erase(chld_pid);
			nick_host.erase(chld_pid);
		}
	}
	
	// unblock SIGCHLD
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0)
		perror("sig_handler_usr1 (sigprocmask)");
}

RETSIGTYPE sig_handler_chld(int sig)
{
	sigchld_critical = 1;
	
	// look for died children (zombies) and evaluate their exit code
	std::pair <pid_t, int> chld_stat;
	int status;
	chld_stat.first = wait(&status), chld_stat.second = status;
	usr1_stat.push_back(chld_stat);
	
	sigchld_critical = 0;
}

void create_irc(const std::string &server, short int port)
{
	irc_handle = ConnectToHost(server.c_str(), port);
	if (irc_handle < 0)
	{
		perror("create_irc (ConnectToHost)");
		exit(-1);
	}
	irc = new iosocketstream(irc_handle);
}

const char *irc_prefix(const std::string &input)
{
	irc_pfx = input;
	if (irc_pfx.find(":", 0) == 0)
		irc_pfx = irc_pfx.substr(1, irc_pfx.find(" ", 0) - 1);
	else
		irc_pfx = "";
	return irc_pfx.c_str();
}

const char *irc_command(const std::string &input)
{
	irc_cmd = input;
	// prefix?
	if (irc_cmd.find(":", 0) == 0)
	{
		irc_cmd = irc_cmd.substr(irc_cmd.find(" ", 0) + 1,
			irc_cmd.length() - irc_cmd.find(" ", 0) - 1);
	}
	// strip leading whitespaces
	while (irc_cmd.find(" ", 0) == 0)
		irc_cmd = irc_cmd.substr(1, irc_cmd.length() - 1);
	if (irc_cmd.find(" ", 0) != irc_cmd.npos)
		irc_cmd = irc_cmd.substr(0, irc_cmd.find(" ", 0));
	return irc_cmd.c_str();
}

const char *irc_params(const std::string &input)
{
	irc_par = input;
	if (irc_par.find(":", 0) == 0)
	{
		irc_par = irc_par.substr(irc_par.find(" ", 0) + 1,
			irc_par.length() - irc_par.find(" ", 0) - 1);
	}
	while (irc_par.find(" ", 0) == 0)
		irc_par = irc_par.substr(1, irc_par.length() - 1);
	if (irc_par.find(" ", 0) != irc_par.npos)
		irc_par = irc_par.substr(irc_par.find(" ", 0) + 1,
			irc_par.length() - irc_par.find(" ", 0) - 1);
	else
		irc_par = "";
	return irc_par.c_str();
}

size_t irc_paramvec(std::string input)
{
	irc_parvec.clear();
	while (input != "")
	{
		// strip whitespaces
		while (input.find(" ", 0) == 0)
			input = input.substr(1, input.length() - 1);
		// escape sequence, last token
		if (input.find(":", 0) == 0)
		{ 
			irc_parvec.push_back(input.substr(1, input.length() - 1));
			break;
		}
		// next token
		else if (input.find(" ", 0) != input.npos)
		{
			irc_parvec.push_back(input.substr(0, input.find(" ", 0)));
			input = input.substr(input.find(" ", 0) + 1,
				input.length() - input.find(" ", 0));
		}
		// last token
		else
		{
			if (input != "")
				irc_parvec.push_back(input);
			break;
		}
	}
	return irc_parvec.size();
}

void init_irc()
{
	// install signal handlers
	signal(SIGINT, sig_handler_quit);
	signal(SIGQUIT, sig_handler_quit);
	signal(SIGTERM, sig_handler_quit);
	signal(SIGPIPE, sig_handler_pipe);
	signal(SIGCHLD, sig_handler_chld);
#ifdef NOHUP
	signal(SIGHUP, SIG_IGN);
#endif
	signal(SIGUSR1, sig_handler_usr1);
	// send NICKname
	*irc << "NICK " << pub.keyid() << std::endl << std::flush;
}

int skat_connect
	(size_t pkr_self, size_t pkr_idx, iosecuresocketstream *&secure, int &handle,
	std::map<std::string, int> gp_ports, const std::vector<std::string> &vnicks,
	const TMCG_PublicKeyRing &pkr)
{
// redirect connection for measurements; first start rinetd on gaos.org
//handle = ConnectToHost("gaos.org", gp_ports[vnicks[pkr_idx]]);
	// create TCP/IP connection
	handle = ConnectToHost(nick_players[vnicks[pkr_idx]].c_str(),
		gp_ports[vnicks[pkr_idx]]);
	if (handle < 0)
		return -4;
	iosocketstream *neighbor = new iosocketstream(handle);
	std::string tmp = "";
	
	// authenticate connection: receive the nonce
	unsigned long int nonce_A = 0, nonce_B = 0;
	*neighbor >> nonce_A;
	neighbor->ignore(1, '\n');
	if (neighbor->good())
	{
		std::ostringstream ost, ost2;
		ost << nonce_A << "<>" << vnicks[pkr_idx];
		// send the signature
		*neighbor << sec.sign(ost.str()) << std::endl << std::flush;
		// create a fresh nonce
		nonce_B = mpz_srandom_ui();
		// send challenge
		*neighbor << nonce_B << std::endl << std::flush;
		// receive the signature
		std::getline(*neighbor, tmp);
		// verify the signature
		ost2 << nonce_B << "<>" << vnicks[pkr_self];
		if (!pkr.keys[pkr_idx].verify(ost2.str(), tmp) || !neighbor->good())
		{
			delete neighbor;
			close(handle);
			return -6;
		}
	}
	else
	{
		delete neighbor;
		close(handle);
		return -6;
	}
	
	// exchange secret keys for securesocketstreams
	char *key1 = new char[TMCG_SAEP_S0], *key2 = new char[TMCG_SAEP_S0],
		*dv = new char[TMCG_SAEP_S0];
	gcry_randomize((unsigned char*)key1, TMCG_SAEP_S0, GCRY_STRONG_RANDOM);
	*neighbor << pkr.keys[pkr_idx].encrypt(key1) << std::endl << std::flush;
	
	std::getline(*neighbor, tmp);
	if (!sec.decrypt(dv, tmp))
	{
		std::cerr << _("TMCG: decrypt() failed") << std::endl;
		delete neighbor;
		delete [] key1, delete [] key2, delete [] dv;
		close(handle);
		return -6;
	}
	memcpy(key2, dv, TMCG_SAEP_S0);
	delete neighbor;
	secure = new iosecuresocketstream(handle, key1, 16, key2, 16);
	delete [] key1, delete [] key2, delete [] dv;
	return 0;
}

int skat_accept
	(opipestream *out_pipe, int ipipe, const std::string &nr, int r,
	int pkr_self, int pkr_idx, iosecuresocketstream *&secure, int &handle,
	const std::vector<std::string> &vnicks, const TMCG_PublicKeyRing &pkr,
	int gp_handle, bool neu, char *ireadbuf, int &ireaded)
{
	struct hostent *hostinf;
	struct sockaddr_in sin;
	if ((hostinf = gethostbyname(nick_players[vnicks[pkr_idx]].c_str())) != NULL)
	{
		memcpy((char*)&sin.sin_addr, hostinf->h_addr, hostinf->h_length);
	}
	else
	{
		perror("skat_accept (gethostbyname)");
		return -4;
	}
	fd_set rfds;									// set of read descriptors
	int mfds = 0;									// highest-numbered descriptor
	while (1)
	{
		// select(2) -- initalize file descriptors
		FD_ZERO(&rfds);
		MFD_SET(gp_handle, &rfds);
		MFD_SET(ipipe, &rfds);
		// select(2)
		int ret = select(mfds + 1, &rfds, NULL, NULL, NULL);
		// error occured
		if (ret < 0)
			if (errno != EINTR)
				perror("skat_accept (select)");
		
		// connection request
		if ((ret > 0) && FD_ISSET(gp_handle, &rfds))
		{
			struct sockaddr_in client_in;
			socklen_t client_len = sizeof(client_in);
			handle = accept(gp_handle,
				(struct sockaddr*) &client_in, &client_len);
			if (handle < 0)
			{
				perror("skat_accept (accept)");
				return -4;
			}
			else
			{
				if (client_in.sin_addr.s_addr == sin.sin_addr.s_addr)
				{
					iosocketstream *neighbor = new iosocketstream(handle);
					
					// create a fresh nonce
					unsigned long int nonce_A = mpz_srandom_ui(), nonce_B = 0;
					std::ostringstream ost, ost2;
					std::string tmp;
					*neighbor << nonce_A << std::endl << std::flush;
					// receive the signature
					std::getline(*neighbor, tmp);
					// verify the signature
					ost << nonce_A << "<>" << vnicks[pkr_self];
					if (!pkr.keys[pkr_idx].verify(ost.str(), tmp) || !neighbor->good())
					{
						delete neighbor;
						close(handle);
						return -6;
					}
					else
					{
						// receive the nonce
						*neighbor >> nonce_B;
						neighbor->ignore(1, '\n');
						if (neighbor->good())
						{
							ost2 << nonce_B << "<>" << vnicks[pkr_idx];
							*neighbor << sec.sign(ost2.str()) << std::endl << std::flush;
							
							// exchange the secret keys for securesocketstream
							char *key1 = new char[TMCG_SAEP_S0],
								*key2 = new char[TMCG_SAEP_S0], *dv = new char[TMCG_SAEP_S0];
							std::getline(*neighbor, tmp);
							if (!sec.decrypt(dv, tmp))
							{
								std::cerr << _("TMCG: decrypt() failed") << std::endl;
								delete neighbor;
								delete [] key1, delete [] key2, delete [] dv;
								close(handle);
								return -6;
							}
							memcpy(key2, dv, TMCG_SAEP_S0);
							
							gcry_randomize((unsigned char*)key1, TMCG_SAEP_S0,
								GCRY_STRONG_RANDOM);
							*neighbor << pkr.keys[pkr_idx].encrypt(key1) << std::endl <<
								std::flush;
							delete neighbor;
							secure = new iosecuresocketstream(handle, key1, 16, key2, 16);
							delete [] key1, delete [] key2, delete [] dv;
							break;
						}
						else
						{
							delete neighbor;
							close(handle);
							return -6;
						}
					}
				}
				else
				{
					std::cerr << _("Unexpected connection from") << ": " << 
						inet_ntoa(client_in.sin_addr) << std::endl;
					close(handle);
					return -6;
				}
			}
		}
		
		// pipe request
		if ((ret > 0) && FD_ISSET(ipipe, &rfds))
		{
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
						return -1;
					}
					if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
					{
						*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" 
							<< nr << "|3~" << r << "!" << std::endl << std::flush;
					}
					if (neu && (cmd.find("KIEBITZ ", 0) == 0))
					{
						std::string nick = cmd.substr(8, cmd.length() - 8);
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
							nick << " :" << _("observers currently not permitted") << 
							std::endl << std::flush;
					}
					if (neu && (cmd.find("JOIN ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
							nick << " :" << _("table completely occupied") << 
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
		}
	}
	return 0;
}

int skat_alive
	(iosecuresocketstream *r, iosecuresocketstream *l)
{
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
			*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
				std::endl << std::flush;
			sleep(1);		// The child has to sleep a second before quitting, because
									// the parent must process the sended PART message first.
		}
		exit(error);
	}
}

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
	gp_nick.push_back(pub.keyid());
	gp_name[pub.keyid()] = pub.name;
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|1~" << -b << "!" << 
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
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << gp_nick.size() <<
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
				*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
					nick << " :" << _("key exchange with owner is incomplete") << 
					std::endl << std::flush;
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
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
						nick << " :" << _("voter was at room creation not present") << 
						std::endl << std::flush;
			}
			else
			{
				std::cout << X << _("key exchange with") << " " << nick << " " << 
					_("is incomplete") << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
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
				*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
					gp_nick.size() << "~" << b << "!" << std::endl << std::flush;
				*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << 
					" :!READY" << std::endl << std::flush;
				break;
			}
		}
	}
	std::cout << X << _("Room") << " " << nr << " " << 
		_("preparing the ballot") << " ..." << std::endl;
	// prepare ballot (create PKR, bind port for secure connections)
	assert(gp_nick.size() <= TMCG_MAX_PLAYERS);
	assert(b <= TMCG_MAX_TYPEBITS);
	SchindelhauerTMCG *ballot_tmcg = 							// n players, 2^b cards
		new SchindelhauerTMCG(security_level, gp_nick.size(), b);
	TMCG_PublicKeyRing pkr(gp_nick.size());
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
			pkr.keys[pkr_i] = pub;
		}
		else
			pkr.keys[pkr_i] = nick_key[*pi];
	}
	int gp_handle, gp_port = BindEmptyPort(7900);
	if ((gp_handle = ListenToPort(gp_port)) < 0)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
			std::endl << std::flush;
		return -4;
	}
	std::ostringstream ost;
	ost << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :PORT " << 
		gp_port << std::endl;
	*out_pipe << ost.str() << std::flush;
	std::cout << X << _("Room") << " " << nr << " " << _("with");
	for (size_t i = 0; i < gp_nick.size(); i++)
		std::cout << " '" << pkr.keys[i].name << "'";
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
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
				gp_nick.size() << "~" << -b << "!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << 
				" :" << _("room completely occupied") << std::endl << std::flush;
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
			{
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
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
					std::cout << XX << _("BALLOT: you voted for value r = ") << 
						vote << std::endl;
					*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << 
						" :VOTE" << std::endl << std::flush;
					gp_voters.push_back(vnicks[pkr_self]);
					has_voted = true;
				}
				else
					std::cout << XX << 
						_("BALLOT ERROR: already voted or bad value <r> ") << 
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
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
						std::endl << std::flush;
					return -70;
				}
				if (client_in.sin_addr.s_addr != sin.sin_addr.s_addr)
				{
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
						std::endl << std::flush;
					return -71;
				}
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
					delete neighbor, close(handle);
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
						std::endl << std::flush;
					return -72;
				}
				else if (!pkr.keys[pkr_idx].verify(challenge.str(), challenge_sig))
				{
					delete neighbor, close(handle);
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
						std::endl << std::flush;
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
						char *key1 = new char[TMCG_SAEP_S0], 
							*key2 = new char[TMCG_SAEP_S0], *dv = new char[TMCG_SAEP_S0];
						neighbor->getline(challenge_sig, sizeof(challenge_sig));
						if (!sec.decrypt(dv, challenge_sig))
						{
							std::cerr << _("TMCG: decrypt() failed") << std::endl;
							delete neighbor, delete [] key1, delete [] key2, delete [] dv;
							close(handle);
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
								std::endl << std::flush;
							return -74;
						}
						memcpy(key2, dv, TMCG_SAEP_S0);
						
						gcry_randomize((unsigned char*)key1, TMCG_SAEP_S0,
							GCRY_STRONG_RANDOM);
						*neighbor << pkr.keys[pkr_idx].encrypt(key1) << std::endl << 
							std::flush;
						ios_in[vnicks[pkr_idx]] = 
							new iosecuresocketstream(handle, key1, 16, key2, 16);
#ifndef NDEBUG
	std::cerr << "ios_in[" << vnicks[pkr_idx] << "]" << std::endl;
#endif
						delete neighbor, delete [] key1, delete [] key2, delete [] dv;
						
						pkr_idx++;
					}
					else
					{
						delete neighbor;
						close(handle);
						*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
							std::endl << std::flush;
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
						*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
							gp_nick.size() << "~" << -b << "!" << std::endl << std::flush;
					}
					if (neu && (cmd.find("JOIN ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
							nick << " :" <<	_("room completely occupied") << std::endl << 
							std::flush;
					}
					if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
					{
						std::string nick = cmd.substr(5, cmd.length() - 5);
						if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
						{
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
								std::endl << std::flush;
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
				memset(tmp, 0, sizeof(tmp));
				ireaded -= cnt_pos;
				memcpy(tmp, ireadbuf + cnt_pos, ireaded);
				memcpy(ireadbuf, tmp, ireaded);
			}
			if (num == 0)
			{
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
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
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
								std::endl << std::flush;
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
								*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
									std::endl << std::flush;
								return -80;
							}
							else if (!pkr.keys[i].verify(response.str(), tmp))
							{
								delete neighbor, close(handle);
								*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
									std::endl << std::flush;
								return -81;
							}
						}
						else
						{
							delete neighbor, close(handle);
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
								std::endl << std::flush;
							return -82;
						}
						
						// exchange secret keys for securesocketstreams
						char *key1 = new char[TMCG_SAEP_S0],
							*key2 = new char[TMCG_SAEP_S0], *dv = new char[TMCG_SAEP_S0];
						gcry_randomize((unsigned char*)key1, TMCG_SAEP_S0,
							GCRY_STRONG_RANDOM);
						*neighbor << pkr.keys[i].encrypt(key1) << std::endl << std::flush;
						
						neighbor->getline(tmp, sizeof(tmp));
						if (!sec.decrypt(dv, tmp))
						{
							std::cerr << _("TMCG: decrypt() failed") << std::endl;
							delete neighbor, delete [] key1, delete [] key2, delete [] dv;
							close(handle);
							*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
								std::endl << std::flush;
							return -84;
						}
						memcpy(key2, dv, TMCG_SAEP_S0);
						ios_out[vnicks[i]] = 
							new iosecuresocketstream(handle, key1, 16, key2, 16);
#ifndef NDEBUG
	std::cerr << "ios_out[" << vnicks[i] << "]" << std::endl;
#endif
						delete neighbor, delete [] key1, delete [] key2, delete [] dv;
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
		ddh_group << COMMON_DDH_GROUP_P << std::endl;
		ddh_group << COMMON_DDH_GROUP_Q << std::endl;
		ddh_group << COMMON_DDH_GROUP_G << std::endl;
		ddh_group << "2" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog_GroupQR(ddh_group);
#else
		vtmf = new BarnettSmartVTMF_dlog;
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
				vtmf->PublishGroup(*ios_out[vnicks[i]]);
		}
#endif
		if (!vtmf->CheckGroup())
		{
			std::cout << ">< " << _("VTMF ERROR") << ": " << 
				_("function CheckGroup() failed") << std::endl;
			return -90;
		}
		vtmf->KeyGenerationProtocol_GenerateKey();
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
			{
				if (!vtmf->KeyGenerationProtocol_UpdateKey(*ios_in[vnicks[i]]))
				{
					std::cout << ">< " << _("VTMF ERROR") << ": " << 
						_("function KeyGenerationProtocol_UpdateKey() failed") << 
						" " << _("for") << " " << vnicks[i]<< std::endl;
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
	}
	else
	{
#ifdef COMMON_DDH_GROUP
		std::stringstream ddh_group;
		ddh_group << COMMON_DDH_GROUP_P << std::endl;
		ddh_group << COMMON_DDH_GROUP_Q << std::endl;
		ddh_group << COMMON_DDH_GROUP_G << std::endl;
		ddh_group << "2" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog_GroupQR(ddh_group);
#else
		vtmf = new BarnettSmartVTMF_dlog(*ios_in[vnicks[0]]);
#endif
		
		if (!vtmf->CheckGroup())
		{
			std::cout << ">< " << _("VTMF ERROR") << ": " << 
				_("function CheckGroup() failed") << std::endl;
			return -90;
		}
		
		vtmf->KeyGenerationProtocol_GenerateKey();
		for (size_t i = 0; i < vnicks.size(); i++)
		{
			if (i != pkr_self)
			{
				if (!vtmf->KeyGenerationProtocol_UpdateKey(*ios_in[vnicks[i]]))
				{
					std::cout << ">< " << _("VTMF ERROR") << ": " << 
						_("function KeyGenerationProtocol_UpdateKey() failed") << 
						" " << _("for") << " " << vnicks[i]<< std::endl;
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
	}
	
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
				std::cerr << XX << _("BALLOT ERROR: bad card from ") << vnicks[i] << 
					std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
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
				if (ballot_tmcg->TMCG_VerifyStackEquality(s, s2, false, vtmf,
					*ios_in[vnicks[i]], *ios_in[vnicks[i]]))
				{
					s.clear();
					s = s2;
					s2.clear();
				}
				else
				{
					std::cerr << XX << _("BALLOT ERROR: bad ZNP from ") << vnicks[i] << 
						std::endl;
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
						std::endl << std::flush;
					return -85;
				}
			}
			else
			{
				std::cerr << XX << _("BALLOT ERROR: bad stack from ") << vnicks[i] << 
					std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
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
					ballot_tmcg->TMCG_ProveStackEquality(s, s2, ss, false, vtmf,
						*ios_out[vnicks[j]], *ios_out[vnicks[j]]);
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
				if (!ballot_tmcg->TMCG_VerifyCardSecret(s[k], vtmf,
					*ios_in[vnicks[i]], *ios_in[vnicks[i]]))
				{
					std::cerr << XX << _("BALLOT ERROR: bad ZNP from ") << vnicks[i] << 
						std::endl;
					*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
						std::endl << std::flush;
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
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :RESULT " << 
			br[k] << std::endl << std::flush;
	}
	std::cout << std::endl;
	sleep(1);
	
	// announce table destruction
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|0~" << -b << 
			"!" << std::endl << std::flush;
	
	// exit from game
	delete vtmf;
	delete ballot_tmcg;
	*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
		std::endl << std::flush;
	delete in_pipe;
	delete out_pipe;
	
	return 0;
}

int skat_child
	(const std::string &nr, int r, bool neu, int ipipe, int opipe, int hpipe,
	const std::string &master)
{
	SchindelhauerTMCG *gp_tmcg =
		new SchindelhauerTMCG(security_level, 3, 5);	// 3 players, 2^5 = 32 cards
	std::list<std::string> gp_nick;
	std::map<std::string, std::string> gp_name;
	char *ipipe_readbuf = new char[65536];
	int ipipe_readed = 0;
	gp_nick.push_back(pub.keyid());
	gp_name[pub.keyid()] = pub.name;
	
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
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
			gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
	
	// wait for players
	while (1)
	{
		char tmp[10000];
		in_pipe->getline(tmp, sizeof(tmp));
		std::string cmd = tmp;
		
		if ((cmd == "") || (cmd.find("!KICK", 0) == 0))
		{
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
				gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("KIEBITZ ", 0) == 0))
		{
			std::string nick = cmd.substr(8, cmd.length() - 8);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << nick << 
				" :" << _("observers currently not permitted") << std::endl << 
				std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
				{
					gp_nick.push_back(nick), gp_name[nick] = nick_key[nick].name;
					*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
						gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
				}
				else
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
						nick << " :" << _("player was at table creation not present") << 
						std::endl << std::flush;
			}
			else
				*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
					nick << " :" << _("key exchange with owner is incomplete") << 
					std::endl << std::flush;
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
					*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
						nick << " :" << _("player was at table creation not present") << 
						std::endl << std::flush;
			}
			else
			{
				std::cerr << X << _("key exchange with") << " " << nick << " " << 
					_("is incomplete") << std::endl;
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
				return -1;
			}
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(gp_nick.begin(), gp_nick.end(), nick)	!= gp_nick.end())
			{
				gp_nick.remove(nick), gp_name.erase(nick);
			}
		}
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			std::string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			std::string msg = cmd.substr(cmd.find(" ", 4) + 1, 
				cmd.length() - cmd.find(" ", 4) - 1);
				
			if ((msg == "!READY") && (nick == master))
				break;
		}
		if (neu && (gp_nick.size() == 3))
		{
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|" << 
				gp_nick.size() << "~" << r << "!" << std::endl << std::flush;
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << 
				" :!READY" <<  std::endl << std::flush;
			break;
		}
	}
	std::cout << X << _("Table") << " " << nr << " " << _("preparing the game") << 
		" ..." << std::endl;
	// prepare game (check number of players, create PKR, create connections)
	if ((gp_nick.size() != 3) || (std::find(gp_nick.begin(), gp_nick.end(),
		pub.keyid()) == gp_nick.end()))
	{
		std::cerr << X << _("wrong number of players") << ": " << 
			gp_nick.size() << std::endl;
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
			std::endl << std::flush;
		return -2;
	}
	TMCG_PublicKeyRing pkr(gp_nick.size());
	std::vector<std::string> vnicks;
	size_t pkr_i = 0, pkr_self = 0;
	gp_nick.sort();
	for (std::list<std::string>::const_iterator pi = gp_nick.begin(); 
		pi != gp_nick.end(); pi++)
	{
		vnicks.push_back(*pi);
		if (*pi == pub.keyid())
		{
			pkr_self = pkr_i;
			pkr.keys[pkr_i++] = pub;
		}
		else
			pkr.keys[pkr_i++] = nick_key[*pi];
	}
	int gp_handle, gp_port = BindEmptyPort(7800);
	if ((gp_handle = ListenToPort(gp_port)) < 0)
	{
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
			std::endl << std::flush;
		return -4;
	}
	
	std::ostringstream ost;
	ost << "PRIVMSG " << MAIN_CHANNEL_UNDERSCORE << nr << " :PORT " << gp_port << 
		std::endl;
	*out_pipe << ost.str() << std::flush;
	std::cout << X << _("Table") << " " << nr << " " << _("with") << " '" <<
		pkr.keys[0].name << "', '" <<
		pkr.keys[1].name << "', '" <<
		pkr.keys[2].name << "' " << _("ready") << "." << std::endl;
	std::list<std::string> gp_rdport;
	std::map<std::string, int> gp_ports;
	while (gp_rdport.size() < 2)
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
			*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|3~" << r << 
				"!" << std::endl << std::flush;
		}
		if (neu && (cmd.find("KIEBITZ ", 0) == 0))
		{
			std::string nick = cmd.substr(8, cmd.length() - 8);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
				nick << " :" << _("observers currently not permitted") << 
				std::endl << std::flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			*out_pipe << "KICK " << MAIN_CHANNEL_UNDERSCORE << nr << " " << 
				nick << " :" << _("table completely occupied") << 
				std::endl << std::flush;
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			std::string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
			{
				*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
					std::endl << std::flush;
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
				if ((std::find(gp_rdport.begin(), gp_rdport.end(), nick)
					== gp_rdport.end()))
				{
					gp_rdport.push_back(nick);
					gp_ports[nick] = atoi(port.c_str());
				}
			}
		}
	}
	std::cout << X << _("Table") << " " << nr << " " <<
		_("establishing secure channels") << " ..." << std::endl;
	int connect_handle, accept_handle, error = 0;
	iosecuresocketstream *left_neighbor, *right_neighbor;
	switch (pkr_self)
	{
		case 0:
			error = skat_connect(pkr_self, 1,
				left_neighbor, connect_handle, gp_ports, vnicks, pkr);
			skat_error(error, out_pipe, nr);
			error = skat_accept(out_pipe, ipipe, nr, r, pkr_self, 2,
				right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu,
				ipipe_readbuf, ipipe_readed);
			skat_error(error, out_pipe, nr);
			break;
		case 1:
			error = skat_accept(out_pipe, ipipe, nr, r, pkr_self, 0,
				right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu,
				ipipe_readbuf, ipipe_readed);
			skat_error(error, out_pipe, nr);
			error = skat_connect(pkr_self, 2,
				left_neighbor, connect_handle, gp_ports, vnicks, pkr);
			skat_error(error, out_pipe, nr);
			break;
		case 2:
			error = skat_accept(out_pipe, ipipe, nr, r, pkr_self, 1,
				right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu,
				ipipe_readbuf, ipipe_readed);
			skat_error(error, out_pipe, nr);
			error = skat_connect(pkr_self, 0,
				left_neighbor, connect_handle, gp_ports, vnicks, pkr);
			skat_error(error, out_pipe, nr);
			break;
	}
	skat_error(skat_alive(right_neighbor, left_neighbor), out_pipe, nr);
	
	if (neu)
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|3~" << 
			vnicks[0] << ", " << vnicks[1] << ", " << vnicks[2] << "!" << 
			std::endl << std::flush;
	
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
				if (dup2(pipe2fd[0], fileno(stdin)) < 0 ||
					dup2(pipe1fd[1], fileno(stdout)) < 0)
						perror("skat_child (dup2)");
				if ((close(pipe1fd[0]) < 0) ||
					(close(pipe1fd[1]) < 0) ||
					(close(pipe2fd[0]) < 0) ||
					(close(pipe2fd[1]) < 0))
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
				std::cout << X << _("Execute control process") <<
					" (" << ctl_pid << "): " << std::flush;
				char buffer[1024];
				memset(buffer, 0, sizeof(buffer));
				ssize_t num = read(ctl_i, buffer, sizeof(buffer));
				if (num > 0)
					std::cout << buffer << std::flush;
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
		*out_pipe << "TOPIC " << MAIN_CHANNEL_UNDERSCORE << nr << " :" << 
			PACKAGE_STRING << std::endl << std::flush;
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
		*out_pipe << "PRIVMSG " << MAIN_CHANNEL << " :" << nr << "|0~" << r << 
			"!" << std::endl << std::flush;
	
	// release the game
	delete gp_tmcg, delete left_neighbor, delete right_neighbor;
	close(connect_handle), close(accept_handle);
	if (exit_code != 6)
		*out_pipe << "PART " << MAIN_CHANNEL_UNDERSCORE << nr << 
			std::endl << std::flush;
	delete in_pipe, delete out_pipe;
	delete [] ipipe_readbuf;
	return exit_code;
}

void read_after_select(fd_set rfds, std::map<pid_t, int> &read_pipe, int what)
{
	std::vector<pid_t> del_pipe;
	for (std::map<pid_t, int>::const_iterator pi = read_pipe.begin(); 
		pi != read_pipe.end(); pi++)
	{
		if ((pi->second >= 0) && FD_ISSET(pi->second, &rfds))
		{
			if (readbuf.find(pi->second) == readbuf.end())
			{
				readbuf[pi->second] = new char[65536];
				readed[pi->second] = 0;
			}
			ssize_t num = read(pi->second,
				readbuf[pi->second] + readed[pi->second], 65536 - readed[pi->second]);
			readed[pi->second] += num;
			if (num == 0)
				del_pipe.push_back(pi->first);
			if (readed[pi->second] > 0)
			{
				std::vector<int> pos_delim;
				int cnt_delim = 0, cnt_pos = 0, pos = 0;
				for (int i = 0; i < readed[pi->second]; i++)
					if (readbuf[pi->second][i] == '\n')
						cnt_delim++, pos_delim.push_back(i);
				
				switch (what)
				{
					case 1: // update of ranking data from RNK childs
						while (cnt_delim >= 2)
						{
							char tmp[65536];
							std::memset(tmp, 0, sizeof(tmp));
							std::memcpy(tmp, readbuf[pi->second] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string rnk1 = tmp;
							std::memset(tmp, 0, sizeof(tmp));
							std::memcpy(tmp, readbuf[pi->second] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							cnt_delim--, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string rnk2 = tmp;
							// do operation
							rnk[rnk1] = rnk2;
						}
						break;
					case 2: // IRC output from game childs
						while (cnt_delim >= 1)
						{
							char tmp[65536];
							std::memset(tmp, 0, sizeof(tmp));
							std::memcpy(tmp, readbuf[pi->second] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string irc1 = tmp;

//std::cerr << "to IRC: " << irc1 << std::endl;

							// do operation
							if (strncasecmp(irc_command(irc1), "PRIVMSG", 7) == 0)
							{
								if (irc_paramvec(irc_params(irc1)) >= 2)
								{
									if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
										(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
									{
										// sign message
										*irc << "PRIVMSG " << irc_parvec[0] << " :" << 
											irc_parvec[1] << "~~~" << sec.sign(irc_parvec[1]) << 
											std::endl <<std::flush;
									}
									else if (irc_parvec[0] == MAIN_CHANNEL)
									{
										for (std::map<std::string, std::string>::const_iterator ni = 
											nick_players.begin(); ni != nick_players.end(); ni++)
										{
											// send announcement PRIVMSG to each player
											*irc << "PRIVMSG " << ni->first << " :" << 
												irc_parvec[1] << std::endl << std::flush;
										}
										// send announcement PRIVMSG to the channel
										// reason: some IRC servers (e.g. freenode.net)
										// block private messages of unregistered users
										*irc << "PRIVMSG " << MAIN_CHANNEL << " :" << 
											irc_parvec[1] << "~+~" << std::endl << std::flush;
										
										// process announcement PRIVMSG
										size_t tabei1 = irc_parvec[1].find("|", 0);
										size_t tabei2 = irc_parvec[1].find("~", 0);
										size_t tabei3 = irc_parvec[1].find("!", 0);
										if ((tabei1 != irc_parvec[1].npos) &&
											(tabei2 != irc_parvec[1].npos) &&
											(tabei3 != irc_parvec[1].npos) && 
											(tabei1 < tabei2) && (tabei2 < tabei3))
										{
											std::string tabmsg1 = irc_parvec[1].substr(0, tabei1);
											std::string tabmsg2 = irc_parvec[1].substr(tabei1 + 1, 
												tabei2 - tabei1 - 1);
											std::string tabmsg3 = irc_parvec[1].substr(tabei2 + 1, 
												tabei3 - tabei2 - 1);	
											if ((std::find(tables.begin(), tables.end(), tabmsg1) 
												== tables.end()) && (tabmsg2 != "0"))
											{
												// new table
												tables.push_back(tabmsg1);
												tables_p[tabmsg1] = atoi(tabmsg2.c_str());
												tables_r[tabmsg1] = atoi(tabmsg3.c_str());
												tables_u[tabmsg1] = tabmsg3;
												tables_o[tabmsg1] = pub.keyid();
											}
											else
											{
												if (tabmsg2 == "0")
												{
													// remove table
													tables_p.erase(tabmsg1), tables_r.erase(tabmsg1);
													tables_u.erase(tabmsg1), tables_o.erase(tabmsg1);
													tables.remove(tabmsg1);
												}
												else
												{
													// update table
													tables_p[tabmsg1] = atoi(tabmsg2.c_str());
													tables_r[tabmsg1] = atoi(tabmsg3.c_str());
													tables_u[tabmsg1] = tabmsg3;
												}
											}
										}
									}
									else
										*irc << irc1 << std::endl << std::flush;
								}
								else
									*irc << irc1 << std::endl << std::flush;
							}
							else
								*irc << irc1 << std::endl << std::flush;
						}
						break;
					case 3: // import from PKI childs
						while (cnt_delim >= 2)
						{
							char tmp[65536];
							std::memset(tmp, 0, sizeof(tmp));
							std::memcpy(tmp, readbuf[pi->second] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string pki1 = tmp;
							std::memset(tmp, 0, sizeof(tmp));
							std::memcpy(tmp, readbuf[pi->second] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							cnt_delim--, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string pki2 = tmp;
							// do operation
							TMCG_PublicKey apkey;
							if (!apkey.import(pki2))
							{
								std::cerr << _("TMCG: public key corrupted") << std::endl;
							}
							else if (pki1 != apkey.keyid())
							{
								std::cerr << _("TMCG: wrong public key") << std::endl;
							}
							else
							{
								std::cout << X << "PKI " << _("identified") <<
									" \"" << pki1 << "\" " << "aka \"" << apkey.name <<
									"\" <" << apkey.email << ">" << std::endl;
								nick_key[pki1] = apkey;
							}
						}
						break;
					default:
						break;
				} // switch
				char tmp[65536];
				std::memset(tmp, 0, sizeof(tmp));
				readed[pi->second] -= cnt_pos;
				std::memcpy(tmp, readbuf[pi->second] + cnt_pos, readed[pi->second]);
				std::memcpy(readbuf[pi->second], tmp, readed[pi->second]);
			}
		}
	}
	for (size_t i = 0; i < del_pipe.size(); i++)
	{
		if (close(read_pipe[del_pipe[i]]) < 0)
			perror("read_after_select (close)");
		delete [] readbuf[read_pipe[del_pipe[i]]];
		readbuf.erase(read_pipe[del_pipe[i]]);
		readed.erase(read_pipe[del_pipe[i]]);
		read_pipe.erase(del_pipe[i]);
	}
	del_pipe.clear();
}

static void process_line(char *line)
{
	char *s;
	if (line == NULL)
		return;
	s = stripwhite(line);
	if (s == NULL)
	{
		free(line);
		return;
	}
	add_history(s);
	
	if (s[0] == '/')
	{
		size_t cmd_argc = irc_paramvec(s + 1);
		std::vector<std::string> cmd_argv = irc_parvec;
		
		if (cmd_argc == 0)
			cmd_argv.push_back("help");
		
		if ((cmd_argv[0] == "quit") || (cmd_argv[0] == "ende"))
		{
			irc_quit = 1;
		}
		else if ((cmd_argv[0] == "on") || (cmd_argv[0] == "an"))
		{
			irc_stat = true;
		}	
		else if ((cmd_argv[0] == "off") || (cmd_argv[0] == "aus"))
		{
			irc_stat = false;
		}
		else if ((cmd_argv[0] == "players") || (cmd_argv[0] == "spieler"))
		{
			for (std::map<std::string, std::string>::const_iterator ni = 
				nick_players.begin(); ni != nick_players.end(); ni++)
			{
				std::string nick = ni->first, host = ni->second;
				std::string name = "?", email = "?", type = "?", fp = "?";
				if (nick_key.find(nick) != nick_key.end())
				{
					// key was found for nick, now get the attributes
					name = nick_key[nick].name;
					email = nick_key[nick].email;
					type = nick_key[nick].type;
					fp = nick_key[nick].fingerprint();
				}
				std::cout << XX << nick << " (" << host << ":" << 
					nick_p7771[nick] << ":" << nick_p7773[nick] << ":" << 
					nick_p7774[nick] << ")" << std::endl;
				std::cout << XX << "   aka \"" << 
					name << "\" <" << email << "> " << std::endl;
				std::cout << XX << "   " << "[ " << 
					nick_package[nick] << ", " << 
					"SECURITY_LEVEL = " << nick_sl[nick] << ", " << 
					"KEY_TYPE = " << type << ", " << std::endl;
				std::cout << XX << "     " << 
					"KEY_FINGERPRINT = " << fp << "]" << std::endl;
			}
		}
		else if ((cmd_argv[0] == "tables") || (cmd_argv[0] == "tische"))
		{
			for (std::list<std::string>::const_iterator ti = tables.begin(); 
				ti != tables.end(); ti++)
			{
				if (tables_r[*ti] > 0)
				{
					if (tables_p[*ti] < 3)
					{
						std::cout << XX << _("table") << " <nr> = " << *ti << 
							", " << _("round(s)") << " <r> = " << tables_r[*ti] << 
							", #" << _("players") << " = " << tables_p[*ti] << 
							", " << _("owner") << " = " << tables_o[*ti] << std::endl;
					}
					else
					{
						std::cout << XX << _("table") << " <nr> = " << *ti << ", " << 
							_("still") << " <r> = " << tables_r[*ti] << " " << 
							_("round(s)") << ", " << _("owner") << " = " << 
							tables_o[*ti] << std::endl;
					}
				}
			}
		}
		else if ((cmd_argv[0] == "rooms") || (cmd_argv[0] == "raeume"))
		{
			for (std::list<std::string>::const_iterator ti = tables.begin(); 
				ti != tables.end(); ti++)
			{
				if (tables_r[*ti] < 0)
				{
					std::cout << XX << _("room") << " <nr> = " << *ti << 
						", <bits> = " << -tables_r[*ti] <<
						", #" << _("voters") << " = " << tables_p[*ti] <<
						", " << _("owner") << " = " << tables_o[*ti] << std::endl;
				}
			}
		}
		else if ((cmd_argv[0] == "rank") || (cmd_argv[0] == "rang"))
		{
			std::list<std::string> rnk_nicktab, rnk_ranktab;
			std::map<std::string, long> rnk_nickpkt, pkt[3], gws[3], vls[3];
			
			// parsing RNK data
			nick_key[pub.keyid()] = pub;
			for (std::map<std::string, std::string>::const_iterator ri = 
				rnk.begin(); ri != rnk.end(); ri++)
			{
				std::string tk_sig1, tk_sig2, tk_sig3;
				std::string tk_header, tk_table;
				std::string tk_game[3], tk_nick[3];
				std::string s = ri->second;
				size_t ei;
				
				// header
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_header = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// table
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_table = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// nick1
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_nick[0] = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// nick2
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_nick[1] = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// nick3
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_nick[2] = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// game1
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_game[0] = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// game2
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_game[1] = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// game3
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_game[2] = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// sig1
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_sig1 = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// sig2
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_sig2 = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				// sig3
				if ((ei = s.find("#", 0)) != s.npos)
				{
					tk_sig3 = s.substr(0, ei);
					s = s.substr(ei + 1, s.length() - ei - 1);
				}
				else
					continue;
				if ((tk_header != "prt") ||
					(tk_nick[0] != pub.sigid(tk_sig1)) ||
					(tk_nick[1] != pub.sigid(tk_sig2)) ||
					(tk_nick[2] != pub.sigid(tk_sig3)) ||
					(nick_key.find(tk_nick[0]) == nick_key.end()) ||
					(nick_key.find(tk_nick[1]) == nick_key.end()) ||
					(nick_key.find(tk_nick[2]) == nick_key.end()))
							continue;
				std::string sig_data = tk_header + "#" + tk_table + "#" +
					tk_nick[0] + "#" + tk_nick[1] + "#" + tk_nick[2] + "#" +
					tk_game[0] + "#" + tk_game[1] + "#" + tk_game[2] + "#";
				if (!nick_key[tk_nick[0]].verify(sig_data, tk_sig1))
					continue;
				if (!nick_key[tk_nick[1]].verify(sig_data, tk_sig2))
					continue;
				if (!nick_key[tk_nick[2]].verify(sig_data, tk_sig3))
					continue;
				std::list<std::string> gp_l;
				std::string gp_s = "";
				for (size_t j = 0; j < 3; j++)
				{
					if (std::find(rnk_nicktab.begin(), rnk_nicktab.end(), 
						tk_nick[j]) == rnk_nicktab.end())
							rnk_nicktab.push_back(tk_nick[j]);
					gp_l.push_back(tk_nick[j]);
				}
				gp_l.sort();
				for (std::list<std::string>::const_iterator gpi = gp_l.begin(); 
					gpi != gp_l.end(); gpi++)
						gp_s = gp_s + (*gpi) + "~";
				for (size_t j = 0; j < 3; j++)
				{
					std::vector<std::string> gp_par;
					size_t ei;
					// parse game
					while ((ei = tk_game[j].find("~", 0)) != tk_game[j].npos)
					{
						gp_par.push_back(tk_game[j].substr(0, ei));
						tk_game[j] = tk_game[j].substr(ei + 1, 
							tk_game[j].length() - ei - 1);
					}
					gp_par.push_back(tk_game[j]);
					int ppp = atoi(gp_par[1].c_str());
					for (size_t jj = 0; jj < 3; jj++)
					{
						if (pkt[jj].find(gp_s) == pkt[jj].end())
							pkt[jj][gp_s] = 0;
						if (gws[jj].find(gp_s) == gws[jj].end())
							gws[jj][gp_s] = 0;
						if (vls[jj].find(gp_s) == vls[jj].end())
							vls[jj][gp_s] = 0;
						if (gp_par[0] == tk_nick[jj])
						{
							pkt[jj][gp_s] += ppp;
							if (ppp > 0)
								gws[jj][gp_s] += 1;
							else
								vls[jj][gp_s] += 1;
						}
					}
				}
			}
			// Berechnen der Leistungspunkte (Erweitertes Seeger-System)
			for (size_t j = 0; j < 3; j++)
			{
				for (std::map<std::string, long>::const_iterator gpi = pkt[j].begin();
					gpi != pkt[j].end(); gpi++)
				{
					long seeger = 0;
					if (gws[j][gpi->first] > vls[j][gpi->first])
						seeger += 50 * (gws[j][gpi->first] - vls[j][gpi->first]);
					for (size_t jj = 0; jj < 3; jj++)
						if (jj != j)
							seeger += 40 * vls[jj][gpi->first];
					pkt[j][gpi->first] += seeger;
				}
			}
			// Ausgabe der Ranglisten mit eigener Beteiligung
			for (std::map<std::string, long>::const_iterator gpi = pkt[0].begin();
				gpi != pkt[0].end(); gpi++)
			{
				std::string gp = gpi->first, gp_w = gpi->first;
				size_t ei;
				std::vector<std::string> gp_p;
				// parse gp
				while ((ei = gp_w.find("~", 0)) != gp_w.npos)
				{
					gp_p.push_back(gp_w.substr(0, ei));
					gp_w = gp_w.substr(ei + 1, gp_w.length() - ei - 1);
				}
				// eigene Beteiligung?
				if ((gp.find(pub.keyid(), 0) != gp.npos) && 
					(gp_p.size() == 3))
				{
					// naives sortieren
					size_t gp1 = 0, gp2 = 0, gp3 = 0;
					if ((pkt[0][gp] >= pkt[1][gp]) && (pkt[1][gp] >= pkt[2][gp]))
						gp1 = 0, gp2 = 1, gp3 = 2;
					if ((pkt[0][gp] >= pkt[1][gp]) && (pkt[1][gp] < pkt[2][gp]))
					{
						if (pkt[0][gp] < pkt[2][gp])
							gp1 = 2, gp2 = 0, gp3 = 1;
						else
							gp1 = 0, gp2 = 2, gp3 = 1;
					}
					if ((pkt[0][gp] < pkt[1][gp]) && (pkt[1][gp] < pkt[2][gp]))
						gp1 = 2, gp2 = 1, gp3 = 0;
					if ((pkt[0][gp] < pkt[1][gp]) && (pkt[1][gp] >= pkt[2][gp]))
					{
						if (pkt[0][gp] < pkt[2][gp])
							gp1 = 1, gp2 = 2, gp3 = 0;
						else
							gp1 = 1, gp2 = 0, gp3 = 2;
					}
					std::cout << "+----+ " << std::endl;
					std::cout << "| 1. | " << nick_key[gp_p[gp1]].name << 
						" : " << pkt[gp1][gp] << " " << _("score points") << std::endl;
					std::cout << "| 2. | " << nick_key[gp_p[gp2]].name << 
						" : " << pkt[gp2][gp] << " " << _("score points") << std::endl;
					std::cout << "| 3. | " << nick_key[gp_p[gp3]].name << 
						" : " << pkt[gp3][gp] << " " << _("score points") << std::endl;
					std::cout << "+----+ " << std::endl;
				}
			}
			nick_key.erase(pub.keyid());
		}
		else if (cmd_argv[0] == "skat")
		{
			if (cmd_argc == 3)
			{
				std::string tnr = cmd_argv[1], trr = cmd_argv[2];
				if (std::find(tables.begin(), tables.end(), tnr) == tables.end())
				{
					int r = atoi(trr.c_str());
					if (r > 0)
					{
						int rnk_pipe[2], in_pipe[2], out_pipe[2];
						if ((pipe(rnk_pipe) < 0) || 
							(pipe(in_pipe) < 0) || (pipe(out_pipe) < 0))
								perror("run_irc (pipe)");
						else if ((game_pid = fork()) < 0)
							perror("run_irc (fork)");
						else
						{
							if (game_pid == 0)
							{
								/* BEGIN child code (game process) */
								signal(SIGQUIT, SIG_DFL);
								signal(SIGTERM, SIG_DFL);
								if ((close(rnk_pipe[0]) < 0) || 
									(close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
										perror("run_irc (close)");
								int ret = skat_child(tnr, r, true, in_pipe[0],
									out_pipe[1], rnk_pipe[1], pub.keyid());
								sleep(1);
								if ((close(rnk_pipe[1]) < 0) || 
									(close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
										perror("run_irc (close)");
								exit(ret);
								/* END child code (game process) */
							}
							else
							{
								if ((close(rnk_pipe[1]) < 0) || 
									(close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
										perror("run_irc (close)");
								games_pid2tnr[game_pid] = tnr;
								games_tnr2pid[tnr] = game_pid;
								games_rnkpipe[game_pid] = rnk_pipe[0];
								games_opipe[game_pid] = out_pipe[0];
								games_ipipe[game_pid] = in_pipe[1];
								*irc << "JOIN " << MAIN_CHANNEL_UNDERSCORE << tnr << 
									std::endl << std::flush;
							}
						}
					}
					else
						std::cout << X << _("wrong number of rounds") << " <r> = " <<
							trr << std::endl;
				}
				else
					std::cout << X << _("table") << " <nr> = \"" << tnr << "\" " <<
						_("already exists") << std::endl;
			}
			else if (cmd_argc == 2)
			{
				std::string tnr = cmd_argv[1];
				if (std::find(tables.begin(), tables.end(), tnr) != tables.end())
				{
					if ((tables_p[tnr] > 0) && (tables_p[tnr] < 3) &&
						(tables_r[tnr] > 0))
					{
						if (games_tnr2pid.find(tnr) == games_tnr2pid.end())
						{
							int rnk_pipe[2], in_pipe[2], out_pipe[2];
							if ((pipe(rnk_pipe) < 0) || 
								(pipe(in_pipe) < 0) || (pipe(out_pipe) < 0))
									perror("run_irc (pipe)");
							else if ((game_pid = fork()) < 0)
								perror("run_irc (fork)");
							else
							{
								if (game_pid == 0)
								{
									/* BEGIN child code (game process) */
									signal(SIGQUIT, SIG_DFL);
									signal(SIGTERM, SIG_DFL);
									if ((close(rnk_pipe[0]) < 0) || 
										(close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
											perror("run_irc (close)");
									int ret = skat_child(tnr, tables_r[tnr], false,
										in_pipe[0], out_pipe[1], rnk_pipe[1], tables_o[tnr]);
									sleep(1);
									if ((close(rnk_pipe[1]) < 0) || 
										(close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
											perror("run_irc (close)");
									exit(ret);
									/* END child code (game process) */
								}
								else
								{
									if ((close(rnk_pipe[1]) < 0) || 
										(close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
											perror("run_irc (close)");
									games_pid2tnr[game_pid] = tnr;
									games_tnr2pid[tnr] = game_pid;
									games_rnkpipe[game_pid] = rnk_pipe[0];
									games_opipe[game_pid] = out_pipe[0];
									games_ipipe[game_pid] = in_pipe[1];
									*irc << "JOIN " << MAIN_CHANNEL_UNDERSCORE << tnr << 
										std::endl << std::flush;
									*irc << "WHO " << MAIN_CHANNEL_UNDERSCORE << tnr << 
										std::endl << std::flush;
								}
							}
						}
						else
							std::cout << X << _("player") << " \"" << pub.name << "\" " <<
								_("is already on table") << " <nr> = " << tnr << std::endl;
					}
					else
						std::cout << X << _("table") << " <nr> = " << tnr << " " <<
							_("is completely occupied") << std::endl;
				}
				else
					std::cout << X << _("table") << " <nr> = " << tnr << " " <<
						_("don't exists (yet)") << std::endl;
			}
			else
				std::cout << X << _("wrong number of arguments") << ": " << cmd_argc << 
					std::endl << X << _("/help shows the list of commands") << std::endl;
		}
		else if ((cmd_argv[0] == "ballot") || (cmd_argv[0] == "abstimmung"))
		{
			if (cmd_argc == 3)
			{
				std::string tnr = cmd_argv[1], tbb = cmd_argv[2];
				if (std::find(tables.begin(), tables.end(), tnr) == tables.end())
				{
					int b = atoi(tbb.c_str());
					if ((b > 0) && (b <= TMCG_MAX_TYPEBITS))
					{
						int in_pipe[2], out_pipe[2];
						if ((pipe(in_pipe) < 0) || (pipe(out_pipe) < 0))
							perror("run_irc (pipe)");
						else if ((ballot_pid = fork()) < 0)
							perror("run_irc (fork)");
						else
						{
							if (ballot_pid == 0)
							{
								/* BEGIN child code (ballot process) */
								signal(SIGQUIT, SIG_DFL);
								signal(SIGTERM, SIG_DFL);
								if ((close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
									perror("run_irc (close)");
								int ret = ballot_child(tnr, b, true, in_pipe[0], out_pipe[1],
									pub.keyid());
#ifndef NDEBUG
	std::cerr << "ballot_child() = " << ret << std::endl;
#endif
								sleep(1);
								if ((close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
									perror("run_irc (close)");
								exit(ret);
								/* END child code (ballot process) */
							}
							else
							{
								if ((close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
									perror("run_irc (close)");
								games_pid2tnr[ballot_pid] = tnr;
								games_tnr2pid[tnr] = ballot_pid;
								games_rnkpipe[ballot_pid] = -1;
								games_opipe[ballot_pid] = out_pipe[0];
								games_ipipe[ballot_pid] = in_pipe[1];
								*irc << "JOIN " << MAIN_CHANNEL_UNDERSCORE << tnr << 
									std::endl << std::flush;
							}
						}
					}
					else
						std::cout << X << _("wrong number of bits") << " <bits> = " <<
							tbb << std::endl;
				}
				else
					std::cout << X << _("room") << " <nr> = \"" << tnr << "\" " <<
						_("already exists") << std::endl;
			}
			else if (cmd_argc == 2)
			{
				std::string tnr = cmd_argv[1];
				if (std::find(tables.begin(), tables.end(), tnr) != tables.end())
				{
					if ((tables_p[tnr] > 0) && (-tables_r[tnr] > 0) && 
						(-tables_r[tnr] <= TMCG_MAX_TYPEBITS))
					{
						if (games_tnr2pid.find(tnr) == games_tnr2pid.end())
						{
							int in_pipe[2], out_pipe[2];
							if ((pipe(in_pipe) < 0) || (pipe(out_pipe) < 0))
								perror("run_irc (pipe)");
							else if ((ballot_pid = fork()) < 0)
								perror("run_irc (fork)");
							else
							{
								if (ballot_pid == 0)
								{
									/* BEGIN child code (ballot process) */
									signal(SIGQUIT, SIG_DFL);
									signal(SIGTERM, SIG_DFL);
									if ((close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
										perror("run_irc (close)");
									int ret = ballot_child(tnr, -tables_r[tnr], false,
										in_pipe[0], out_pipe[1], tables_o[tnr]);
#ifndef NDEBUG
	std::cerr << "ballot_child() = " << ret << std::endl;
#endif
									sleep(1);
									if ((close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
										perror("run_irc (close)");
									exit(ret);
									/* END child code (ballot process) */
								}
								else
								{
									if ((close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
										perror("run_irc (close)");
									games_pid2tnr[ballot_pid] = tnr;
									games_tnr2pid[tnr] = ballot_pid;
									games_rnkpipe[ballot_pid] = -1;
									games_opipe[ballot_pid] = out_pipe[0];
									games_ipipe[ballot_pid] = in_pipe[1];
									*irc << "JOIN " << MAIN_CHANNEL_UNDERSCORE << tnr << 
										std::endl << std::flush;
									*irc << "WHO " << MAIN_CHANNEL_UNDERSCORE << tnr << 
										std::endl << std::flush;
								}
							}
						}
						else
							std::cout << X << _("voter") << " \"" << pub.name << "\" " <<
								_("is already in room") << " <nr> = " << tnr << std::endl;
					}
					else
						std::cout << X << _("room") << " <nr> = " << tnr << " " <<
							_("is closed") << std::endl;
				}
				else
					std::cout << X << _("room") << " <nr> = " << tnr << " " <<
						_("don't exists (yet)") << std::endl;
			}
			else
				std::cout << X << _("wrong number of arguments") << ": " << cmd_argc << 
					std::endl << X << _("/help shows the list of commands") << std::endl;
		}
		else if (cmd_argv[0] == "export")
		{
			if (cmd_argc == 2)
			{
				std::ofstream ofs;
				
				ofs.exceptions(std::ofstream::failbit | std::ofstream::badbit);
				try
				{
					ofs.open(cmd_argv[1].c_str(), 
						std::ofstream::out | std::ofstream::trunc);
					if (ofs.is_open())
					{
						ofs << pub << std::endl;
						ofs.close();
					}
					else
					{
						std::cout << X << _("opening file") << " " << cmd_argv[1] << 
							" " << _("failed") << std::endl;
					}
				}
				catch (std::ofstream::failure e)
				{
					std::cout << X << _("writing file") << " " << cmd_argv[1] << 
						" " << _("failed") << ": " << e.what() << std::endl;
				}
			}
			else
				std::cout << X << _("wrong number of arguments") << ": " << 
					(cmd_argc - 1) << " " << _("instead of") << " 1" << std::endl;
		}
		else if (cmd_argv[0] == "import")
		{
			if (cmd_argc == 2)
			{
				TMCG_PublicKey apkey;
				std::ifstream ifs;
				char *buffer = new char[KEY_SIZE];
				
				if (buffer != NULL)
				{
					ifs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
					try
					{
						ifs.open(cmd_argv[1].c_str(), std::ifstream::in);
						if (ifs.is_open())
						{
							ifs.getline(buffer, KEY_SIZE);
							ifs.close();
							
							if (!apkey.import(buffer))
							{
								std::cout << X << _("TMCG: public key corrupted") << std::endl;
							}
							else if ((nick_key.find(apkey.keyid()) != nick_key.end()) ||
								(apkey.keyid() == pub.keyid()))
							{
								std::cout << X << _("public key already present") << std::endl;
							}
							else
							{
								std::cout << X << _("Checking the key") << " \"" << 
									apkey.keyid() << "\". " << _("Please wait") << "..." << 
									std::endl;
								if (!apkey.check())
								{
									std::cout << X << _("TMCG: invalid public key") << std::endl;
								}
								else
								{
									nick_key[apkey.keyid()] = apkey;
									std::cout << X << "PKI " << _("imports") << 
										" \"" << apkey.keyid() << "\" " << "aka \"" << 
										apkey.name << "\" <" << apkey.email << ">" << std::endl;
								}
							}
						}
						else
						{
							std::cout << X << _("opening file") << " " << cmd_argv[1] << 
								" " << _("failed") << std::endl;
						}
					}
					catch (std::ifstream::failure e)
					{
						std::cout << X << _("reading file") << " " << cmd_argv[1] << 
							" " << _("failed") << ": " << e.what() << std::endl;
					}
					delete [] buffer;
				}
				else
				{
					std::cout << X << _("out of memory") << std::endl;
				}
			}
			else
				std::cout << X << _("wrong number of arguments") << ": " << 
					(cmd_argc - 1) << " " << _("instead of") << " 1" << std::endl;
		}
		else if ((cmd_argv[0] == "help") || (cmd_argv[0] == "hilfe"))
		{
			std::cout << XX << _("/quit") << " -- " << 
				_("quit SecureSkat") << std::endl;
			std::cout << XX << _("/on") << " -- " << 
				_("turn on the output of IRC channel") << 
				" " << MAIN_CHANNEL << std::endl;
			std::cout << XX << _("/off") << " -- " << 
				_("turn off the output of IRC channel") <<
				" " << MAIN_CHANNEL << std::endl;
			std::cout << XX << _("/players") << " -- " << 
				_("show the list of possible participants") << std::endl;
			std::cout << XX << _("/tables") << " -- " << 
				_("show the list of existing game tables") << std::endl;
			std::cout << XX << _("/rooms") << " -- " << 
				_("show the list of existing voting rooms") << std::endl;
			std::cout << XX << _("/rank") << " -- " << 
				_("show your current rank in all score lists") << std::endl;
			std::cout << XX << _("/export") << " <fn> -- " << 
				_("exports your public key to file <fn>") << std::endl;
			std::cout << XX << _("/import") << " <fn> -- " << 
				_("imports a public key from file <fn>") << std::endl;
			std::cout << XX << _("/ballot") << " <nr> <b> -- " <<
				_("create the room <nr> for voting between 2^<b> values") << std::endl;
			std::cout << XX << _("/ballot") << " <nr> -- " << 
				_("join the voting in room <nr>") << std::endl;
			std::cout << XXX << "/<nr> open -- " << 
				_("open the voting process in room <nr> (only owner)") << std::endl;
			std::cout << XXX << "/<nr> vote <r> -- " << 
				_("vote in room <nr> for value <r>") << std::endl;
			std::cout << XX << "/skat <nr> <r> -- " << 
				_("create the table <nr> for playing <r> rounds") << std::endl;
			std::cout << XX << "/skat <nr> -- " << 
				_("join the game on table <nr>") << std::endl;
			std::cout << XX << "/<nr> <cmd> -- " << 
				_("execute the command <cmd> on table <nr>") << std::endl;
			std::cout << XXX << "/<nr> " << _("view") << " --- " << 
				_("show your own cards and additional information") << std::endl;
			std::cout << XXX << "/<nr> " << _("bid") << " --- " << 
				_("bid or justify a bid") << std::endl;
			std::cout << XXX << "/<nr> " << _("pass") << " --- " << 
				_("pass the biding") << std::endl;
			std::cout << XXX << "/<nr> hand --- " << 
				_("play without taking the two cards") << std::endl;
			std::cout << XXX << "/<nr> skat --- " << 
				_("take the two cards and show them") << std::endl;
			std::cout << XXX << "/<nr> " << _("push") << " <k1> <k2> --- " << 
				_("put away the cards <k1> and <k2>") << std::endl;
			std::cout << XXX << "/<nr> " << _("announce") << " <s> [op] --- " << 
				_("announce the game <s> ([op] is optional)") << std::endl;
			std::cout << XXX << "/<nr> " << _("play") << " <k1> --- " << 
				_("play the card <k1>") << std::endl;
			std::cout << XX << "<nr>, <fn> " << 
				_("are arbitrary strings") << std::endl;
			std::cout << XX << "<r>, <b> " << 
				_("are unsigned integers") << std::endl;
			std::cout << XXX << "<k1>, <k2> ::= { Sc, Ro, Gr, Ei } " << 
				_("followed by") << " { 7, 8, 9, U, O, K, 10, A }" << std::endl;
			std::cout << XXX << "<s> " << _("is from") << 
				" { Sc, Ro, Gr, Nu, Ei, Gd }"	<< std::endl;
			std::cout << XXX << "[op] " << _("is from") <<
				" { Sn, Sw, Ov }" << std::endl;
		}
		else
		{
			bool found = false;
			for (std::map<std::string, pid_t>::const_iterator gi = games_tnr2pid.begin(); 
				gi != games_tnr2pid.end(); gi++)
			{
				if (cmd_argv[0] == gi->first)
				{
					found = true;
					opipestream *npipe = new opipestream(games_ipipe[gi->second]);
					*npipe << "CMD ";
					for (size_t gj = 1; gj < cmd_argc; gj++)
						*npipe << cmd_argv[gj] << " ";
					*npipe << std::endl << std::flush;
					delete npipe;
				}
			}
			if (!found)
				std::cout << X << _("unknown command") << ": \"/" << cmd_argv[0] << 
					"\"" << std::endl << X << _("/help shows the list of commands") << std::endl;
		}
	}
	else
	{
		if ((s != NULL) && (strlen(s) > 0))
		{
			// sign and send chat message
			*irc << "PRIVMSG " << MAIN_CHANNEL << " :" << s << "~~~" << 
				sec.sign(s) << std::endl << std::flush;
			std::cout << "<" << pub.name << "> " << s << std::endl;
		}
	}
	free(line);
}

void run_irc()
{
	bool first_command = true, first_entry = false, entry_ok = false;
	fd_set rfds;										// set of read descriptors
	int mfds = 0;										// highest-numbered descriptor
	struct timeval tv;							// timeout structure for select(2)
	char irc_readbuf[32768];				// read buffer
	int irc_readed = 0;							// read pointer
	unsigned long ann_counter = 0;	// announcement counter
	unsigned long clr_counter = 0;	// clear tables counter
#ifdef AUTOJOIN
	unsigned long atj_counter = 0;	// autojoin counter
#endif
		
	while (irc->good() && !irc_quit)
	{
		// select(2) -- initalize file descriptors
		FD_ZERO(&rfds);
#ifndef NOHUP
		MFD_SET(fileno(stdin), &rfds);
#endif
		MFD_SET(irc_handle, &rfds);
		MFD_SET(pki7771_handle, &rfds);
		MFD_SET(rnk7773_handle, &rfds);
		MFD_SET(rnk7774_handle, &rfds);
		
		// PKI pipes from childs
		for (std::map<pid_t, int>::const_iterator pi = nick_pipe.begin();
			pi != nick_pipe.end(); pi++)
				MFD_SET(pi->second, &rfds);
				
		// RNK pipes from childs
		for (std::map<pid_t, int>::const_iterator pi = rnk_pipe.begin();
			pi != rnk_pipe.end(); pi++)
				MFD_SET(pi->second, &rfds);
		
		// RNK pipes from game childs
		for (std::map<pid_t, int>::const_iterator pi = games_rnkpipe.begin();
			pi != games_rnkpipe.end(); pi++)
				if (pi->second >= 0)
					MFD_SET(pi->second, &rfds);
		
		// OUT pipes from game childs
		for (std::map<pid_t, int>::const_iterator pi = games_opipe.begin();
			pi != games_opipe.end(); pi++)
				MFD_SET(pi->second, &rfds);
		
		// select(2) -- initalize timeout
		tv.tv_sec = 1L;			// seconds
		tv.tv_usec = 0L;		// microseconds
		
		// select(2) -- do everything with asynchronous I/O
		int ret = select(mfds + 1, &rfds, NULL, NULL, &tv);
		
		// error occured
		if (ret < 0)
		{
			if (errno != EINTR)
				perror("run_irc (select)");
			else
				continue;
		}
		
		// anything happend in any descriptor set
		if (ret > 0)
		{
			// RNK pipes from children
			// ----------------------------------------------------------------------
			read_after_select(rfds, rnk_pipe, 1);
			
			// RNK pipes from game children
			// ----------------------------------------------------------------------
			read_after_select(rfds, games_rnkpipe, 1);
			
			// OUT pipes from game children
			// ----------------------------------------------------------------------
			read_after_select(rfds, games_opipe, 2);
						
			// PKI pipes from children
			// ----------------------------------------------------------------------
			read_after_select(rfds, nick_pipe, 3);
			
			// RNK (export rank list on port 7773)
			// ----------------------------------------------------------------------
			if (FD_ISSET(rnk7773_handle, &rfds))
			{
				struct sockaddr_in client_in;
				socklen_t client_len = sizeof(client_in);
				int client_handle = accept(rnk7773_handle, 
					(struct sockaddr*) &client_in, &client_len);
				
				if (client_handle < 0)
				{
					perror("run_irc (accept)");
				}
				else
				{
					iosocketstream *rnk_io = new iosocketstream(client_handle);
					*rnk_io << rnk.size() << std::endl << std::flush;
					for (std::map<std::string, std::string>::const_iterator pi = rnk.begin(); 
						pi != rnk.end(); pi++)
					{
						*rnk_io << pi->first << std::endl << std::flush;
					}
					delete rnk_io;
					if (close(client_handle) < 0)
						perror("run_irc (close)");
				}
			}
			
			// PKI (export public key on port 7771)
			// ----------------------------------------------------------------------
			if (FD_ISSET(pki7771_handle, &rfds))
			{
				struct sockaddr_in client_in;
				socklen_t client_len = sizeof(client_in);
				int client_handle = accept(pki7771_handle, 
					(struct sockaddr*) &client_in, &client_len);
				
				if (client_handle < 0)
				{
					perror("run_irc (accept)");
				}
				else
				{
					iosocketstream *pki = new iosocketstream(client_handle);
					*pki << pub << std::endl << std::flush;
					delete pki;
					if (close(client_handle) < 0)
						perror("run_irc (close)");
				}
			}
			
			// RNK (get rank entry on port 7774)
			// ----------------------------------------------------------------------
			if (FD_ISSET(rnk7774_handle, &rfds))
			{
				struct sockaddr_in client_in;
				socklen_t client_len = sizeof(client_in);
				int client_handle = accept(rnk7774_handle, 
					(struct sockaddr*) &client_in, &client_len);
				
				// error occured
				if (client_handle < 0)
				{
					perror("run_irc (accept)");
				}
				else if (rnkrpl_pid.size() >= RNK_CHILDS)
				{
					if (close(client_handle) < 0)
						perror("run_irc (close)");
				}
				else
				{
					pid_t client_pid;
					if ((client_pid = fork()) < 0)
					{
						perror("run_irc (fork)");
						if (close(client_handle) < 0)
							perror("run_irc (close)");
					}
					else
					{
						if (client_pid == 0)
						{
							signal(SIGQUIT, SIG_DFL);
							signal(SIGTERM, SIG_DFL);
							
							/* BEGIN child code (ranking data) */
							iosocketstream *client_ios = new iosocketstream(client_handle);
							char *tmp = new char[100000L];
							client_ios->getline(tmp, 100000L);
							
							if (rnk.find(tmp) != rnk.end())
								*client_ios << rnk[tmp] << std::endl << std::flush;
							else
								*client_ios << std::endl << std::flush;
							delete client_ios, delete [] tmp;
							exit(0);
							/* END child code (ranking data) */
						}
						else
						{
							rnkrpl_pid.push_back(client_pid);
							if (close(client_handle) < 0)
								perror("run_irc (close)");
						}
					}
				}
			}
			
#ifndef NOHUP
			// read from stdin
			// ----------------------------------------------------------------------
			if (FD_ISSET(fileno(stdin), &rfds))
			{
				rl_callback_read_char();
			}
#endif
			
			// read from IRC connection
			// ----------------------------------------------------------------------
			if (FD_ISSET(irc_handle, &rfds))
			{
				ssize_t num = read(irc_handle, irc_readbuf + irc_readed, 
					sizeof(irc_readbuf) - irc_readed);
				irc_readed += num;
				
				if (num == 0)
				{
					std::cerr << _("IRC ERROR: connection with server collapsed") <<
						std::endl;
					break;
				}
				
				if (irc_readed > 0)
				{
					std::vector<int> pos_delim;
					int cnt_delim = 0, cnt_pos = 0, pos = 0;
					for (int i = 0; i < irc_readed; i++)
					{
						if (irc_readbuf[i] == '\n')
							cnt_delim++, pos_delim.push_back(i);
						if (irc_readbuf[i] == '\015')
							irc_readbuf[i] = '\n', cnt_delim++, pos_delim.push_back(i);
					}
					while (cnt_delim >= 1)
					{
						char tmp[65536];
						memset(tmp, 0, sizeof(tmp));
						memcpy(tmp, irc_readbuf + cnt_pos, pos_delim[pos] - cnt_pos);
						--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
						irc_reply = tmp;
				
				// parse NICK and HOST from IRC prefix
				std::string pfx = irc_prefix(irc_reply);
				std::string nick = "?", host = "?";
				if ((pfx.find("!", 0) != pfx.npos) && (pfx.find("@", 0) != pfx.npos))
				{
					nick = pfx.substr(0, pfx.find("!", 0));
					host = pfx.substr(pfx.find("@", 0) + 1, 
						pfx.length() - pfx.find("@", 0) - 1);
				}
				
				if (strncasecmp(irc_command(irc_reply), "PING", 4) == 0)
				{
					*irc << "PONG " << irc_params(irc_reply) << std::endl << std::flush;
				}
				else if (strncasecmp(irc_command(irc_reply), "001", 3) == 0)
				{
					entry_ok = true, first_entry = true;
				}
				else if ((strncasecmp(irc_command(irc_reply), "436", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "462", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "433", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "468", 3) == 0))
				{
					std::cerr << _("IRC ERROR: not registered at IRC server") << std::endl;
					std::cerr << irc_reply << std::endl;
					irc_quit = 1;
					break;
				}
				else if (strncasecmp(irc_command(irc_reply), "JOIN", 4) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 1)
					{
						if (irc_parvec[0] == MAIN_CHANNEL)
						{
							if (nick.find(pub.keyid(), 0) == 0)
							{
								std::cout << X << _("you join channel") << " " << 
									irc_parvec[0] << std::endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								*irc << "WHO " << irc_parvec[0] << std::endl << std::flush;
							}
							else
							{
								if (irc_stat)
									std::cout << X << _("observer") << " \"" << nick << "\" ("
										<< host << ") " << _("joins channel") << " " << 
										irc_parvec[0] << std::endl;
							}
						}
						else if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
							(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
						{
							std::string tb = 
								irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
								irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
							
							if (nick.find(pub.keyid(), 0) == 0)
							{
								std::cout << X << _("you join") << " " << tb << std::endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "JOIN " << nick << std::endl << std::flush;
									delete npipe;
								}
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								std::cout << X << _("player") << " \"" << nick << "\" (" <<
									host << ") " << _("joins") << " " << tb << std::endl;
							}
							else
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "KIEBITZ " << nick << std::endl << std::flush;
									delete npipe;
								}
								std::cout << X << _("observer") << " \"" << nick << "\" (" <<
									host << ") " << _("joins") << " " << tb << std::endl;
							}
						}
					}
				}
				else if ((strncasecmp(irc_command(irc_reply), "471", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "473", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "474", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "403", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "405", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "475", 3) == 0))
				{
					std::cerr << _("IRC ERROR: join to channel failed") << std::endl;
					std::cerr << irc_reply << std::endl;
				}
				else if (strncasecmp(irc_command(irc_reply), "PART", 4) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 1)
					{
						if (irc_parvec[0] == MAIN_CHANNEL)
						{
							if (nick.find(pub.keyid(), 0) == 0)
							{
								std::cout << X << _("you leave channel") << " " <<
									irc_parvec[0] << std::endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								nick_players.erase(nick), nick_sl.erase(nick);
								nick_p7771.erase(nick), nick_p7772.erase(nick);
								nick_p7773.erase(nick), nick_p7774.erase(nick);
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								if (irc_stat)
									std::cout << X << _("player") << " \"" << nick << "\" (" << 
										host << ") " << _("leaves channel") << " " << 
										irc_parvec[0] << std::endl;
							}
							else
							{
								if (irc_stat)
									std::cout << X << _("observer") << " \"" << nick << "\" (" <<
										host << ") " << _("leaves channel") << " " <<
										irc_parvec[0] << std::endl;
							}
						}
						else if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
							(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
						{
							std::string tb = 
								irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
								irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
								
							if (nick.find(pub.keyid(), 0) == 0)
							{
								std::cout << X << _("you leave") << " " << tb << std::endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "PART " << nick << std::endl << std::flush;
									delete npipe;
								}
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								std::cout << X << _("player") << " \"" << nick << "\" (" <<
									host << ") " << _("leaves") << " " << tb << std::endl;
							}
							else
							{
								std::cout << X << _("observer") << " \"" << nick << "\" (" <<
									host << ") " << _("leaves") << " " << tb << std::endl;
							}
						}
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "KICK", 4) == 0)
				{
					int pvs = irc_paramvec(irc_params(irc_reply));
					if (pvs >= 2)
					{
						if (irc_parvec[0] == MAIN_CHANNEL)
						{
							if (irc_parvec[1].find(pub.keyid(), 0) == 0)
							{
								std::cout << X << _("you kicked from channel") << " " << 
									irc_parvec[0] << " " << _("by operator") << " " << 
									nick << std::endl;
								if (pvs == 3)
									std::cout << X << _("reason") << ": " << irc_parvec[2] << std::endl;
								irc_quit = 1;
								break;
							}
							else if (irc_parvec[1].find(public_prefix, 0) == 0)
							{
								nick_players.erase(irc_parvec[1]), nick_sl.erase(nick);
								nick_p7771.erase(nick),	nick_p7772.erase(nick);
								nick_p7773.erase(nick),	nick_p7774.erase(nick);
								if (nick_key.find(irc_parvec[1]) != nick_key.end())
									host = nick_key[irc_parvec[1]].name;
								if (irc_stat)
									std::cout << X << _("player") << " \"" << host << "\" " <<
										_("kicked from channel") << " " << irc_parvec[0] << " " <<
										_("by operator") << " " << nick << std::endl;
								if (irc_stat && (pvs == 3))
									std::cout << X << _("reason") << ": " << irc_parvec[2] << std::endl;
							}
							else
							{
								if (irc_stat)
									std::cout << X << _("observer") << " \"" << host << "\" " <<
										_("kicked from channel") << " " << irc_parvec[0] << " " <<
										_("by operator") << " " << nick << std::endl;
								if (irc_stat && (pvs == 3))
									std::cout << X << _("reason") << ": " << irc_parvec[2] << std::endl;
							}
						}
						else if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) &&
							(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
						{
							std::string tb = 
								irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
								irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
							
							if (irc_parvec[1].find(pub.keyid(), 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "!KICK" << std::endl << std::flush;
									delete npipe;
								}
								std::cout << X << _("you kicked from") << " " << tb << std::endl;
								if (pvs == 3)
									std::cout << X << _("reason") << ": " << irc_parvec[2] << std::endl;
							}
							else if (irc_parvec[1].find(public_prefix, 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "KICK " << irc_parvec[1] << std::endl << std::flush;
									delete npipe;
								}
								if (nick_key.find(irc_parvec[1]) != nick_key.end())
									nick = nick_key[irc_parvec[1]].name;
								std::cout << X << _("player") << " \"" << nick << "\" " <<
										_("kicked from") << " " << tb << std::endl;
								if (pvs == 3)
									std::cout << X << _("reason") << ": " << irc_parvec[2] << std::endl;	
							}
							else
							{
								std::cout << X << _("observer") << " \"" << irc_parvec[1] << 
									"\" " << _("kicked from") << " " << tb << std::endl;
								if (pvs == 3)
									std::cout << X << _("reason") << ": " << irc_parvec[2] << std::endl;	
							}
						}
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "QUIT", 4) == 0)
				{
					if (nick.find(pub.keyid(), 0) == 0)
					{
						std::cout << X << _("you quit SecureSkat") << std::endl;
					}
					else if (nick.find(public_prefix, 0) == 0)
					{
						nick_players.erase(nick),nick_sl.erase(nick);
						nick_p7771.erase(nick), nick_p7772.erase(nick);
						nick_p7773.erase(nick), nick_p7774.erase(nick);
						for (std::map<std::string, pid_t>::const_iterator gi = games_tnr2pid.begin();
							gi != games_tnr2pid.end(); gi++)
						{
							opipestream *npipe = 
								new opipestream(games_ipipe[gi->second]);
							*npipe << "QUIT " << nick << std::endl << std::flush;
							delete npipe;
						}
						if (nick_key.find(nick) != nick_key.end())
							nick = nick_key[nick].name;
						if (irc_stat)
							std::cout << X << _("player") << " \"" << nick << "\" (" << host << 
								") " << _("quits SecureSkat") << std::endl;
					}
					else
					{
						if (irc_stat)
							std::cout << X << _("observer") << " \"" << nick << "\" (" << host <<
								") " << _("quits IRC client") << std::endl;
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "352", 3) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 8)
					{
						if (irc_parvec[5] != pub.keyid())
						{
							if (irc_parvec[1] == MAIN_CHANNEL)
							{
								if (irc_parvec[5].find(public_prefix, 0) == 0)
								{
									if ((irc_stat) && (irc_parvec[3] == "localhost"))
										std::cerr << _("WARNING: host of player") << " \"" <<
											irc_parvec[5] << "\" " << 
											_("has unqualified domain (no FQDN)") << std::endl;
									std::string tmp = irc_parvec[7], package = "unknown";
									int p7771 = 0, p7772 = 0, p7773 = 0, p7774 = 0, sl = 0;
									size_t a0 = tmp.find(" ", 0);
									size_t ai = tmp.find("|", 0), bi = tmp.find("~", 0);
									size_t ci = tmp.find("!", 0), di = tmp.find("#", 0);
									size_t ei = tmp.find("?", 0), fi = tmp.find("/", 0);
									if ((a0 != tmp.npos) && (ai != tmp.npos) && 
										(bi != tmp.npos) && (ci != tmp.npos) && 
										(di != tmp.npos) && (ei != tmp.npos) && 
										(fi != tmp.npos) && (a0 < ai) && (ai < bi) && 
										(bi < ci) && (ci < di) && (di < ei) && (ei < fi))
									{
										package = tmp.substr(a0 + 1, ai - a0 - 1);
										std::string ptmp7771 = tmp.substr(ai + 1, bi - ai - 1);
										std::string ptmp7772 = tmp.substr(bi + 1, ci - bi - 1);
										std::string ptmp7773 = tmp.substr(ci + 1, di - ci - 1);
										std::string ptmp7774 = tmp.substr(di + 1, ei - di - 1);
										std::string sltmp = tmp.substr(ei + 1, fi - ei - 1);
										p7771 = atoi(ptmp7771.c_str());
										p7772 = atoi(ptmp7772.c_str());
										p7773 = atoi(ptmp7773.c_str());
										p7774 = atoi(ptmp7774.c_str());
										sl = atoi(sltmp.c_str());
									}
									nick_package[irc_parvec[5]] = package;
									nick_p7771[irc_parvec[5]] = p7771;
									nick_p7772[irc_parvec[5]] = p7772;
									nick_p7773[irc_parvec[5]] = p7773;
									nick_p7774[irc_parvec[5]] = p7774;
									nick_sl[irc_parvec[5]] = sl;
									nick_players[irc_parvec[5]] = irc_parvec[3];
									if (nick_key.find(irc_parvec[5]) != nick_key.end())
										irc_parvec[5] = nick_key[irc_parvec[5]].name;
									if (irc_stat)
										std::cout << X << _("player") << " \"" << irc_parvec[5] << 
											"\" (" << irc_parvec[3] << ") " << _("is in channel") <<
											" " << irc_parvec[1] << std::endl;
								}
								else
								{
									if (irc_stat)
										std::cout << X << _("observer") << " \"" << irc_parvec[5] << 
											"\" (" << irc_parvec[3] << ") " << _("is in channel") <<
											" " << irc_parvec[1] << std::endl;
								}
							}
							else if ((irc_parvec[1].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) &&
								(irc_parvec[1].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
							{
								std::string tb = 
									irc_parvec[1].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
									irc_parvec[1].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
								if (irc_parvec[5].find(public_prefix, 0) == 0)
								{
									if (games_tnr2pid.find(tb) != games_tnr2pid.end())
									{
										opipestream *npipe = 
											new opipestream(games_ipipe[games_tnr2pid[tb]]);
										*npipe << "WHO " << irc_parvec[5] << std::endl << std::flush;
										delete npipe;
									}
									if (nick_key.find(irc_parvec[5]) != nick_key.end())
										irc_parvec[5] = nick_key[irc_parvec[5]].name;
									if (irc_stat)
										std::cout << X << _("player") << " \"" << irc_parvec[5] << 
											"\" (" << irc_parvec[3] << ") " << _("is at") <<
											" " << irc_parvec[1] << std::endl;
								}
							}
						}
					}	
				} // MOTD start line and end line
				else if ((strncasecmp(irc_command(irc_reply), "375", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "376", 3) == 0))
				{
					std::cout << std::endl;
				} // MOTD text line
				else if (strncasecmp(irc_command(irc_reply), "372", 3) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 2)
					{
						std::string tms = irc_parvec[1].substr(1, irc_parvec[1].length() - 1);
						std::cout << X << tms << std::endl;
					}
				} // PRIVMSG
				else if (strncasecmp(irc_command(irc_reply), "PRIVMSG", 7) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 2)
					{
						// control messages
						if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
							(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)) && 
							(nick.find(public_prefix, 0) == 0))
						{
							std::string tb = 
								irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
								irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
							if (games_tnr2pid.find(tb) != games_tnr2pid.end())
							{
								size_t tei = irc_parvec[1].find("~~~");
								if (tei != irc_parvec[1].npos)
								{
									std::string realmsg = irc_parvec[1].substr(0, tei);
									std::string sig = irc_parvec[1].substr(tei + 3, 
										irc_parvec[1].length() - realmsg.length() - 3);
									if (nick_key.find(nick) != nick_key.end())
									{
										if (nick_key[nick].verify(realmsg, sig))
										{
											opipestream *npipe = 
												new opipestream(games_ipipe[games_tnr2pid[tb]]);
											*npipe << "MSG " << nick << " " << realmsg <<
											std::endl << std::flush;
											delete npipe;
										}
										else
											std::cerr << _("TMCG: verify() failed") << std::endl;
									}
									else
										std::cerr << _("TMCG: no public key available") << std::endl;
								}
							}
						}
						// announce and no channel messages
						if (((irc_parvec[1].find("~+~") != irc_parvec[1].npos) && 
								(irc_parvec[0] == MAIN_CHANNEL))
							||
							((irc_parvec[0] != MAIN_CHANNEL) &&
								(nick.find(public_prefix, 0) == 0) &&
								((irc_parvec[0] == pub.keyid()) &&
									(nick != pub.keyid()))))
						{
							size_t tabei1 = irc_parvec[1].find("|", 0);
							size_t tabei2 = irc_parvec[1].find("~", 0);
							size_t tabei3 = irc_parvec[1].find("!", 0);
							if ((tabei1 != irc_parvec[1].npos) &&
								(tabei2 != irc_parvec[1].npos) &&
								(tabei3 != irc_parvec[1].npos) && 
								(tabei1 < tabei2) && (tabei2 < tabei3))
							{
								std::string tabmsg1 = irc_parvec[1].substr(0, tabei1);
								std::string tabmsg2 = irc_parvec[1].substr(tabei1 + 1, 
									tabei2 - tabei1 - 1);
								std::string tabmsg3 = irc_parvec[1].substr(tabei2 + 1, 
									tabei3 - tabei2 - 1);	
								if ((std::find(tables.begin(), tables.end(), tabmsg1) 
									== tables.end()) && (tabmsg2 != "0"))
								{
									// new table
									tables.push_back(tabmsg1);
									tables_p[tabmsg1] = atoi(tabmsg2.c_str());
									tables_r[tabmsg1] = atoi(tabmsg3.c_str());
									tables_u[tabmsg1] = tabmsg3;
									tables_o[tabmsg1] = nick;
								}	
								else
								{
									if (nick == tables_o[tabmsg1])
									{
										if (tabmsg2 == "0")
										{
											// remove table
											tables_p.erase(tabmsg1), tables_r.erase(tabmsg1);
											tables_u.erase(tabmsg1), tables_o.erase(tabmsg1);
											tables.remove(tabmsg1);
										}
										else
										{
											// update table
											tables_p[tabmsg1] = atoi(tabmsg2.c_str());
											tables_r[tabmsg1] = atoi(tabmsg3.c_str());
											tables_u[tabmsg1] = tabmsg3;
										}
									}
									else
										std::cout << XX << _("player") << " \"" << nick << 
											"\" (" << host << ") " << 
											_("announces unauthorized session") << " " <<
											tabmsg1 << std::endl;
								}
							}
							else if (irc_stat)
							{
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								std::cout << ">" << nick << "< " << irc_parvec[1] << std::endl;
							}
						}// chat messages
						else if (irc_stat && (irc_parvec[0] == MAIN_CHANNEL))
						{
							size_t tei = irc_parvec[1].find("~~~");
							if ((nick.find(public_prefix, 0) == 0) &&
								(nick_key.find(nick) != nick_key.end()) &&
								(tei != irc_parvec[1].npos))
							{
								std::string realmsg = irc_parvec[1].substr(0, tei);
								std::string sig = irc_parvec[1].substr(tei + 3, 
									irc_parvec[1].length() - realmsg.length() - 3);
								if (nick_key[nick].verify(realmsg, sig))
								{
									nick = nick_key[nick].name;
									std::cout << "<" << nick << "> " << realmsg << std::endl;
								}
								else
									std::cerr << _("TMCG: verify() failed") << std::endl;
							}
							else
								std::cout << "<?" << nick << "?> " << irc_parvec[1] << std::endl;
						} // other messages
						else if (irc_stat &&
							((irc_parvec[0] == pub.keyid()) &&
							(nick != pub.keyid())))
						{
							std::cout << ">?" << nick << "?< " << irc_parvec[1] << std::endl;
						}
					}
				}
				else if ((strncasecmp(irc_command(irc_reply), "NOTICE", 6) == 0) || 
					(strncasecmp(irc_command(irc_reply), "020", 3) == 0))
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 2)
					{
						std::cout << "[NOTICE] " << irc_parvec[1] << std::endl;
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "ERROR", 5) == 0)
				{
					std::cerr << "[ERROR] " << irc_reply << std::endl;
				}
				else
				{
					// unparsed IRC-message -- ignore it
//std::cerr << "IRC: unparsed message:" << std::endl;
//std::cerr << "[UNPARSED]" << irc_reply << std::endl;
				}
				
					}
					char tmp[65536];
					memset(tmp, 0, sizeof(tmp));
					irc_readed -= cnt_pos;
					memcpy(tmp, irc_readbuf + cnt_pos, irc_readed);
					memcpy(irc_readbuf, tmp, irc_readed);
				}
			}
		}
		
		// timeout occured
		if (ret == 0)
		{
			// use signal blocking for atomic operations (really a dirty hack :-)
			raise(SIGUSR1);
			
			// re-install signal handlers (some unices do not restore them)
			signal(SIGINT, sig_handler_quit);
			signal(SIGQUIT, sig_handler_quit);
			signal(SIGTERM, sig_handler_quit);
			signal(SIGPIPE, sig_handler_pipe);
			signal(SIGCHLD, sig_handler_chld);
#ifdef NOHUP
			signal(SIGHUP, SIG_IGN);
#endif
			signal(SIGUSR1, sig_handler_usr1);
			
			if (first_command)
			{
				char ptmp[100];
				snprintf(ptmp, sizeof(ptmp), "|%d~%d!%d#%d?%d/", 
					pki7771_port, pki7772_port, rnk7773_port, rnk7774_port,
					(int)security_level);
				std::string uname = pub.keyid();
				if (uname.length() > 4)
				{
					std::string uname2 = "os";
					for (size_t ic = 4; ic < uname.length(); ic++)
					{
						if (islower(uname[ic]))
							uname2 += uname[ic];
						else if (isdigit(uname[ic]))
							uname2 += ('a' + (uname[ic] - 0x30));
						else if (isupper(uname[ic]))
							uname2 += ('a' + (uname[ic] - 0x40));
					}
					uname = uname2;
				}
				else
					uname = "unknown";
				*irc << "USER " << uname << " 0 0 :" << PACKAGE_STRING << ptmp << 
					std::endl << std::flush;
				first_command = false;
			}
			else if (first_entry)
			{
				*irc << "JOIN " << MAIN_CHANNEL << std::endl << std::flush;
				*irc << "WHO " << MAIN_CHANNEL << std::endl << std::flush;
				first_entry = false;
			}
			else if (entry_ok)
			{
#ifdef AUTOJOIN
				// timer: autojoin to known tables each AUTOJOIN_TIMEOUT seconds
				if (atj_counter >= AUTOJOIN_TIMEOUT)
				{
					for (std::list<std::string>::const_iterator ti = tables.begin(); 
						ti != tables.end(); ti++)
					{
						// if not joined in a game, do AUTOJOIN (greedy behaviour)
						if (games_tnr2pid.find(*ti) == games_tnr2pid.end())
						{
							char *command = (char*)malloc(500);
							if (command == NULL)
							{
								std::cerr << _("MALLOC ERROR: out of memory") << std::endl;
								exit(-1);
							}
							memset(command, 0, 500);
							strncat(command, "/skat ", 25);
							strncat(command, ti->c_str(), 475);
							process_line(command);
							// free(command) is already done by process_line()
						}
					}
					atj_counter = 0;
				}
				else
					atj_counter++;
#endif
				// timer: clear all tables every CLEAR_TIMEOUT seconds
				if (clr_counter >= CLEAR_TIMEOUT)
				{
					tables.clear();
					clr_counter = 0;
					ann_counter += ANNOUNCE_TIMEOUT;
				}
				else
					clr_counter++;
				// timer: announce own tables every ANNOUNCE_TIMEOUT seconds
				if (ann_counter >= ANNOUNCE_TIMEOUT)
				{
					for (std::map<pid_t, int>::const_iterator pi = games_ipipe.begin();
						pi != games_ipipe.end(); ++pi)
					{
						opipestream *npipe = new opipestream(pi->second);
						*npipe << "!ANNOUNCE" << std::endl << std::flush;
						delete npipe;
					}
					ann_counter = 0;
				}
				else
					ann_counter++;
			}
			
			// send SIGQUIT to all PKI processes -- PKI TIMEMOUT
			for (std::list<pid_t>::const_iterator pidi = nick_pids.begin();
				pidi != nick_pids.end(); pidi++)
			{
				if (nick_ncnt[nick_nick[*pidi]] > PKI_TIMEOUT)
					if (kill(*pidi, SIGQUIT) < 0)
						perror("run_irc (kill)");
			}
			
			// send SIGQUIT to all RNK processes -- RNK TIMEMOUT
			for (std::list<pid_t>::const_iterator pidi = rnk_pids.begin();
				pidi != rnk_pids.end(); pidi++)
			{
				if (nick_rnkcnt[rnk_nick[*pidi]] > RNK_TIMEOUT)
					if (kill(*pidi, SIGQUIT) < 0)
						perror("run_irc (kill)");
			}
			
			// start RNK or PKI process
			for (std::map<std::string, std::string>::const_iterator ni = nick_players.begin();
					ni != nick_players.end(); ni++)
			{
				std::string nick = ni->first, host = ni->second;
				
				// RNK
				if (nick_rcnt.find(nick) == nick_rcnt.end())
					nick_rcnt[nick] = RNK_TIMEOUT;
				else
					nick_rcnt[nick] += 1;
				if (nick_rnkcnt.find(nick) != nick_rnkcnt.end())
					nick_rnkcnt[nick] += 1;
				if ((nick_rcnt[nick] > RNK_TIMEOUT) &&
					(nick_rnkcnt.find(nick) == nick_rnkcnt.end()))
				{
					nick_rcnt[nick] = 0;
					int fd_pipe[2];
					if (pipe(fd_pipe) < 0)
						perror("run_irc (pipe)");
					else if ((rnk_pid = fork()) < 0)
						perror("run_irc (fork)");
					else
					{
						if (rnk_pid == 0)
						{
							signal(SIGQUIT, SIG_DFL);
							signal(SIGTERM, SIG_DFL);
							
							// begin -- child code
							sleep(1);
							if (close(fd_pipe[0]) < 0)
							{
								perror("run_irc [child] (close)");
								exit(-1);
							}
							opipestream *npipe = new opipestream(fd_pipe[1]);
							size_t rnk_idsize = 0;
							std::vector<std::string> rnk_idlist;
							
							// create TCP/IP connection
							int nick_handle = ConnectToHost(host.c_str(), nick_p7773[nick]);
							if (nick_handle < 0)
							{
								std::cerr << "run_irc [RNK/child] (ConnectToHost)" << std::endl;
								exit(-1);
							}
							iosocketstream *nrnk = new iosocketstream(nick_handle);
							
							// get RNK list
							char *tmp = new char[RNK_SIZE];
							if (tmp == NULL)
							{
								std::cerr << _("RNK ERROR: out of memory") << std::endl;
								exit(-1);
							}
							nrnk->getline(tmp, RNK_SIZE);
							rnk_idsize = strtoul(tmp, NULL, 10);
							for (size_t i = 0; i < rnk_idsize; i++)
							{
								nrnk->getline(tmp, RNK_SIZE);
								if (rnk.find(tmp) == rnk.end())
									rnk_idlist.push_back(tmp);
							}
							
							// close TCP/IP connection
							delete nrnk;
							if (close(nick_handle) < 0)
								perror("run_irc [RNK/child] (close)");
							
							// iterate RNK list
							for (std::vector<std::string>::const_iterator ri = rnk_idlist.begin();
								ri != rnk_idlist.end(); ri++)
							{
								// create TCP/IP connection
								int rhd = ConnectToHost(host.c_str(), nick_p7774[nick]);
								if (rhd < 0)
								{
									std::cerr << "run_irc [RNK2/child] (ConnectToHost)" << std::endl;
									exit(-1);
								}
								iosocketstream *nrpl = new iosocketstream(rhd);
								
								// get RNK data and send it to parent
								*nrpl << *ri << std::endl << std::flush;
								nrpl->getline(tmp, RNK_SIZE);
								*npipe << *ri << std::endl << std::flush;
								*npipe << tmp << std::endl << std::flush;
								
								// close TCP/IP connection
								delete nrpl;
								if (close(rhd) < 0)
									perror("run_irc [RNK2/child] (close)");
							}
							*npipe << "EOF" << std::endl << std::flush;
							delete npipe;
							delete [] tmp;
							if (close(fd_pipe[1]) < 0)
								perror("run_irc (close)");
							
							exit(0);
							// end -- child code
						}
						else
						{
							if (close(fd_pipe[1]) < 0)
								perror("run_irc (close)");
							rnk_pids.push_back(rnk_pid);
							nick_rnkcnt[nick] = 1;
							nick_rnkpid[nick] = rnk_pid;
							rnk_nick[rnk_pid] = nick;
							rnk_pipe[rnk_pid] = fd_pipe[0];
						}
					}
				}
				
				// PKI
				if ((nick_key.find(nick) == nick_key.end()) && 
					(std::find(nick_ninf.begin(), nick_ninf.end(), nick) 
					== nick_ninf.end()))
				{
					int fd_pipe[2];
					if (pipe(fd_pipe) < 0)
						perror("run_irc (pipe)");
					if ((nick_pid = fork()) < 0)
						perror("run_irc (fork)");
					else
					{
						if (nick_pid == 0)
						{
							signal(SIGQUIT, SIG_DFL);
							signal(SIGTERM, SIG_DFL);
							
							// begin -- child code
							sleep(1);
							if (close(fd_pipe[0]) < 0)
							{
								perror("run_irc [child] (close)");
								exit(-1);
							}
							opipestream *npipe = new opipestream(fd_pipe[1]);
							
							// create TCP/IP connection
							int nick_handle = ConnectToHost(host.c_str(), nick_p7771[nick]);
							if (nick_handle < 0)
							{
								std::cerr << "run_irc [PKI/child] (ConnectToHost)" << std::endl;
								exit(-1);
							}
							iosocketstream *nkey = new iosocketstream(nick_handle);
							
							// get public key
							char *tmp = new char[KEY_SIZE];
							if (tmp == NULL)
							{
								std::cerr << _("PKI ERROR: out of memory") << std::endl;
								exit(-1);
							}
							nkey->getline(tmp, KEY_SIZE);
							public_key = tmp;
							
							// close TCP/IP connection
							delete nkey;
							delete [] tmp;
							if (close(nick_handle) < 0)
								perror("run_irc [PKI/child] (close)");
							
							// import public key
							TMCG_PublicKey pkey;
							if (!pkey.import(public_key))
							{
								std::cerr << _("TMCG: public key corrupted") << std::endl;
								exit(-2);
							}
							
							// check keyID
							if (nick != pkey.keyid())
							{
								std::cerr << _("TMCG: wrong public key") << std::endl;
								exit(-3);
							}
							
							// check NIZK
							if (!pkey.check())
							{
								std::cerr << _("TMCG: invalid public key") << std::endl;
								exit(-4);
							}
							
							// send valid public key to parent
							*npipe << nick << std::endl << std::flush;
							*npipe << public_key << std::endl << std::flush;
							
							delete npipe;
							if (close(fd_pipe[1]) < 0)
								perror("run_irc [child] (close)");
							exit(0);
							// end -- child code
						}
						else
						{
							if (close(fd_pipe[1]) < 0)
								perror("run_irc (close)");
							nick_pids.push_back(nick_pid);
							nick_ninf.push_back(nick);
							nick_ncnt[nick] = 1;
							nick_nick[nick_pid] = nick;
							nick_host[nick_pid] = host;
							nick_pipe[nick_pid] = fd_pipe[0];
						}
					}
				}
				else if (std::find(nick_ninf.begin(), nick_ninf.end(), nick) 
					!= nick_ninf.end())
				{
					nick_ncnt[nick] += 1;
				}
			}
		}
	}
	if (!irc->good())
		std::cerr << _("IRC ERROR: connection with server collapsed") << std::endl;
}

void done_irc()
{
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	*irc << "PART " << MAIN_CHANNEL << std::endl << std::flush;
	*irc << "QUIT :SecureSkat rulez!" << std::endl << std::flush;
	for (std::map<pid_t, std::string>::const_iterator pidi = games_pid2tnr.begin();
		pidi != games_pid2tnr.end(); pidi++)
	{
		if (kill(pidi->first, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(pidi->first, NULL, 0);
	}
	games_pid2tnr.clear(), games_tnr2pid.clear();
	for (std::list<pid_t>::const_iterator pidi = nick_pids.begin();
		pidi != nick_pids.end(); pidi++)
	{
		if (kill(*pidi, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(*pidi, NULL, 0);
	}
	nick_pids.clear(), nick_nick.clear(), nick_host.clear(),
		nick_ninf.clear(), nick_ncnt.clear(), nick_players.clear();
	for (std::list<pid_t>::const_iterator pidi = pkiprf_pid.begin();
		pidi != pkiprf_pid.end(); pidi++)
	{
		if (kill(*pidi, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(*pidi, NULL, 0);
	}
	pkiprf_pid.clear();
	for (std::list<pid_t>::const_iterator pidi = rnkrpl_pid.begin();
		pidi != rnkrpl_pid.end(); pidi++)
	{
		if (kill(*pidi, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(*pidi, NULL, 0);
	}
	rnkrpl_pid.clear();
}

void release_irc()
{
	delete irc;
	if (close(irc_handle) < 0)
		perror("release_irc (close)");
}

void init_term()
{
	if (tcgetattr(fileno(stdin), &old_term) < 0)
	{
		perror("init_term (tcgetattr)");
		exit(-1);
	}
	new_term = old_term;
	new_term.c_lflag &= ~ICANON, new_term.c_cc[VTIME] = 1;
	if (tcsetattr(fileno(stdin), TCSANOW, &new_term) < 0)
	{
		perror("init_term (tcsetattr)");
		exit(-1);
	}
	rl_readline_name = "SecureSkat";
#ifdef _RL_FUNCTION_TYPEDEF
	rl_callback_handler_install(NULL, (rl_vcpfunc_t*)process_line);
#else
	rl_callback_handler_install(NULL, (VFunction*)process_line);
#endif
}

void done_term()
{
	rl_callback_handler_remove();
	if (tcsetattr(fileno(stdin), TCSANOW, &old_term) < 0)
		perror("done_term (tcsetattr)");
}

int main(int argc, char* argv[], char* envp[])
{
	char *home = NULL;
	std::string cmd = argv[0], homedir = "";
	std::cout << PACKAGE_STRING <<
		", (c) 2002 -- 2006  Heiko Stamer <stamer@gaos.org>, GNU GPL" << std::endl <<
		" $Id: SecureSkat.cc,v 1.46 2007/03/23 22:50:03 stamer Exp $ " << std::endl;
	
#ifdef ENABLE_NLS
#ifdef HAVE_LC_MESSAGES
	setlocale(LC_TIME, "");
	setlocale(LC_MESSAGES, "");
#else
	setlocale(LC_ALL, "");
#endif
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	std::cout << "++ " << _("Internationalization support") << ": " << 
		LOCALEDIR << std::endl;
#endif
	
	// environment variable HOME
	home = getenv("HOME");
	if (home != NULL)
		homedir = home, homedir += "/.SecureSkat/";
	else
		homedir = "~/.SecureSkat/";
	std::cout << "++ " << _("PKI/RNK database directory") << ": " << 
		homedir << std::endl;
	
	struct stat stat_buffer;
	if (stat(homedir.c_str(), &stat_buffer))
	{
		if (errno == ENOENT)
		{
			// directory doesn't exist
			if (mkdir(homedir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR))
			{
				std::cerr << _("Can't create directory!") << " (" << 
					strerror(errno) << ")" << std::endl;
				return EXIT_FAILURE;
			}
		}
		else
		{
			std::cerr << _("Can't get the status of the directory!") << " (" << 
				strerror(errno) << ")" << std::endl;
			return EXIT_FAILURE;
		}
	}
	else
	{
		if (!S_ISDIR(stat_buffer.st_mode))
		{
			std::cerr << _("Path is not a directory!") << std::endl;
			return EXIT_FAILURE;
		}
		if (stat_buffer.st_uid != getuid())
		{
			std::cerr << _("Wrong owner of the directory!") << std::endl;
			return EXIT_FAILURE;
		}
		if ((stat_buffer.st_mode & (S_IRUSR | S_IWUSR | S_IXUSR)) !=
			(S_IRUSR | S_IWUSR | S_IXUSR))
		{
			std::cerr << _("Missing permissions on the directory!") << std::endl;
			return EXIT_FAILURE;
		}
	}
	
	if (((argc == 5) && isdigit(argv[2][0]) && isdigit(argv[3][0])) || 
		((argc == 4) && isdigit(argv[2][0]) && isdigit(argv[3][0])) || 
		((argc == 3) && isdigit(argv[2][0])) || 
		(argc == 2))
	{
		// default values
		irc_port = 6667;
		security_level = 16;
		game_ctl = "";
		game_env = NULL;
		
		// evaluate the command line switches
		switch (argc)
		{
			case 5:
				game_ctl = argv[4];
				game_env = envp;
			case 4:
				security_level = atoi(argv[3]);
			case 3:
				irc_port = atoi(argv[2]);
		}
		
		// initalize libTMCG
		if (!init_libTMCG())
		{
			std::cerr << _("Initalization of libTMCG failed!") << std::endl;
			return EXIT_FAILURE;
		}
		
		get_secret_key(homedir + "SecureSkat.skr", sec, public_prefix);
		pub = TMCG_PublicKey(sec); // extract the public part of the secret key
		std::cout << _("Your key fingerprint") << ": " << pub.fingerprint() << 
			std::endl;
		get_public_keys(homedir + "SecureSkat.pkr", nick_key); // get public keys
		
		create_pki(pki7771_port, pki7771_handle);
		create_rnk(rnk7773_port, rnk7774_port, rnk7773_handle, rnk7774_handle);
		load_rnk(homedir + "SecureSkat.rnk", rnk);
		create_irc(argv[1], irc_port);
		init_irc();
		std::cout <<
			_("Usage") << ": " <<
			_("type /help for the command list or read the file README") <<
			std::endl;
#ifndef NOHUP
		init_term();
#endif
		run_irc(); // main loop
#ifndef NOHUP
		done_term();
#endif
		done_irc();
		release_irc();
		save_rnk(homedir + "SecureSkat.rnk", rnk);
		release_rnk(rnk7773_handle, rnk7774_handle);
		release_pki(pki7771_handle);
		set_public_keys(homedir + "SecureSkat.pkr", nick_key);
		
		return EXIT_SUCCESS;
	}
	
	std::cout << _("Usage") << ": " << cmd <<
		" IRC_SERVER<string> [ IRC_PORT<int> " <<
		"[ SECURITY_LEVEL<int> ..." << std::endl;
	std::cout << "       " << " ... [ CONTROL_PROGRAM<string> ] ] ]" << std::endl;
	return EXIT_FAILURE;
}
