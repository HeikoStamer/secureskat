/*******************************************************************************
   SecureSkat.cc, secure multiplayer implementation of german card game "Skat"

 Copyright (C) 2002, 2003, 2004 Heiko Stamer, <stamer@gaos.org>

   This program is free software; you can redistribute it and/or modify
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

// autoconf header
#if HAVE_CONFIG_H
	#include "config.h"
#endif

// C/C++ header
#include <stdio.h>
#include <cstdlib>
#include <cstdarg>
#include <cassert>
#include <cstring>
#include <strings.h>
#include <csignal>
#include <unistd.h>
#include <ctime>
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <termios.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <zlib.h>
#include <clocale>
#include <libintl.h>

// STL classes
#include <string>
#include <map>
#include <vector>
#include <list>
#include <algorithm>
#include <iostream>
#include <sstream>

#include <SchindelhauerTMCG.hh>
#include "socketstream.hh"
#include "securesocketstream.hh"
#include "pipestream.hh"
#include "SecureSkat_misc.hh"
#include "SecureSkat_pki.hh"
#include "SecureSkat_rnk.hh"
#include "SecureSkat_vtmf.hh"

using namespace std;
#define MFD_SET(fd, where) { FD_SET(fd, where); mfds = (fd > mfds) ? fd : mfds; }
#ifdef ENABLE_NLS
	#define _(String) gettext(String)
#else
	#define _(String) String
#endif

// define TIMEOUT (in seconds)
#define PKI_TIMEOUT							1500
#define RNK_TIMEOUT							500
#define ANNOUNCE_TIMEOUT				5
#define CLEAR_TIMEOUT						60
#define AUTOJOIN_TIMEOUT				75

// define BOUNDS (in child processes)
#define PKI_CHILDS							10
#define RNK_CHILDS							5

SchindelhauerTMCG								*tmcg;
mpz_ui													security_level = 16;
string													game_ctl;
char														**game_env;
TMCG_SecretKey 									sec;
TMCG_PublicKey 									pub;
map<int, char*> 								readbuf;
map<int, ssize_t>								readed;

TMCG_KeyString 									secret_key, public_key, public_prefix;
list< pair<pid_t, int> >				usr1_stat;
map<string, string>							nick_players;
map<string, int>								nick_p7771, nick_p7772, 
																nick_p7773, nick_p7774, nick_sl;
map<string, TMCG_PublicKey>			nick_key;
list<string>										tables;
map<string, int>								tables_r, tables_p;
map<string, string>							tables_u, tables_o;
pid_t														game_pid, ballot_pid;
map<string, pid_t>							games_tnr2pid;
map<pid_t, string>							games_pid2tnr;
map<pid_t, int>									games_rnkpipe, games_opipe, games_ipipe;

pid_t														nick_pid;
list<pid_t>											nick_pids;
list<string>										nick_ninf;
map<string, int>								nick_ncnt;
map<pid_t, string>							nick_nick, nick_host;
map<pid_t, int>									nick_pipe;

list<pid_t>											rnk_pids, rnkrpl_pid;
pid_t														rnk_pid;
map<string, string>							rnk;
map<string, int>								nick_rnkcnt, nick_rcnt;
map<string, pid_t>							nick_rnkpid;
map<pid_t, string>							rnk_nick;
map<pid_t, int>									rnk_pipe;

int															pki7771_port, pki7772_port, 
																rnk7773_port, rnk7774_port;
int															pki7771_handle, pki7772_handle,
																rnk7773_handle, rnk7774_handle;
list<pid_t>											pkiprf_pid;

map<string, int>								bad_nick;

string													irc_reply, irc_pfx, irc_cmd, irc_par;
int															irc_port, irc_handle, ctl_pid = 0;
vector<string>									irc_parvec;
bool														irc_stat = true;
iosocketstream									*irc;

string													X = ">< ", XX = "><>< ", XXX = "><><>< ";
struct termios									old_term, new_term;

sig_atomic_t		irc_quit = 0, sigchld_critical = 0;

#ifndef RETSIGTYPE
	#define RETSIGTYPE void
#endif

RETSIGTYPE sig_handler_quit(int sig)
{
	cerr << "... SIGNAL " << sig << " RECEIVED ..." << endl;
	irc_quit = 1;
}

RETSIGTYPE sig_handler_skat_quit(int sig)
{
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
		pair <pid_t, int> chld_stat = usr1_stat.front();
		usr1_stat.pop_front();
		pid_t chld_pid = chld_stat.first;
		int status = chld_stat.second;
		
		if (games_pid2tnr.find(chld_pid) != games_pid2tnr.end())
		{
			string tnr = games_pid2tnr[chld_pid];
			if (WIFEXITED(status))
			{
				if (WEXITSTATUS(status) == 0)
					cerr << X << _("Session") << " \"" << tnr << "\" " << 
						_("succeeded properly") << endl;
				else
					cerr << X << _("Session") << " \"" << tnr << "\" " << 
						_("failed. Error code: WEXITSTATUS ") << 
						WEXITSTATUS(status) << endl;
			}
			if (WIFSIGNALED(status))
			{
				cerr << X << _("Session") << " \"" << tnr << "\" " << 
					_("failed. Error code: WTERMSIG ") <<
					WTERMSIG(status) << endl;
			}
			games_tnr2pid.erase(games_pid2tnr[chld_pid]);
			games_pid2tnr.erase(chld_pid);
		}
		else if (std::find(pkiprf_pid.begin(), pkiprf_pid.end(), chld_pid) !=
			pkiprf_pid.end())
		{
			cerr << X << "PKI (pid = " << chld_pid << ") " << 
				_("succeeded properly") << endl;
			pkiprf_pid.remove(chld_pid);
		}
		else if (std::find(rnkrpl_pid.begin(), rnkrpl_pid.end(), chld_pid) !=
			rnkrpl_pid.end())
		{
			cerr << X << "RNK (pid = " << chld_pid << ") " << 
				_("succeeded properly") << endl;
			rnkrpl_pid.remove(chld_pid);
		}
		else if (std::find(rnk_pids.begin(), rnk_pids.end(), chld_pid) !=
			rnk_pids.end())
		{
			if (WIFEXITED(status))
			{
				if (WEXITSTATUS(status) != 0)
				{
					cerr << X << "RNK (pid = " << chld_pid << ") " <<
						_("failed. Error code: WEXITSTATUS ") << 
						WEXITSTATUS(status) << endl;
				}
			}
			if (WIFSIGNALED(status))
			{
				cerr << X << "RNK (pid = " << chld_pid << ") " << 
					_("failed. Error code: WTERMSIG ") << 
					WTERMSIG(status) << endl;
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
					cerr << X << "PKI " << chld_pid << "/" << nick_nick[chld_pid] << 
						" " << _("failed. Error code: WEXITSTATUS ") << 
						WEXITSTATUS(status) << endl;
				}
			}
			if (WIFSIGNALED(status))
			{
				cerr << X << "PKI " << chld_pid << "/" << nick_nick[chld_pid] <<
					" " << _("failed. Error code: WTERMSIG ") << 
					WTERMSIG(status) << endl;
			}
			
			// remove bad nick from player list
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
	pair <pid_t, int> chld_stat;
	int status;
	chld_stat.first = wait(&status), chld_stat.second = status;
	usr1_stat.push_back(chld_stat);
	
	sigchld_critical = 0;
}

void create_irc(const string &server, short int port)
{
	irc_handle = ConnectToHost(server.c_str(), port);
	if (irc_handle < 0)
	{
		perror("create_irc (ConnectToHost)");
		exit(-1);
	}
	irc = new iosocketstream(irc_handle);
}

const char *irc_prefix(const string &input)
{
	irc_pfx = input;
	if (irc_pfx.find(":", 0) == 0)
		irc_pfx = irc_pfx.substr(1, irc_pfx.find(" ", 0) - 1);
	else
		irc_pfx = "";
	return irc_pfx.c_str();
}

const char *irc_command(const string &input)
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

const char *irc_params(const string &input)
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

size_t irc_paramvec(string input)
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
	*irc << "NICK " << tmcg->TMCG_ExportKeyID(pub) << endl << flush;
}

void skat_connect
	(opipestream *out_pipe, const string &nr, SchindelhauerTMCG *t,
	size_t pkr_self, size_t pkr_idx, iosecuresocketstream *&secure, int &handle, 
	map<string, int> gp_ports, const vector<string> &vnicks,
	TMCG_PublicKeyRing pkr)
{
	// create TCP/IP connection
	handle = ConnectToHost(
		nick_players[vnicks[pkr_idx]].c_str(),
		gp_ports[vnicks[pkr_idx]]
	);
	if (handle < 0)
	{
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		sleep(1),	exit(-4);
	}
	iosocketstream *neighbor = new iosocketstream(handle);

	// authenticate connection
	char tmp[TMCG_MAX_CARD_CHARS];
	TMCG_CardSecret cs;
	// receive challenge
	neighbor->getline(tmp, sizeof(tmp));
	if (t->TMCG_ImportCardSecret(cs, tmp))
	{
		string chlg1 = tmp, chlg2 = "";
		chlg1 += "<>" + vnicks[pkr_idx];
		// send signature
		*neighbor << t->TMCG_SignData(sec, chlg1) << endl << flush;
		// create new challenge
		t->TMCG_CreateCardSecret(cs, pkr, pkr_self);
		// send challenge
		*neighbor << cs << endl << flush;
		// receive signature
		neighbor->getline(tmp, sizeof(tmp));
		// verify signature
		ostringstream ost;
		ost << cs, chlg2 = ost.str() + "<>" + vnicks[pkr_self];
		if (!t->TMCG_VerifyData(pkr.key[pkr_idx], chlg2, tmp) || !neighbor->good())
		{
			delete neighbor;
			close(handle);
			*out_pipe << "PART #openSkat_" << nr << endl << flush;
			sleep(1),	exit(-6);
		}
	}
	else
	{
		delete neighbor;
		close(handle);
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		sleep(1),	exit(-6);
	}

	// exchange secret keys for securesocketstreams
	assert (gcry_md_test_algo (GCRY_MD_RMD160) == 0);
	char *key1 = new char[gcry_md_get_algo_dlen (GCRY_MD_RMD160)];
	char *key2 = new char[gcry_md_get_algo_dlen (GCRY_MD_RMD160)];
	gcry_randomize((unsigned char*)key1, 
		gcry_md_get_algo_dlen (GCRY_MD_RMD160), GCRY_STRONG_RANDOM);
	const char *ev = t->TMCG_EncryptValue(pkr.key[pkr_idx], key1);
	if (ev == NULL)
	{
		cerr << _("TMCG: EncryptValue() failed") << endl;
		delete neighbor;
		close(handle);
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		sleep(1),	exit(-6);
	}
	*neighbor << ev << endl << flush;

	neighbor->getline(tmp, sizeof(tmp));
	const char *dv = t->TMCG_DecryptValue(sec, tmp);
	if (dv == NULL)
	{
		cerr << _("TMCG: DecryptValue() failed") << endl;
		delete neighbor;
		close(handle);
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		sleep(1),	exit(-6);
	}
	memcpy(key2, dv, gcry_md_get_algo_dlen (GCRY_MD_RMD160)); 
	delete neighbor;
	secure = new iosecuresocketstream(handle, key1, 16, key2, 16);
	delete [] key1, delete [] key2;
}

void skat_accept (opipestream *out_pipe, int ipipe, const string &nr, int r,
	SchindelhauerTMCG *t, int pkr_self, int pkr_idx, 
	iosecuresocketstream *&secure, int &handle, const vector<string> &vnicks,
	const TMCG_PublicKeyRing &pkr, int gp_handle, bool neu, char *ireadbuf, int &ireaded)
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
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		sleep(1),	exit(-4);
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
				perror("skat_accept (accept)");
			else
			{
				if (client_in.sin_addr.s_addr == sin.sin_addr.s_addr)
				{
					iosocketstream *neighbor = new iosocketstream(handle);
					TMCG_CardSecret cs;
					t->TMCG_CreateCardSecret(cs, pkr, pkr_self);
					*neighbor << cs << endl << flush;
					char tmp[TMCG_MAX_CARD_CHARS];
					neighbor->getline(tmp, sizeof(tmp));
					ostringstream ost;
					ost << cs;
					if (!t->TMCG_VerifyData(pkr.key[pkr_idx], ost.str() + "<>" + 
						vnicks[pkr_self], tmp) || !neighbor->good())
					{
						delete neighbor;
						close(handle);
						*out_pipe << "PART #openSkat_" << nr << endl << flush;
						sleep(1),	exit(-6);
					}
					else
					{
						neighbor->getline(tmp, sizeof(tmp));
						if (t->TMCG_ImportCardSecret(cs, tmp))
						{
							string st = tmp;
							st += "<>" + vnicks[pkr_idx];
							*neighbor << t->TMCG_SignData(sec, st) << endl << flush;
							
							// exchange secret keys for securesocketstreams
							assert (gcry_md_test_algo (GCRY_MD_RMD160) == 0);
							char *key1 = new char[gcry_md_get_algo_dlen (GCRY_MD_RMD160)];
							char *key2 = new char[gcry_md_get_algo_dlen (GCRY_MD_RMD160)];
							neighbor->getline(tmp, sizeof(tmp));
							const char *dv = t->TMCG_DecryptValue(sec, tmp);
							if (dv == NULL)
							{
								cerr << _("TMCG: DecryptValue() failed") << endl;
								delete neighbor;
								close(handle);
								*out_pipe << "PART #openSkat_" << nr << endl << flush;
								sleep(1),	exit(-6);
							}
							memcpy(key2, dv, gcry_md_get_algo_dlen (GCRY_MD_RMD160));
							
							gcry_randomize((unsigned char*)key1, 
								gcry_md_get_algo_dlen (GCRY_MD_RMD160), GCRY_STRONG_RANDOM);
							const char *ev = t->TMCG_EncryptValue(pkr.key[pkr_idx], key1);
							if (ev == NULL)
							{
								cerr << _("TMCG: EncryptValue() failed") << endl;
								delete neighbor;
								close(handle);
								*out_pipe << "PART #openSkat_" << nr << endl << flush;
								sleep(1),	exit(-6);
							}
							*neighbor << ev << endl << flush;
							delete neighbor;
							secure = new iosecuresocketstream(handle, key1, 16, key2, 16);
							delete [] key1, delete [] key2;
							break;
						}
						else
						{
							delete neighbor;
							close(handle);
							*out_pipe << "PART #openSkat_" << nr << endl << flush;
							sleep(1),	exit(-6);
						}
					}
				}
				else
				{
					close(handle);
					*out_pipe << "PART #openSkat_" << nr << endl << flush;
					sleep(1),	exit(-6);
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
				vector<int> pos_delim;
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
					string cmd = tmp;
					// do operation
					if ((cmd == "") || (cmd.find("!KICK", 0) == 0))
					{
						exit(-1);
					}
					if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
					{
						*out_pipe << "PRIVMSG #openSkat :" 
							<< nr << "|3~" << r << "!" << endl << flush;
					}	
					if (neu && (cmd.find("KIEBITZ ", 0) == 0))
					{
						string nick = cmd.substr(8, cmd.length() - 8);
						*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
							_("observers currently not permitted") << endl << flush;
					}
					if (neu && (cmd.find("JOIN ", 0) == 0))
					{
						string nick = cmd.substr(5, cmd.length() - 5);
						*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
							_("table completely occupied") << endl << flush;
					}
					if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
					{
						string nick = cmd.substr(5, cmd.length() - 5);
						if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
						{
							*out_pipe << "PART #openSkat_" << nr << endl << flush;
							sleep(1), exit(-5);
						}
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
				*out_pipe << "PART #openSkat_" << nr << endl << flush;
				sleep(1), exit(-50);
			}
		}
	}
}

void skat_alive(opipestream *out_pipe, const string &nr, 
	iosecuresocketstream *r, iosecuresocketstream *l)
{
	if (!r->good() || !l->good())
	{
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		sleep(1), exit(-5);
	}
}

#include "SecureSkat_ballot.inc"

int skat_child
	(const string &nr, int r, bool neu, int ipipe, int opipe, int hpipe, const string &master)
{
	SchindelhauerTMCG *gp_tmcg = 
		new SchindelhauerTMCG(security_level, 3, 5);	// 3 players, 32 cards
	list<string> gp_nick;
	map<string, string> gp_name;
	char *ipipe_readbuf = new char[65536];
	int ipipe_readed = 0;
	if (ipipe_readbuf == NULL)
	{
		cerr << _("MALLOC ERROR: out of memory") << endl;
		exit(-1);
	}
	gp_nick.push_back(gp_tmcg->TMCG_ExportKeyID(pub));
	gp_name[gp_tmcg->TMCG_ExportKeyID(pub)] = pub.name;
	
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
		*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << gp_nick.size() <<
			"~" << r << "!" << endl << flush;
	
	// wait for players
	while (1)
	{
		char tmp[10000];
		in_pipe->getline(tmp, sizeof(tmp));
		string cmd = tmp;
		
		if ((cmd == "") || (cmd.find("!KICK", 0) == 0))
		{
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << gp_nick.size() <<
				"~" << r << "!" << endl << flush;
		}
		if (neu && (cmd.find("KIEBITZ ", 0) == 0))
		{
			string nick = cmd.substr(8, cmd.length() - 8);
			*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
				_("observers currently not permitted") << endl << flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			string nick = cmd.substr(5, cmd.length() - 5);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
				{
					gp_nick.push_back(nick), gp_name[nick] = nick_key[nick].name;
					*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << 
						gp_nick.size() << "~" << r << "!" << endl << flush;
				}
				else
					*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
						_("player was at table creation not present") << endl << flush;
			}
			else
				*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
					_("key exchange with owner is incomplete") << endl << flush;
		}
		if (!neu && ((cmd.find("JOIN ", 0) == 0) || (cmd.find("WHO ", 0) == 0)))
		{
			string nick = (cmd.find("JOIN ", 0) == 0) ?
				cmd.substr(5, cmd.length() - 5) : cmd.substr(4, cmd.length() - 4);
			if (nick_key.find(nick) != nick_key.end())
			{
				if (nick_players.find(nick) != nick_players.end())
					gp_nick.push_back(nick), gp_name[nick] = nick_key[nick].name;
				else
					*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
						_("player was at table creation not present") << endl << flush;
			}
			else
			{
				cerr << X << _("key exchange with") << " " << nick << " " << 
					_("is incomplete") << endl;
				*out_pipe << "PART #openSkat_" << nr << endl << flush;
				return -1;
			}
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(gp_nick.begin(), gp_nick.end(), nick)	!= gp_nick.end())
			{
				gp_nick.remove(nick),	gp_name.erase(nick);
			}
		}
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			string msg = cmd.substr(cmd.find(" ", 4) + 1, 
				cmd.length() - cmd.find(" ", 4) - 1);
				
			if ((msg == "!READY") && (nick == master))
				break;
		}
		if (neu && (gp_nick.size() == 3))
		{
			*out_pipe << "PRIVMSG #openSkat :" << nr << "|" << gp_nick.size() <<
				"~" << r << "!" << endl << flush;
			*out_pipe << "PRIVMSG #openSkat_" << nr << " :!READY" << endl << flush;
			break;
		}
	}
	cout << X << _("Table") << " " << nr << " " << _("preparing the game") << 
		" ..." << endl;
	// prepare game (check number of players, create PKR, create connections)
	if ((gp_nick.size() != 3) || (std::find(gp_nick.begin(), gp_nick.end(),
		gp_tmcg->TMCG_ExportKeyID(pub)) == gp_nick.end()))
	{
		cerr << X << _("wrong number of players") << ": " << 
			gp_nick.size() << endl;
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		return -2;
	}
	TMCG_PublicKeyRing pkr;
	vector<string> vnicks;
	size_t pkr_i = 0, pkr_self = 0;
	gp_nick.sort();
	for (list<string>::const_iterator pi = gp_nick.begin(); 
		pi != gp_nick.end(); pi++)
	{
		vnicks.push_back(*pi);
		if (*pi == gp_tmcg->TMCG_ExportKeyID(pub))
		{
			pkr_self = pkr_i;
			pkr.key[pkr_i++] = pub;
		}
		else
			pkr.key[pkr_i++] = nick_key[*pi];
	}
	int gp_port = BindEmptyPort(7800), gp_handle;
	if ((gp_handle = ListenToPort(gp_port)) < 0)
	{
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
		return -4;
	}
	
	ostringstream ost;
	ost << "PRIVMSG #openSkat_" << nr << " :PORT " << gp_port << endl;
	*out_pipe << ost.str() << flush;
	cout << X << _("Table") << " " << nr << " " << _("with") << " '" << 
		pkr.key[0].name << "', '" << 
		pkr.key[1].name << "', '" << 
		pkr.key[2].name << "' " << _("ready") << "." << endl;	
	list<string> gp_rdport;
	map<string, int> gp_ports;
	while (gp_rdport.size() < 2)
	{
		char tmp[10000];
		in_pipe->getline(tmp, sizeof(tmp));
		string cmd = tmp;
	
		if (cmd.find("!KICK", 0) == 0)
		{
			return -1;
		}
		if (neu && (cmd.find("!ANNOUNCE", 0) == 0))
		{
			*out_pipe << "PRIVMSG #openSkat :" << nr << "|3~" << r << "!" << 
				endl << flush;
		}		
		if (neu && (cmd.find("KIEBITZ ", 0) == 0))
		{
			string nick = cmd.substr(8, cmd.length() - 8);
			*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
				_("observers currently not permitted") << endl << flush;
		}
		if (neu && (cmd.find("JOIN ", 0) == 0))
		{
			string nick = cmd.substr(5, cmd.length() - 5);
			*out_pipe << "KICK #openSkat_" << nr << " " << nick << " :" <<
				_("table completely occupied") << endl << flush;
		}
		if ((cmd.find("PART ", 0) == 0) || (cmd.find("QUIT ", 0) == 0))
		{
			string nick = cmd.substr(5, cmd.length() - 5);
			if (std::find(vnicks.begin(), vnicks.end(), nick) != vnicks.end())
			{
				*out_pipe << "PART #openSkat_" << nr << endl << flush;
				return -5;
			}
		}
		if ((cmd.find("MSG ", 0) == 0) && (cmd.find(" ", 4) != cmd.npos))
		{
			string nick = cmd.substr(4, cmd.find(" ", 4) - 4);
			string msg = cmd.substr(cmd.find(" ", 4) + 1, 
				cmd.length() - cmd.find(" ", 4) - 1);
			if (msg.find("PORT ", 0) == 0)
			{
				string port = msg.substr(5, msg.length() - 5);
				if ((std::find(gp_rdport.begin(), gp_rdport.end(), nick) 
					== gp_rdport.end()))
				{
					gp_rdport.push_back(nick);
					gp_ports[nick] = atoi(port.c_str());
				}
			}
		}
	}
	cout << X << _("Table") << " " << nr << " " <<
		_("establishing secure channels") << " ..." << endl;
	int connect_handle, accept_handle;
	iosecuresocketstream *left_neighbor, *right_neighbor;
	if (pkr_self == 0)
	{
		skat_connect(out_pipe, nr, gp_tmcg, pkr_self, 1, 
			left_neighbor, connect_handle, gp_ports, vnicks, pkr);
		skat_accept(out_pipe, ipipe, nr, r, gp_tmcg, pkr_self, 2, 
			right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu,
			ipipe_readbuf, ipipe_readed);
	}
	else if (pkr_self == 1)
	{
		skat_accept(out_pipe, ipipe, nr, r, gp_tmcg, pkr_self, 0,
			right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu,
			ipipe_readbuf, ipipe_readed);
		skat_connect(out_pipe, nr, gp_tmcg, pkr_self, 2, 
			left_neighbor, connect_handle, gp_ports, vnicks, pkr); 
	}
	else if (pkr_self == 2)
	{
		skat_accept(out_pipe, ipipe, nr, r, gp_tmcg, pkr_self, 1,
			right_neighbor, accept_handle, vnicks, pkr, gp_handle, neu,
			ipipe_readbuf, ipipe_readed);
		skat_connect(out_pipe, nr, gp_tmcg, pkr_self, 0, 
			left_neighbor, connect_handle, gp_ports, vnicks, pkr);
	}
	skat_alive(out_pipe, nr, right_neighbor, left_neighbor);
	if (neu)
		*out_pipe << "PRIVMSG #openSkat :" << nr << "|3~" << vnicks[0] << ", " <<
			vnicks[1] << ", " << vnicks[2] << "!" << endl << flush;
	
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
			}
			else
			{
				pctl = true;
				if ((close(pipe1fd[1]) < 0) || (close(pipe2fd[0]) < 0))
					perror("skat_child (close)");
				ctl_i = pipe1fd[0], ctl_o = pipe2fd[1];
				cout << X << _("Execute control process") << " (" << ctl_pid << 
					"): " << flush;
				char buffer[1024];
				bzero(buffer, sizeof(buffer));
				ssize_t num = read(ctl_i, buffer, sizeof(buffer));
				if (num > 0)
					cout << buffer << flush;
				else
					cout << "... " << _("failed!") << endl;
			}
		}
	}
	
	// start game
	cout << X << _("Table") << " " << nr << " " << _("start the game.") << endl;
	int exit_code = skat_game(nr, r, pkr_self, neu, opipe, ipipe, ctl_o, ctl_i,
		gp_tmcg, pkr, sec, right_neighbor, left_neighbor, vnicks, hpipe, pctl,
		ipipe_readbuf, ipipe_readed);
	
	// stop gui or ai (control program)
	if (ctl_pid > 0)
	{
		if (kill(ctl_pid, SIGQUIT) < 0)
			perror("skat_child (kill)");
		waitpid(ctl_pid, NULL, 0);
	}
	
	if (neu)
		*out_pipe << "PRIVMSG #openSkat :" << nr << "|0~" << r << "!" << 
			endl << flush;
	
	// exit from game
	delete gp_tmcg, delete left_neighbor, delete right_neighbor;
	close(connect_handle), close(accept_handle);
	if (exit_code != 6)
		*out_pipe << "PART #openSkat_" << nr << endl << flush;
	delete in_pipe, out_pipe;
	delete [] ipipe_readbuf;
	return exit_code;
}

void read_after_select(fd_set rfds, map<pid_t, int> &read_pipe, int what)
{
	vector<pid_t> del_pipe;
	for (map<pid_t, int>::const_iterator pi = read_pipe.begin(); 
		pi != read_pipe.end(); pi++)
	{
		if ((pi->second >= 0) && FD_ISSET(pi->second, &rfds))
		{
			if (readbuf.find(pi->second) == readbuf.end())
			{
				readbuf[pi->second] = new char[65536];
				if (readbuf[pi->second] == NULL)
				{
					cerr << _("MALLOC ERROR: out of memory") << endl;
					exit(-1);
				}
				readed[pi->second] = 0;
			}
			ssize_t num = read(pi->second,
				readbuf[pi->second] + readed[pi->second], 65536 - readed[pi->second]);
			readed[pi->second] += num;
			if (num == 0)
				del_pipe.push_back(pi->first);
			if (readed[pi->second] > 0)
			{
				vector<int> pos_delim;
				int cnt_delim = 0, cnt_pos = 0, pos = 0;
				for (int i = 0; i < readed[pi->second]; i++)
					if (readbuf[pi->second][i] == '\n')
						cnt_delim++, pos_delim.push_back(i);
				if (what == 1)
				{
					while (cnt_delim >= 2)
					{
						char tmp[65536];
						bzero(tmp, sizeof(tmp));
						memcpy(tmp, readbuf[pi->second] + cnt_pos, 
							pos_delim[pos] - cnt_pos);
						--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
						string rnk1 = tmp;
						bzero(tmp, sizeof(tmp));
						memcpy(tmp, readbuf[pi->second] + cnt_pos, 
							pos_delim[pos] - cnt_pos);
						cnt_delim--, cnt_pos = pos_delim[pos] + 1, pos++;
						string rnk2 = tmp;
						// do operation
						rnk[rnk1] = rnk2;
					}
				}
				else if (what == 2)
				{
					while (cnt_delim >= 1)
					{
						char tmp[65536];
						bzero(tmp, sizeof(tmp));
						memcpy(tmp, readbuf[pi->second] + cnt_pos, 
							pos_delim[pos] - cnt_pos);
						--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
						string irc1 = tmp;
						
						// do operation
						if (strncasecmp(irc_command(irc1), "PRIVMSG", 7) == 0)
						{
							if (irc_paramvec(irc_params(irc1)) >= 2)
							{
								if ((irc_parvec[0].find("#openSkat_", 0) == 0) && 
									(irc_parvec[0].length() > 10))
								{
									// sign message
									string sig = tmcg->TMCG_SignData(sec, irc_parvec[1]);
									*irc << "PRIVMSG " << irc_parvec[0] << " :" <<
										irc_parvec[1] << "~~~" << sig << endl << flush;
								}
								else if (irc_parvec[0] == "#openSkat")
								{
									for (map<string, string>::const_iterator ni = 
										nick_players.begin(); ni != nick_players.end(); ni++)
									{
										// send announcement PRIVMSG to each player
										*irc << "PRIVMSG " << ni->first << " :" << 
											irc_parvec[1] << endl << flush;
									}
									
									// process announcement PRIVMSG
									size_t tabei1 = irc_parvec[1].find("|", 0);
									size_t tabei2 = irc_parvec[1].find("~", 0);
									size_t tabei3 = irc_parvec[1].find("!", 0);
									if ((tabei1 != irc_parvec[1].npos) &&
										(tabei2 != irc_parvec[1].npos) &&
										(tabei3 != irc_parvec[1].npos) && 
										(tabei1 < tabei2) && (tabei2 < tabei3))
									{
										string tabmsg1 = irc_parvec[1].substr(0, tabei1);
										string tabmsg2 = irc_parvec[1].substr(tabei1 + 1, 
											tabei2 - tabei1 - 1);
										string tabmsg3 = irc_parvec[1].substr(tabei2 + 1, 
											tabei3 - tabei2 - 1);	
										if ((std::find(tables.begin(), tables.end(), tabmsg1) 
											== tables.end()) && (tabmsg2 != "0"))
										{
											// new table
											tables.push_back(tabmsg1);
											tables_p[tabmsg1] = atoi(tabmsg2.c_str());
											tables_r[tabmsg1] = atoi(tabmsg3.c_str());
											tables_u[tabmsg1] = tabmsg3;
											tables_o[tabmsg1] = tmcg->TMCG_ExportKeyID(pub);
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
									*irc << irc1 << endl << flush;
							}
							else
								*irc << irc1 << endl << flush;
						}
						else
							*irc << irc1 << endl << flush;
					}
				}
				else if (what == 3)
				{
					while (cnt_delim >= 2)
					{
						char tmp[65536];
						bzero(tmp, sizeof(tmp));
						memcpy(tmp, readbuf[pi->second] + cnt_pos, 
							pos_delim[pos] - cnt_pos);
						--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
						TMCG_KeyString pki1 = tmp;
						bzero(tmp, sizeof(tmp));
						memcpy(tmp, readbuf[pi->second] + cnt_pos, 
							pos_delim[pos] - cnt_pos);
						cnt_delim--, cnt_pos = pos_delim[pos] + 1, pos++;
						TMCG_KeyString pki2 = tmp;
						// do operation
						TMCG_PublicKey apkey;
						if (!tmcg->TMCG_ImportKey(apkey, pki2))
						{
							cerr << _("TMCG: public key import error") << endl;
						}
						else if (pki1 != tmcg->TMCG_ExportKeyID(apkey))
						{
							cerr << _("TMCG: wrong public key") << endl;
						}
						else
						{
							cout << X << "PKI " << _("identified") << 
								" \"" << pki1 << "\" " << "aka \"" << apkey.name << 
								"\" <" << apkey.email << ">" << endl;
							nick_key[pki1] = apkey;
						}
					}
				}
				char tmp[65536];
				bzero(tmp, sizeof(tmp));
				readed[pi->second] -= cnt_pos;
				memcpy(tmp, readbuf[pi->second] + cnt_pos, readed[pi->second]);
				memcpy(readbuf[pi->second], tmp, readed[pi->second]);
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
		vector<string> cmd_argv = irc_parvec;
		
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
			for (map<string, string>::const_iterator ni = nick_players.begin();
				ni != nick_players.end(); ni++)
			{
				string nick = ni->first, host = ni->second;
				string name = "?", email = "?", type = "?";
				if (nick_key.find(nick) != nick_key.end())
				{
					name = nick_key[nick].name;
					email = nick_key[nick].email;
					type = nick_key[nick].type;
				}
				cout << XX << nick << " (" << host << ":" << 
					nick_p7771[nick] << ":" << nick_p7773[nick] << ":" <<
					nick_p7774[nick] << ")" << endl;
				cout << XX << "    aka " << name << " <" << email << "> " << endl;
				cout << XX << "    " << "[ " << 
					"SECURITY_LEVEL = " << nick_sl[nick] << ", " <<
					"KEY_TYPE = " << type << " " <<
					"]" << endl;
			}
		}
		else if ((cmd_argv[0] == "tables") || (cmd_argv[0] == "tische"))
		{
			for (list<string>::const_iterator ti = tables.begin(); 
				ti != tables.end(); ti++)
			{
				if (tables_r[*ti] > 0)
				{
					if (tables_p[*ti] < 3)
					{
						cout << XX << _("table") << " <nr> = " << *ti << 
							", " << _("rounds") << " <r> = " << tables_r[*ti] <<
							", # " << _("players") << " = " << tables_p[*ti] <<
							", " << _("owner") << " = " << tables_o[*ti] << endl;
					}
					else
					{
						cout << XX << _("table") << " <nr> = " << *ti << ", " << 
							_("still") << " <r> = " << tables_r[*ti] << " " << _("rounds") <<
							", " << _("owner") << " = " << tables_o[*ti] << endl;
					}
				}
			}
		}
		else if ((cmd_argv[0] == "rooms") || (cmd_argv[0] == "r?me"))
		{
			for (list<string>::const_iterator ti = tables.begin(); 
				ti != tables.end(); ti++)
			{
				if (tables_r[*ti] < 0)
				{
					cout << XX << _("room") << " <nr> = " << *ti << 
						", <bits> = " << -tables_r[*ti] <<
						", # " << _("voters") << " = " << tables_p[*ti] <<
						", " << _("owner") << " = " << tables_o[*ti] << endl;
				}
			}
		}
		else if ((cmd_argv[0] == "rank") || (cmd_argv[0] == "rang"))
		{
			list<string> rnk_nicktab, rnk_ranktab;
			map<string, long> rnk_nickpkt, pkt[3], gws[3], vls[3];
						
			// Parsen der RNK Daten
			nick_key[tmcg->TMCG_ExportKeyID(pub)] = pub;
			for (map<string, string>::const_iterator ri = rnk.begin(); 
				ri != rnk.end(); ri++)
			{
				TMCG_Signature tk_sig1, tk_sig2, tk_sig3;
				string tk_header, tk_table;
				string tk_game[3], tk_nick[3];
				string s = ri->second;
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
					(tk_nick[0] != tmcg->TMCG_ExportKeyID(tk_sig1)) ||
					(tk_nick[1] != tmcg->TMCG_ExportKeyID(tk_sig2)) ||
					(tk_nick[2] != tmcg->TMCG_ExportKeyID(tk_sig3)) ||
					(nick_key.find(tk_nick[0]) == nick_key.end()) ||
					(nick_key.find(tk_nick[1]) == nick_key.end()) ||
					(nick_key.find(tk_nick[2]) == nick_key.end()))
							continue;
				TMCG_DataString sig_data = tk_header + "#" + tk_table + "#" +
					tk_nick[0] + "#" + tk_nick[1] + "#" + tk_nick[2] + "#" +
					tk_game[0] + "#" + tk_game[1] + "#" + tk_game[2] + "#";
				if (!tmcg->TMCG_VerifyData(nick_key[tk_nick[0]], sig_data, tk_sig1))
					continue;
				if (!tmcg->TMCG_VerifyData(nick_key[tk_nick[1]], sig_data, tk_sig2))
					continue;
				if (!tmcg->TMCG_VerifyData(nick_key[tk_nick[2]], sig_data, tk_sig3))
					continue;
				list<string> gp_l;
				string gp_s = "";
				for (size_t j = 0; j < 3; j++)
				{
					if (std::find(rnk_nicktab.begin(), rnk_nicktab.end(), 
						tk_nick[j]) == rnk_nicktab.end())
							rnk_nicktab.push_back(tk_nick[j]);
					gp_l.push_back(tk_nick[j]);
				}
				gp_l.sort();
				for (list<string>::const_iterator gpi = gp_l.begin(); 
					gpi != gp_l.end(); gpi++)
						gp_s = gp_s + (*gpi) + "~";
				for (size_t j = 0; j < 3; j++)
				{
					vector<string> gp_par;
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
				for (map<string, long>::const_iterator gpi = pkt[j].begin();
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
			for (map<string, long>::const_iterator gpi = pkt[0].begin();
				gpi != pkt[0].end(); gpi++)
			{
				string gp = gpi->first, gp_w = gpi->first;
				size_t ei;
				vector<string> gp_p;
				// parse gp
				while ((ei = gp_w.find("~", 0)) != gp_w.npos)
				{
					gp_p.push_back(gp_w.substr(0, ei));
					gp_w = gp_w.substr(ei + 1, gp_w.length() - ei - 1);
				}
				// eigene Beteiligung?
				if ((gp.find(tmcg->TMCG_ExportKeyID(pub), 0) != gp.npos) && 
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
					cout << "+----+ " << endl;
					cout << "| 1. | " << nick_key[gp_p[gp1]].name << 
						" : " << pkt[gp1][gp] << " " << _("score points") << endl;
					cout << "| 2. | " << nick_key[gp_p[gp2]].name << 
						" : " << pkt[gp2][gp] << " " << _("score points") << endl;
					cout << "| 3. | " << nick_key[gp_p[gp3]].name << 
						" : " << pkt[gp3][gp] << " " << _("score points") << endl;
					cout << "+----+ " << endl;
				}
			}
			nick_key.erase(tmcg->TMCG_ExportKeyID(pub));
		}
		else if (cmd_argv[0] == "skat")
		{
			if (cmd_argc == 3)
			{
				string tnr = cmd_argv[1], trr = cmd_argv[2];
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
								signal(SIGQUIT, SIG_DFL), signal(SIGTERM, SIG_DFL);
								if ((close(rnk_pipe[0]) < 0) || 
									(close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
										perror("run_irc (close)");
								int ret = skat_child(tnr, r, true, in_pipe[0], 
									out_pipe[1], rnk_pipe[1], tmcg->TMCG_ExportKeyID(pub));
								sleep(1);
								if ((close(rnk_pipe[1]) < 0) || 
									(close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
										perror("run_irc (close)");
								exit(ret);
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
								*irc << "JOIN #openSkat_" << tnr << endl << flush;
							}
						}
					}
					else
						cout << X << _("wrong number of rounds") << " <r> = " <<
							trr << endl;
				}
				else
					cout << X << _("table") << " <nr> = \"" << tnr << "\" " <<
						_("already exists") << endl;
			}
			else if (cmd_argc == 2)
			{
				string tnr = cmd_argv[1];
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
									signal(SIGQUIT, SIG_DFL), signal(SIGTERM, SIG_DFL);
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
									*irc << "JOIN #openSkat_" << tnr << endl << flush;
									*irc << "WHO #openSkat_" << tnr << endl << flush;
								}
							}
						}
						else
							cout << X << _("player") << " \"" << pub.name << "\" " <<
								_("is already on table") << " <nr> = " << tnr << endl;
					}
					else
						cout << X << _("table") << " <nr> = " << tnr << " " <<
							_("is completely occupied") << endl;
				}
				else
					cout << X << _("table") << " <nr> = " << tnr << " " <<
						_("don't exists (yet)") << endl;
			}
			else
				cout << X << _("wrong number of arguments") << ": " << cmd_argc << 
					endl << X << _("/help shows the list of commands") << endl;
		}
		else if ((cmd_argv[0] == "ballot") || (cmd_argv[0] == "abstimmung"))
		{
			if (cmd_argc == 3)
			{
				string tnr = cmd_argv[1], tbb = cmd_argv[2];
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
								signal(SIGQUIT, SIG_DFL), signal(SIGTERM, SIG_DFL);
								if ((close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
									perror("run_irc (close)");
								int ret = ballot_child(tnr, b, true, in_pipe[0], out_pipe[1],
									tmcg->TMCG_ExportKeyID(pub));
								sleep(1);
								if ((close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
									perror("run_irc (close)");
								exit(ret);
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
								*irc << "JOIN #openSkat_" << tnr << endl << flush;
							}
						}
					}
					else
						cout << X << _("wrong number of bits") << " <bits> = " <<
							tbb << endl;
				}
				else
					cout << X << _("room") << " <nr> = \"" << tnr << "\" " <<
						_("already exists") << endl;
			}
			else if (cmd_argc == 2)
			{
				string tnr = cmd_argv[1];
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
									signal(SIGQUIT, SIG_DFL), signal(SIGTERM, SIG_DFL);
									if ((close(out_pipe[0]) < 0) || (close(in_pipe[1]) < 0))
										perror("run_irc (close)");
									int ret = ballot_child(tnr, -tables_r[tnr], false,
										in_pipe[0], out_pipe[1], tables_o[tnr]);
									sleep(1);
									if ((close(out_pipe[1]) < 0) || (close(in_pipe[0]) < 0))
										perror("run_irc (close)");
									exit(ret);
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
									*irc << "JOIN #openSkat_" << tnr << endl << flush;
									*irc << "WHO #openSkat_" << tnr << endl << flush;
								}
							}
						}
						else
							cout << X << _("voter") << " \"" << pub.name << "\" " <<
								_("is already in room") << " <nr> = " << tnr << endl;
					}
					else
						cout << X << _("room") << " <nr> = " << tnr << " " <<
							_("is closed") << endl;
				}
				else
					cout << X << _("room") << " <nr> = " << tnr << " " <<
						_("don't exists (yet)") << endl;
			}
			else
				cout << X << _("wrong number of arguments") << ": " << cmd_argc << 
					endl << X << _("/help shows the list of commands") << endl;
		}
		else if ((cmd_argv[0] == "help") || (cmd_argv[0] == "hilfe"))
		{
			cout << XX << _("/quit") << " -- " <<
				_("quit SecureSkat") << endl;
			cout << XX << _("/on") << " -- " <<
				_("turn output of IRC channel #openSkat on") << endl;
			cout << XX << ("/off") << " -- " <<
				_("turn output of IRC channel #openSkat off") << endl;
			cout << XX << ("/players") << " -- " <<
				_("show list of possible participants") << endl;
			cout << XX << ("/tables") << " -- " <<
				_("show list of existing game tables") << endl;
			cout << XX << ("/rooms") << " -- " <<
				_("show list of existing voting rooms") << endl;
			cout << XX << _("/rank") << " -- " <<
				_("show your current rank in all score lists") << endl;
			cout << XX << _("/ballot") << " <nr> <bits> -- " <<
				_("create room <nr> for voting between 2^<bits> values") << endl;
			cout << XX << _("/ballot") << " <nr> -- " <<
				_("join the voting in room <nr>") << endl;
			cout << XXX << "/<nr> open -- " <<
				_("open the voting process in room <nr> (only owner)") << endl;
			cout << XXX << "/<nr> vote <r> -- " <<
				_("vote in room <nr> for value <r>") << endl;
			cout << XX << "/skat <nr> <r> -- " <<
				_("create table <nr> for playing <r> rounds") << endl;
			cout << XX << "/skat <nr> -- " <<
				_("join the game on table <nr>") << endl;
			cout << XX << "/<nr> <cmd> -- " <<
				_("execute command <cmd> on table <nr>") << ":" << endl;
			cout << XXX << "/<nr> blatt --- " <<
				_("show own cards and additional information") << endl;
			cout << XXX << "/<nr> reize --- " <<
				_("bid or justify a bid") << endl;
			cout << XXX << "/<nr> passe --- " <<
				_("pass biding") << endl;
			cout << XXX << "/<nr> hand --- " <<
				_("play without taking the two cards") << endl;
			cout << XXX << "/<nr> skat --- " <<
				_("take the two cards and show all") << endl;
			cout << XXX << "/<nr> druecke <k1> <k2> --- " <<
				_("put away card <k1> and <k2>") << endl;
			cout << XXX << "/<nr> sagean <spiel> [zusatz] --- " <<
				_("announce game <spiel> ([zusatz] is optional)") << endl;
			cout << XXX << "/<nr> lege <k1> --- " <<
				_("play card <k1>") << endl;
			cout << XX << "<nr> " << _("arbitrary string") << endl;
			cout << XX << "<r> " << _("unsigned integer") << endl;
			cout << XXX << "<k1>, <k2> ::= { Sc, Ro, Gr, Ei } || " <<
				"{ 7, 8, 9, U, O, K, 10, A }" << endl;
			cout << XXX << "<spiel> " << _("from") << " { Sc, Ro, Gr, Nu, Ei, Gd }"
				<< endl;
			cout << XXX << "[zusatz] " << _("from") << " { Sn, Sw, Ov }" << endl;
		}
		else
		{
			bool found = false;
			for (map<string, pid_t>::const_iterator gi = games_tnr2pid.begin(); 
				gi != games_tnr2pid.end(); gi++)
			{
				if (cmd_argv[0] == gi->first)
				{
					found = true;
					opipestream *npipe = new opipestream(games_ipipe[gi->second]);
					*npipe << "CMD ";
					for (size_t gj = 1; gj < cmd_argc; gj++)
						*npipe << cmd_argv[gj] << " ";
					*npipe << endl << flush;
					delete npipe;
				}
			}
			if (!found)
				cout << X << _("unknown command") << ": \"/" << cmd_argv[0] << 
					"\"" << endl << X << _("/help shows the list of commands") << endl;
		}
	}
	else
	{
		if ((s != NULL) && (strlen(s) > 0))
		{
			// sign and send chat message
			string sig = tmcg->TMCG_SignData(sec, s);
			*irc << "PRIVMSG #openSkat :" << s << "~~~" << sig << endl << flush;
			cout << "<" << pub.name << "> " << s << endl;
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
		MFD_SET(pki7772_handle, &rfds);
		MFD_SET(rnk7773_handle, &rfds);
		MFD_SET(rnk7774_handle, &rfds);
		
		// PKI pipes from childs
		for (map<pid_t, int>::const_iterator pi = nick_pipe.begin();
			pi != nick_pipe.end(); pi++)
				MFD_SET(pi->second, &rfds);
				
		// RNK pipes from childs
		for (map<pid_t, int>::const_iterator pi = rnk_pipe.begin();
			pi != rnk_pipe.end(); pi++)
				MFD_SET(pi->second, &rfds);
		
		// RNK pipes from game childs
		for (map<pid_t, int>::const_iterator pi = games_rnkpipe.begin();
			pi != games_rnkpipe.end(); pi++)
				if (pi->second >= 0)
					MFD_SET(pi->second, &rfds);
		
		// OUT pipes from game childs
		for (map<pid_t, int>::const_iterator pi = games_opipe.begin();
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
					*rnk_io << rnk.size() << endl << flush;
					for (map<string, string>::const_iterator pi = rnk.begin(); 
						pi != rnk.end(); pi++)
					{
						*rnk_io << pi->first << endl << flush;
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
					*pki << pub << endl << flush;
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
							signal(SIGQUIT, SIG_DFL),	signal(SIGTERM, SIG_DFL);
							
							// begin -- child code
							iosocketstream *client_ios = new iosocketstream(client_handle);
							char *tmp = new char[100000L];
							client_ios->getline(tmp, 100000L);
							
							if (rnk.find(tmp) != rnk.end())
								*client_ios << rnk[tmp] << endl << flush;
							else
								*client_ios << endl << flush;
							delete client_ios, delete [] tmp;
							exit(0);
							// end -- child code
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
					cerr << _("IRC ERROR: connection with server collapsed") << endl;
					break;
				}
				
				if (irc_readed > 0)
				{
					vector<int> pos_delim;
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
						bzero(tmp, sizeof(tmp));
						memcpy(tmp, irc_readbuf + cnt_pos, pos_delim[pos] - cnt_pos);
						--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
						irc_reply = tmp;
				
				// parse NICK and HOST from IRC prefix
				string pfx = irc_prefix(irc_reply);
				string nick = "?", host = "?";
				if ((pfx.find("!", 0) != pfx.npos) && (pfx.find("@", 0) != pfx.npos))
				{
					nick = pfx.substr(0, pfx.find("!", 0));
					host = pfx.substr(pfx.find("@", 0) + 1, 
						pfx.length() - pfx.find("@", 0) - 1);
				}
				
				if (strncasecmp(irc_command(irc_reply), "PING", 4) == 0)
				{				
					*irc << "PONG " << irc_params(irc_reply) << endl << flush;
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
					cerr << _("IRC ERROR: not registered at IRC server") << endl;
					cerr << irc_reply << endl;
					irc_quit = 1;
					break;
				}
				else if (strncasecmp(irc_command(irc_reply), "JOIN", 4) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 1)
					{
						if (irc_parvec[0] == "#openSkat")
						{
							if (nick.find(tmcg->TMCG_ExportKeyID(pub), 0) == 0)
							{
								cout << X << _("you join channel") << " " << 
									irc_parvec[0] << endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								*irc << "WHO " << irc_parvec[0] << endl << flush;
							}
							else
							{
								if (irc_stat)
									cout << X << _("observer") << " \"" << nick << "\" ("
										<< host << ") " << _("joins channel") << " " << 
										irc_parvec[0] << endl;
							}
						}
						else if ((irc_parvec[0].find("#openSkat_", 0) == 0) && 
							(irc_parvec[0].length() > 10))
						{
							string tb = 
								irc_parvec[0].substr(10, irc_parvec[0].length() - 10);
								
							if (nick.find(tmcg->TMCG_ExportKeyID(pub), 0)	== 0)
							{
								cout << X << _("you join") << " " << tb << endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "JOIN " << nick << endl << flush;
									delete npipe;
								}
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								cout << X << _("player") << " \"" << nick << "\" (" <<
									host << ") " << _("joins") << " " << tb << endl;
							}
							else
							{	
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "KIEBITZ " << nick << endl << flush;
									delete npipe;
								}
								cout << X << _("observer") << " \"" << nick << "\" (" <<
									host << ") " << _("joins") << " " << tb << endl;
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
//cerr << "IRC: could not join to channel, channel error:" << endl;
//cerr << irc_reply << endl;
				}
				else if (strncasecmp(irc_command(irc_reply), "PART", 4) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 1)
					{
						if (irc_parvec[0] == "#openSkat")
						{
							if (nick.find(tmcg->TMCG_ExportKeyID(pub), 0)	== 0)
							{
								cout << X << _("you leave channel") << " " <<
									irc_parvec[0] << endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								nick_players.erase(nick), nick_sl.erase(nick);
								nick_p7771.erase(nick),	nick_p7772.erase(nick);
								nick_p7773.erase(nick),	nick_p7774.erase(nick);
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								if (irc_stat)
									cout << X << _("player") << " \"" << nick << "\" (" << 
										host << ") " << _("leaves channel") << " " << 
										irc_parvec[0] << endl;
							}
							else
							{
								if (irc_stat)
									cout << X << _("observer") << " \"" << nick << "\" (" <<
										host << ") " << _("leaves channel") << " " <<
										irc_parvec[0] << endl;
							}
						}
						else if ((irc_parvec[0].find("#openSkat_", 0) == 0) && 
							(irc_parvec[0].length() > 10))
						{
							string tb = 
								irc_parvec[0].substr(10, irc_parvec[0].length() - 10);
								
							if (nick.find(tmcg->TMCG_ExportKeyID(pub), 0)	== 0)
							{
								cout << X << _("you leave") << " " << tb << endl;
							}
							else if (nick.find(public_prefix, 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "PART " << nick << endl << flush;
									delete npipe;
								}
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								cout << X << _("player") << " \"" << nick << "\" (" <<
									host << ") " << _("leaves") << " " << tb << endl;
							}
							else
							{
								cout << X << _("observer") << " \"" << nick << "\" (" <<
									host << ") " << _("leaves") << " " << tb << endl;
							}
						}
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "KICK", 4) == 0)
				{
					int pvs = irc_paramvec(irc_params(irc_reply));
					if (pvs >= 2)
					{
						if (irc_parvec[0] == "#openSkat")
						{
							if (irc_parvec[1].find(tmcg->TMCG_ExportKeyID(pub), 0) == 0)
							{
								cout << X << _("you kicked from channel") << " " << 
									irc_parvec[0] << " " << _("by operator") << " " << 
									nick << endl;
								if (pvs == 3)
									cout << X << _("reason") << ": " << irc_parvec[2] << endl;
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
									cout << X << _("player") << " \"" << host << "\" " <<
										_("kicked from channel") << " " << irc_parvec[0] << " " <<
										_("by operator") << " " << nick << endl;
								if (irc_stat && (pvs == 3))
									cout << X << _("reason") << ": " << irc_parvec[2] << endl;
							}
							else
							{
								if (irc_stat)
									cout << X << _("observer") << " \"" << host << "\" " <<
										_("kicked from channel") << " " << irc_parvec[0] << " " <<
										_("by operator") << " " << nick << endl;
								if (irc_stat && (pvs == 3))
									cout << X << _("reason") << ": " << irc_parvec[2] << endl;
							}
						}
						else if ((irc_parvec[0].find("#openSkat_", 0) == 0) && 
							(irc_parvec[0].length() > 10))
						{
							string tb = 
								irc_parvec[0].substr(10, irc_parvec[0].length() - 10);
								
							if (irc_parvec[1].find(tmcg->TMCG_ExportKeyID(pub), 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "!KICK" << endl << flush;
									delete npipe;
								}
								cout << X << _("you kicked from") << " " << tb << endl;
								if (pvs == 3)
									cout << X << _("reason") << ": " << irc_parvec[2] << endl;
							}
							else if (irc_parvec[1].find(public_prefix, 0) == 0)
							{
								if (games_tnr2pid.find(tb) != games_tnr2pid.end())
								{
									opipestream *npipe = 
										new opipestream(games_ipipe[games_tnr2pid[tb]]);
									*npipe << "KICK " << irc_parvec[1] << endl << flush;
									delete npipe;
								}
								if (nick_key.find(irc_parvec[1]) != nick_key.end())
									nick = nick_key[irc_parvec[1]].name;
								cout << X << _("player") << " \"" << nick << "\" " <<
										_("kicked from") << " " << tb << endl;
								if (pvs == 3)
									cout << X << _("reason") << ": " << irc_parvec[2] << endl;	
							}
							else
							{
								cout << X << _("observer") << " \"" << irc_parvec[1] << 
									"\" " << _("kicked from") << " " << tb << endl;
								if (pvs == 3)
									cout << X << _("reason") << ": " << irc_parvec[2] << endl;	
							}
						}
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "QUIT", 4) == 0)
				{
					if (nick.find(tmcg->TMCG_ExportKeyID(pub), 0) == 0)
					{
						cout << X << _("you quit SecureSkat") << endl;
					}
					else if (nick.find(public_prefix, 0) == 0)
					{
						nick_players.erase(nick),nick_sl.erase(nick); 
						nick_p7771.erase(nick), nick_p7772.erase(nick);
						nick_p7773.erase(nick), nick_p7774.erase(nick);
						for (map<string, pid_t>::const_iterator gi = games_tnr2pid.begin();
							gi != games_tnr2pid.end(); gi++)
						{
							opipestream *npipe = 
								new opipestream(games_ipipe[gi->second]);
							*npipe << "QUIT " << nick << endl << flush;
							delete npipe;
						}
						if (nick_key.find(nick) != nick_key.end())
							nick = nick_key[nick].name;
						if (irc_stat)
							cout << X << _("player") << " \"" << nick << "\" (" << host << 
								") " << _("quits SecureSkat") << endl;
					}
					else
					{
						if (irc_stat)
							cout << X << _("observer") << " \"" << nick << "\" (" << host <<
								") " << _("quits IRC client") << endl;
					}
				}
				else if (strncasecmp(irc_command(irc_reply), "352", 3) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 8)
					{
						if (irc_parvec[5] != tmcg->TMCG_ExportKeyID(pub))
						{
							if (irc_parvec[1] == "#openSkat")
							{
								if (irc_parvec[5].find(public_prefix, 0) == 0)
								{
									if ((irc_stat) && (irc_parvec[3] == "localhost"))
										cerr << _("WARNING: host of player") << " \"" <<
											irc_parvec[5] << "\" " << 
											_("has unqualified domain (no FQDN)") << endl;
									string tmp = irc_parvec[7];
									int p7771 = 0, p7772 = 0, p7773 = 0, p7774 = 0, sl = 0;
									size_t ai = tmp.find("|", 0), bi = tmp.find("~", 0);
									size_t ci = tmp.find("!", 0), di = tmp.find("#", 0);
									size_t ei = tmp.find("?", 0), fi = tmp.find("/", 0);
									if ((ai != tmp.npos) && (bi != tmp.npos) && 
										(ci != tmp.npos) && (di != tmp.npos) &&
										(ei != tmp.npos) && (fi != tmp.npos) &&
										(ai < bi) && (bi < ci) && (ci < di) &&
										(di < ei) && (ei < fi))
									{
										string ptmp7771 = tmp.substr(ai + 1, bi - ai - 1);
										string ptmp7772 = tmp.substr(bi + 1, ci - bi - 1);
										string ptmp7773 = tmp.substr(ci + 1, di - ci - 1);
										string ptmp7774 = tmp.substr(di + 1, ei - di - 1);
										string sltmp = tmp.substr(ei + 1, fi - ei - 1);
										p7771 = atoi(ptmp7771.c_str());
										p7772 = atoi(ptmp7772.c_str());
										p7773 = atoi(ptmp7773.c_str());
										p7774 = atoi(ptmp7774.c_str());
										sl = atoi(sltmp.c_str());
									}
									nick_p7771[irc_parvec[5]] = p7771;
									nick_p7772[irc_parvec[5]] = p7772;
									nick_p7773[irc_parvec[5]] = p7773;
									nick_p7774[irc_parvec[5]] = p7774;
									nick_sl[irc_parvec[5]] = sl;
									nick_players[irc_parvec[5]] = irc_parvec[3];
									if (nick_key.find(irc_parvec[5]) != nick_key.end())
										irc_parvec[5] = nick_key[irc_parvec[5]].name;
									if (irc_stat)
										cout << X << _("player") << " \"" << irc_parvec[5] << 
											"\" (" << irc_parvec[3] << ") " << _("is in channel") <<
											" " << irc_parvec[1] << endl;
								}
								else
								{
									if (irc_stat)
										cout << X << _("observer") << " \"" << irc_parvec[5] << 
											"\" (" << irc_parvec[3] << ") " << _("is in channel") <<
											" " << irc_parvec[1] << endl;
								}
							}
							else if ((irc_parvec[1].find("#openSkat_", 0) == 0) && 
							(irc_parvec[1].length() > 10))
							{
								string tb = 
									irc_parvec[1].substr(10, irc_parvec[1].length() - 10);
								if (irc_parvec[5].find(public_prefix, 0) == 0)
								{
									if (games_tnr2pid.find(tb) != games_tnr2pid.end())
									{
										opipestream *npipe = 
											new opipestream(games_ipipe[games_tnr2pid[tb]]);
										*npipe << "WHO " << irc_parvec[5] << endl << flush;
										delete npipe;
									}
									if (nick_key.find(irc_parvec[5]) != nick_key.end())
										irc_parvec[5] = nick_key[irc_parvec[5]].name;
									if (irc_stat)
										cout << X << _("player") << " \"" << irc_parvec[5] << 
											"\" (" << irc_parvec[3] << ") " << _("is at") <<
											" " << irc_parvec[1] << endl;
								}
							}
						}
					}	
				} // MOTD start line and end line
				else if ((strncasecmp(irc_command(irc_reply), "375", 3) == 0) ||
					(strncasecmp(irc_command(irc_reply), "376", 3) == 0))
				{
					cout << endl;
				} // MOTD text line
				else if (strncasecmp(irc_command(irc_reply), "372", 3) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 2)
					{
						string tms = irc_parvec[1].substr(1, irc_parvec[1].length() - 1);
						cout << X << tms << endl;
					}
				} // PRIVMSG
				else if (strncasecmp(irc_command(irc_reply), "PRIVMSG", 7) == 0)
				{
					if (irc_paramvec(irc_params(irc_reply)) >= 2)
					{
						// control messages
						if ((irc_parvec[0].find("#openSkat_", 0) == 0) && 
							(irc_parvec[0].length() > 10) && 
							(nick.find(public_prefix, 0) == 0))
						{
							string tb = irc_parvec[0].substr(10, irc_parvec[0].length() - 10);
							if (games_tnr2pid.find(tb) != games_tnr2pid.end())
							{
								size_t tei = irc_parvec[1].find("~~~");
								if (tei != irc_parvec[1].npos)
								{
									string realmsg = irc_parvec[1].substr(0, tei);
									TMCG_Signature sig = irc_parvec[1].substr(tei + 3, 
										irc_parvec[1].length() - realmsg.length() - 3);
									if (nick_key.find(nick) != nick_key.end())
									{
										if (tmcg->TMCG_VerifyData(nick_key[nick], realmsg, sig))
										{
											opipestream *npipe = 
												new opipestream(games_ipipe[games_tnr2pid[tb]]);
											*npipe << "MSG " << nick << " " << realmsg <<
											endl << flush;
											delete npipe;
										}
										else
											cerr << _("TMCG: VerifyData() failed") << endl;
									}
									else
										cerr << _("TMCG: no public key available") << endl;
								}
							}
						}
						// chat messages
						if (irc_stat && (irc_parvec[0] == "#openSkat"))
						{
							size_t tei = irc_parvec[1].find("~~~");
							if ((nick.find(public_prefix, 0) == 0) &&
								(nick_key.find(nick) != nick_key.end()) &&
								(tei != irc_parvec[1].npos))
							{
								string realmsg = irc_parvec[1].substr(0, tei);
								TMCG_Signature sig = irc_parvec[1].substr(tei + 3, 
									irc_parvec[1].length() - realmsg.length() - 3);
								if (tmcg->TMCG_VerifyData(nick_key[nick], realmsg, sig))
								{
									nick = nick_key[nick].name;
									cout << "<" << nick << "> " << realmsg << endl;
								}
								else
									cerr << _("TMCG: VerifyData() failed") << endl;
							}
							else
								cout << "<?" << nick << "?> " << irc_parvec[1] << endl;
						} // announce and no channel messages
						else if ((nick.find(public_prefix, 0) == 0) &&
							((irc_parvec[0] == tmcg->TMCG_ExportKeyID(pub)) &&
							(nick != tmcg->TMCG_ExportKeyID(pub))))
						{
							size_t tabei1 = irc_parvec[1].find("|", 0);
							size_t tabei2 = irc_parvec[1].find("~", 0);
							size_t tabei3 = irc_parvec[1].find("!", 0);
							if ((tabei1 != irc_parvec[1].npos) &&
								(tabei2 != irc_parvec[1].npos) &&
								(tabei3 != irc_parvec[1].npos) && 
								(tabei1 < tabei2) && (tabei2 < tabei3))
							{
								string tabmsg1 = irc_parvec[1].substr(0, tabei1);
								string tabmsg2 = irc_parvec[1].substr(tabei1 + 1, 
									tabei2 - tabei1 - 1);
								string tabmsg3 = irc_parvec[1].substr(tabei2 + 1, 
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
										cout << XX << _("player") << " \"" << nick << 
											"\" (" << host << ") " << 
											_("announces unauthorized session") << " " <<
											tabmsg1 << endl;
								}						
							}
							else if (irc_stat)
							{
								if (nick_key.find(nick) != nick_key.end())
									nick = nick_key[nick].name;
								cout << ">" << nick << "< " << irc_parvec[1] << endl;
							}
						}
						else if (irc_stat &&
							((irc_parvec[0] == tmcg->TMCG_ExportKeyID(pub)) &&
							(nick != tmcg->TMCG_ExportKeyID(pub))))
						{
							cout << ">?" << nick << "?< " << irc_parvec[1] << endl;
						}
					}
				}
				else
				{ 
					// unparsed IRC-message -- ignore this one
				}
				
					}
					char tmp[65536];
					bzero(tmp, sizeof(tmp));
					irc_readed -= cnt_pos;
					memcpy(tmp, irc_readbuf + cnt_pos, irc_readed);
					memcpy(irc_readbuf, tmp, irc_readed);
				}
			}
		}
		
		// timeout occured
		if (ret == 0)
		{
			// use signal blocking for atomic operations (dirty hack :-)
			raise(SIGUSR1);
			
			// re-install signal handlers due to bug in some unices
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
					(int)tmcg->TMCG_SecurityLevel);
				string uname = tmcg->TMCG_ExportKeyID(pub);
				if (uname.length() > 4)
				{
					string uname2 = "os";
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
					endl << flush;
				first_command = false;
			}
			else if (first_entry)
			{
				*irc << "JOIN #openSkat" << endl << flush;
				*irc << "WHO #openSkat" << endl << flush;
				first_entry = false;
			}
			else if (entry_ok)
			{
#ifdef AUTOJOIN
				// timer: autojoin to known tables each AUTOJOIN_TIMEOUT seconds
				if (atj_counter >= AUTOJOIN_TIMEOUT)
				{
					for (list<string>::const_iterator ti = tables.begin(); 
						ti != tables.end(); ti++)
					{
						// if not joined in game, do AUTOJOIN (greedy behaviour)
						if (games_tnr2pid.find(*ti) == games_tnr2pid.end())
						{
							char *command = (char*)malloc(500);
							if (command == NULL)
							{
								cerr << _("MALLOC ERROR: out of memory") << endl;
								exit(-1);
							}
							bzero(command, 500);
							strncat(command, "/skat ", 25);
							strncat(command, ti->c_str(), 475);
							process_line(command);
							// free(2) of 'command' is already done in 'process_line'
						}
					}
					atj_counter = 0;
				}
				else
					atj_counter++;
#endif
				
				// timer: announce table stats each ANNOUNCE_TIMEOUT seconds
				if (ann_counter >= ANNOUNCE_TIMEOUT)
				{
					// timer: clear all tables each CLEAR_TIMEOUT seconds
					if (clr_counter >= CLEAR_TIMEOUT)
					{
						tables.clear();
						clr_counter = 0;
					}
					else
						clr_counter++;
					
					for (map<pid_t, int>::const_iterator pi = games_ipipe.begin();
						pi != games_ipipe.end(); ++pi)
					{
						opipestream *npipe = new opipestream(pi->second);
						*npipe << "!ANNOUNCE" << endl << flush;
						delete npipe;
					}
					ann_counter = 0;
				}
				else
					ann_counter++;
			}
			
			// send SIGQUIT to all PKI processes -- PKI TIMEMOUT
			for (list<pid_t>::const_iterator pidi = nick_pids.begin();
				pidi != nick_pids.end(); pidi++)
			{
				if (nick_ncnt[nick_nick[*pidi]] > PKI_TIMEOUT)
					if (kill(*pidi, SIGQUIT) < 0)
						perror("run_irc (kill)");
			}
			
			// send SIGQUIT to all RNK processes -- RNK TIMEMOUT
			for (list<pid_t>::const_iterator pidi = rnk_pids.begin();
				pidi != rnk_pids.end(); pidi++)
			{
				if (nick_rnkcnt[rnk_nick[*pidi]] > RNK_TIMEOUT)
					if (kill(*pidi, SIGQUIT) < 0)
						perror("run_irc (kill)");
			}
			
			// start RNK or PKI process
			for (map<string, string>::const_iterator ni = nick_players.begin();
					ni != nick_players.end(); ni++)
			{
				string nick = ni->first, host = ni->second;
				
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
							signal(SIGQUIT, SIG_DFL), signal(SIGTERM, SIG_DFL);
							
							// begin -- child code
							sleep(1);
							if (close(fd_pipe[0]) < 0)
							{
								perror("run_irc [child] (close)");
								exit(-1);
							}
							opipestream *npipe = new opipestream(fd_pipe[1]);
							size_t rnk_idsize = 0;
							vector<string> rnk_idlist;
							
							// create TCP/IP connection
							int nick_handle = ConnectToHost(host.c_str(), nick_p7773[nick]);
							if (nick_handle < 0)
							{
								cerr << "run_irc [RNK/child] (ConnectToHost)" << endl;
								exit(-1);
							}
							iosocketstream *nrnk = new iosocketstream(nick_handle);
							
							// get RNK list
							char *tmp = new char[1000000L];
							if (tmp == NULL)
							{
								cerr << _("RNK ERROR: out of memory") << endl;
								exit(-1);
							}
							nrnk->getline(tmp, 1000000L);
							rnk_idsize = strtoul(tmp, NULL, 10);
							for (size_t i = 0; i < rnk_idsize; i++)
							{
								nrnk->getline(tmp, 1000000L);
								if (rnk.find(tmp) == rnk.end())
									rnk_idlist.push_back(tmp);
							}
							
							// close TCP/IP connection
							delete nrnk;
							if (close(nick_handle) < 0)
								perror("run_irc [RNK/child] (close)");
							
							// iterate RNK list
							for (vector<string>::const_iterator ri = rnk_idlist.begin();
								ri != rnk_idlist.end(); ri++)
							{
								// create TCP/IP connection
								int rhd = ConnectToHost(host.c_str(), nick_p7774[nick]);
								if (rhd < 0)
								{
									cerr << "run_irc [RNK2/child] (ConnectToHost)" << endl;
									exit(-1);
								}
								iosocketstream *nrpl = new iosocketstream(rhd);
								
								// get RNK data and send it to parent
								*nrpl << *ri << endl << flush;
								nrpl->getline(tmp, 1000000L);
								*npipe << *ri << endl << flush;
								*npipe << tmp << endl << flush;
								
								// close TCP/IP connection
								delete nrpl;
								if (close(rhd) < 0)
									perror("run_irc [RNK2/child] (close)");
							}
							*npipe << "EOF" << endl << flush;
							delete npipe, delete [] tmp;
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
							signal(SIGQUIT, SIG_DFL),	signal(SIGTERM, SIG_DFL);
							
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
								cerr << "run_irc [PKI/child] (ConnectToHost)" << endl;
								exit(-1);
							}
							iosocketstream *nkey = new iosocketstream(nick_handle);
							
							// get public key
							char *tmp = new char[1000000L];
							if (tmp == NULL)
							{
								cerr << _("PKI ERROR: out of memory") << endl;
								exit(-1);
							}
							nkey->getline(tmp, 1000000L);
							public_key = tmp;
							
							// close TCP/IP connection
							delete nkey, delete [] tmp;
							if (close(nick_handle) < 0)
								perror("run_irc [PKI/child] (close)");
							
							// import public key
							TMCG_PublicKey pkey;
							if (!tmcg->TMCG_ImportKey(pkey, public_key))
							{
								cerr << _("TMCG: public key import error") << endl;
								exit(-2);
							}
							
							// check keyID
							if (nick != tmcg->TMCG_ExportKeyID(pkey))
							{
								cerr << _("TMCG: wrong public key") << endl;
								exit(-3);
							}
							
							// check NIZK
							if (!tmcg->TMCG_CheckKey(pkey))
							{
								cerr << _("TMCG: public key not valid") << endl;
								exit(-4);
							}
							
							// send valid public key to parent
							*npipe << nick << endl << flush;
							*npipe << public_key << endl << flush;
							
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
		cerr << _("IRC ERROR: connection with server collapsed") << endl;
}

void done_irc()
{
	signal(SIGINT, SIG_IGN), signal(SIGQUIT, SIG_IGN), signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN), signal(SIGPIPE, SIG_IGN), signal(SIGHUP, SIG_IGN);
	*irc << "PART #openSkat" << endl << flush;
	*irc << "QUIT :SecureSkat rulez!" << endl << flush;
	for (map<pid_t, string>::const_iterator pidi = games_pid2tnr.begin();
		pidi != games_pid2tnr.end(); pidi++)
	{
		if (kill(pidi->first, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(pidi->first, NULL, 0);
	}
	games_pid2tnr.clear(), games_tnr2pid.clear();
	for (list<pid_t>::const_iterator pidi = nick_pids.begin();
		pidi != nick_pids.end(); pidi++)
	{
		if (kill(*pidi, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(*pidi, NULL, 0);
	}
	nick_pids.clear(), nick_nick.clear(), nick_host.clear(),
		nick_ninf.clear(), nick_ncnt.clear(), nick_players.clear();
	for (list<pid_t>::const_iterator pidi = pkiprf_pid.begin();
		pidi != pkiprf_pid.end(); pidi++)
	{
		if (kill(*pidi, SIGQUIT) < 0)
			perror("done_irc (kill)");
		waitpid(*pidi, NULL, 0);
	}
	pkiprf_pid.clear();
	for (list<pid_t>::const_iterator pidi = rnkrpl_pid.begin();
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
	{
		perror("done_term (tcsetattr)");
		exit(-1);
	}
}

int main(int argc, char* argv[], char* envp[])
{
	string cmd = argv[0];
	cout << PACKAGE_STRING <<
		", (c) 2002-2004 Heiko Stamer <stamer@gaos.org>, GNU GPL" << endl <<
		" $Id: SecureSkat.cc,v 1.3 2004/11/24 22:08:36 stamer Exp $ " << endl;
	
#ifdef ENABLE_NLS
#ifdef HAVE_LC_MESSAGES
	setlocale(LC_TIME, "");
	setlocale(LC_MESSAGES, "");
#else
	setlocale(LC_ALL, "");
#endif
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif
	
	if (((argc == 5) && isdigit(argv[2][0]) && isdigit(argv[3][0])) ||
		((argc == 4) && isdigit(argv[2][0]) && isdigit(argv[3][0])) ||
		((argc == 3) && isdigit(argv[2][0])) ||
		(argc == 2))
	{
		if (argc == 5)
		{
			irc_port = atoi(argv[2]);
			security_level = atoi(argv[3]);
			game_ctl = argv[4];
			game_env = envp;
		}
		else if (argc == 4)
		{
			irc_port = atoi(argv[2]);
			security_level = atoi(argv[3]);
			game_ctl = "";
			game_env = NULL;
		}
		else if (argc == 3)
		{
			irc_port = atoi(argv[2]);
			security_level = 16;
			game_ctl = "";
			game_env = NULL;
		}
		else
		{
			irc_port = 6667;
			security_level = 16;
			game_ctl = "";
			game_env = NULL;
		}
		tmcg = new SchindelhauerTMCG(security_level, 3, 5); // 3 players, 32 cards
		get_public_keys(cmd + ".pkr", tmcg, nick_key);
		get_secret_key(cmd + ".skr", tmcg, sec, public_prefix);
		tmcg->TMCG_CreateKey(pub, sec);
		
		create_pki(pki7771_port, pki7771_handle);
		create_rnk(rnk7773_port, rnk7774_port, rnk7773_handle, rnk7774_handle);
		load_rnk(cmd + ".rnk", rnk);
		create_irc(argv[1], irc_port);
		init_irc();
		cout << _("Usage: type /help for command list or read file README") << endl;
#ifndef NOHUP
		init_term();
#endif
		run_irc();
#ifndef NOHUP
		done_term();
#endif
		done_irc();
		release_irc();
		save_rnk(cmd + ".rnk", rnk);
		release_rnk(rnk7773_handle, rnk7774_handle);
		release_pki(pki7771_handle);
		set_public_keys(cmd + ".pkr", tmcg, nick_key);
		tmcg->TMCG_ReleaseKey(pub), tmcg->TMCG_ReleaseKey(sec);
		delete tmcg;
		return 0;
	}
	
	cout << _("Usage: ") << cmd << " IRC_SERVER<string> [ IRC_PORT<int> " <<
		"[ SECURITY_LEVEL<int> ..." << endl;
	cout << "       " << " ... [ CONTROL_PROGRAM<string> ] ] ]" << endl;
	return -1;
}
