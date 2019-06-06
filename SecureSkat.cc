/*******************************************************************************
   SecureSkat.cc, Secure Peer-to-Peer Implementation of the Card Game "Skat"

 Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2009,
               2016, 2017, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

// Note for the curious reader: The really interesting stuff is in LibTMCG.

// To be (included), or not to be (included) ...
#include "SecureSkat_defs.hh"
#include "SecureSkat_misc.hh"
#include "SecureSkat_pki.hh"
#include "SecureSkat_rnk.hh"
#include "SecureSkat_irc.hh"
#include "SecureSkat_vote.hh"
#include "SecureSkat_skat.hh"

volatile sig_atomic_t irc_quit = 0, sigchld_critical = 0; // atomic flags

// This is the signal handler called when receiving SIGINT, (SIGHUP), SIGQUIT,
// and SIGTERM, respectively. It only changes one atomic flag.
RETSIGTYPE sig_handler_quit
	(int sig)
{
#ifndef NDEBUG
	std::cerr << "sig_handler_quit(): got signal " << sig << std::endl;
#endif
	// set the 'quit flag'
	irc_quit = 1;
}

// This is the signal handler called when receiving SIGPIPE. It does nothing.
RETSIGTYPE sig_handler_pipe
	(int sig)
{
#ifndef NDEBUG
	if (sig != SIGPIPE)
		std::cerr << "sig_handler_pipe(): got signal " << sig << std::endl;
#endif
}

// We do a lot of 'signal magic' such that SecureSkat appears to be a single
// thread when accessing shared data, however, most jobs are done by childs.
// In particular, we avoid expensive (dead)locking mechanisms to control our
// concurrent write attemps to common data structures. However, it would be
// convenient to get rid of this hack. The main assumption is here: all SIGCHLD
// requests are queued and processed sequentially by the kernel.
std::list< std::pair<pid_t, int> > usr1_stat;   // list of (child PID, exitcode)
std::map<std::string, pid_t> games_tnr2pid;     // map: table name => game PID
std::map<pid_t, std::string> games_pid2tnr;     // map: game PID => table name
std::list<pid_t> rnkrpl_pid;                    // list: PIDs of RNK replies
std::list<pid_t> rnk_pids;                      // list: PIDs of RNK requests
std::map<std::string, int> nick_rnkcnt;         // map: nick name => time ticks
std::map<std::string, pid_t> nick_rnkpid;       // map: nick name => RNK PID
std::map<pid_t, std::string> rnk_nick;          // map: RNK PID => nick name
std::map<pid_t, std::string> nick_nick;         // map: PKI PID => nick name
std::map<std::string, int> bad_nick;            // map: nick name => PKI attemps
std::list<pid_t> nick_pids;                     // list: PIDs of PKI requests

// TODO: put all those player data into a single access structure
std::map<std::string, std::string> nick_players; // map: nick name => hostname 
std::map<std::string, std::string> nick_package;
std::map<std::string, int> nick_p7771, nick_p7772, nick_p7773, nick_p7774;
std::map<std::string, int> nick_sl;
std::list<std::string> nick_ninf;
std::map<std::string, int> nick_ncnt;
std::map<pid_t, std::string> nick_host;

// This is the signal handler called when receiving SIGUSR1. Here is the magic.
RETSIGTYPE sig_handler_usr1
	(int sig)
{
	sigset_t sigset;
#ifndef NDEBUG
	if (sig != SIGUSR1)
		std::cerr << "sig_handler_usr1(): got signal " << sig << std::endl;
#endif
	
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
	
	// process all data updates sequentially
	while (!usr1_stat.empty())
	{
		std::pair <pid_t, int> chld_stat = usr1_stat.front();
		pid_t chld_pid = chld_stat.first;
		int status = chld_stat.second;
		
		// remove current entry from queue
		usr1_stat.pop_front();
		
		// process current entry, if PID is found
		if (games_pid2tnr.find(chld_pid) != games_pid2tnr.end())
		{
			std::string tnr = games_pid2tnr[chld_pid];
			if (WIFEXITED(status))
			{
				// print success resp. error message
				if (WEXITSTATUS(status) == 0)
				{
					std::cerr << ">< " << _("Session") << " \"" << tnr <<
						"\" " << _("succeeded properly") << std::endl;
				}                
				else
				{
					std::cerr << ">< " << _("Session") << " \"" << tnr <<
						"\" " << _("failed. Error code") << ": WEXITSTATUS " <<
						WEXITSTATUS(status) << std::endl;
				}
			}
			if (WIFSIGNALED(status))
			{
				// print error message
				std::cerr << ">< " << _("Session") << " \"" << tnr << "\" " <<
					_("failed. Error code") << ": WTERMSIG " <<
					WTERMSIG(status) << std::endl;
			}
			// remove associated data
			games_tnr2pid.erase(tnr);
			games_pid2tnr.erase(chld_pid);
		}
		else if (std::find(rnkrpl_pid.begin(), rnkrpl_pid.end(), chld_pid) !=
			rnkrpl_pid.end())
		{
			// print success message
			std::cerr << ">< " << "RNK (pid = " << chld_pid << ") " <<
				_("succeeded properly") << std::endl;
			// remove associated data
			rnkrpl_pid.remove(chld_pid);
		}
		else if (std::find(rnk_pids.begin(), rnk_pids.end(), chld_pid) !=
			rnk_pids.end())
		{
			if (WIFEXITED(status) && (WEXITSTATUS(status) != 0))
			{
				// print error message
				std::cerr << ">< " << "RNK (pid = " << chld_pid << ") " <<
					_("failed. Error code") << ": WEXITSTATUS " <<
					WEXITSTATUS(status) << std::endl;
			}
			if (WIFSIGNALED(status))
			{
				// print error message
				std::cerr << ">< " << "RNK (pid = " << chld_pid << ") " <<
					_("failed. Error code") << ": WTERMSIG " <<
					WTERMSIG(status) << std::endl;
			}
			// remove associated data
			rnk_pids.remove(chld_pid);
			nick_rnkcnt.erase(rnk_nick[chld_pid]);
			nick_rnkpid.erase(rnk_nick[chld_pid]);
			rnk_nick.erase(chld_pid);
		}
		else if (nick_nick.find(chld_pid) != nick_nick.end())
		{
			if (WIFEXITED(status) && (WEXITSTATUS(status) != 0))
			{
				// print error message
				std::cerr << ">< " << "PKI " << chld_pid << "/" <<
					nick_nick[chld_pid] << " " << _("failed. Error code") <<
					": WEXITSTATUS " << WEXITSTATUS(status) << std::endl;
			}
			if (WIFSIGNALED(status))
			{
				// print error message
				std::cerr << ">< " << "PKI " << chld_pid << "/" <<
					nick_nick[chld_pid] << " " << _("failed. Error code") <<
					": WTERMSIG " << WTERMSIG(status) << std::endl;
			}
			// remove a bad nick (i.e. DoS attack on PKI) from the players list
			std::string nn = nick_nick[chld_pid];
			if (bad_nick.find(nn) == bad_nick.end())
				bad_nick[nn] = 0; // initialize counter
			if (bad_nick[nn] <= 3)
			{
				bad_nick[nn] += 1; // increase counter
			}
			else
			{
				nick_players.erase(nn);
				nick_package.erase(nn);
				nick_p7771.erase(nn);
				nick_p7772.erase(nn);
				nick_p7773.erase(nn);
				nick_p7774.erase(nn);
				nick_sl.erase(nn);
			}
			// remove associated data		
			nick_ncnt.erase(nn);
			nick_ninf.remove(nn);
			nick_pids.remove(chld_pid);
			nick_nick.erase(chld_pid);
			nick_host.erase(chld_pid);
		}
		else
		{
#ifndef NDEBUG
			std::cerr << "sig_handler_usr1(): unknown child with PID " <<
				chld_pid << std::endl;
#endif
		}
	} // end of while body
	
	// unblock SIGCHLD
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0)
		perror("sig_handler_usr1 (sigprocmask)");
}

// This is the signal handler called when receiving SIGCHLD. Here is the grave.
RETSIGTYPE sig_handler_chld
	(int sig)
{
	sigchld_critical = 1;   // enter critical section
#ifndef NDEBUG
	if (sig != SIGCHLD)
		std::cerr << "sig_handler_chld(): got signal " << sig << std::endl;
#endif
    
	// look for died children (zombies) and evaluate their exit code
	std::pair<pid_t, int> chld_stat;
	int status;
	chld_stat.first = wait(&status), chld_stat.second = status;
	usr1_stat.push_back(chld_stat);
	
	sigchld_critical = 0;   // leave critical section
}

// -----------------------------------------------------------------------------

// Global variables are very ugly, however, they are required for KISS here :-(
std::string game_ctl;           // name and path of the game control program
char **game_env;                // pointer to the pointer of the environment
TMCG_SecretKey sec;             // secret key of the player
TMCG_PublicKey pub;             // public key of the player
std::map<int, char*> readbuf;   // map of pointers to allocated read buffers
std::map<int, size_t> readed;   // map of counters of those read buffers

std::string secret_key, public_prefix;
std::map<std::string, TMCG_PublicKey> nick_key;
std::list<std::string> tables;
std::map<std::string, int> tables_r, tables_p;
std::map<std::string, std::string> tables_u, tables_o;
pid_t game_pid, ballot_pid;
std::map<pid_t, int> games_rnkpipe, games_opipe, games_ipipe;

pid_t nick_pid;
std::map<pid_t, int> nick_pipe;

pid_t rnk_pid;
std::map<std::string, std::string> rnk;
std::map<std::string, int> nick_rcnt;
std::map<pid_t, int> rnk_pipe;

int pki7771_port, rnk7773_port, rnk7774_port;           // used port numbers
int pki7771_handle, rnk7773_handle, rnk7774_handle;     // file descriptors

int irc_handle;
bool irc_stat = true;
iosocketstream *irc; // TCP/IP stream to IRC server

// The following functions are written quick'n'dirty. Be warned!
void read_after_select
	(fd_set rfds, std::map<pid_t, int> &read_pipe, int what)
{
	std::vector<pid_t> del_pipe; // PIDs of pipes that should be closed later
	for (m_ci_pid_t_int pi = read_pipe.begin(); pi != read_pipe.end(); ++pi)
	{
		int fd = pi->second; // file descriptor of the pipe
		if (fd < 0)
			continue;
		if (FD_ISSET(fd, &rfds))
		{
			size_t rbs = 65536; // size of the read buffer
			if (readbuf.count(fd) == 0)
			{
				// allocate a new read buffer for the pipe, if not exists yet
				readbuf[fd] = new char[rbs];
				// initialize read buffer offset
				readed[fd] = 0;
			}
			// read data from pipe
			ssize_t num = 0;
			size_t max_read = rbs - readed[fd];
			if (max_read > 0)
			{
				num = read(fd, readbuf[fd] + readed[fd], max_read);
				if (num <= 0)
				{
					if (errno != EINTR)
					{
						if (num < 0)
						{
							std::cerr << _("read error for PID") << " " <<
								pi->first << " " << _("encountered") <<
								" [errno=" << errno << "]" << std::endl;
						}
						del_pipe.push_back(pi->first); // close this pipe later
					}
				}
				else
					readed[fd] += num;
			}
			else
			{
				std::cerr << _("read buffer for PID") << " " << pi->first <<
					" " << _("exceeded") << std::endl;
				// consume some data from pipe without buffering FIXME: why?
				char *tmp = new char[rbs]; // allocate temporary buffer
				num = read(fd, tmp, rbs);
				if (num <= 0)
					del_pipe.push_back(pi->first); // close this pipe later
				delete [] tmp;
			}
			// process data
			if (readed[fd] > 0)
			{
				std::vector<size_t> pos_delim; // positions of line delimiters
				size_t cnt_delim = 0, cnt_pos = 0, pos = 0;
				for (size_t i = 0; i < readed[fd]; i++)
				{
					if (readbuf[fd][i] == '\n')
						cnt_delim++, pos_delim.push_back(i);
				}
				char *tmp = new char[rbs]; // allocate a buffer of size rbs
				switch (what)
				{
					case 1: // update of ranking data from RNK childs
						while (cnt_delim >= 2)
						{
							std::memset(tmp, 0, rbs);
							std::memcpy(tmp, readbuf[fd] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string rnk1 = tmp;
							std::memset(tmp, 0, rbs);
							std::memcpy(tmp, readbuf[fd] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string rnk2 = tmp;
							// do operation
							rnk[rnk1] = rnk2;
						}
						break;
					case 2: // IRC output from game childs
						while (cnt_delim >= 1)
						{
							std::memset(tmp, 0, rbs);
							std::memcpy(tmp, readbuf[fd] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string irc1 = tmp;
//std::cerr << "to IRC: " << irc1 << std::endl;
							// do operation
							pipe_irc(irc, irc1, sec, pub.keyid(5), nick_players,
								tables, tables_r, tables_p, tables_u, tables_o);
						}
						break;
					case 3: // import from PKI childs
						while (cnt_delim >= 2)
						{
							std::memset(tmp, 0, rbs);
							std::memcpy(tmp, readbuf[fd] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string pki1 = tmp;
							std::memset(tmp, 0, rbs);
							std::memcpy(tmp, readbuf[fd] + cnt_pos,
								pos_delim[pos] - cnt_pos);
							--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
							std::string pki2 = tmp;
							// do operation
							TMCG_PublicKey apkey;
							if (!apkey.import(pki2))
							{
								std::cerr << _("TMCG: public key corrupted") <<
									std::endl;
							}
							else if (pki1 != apkey.keyid(5))
							{
								std::cerr << _("TMCG: wrong public key") <<
									std::endl;
								std::cerr << pki1 << " vs. " <<
									apkey.keyid(5) << std::endl;
							}
							else
							{
								std::cout << X << "PKI " << _("identified") <<
									" \"" << pki1 << "\" " << "aka \"" << 
									apkey.name << "\" <" << apkey.email << 
									">" << std::endl;
								nick_key[pki1] = apkey;
							}
						}
						break;
					default:
						break;
				} // end of switch
				std::memset(tmp, 0, rbs);
				readed[fd] -= cnt_pos;
				std::memcpy(tmp, readbuf[fd] + cnt_pos, readed[fd]);
				std::memcpy(readbuf[fd], tmp, readed[fd]);
				delete [] tmp;
			}
		}
	}
	// close dead pipes
	for (size_t i = 0; i < del_pipe.size(); i++)
	{
		int fd = read_pipe[del_pipe[i]]; // file descriptor of the pipe
		delete [] readbuf[fd];
		readbuf.erase(fd);
		readed.erase(fd);
		read_pipe.erase(del_pipe[i]);
		if (close(fd) < 0)
			perror("read_after_select (close)");
	}
	del_pipe.clear();
}

static void process_line
	(char *line)
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
		std::vector<std::string> cmd_argv;
		size_t cmd_argc = irc_paramvec(s + 1, cmd_argv); // recognize arguments
		
		if (cmd_argc == 0)
			cmd_argv.push_back("help"); // print help, if no command is supplied
		
		if ((cmd_argv[0] == "quit") || (cmd_argv[0] == "ende"))
		{
			irc_quit = 1; // toggle quit flag
		}
		else if ((cmd_argv[0] == "on") || (cmd_argv[0] == "an"))
		{
			irc_stat = true; // turn output of chat messages on
		}	
		else if ((cmd_argv[0] == "off") || (cmd_argv[0] == "aus"))
		{
			irc_stat = false; // turn output of chat messages off
		}
		else if ((cmd_argv[0] == "players") || (cmd_argv[0] == "spieler"))
		{
			for (m_ci_string ni = nick_players.begin();
				ni != nick_players.end(); ++ni)
			{
				std::string nick = ni->first, host = ni->second;
				std::string name = "?", email = "?", type = "?", fp = "?";
				if (nick_key.find(nick) != nick_key.end())
				{
					// A key was found for nick, now get the attributes ...
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
			for (l_ci_string ti = tables.begin(); ti != tables.end(); ++ti)
			{
				if (tables_r[*ti] > 0)
				{
					if (tables_p[*ti] < 3)
					{
						std::cout << XX << _("table") << " <nr> = " << *ti << 
							", " << _("round(s)") << " <r> = " << tables_r[*ti] << 
							", #" << _("players") << " = " << tables_p[*ti] << 
							", " << _("owner") << " = " << tables_o[*ti] <<
							std::endl;
					}
					else
					{
						std::cout << XX << _("table") << " <nr> = " << *ti <<
							", " <<  _("still") << " <r> = " << tables_r[*ti] <<
							" " <<  _("round(s)") << ", " << _("owner") <<
							" = " << tables_o[*ti] << std::endl;
					}
				}
			}
		}
		else if ((cmd_argv[0] == "rooms") || (cmd_argv[0] == "raeume"))
		{
			for (l_ci_string ti = tables.begin(); ti != tables.end(); ++ti)
			{
				if (tables_r[*ti] < 0)
				{
					std::cout << XX << _("room") << " <nr> = " << *ti << 
						", <bits> = " << -tables_r[*ti] <<
						", #" << _("voters") << " = " << tables_p[*ti] <<
						", " << _("owner") << " = " << tables_o[*ti] <<
						std::endl;
				}
			}
		}
		else if ((cmd_argv[0] == "rank") || (cmd_argv[0] == "rang"))
		{
			std::list<std::string> rnk_nicktab;
			std::map<std::string, long> pkt[3], gws[3], vls[3];
			size_t prt_counter = 0, prt_counter_valid = 0;
            
			// temporarily add the own public key
			nick_key[pub.keyid(5)] = pub;
			// parse the obtained RNK data
			for (m_ci_string ri = rnk.begin(); ri != rnk.end(); ++ri)
			{
				std::string tk_sig1, tk_sig2, tk_sig3;
				std::string tk_header, tk_table;
				std::string tk_game[3], tk_nick[3];
				std::string so = ri->second;
				size_t ei;
				prt_counter++;
				// header
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_header = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// table
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_table = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// nick1
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_nick[0] = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// nick2
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_nick[1] = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// nick3
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_nick[2] = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// game1
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_game[0] = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// game2
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_game[1] = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// game3
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_game[2] = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// sig1
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_sig1 = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// sig2
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_sig2 = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				// sig3
				if ((ei = so.find("#", 0)) != so.npos)
				{
					tk_sig3 = so.substr(0, ei);
					so = so.substr(ei + 1, so.length() - ei - 1);
				}
				else
					continue;
				if ((tk_header != "prt") ||
					// FIXME: sigid is ID8, but nick is ID5: look for a prefix
					//(tk_nick[0] != pub.sigid(tk_sig1)) ||
					//(tk_nick[1] != pub.sigid(tk_sig2)) ||
					//(tk_nick[2] != pub.sigid(tk_sig3)) ||
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
				prt_counter_valid++;
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
				for (l_ci_string gpi = gp_l.begin(); gpi != gp_l.end(); ++gpi)
					gp_s = gp_s + (*gpi) + "~";
				for (size_t j = 0; j < 3; j++)
				{
					std::vector<std::string> gp_par;
					// parse a single game
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
			std::cout << prt_counter_valid << " " << _("out of") << " " <<
				prt_counter << " " << _("game protocols are valid") << "." <<
				std::endl;
			// Berechnen der Leistungspunkte (Erweitertes Seeger-System)
			for (size_t j = 0; j < 3; j++)
			{
				for (m_ci_string_long g = pkt[j].begin(); g != pkt[j].end(); ++g)
				{
					long seeger = 0;
					if (gws[j][g->first] > vls[j][g->first])
						seeger += 50 * (gws[j][g->first] - vls[j][g->first]);
					for (size_t jj = 0; jj < 3; jj++)
					{
						if (jj != j)
							seeger += 40 * vls[jj][g->first];
					}
					pkt[j][g->first] += seeger;
				}
			}
			// Ausgabe der Ranglisten mit eigener Beteiligung
			for (m_ci_string_long g = pkt[0].begin(); g != pkt[0].end(); ++g)
			{
				std::string gp = g->first, gp_w = g->first;
				size_t ei;
				std::vector<std::string> gp_p;
				// parse gp
				while ((ei = gp_w.find("~", 0)) != gp_w.npos)
				{
					gp_p.push_back(gp_w.substr(0, ei));
					gp_w = gp_w.substr(ei + 1, gp_w.length() - ei - 1);
				}
				// eigene Beteiligung?
				if ((gp.find(pub.keyid(5), 0) != gp.npos) && (gp_p.size() == 3))
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
						" : " << pkt[gp1][gp] << " " << _("score points") <<
						std::endl;
					std::cout << "| 2. | " << nick_key[gp_p[gp2]].name << 
						" : " << pkt[gp2][gp] << " " << _("score points") <<
						std::endl;
					std::cout << "| 3. | " << nick_key[gp_p[gp3]].name << 
						" : " << pkt[gp3][gp] << " " << _("score points") <<
						std::endl;
					std::cout << "+----+ " << std::endl;
				}
			}
			// remove the temporarily added own key
			nick_key.erase(pub.keyid(5));
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
						int r_pipe[2], in_pipe[2], out_pipe[2];
						if ((pipe(r_pipe) < 0) || (pipe(in_pipe) < 0) ||
							(pipe(out_pipe) < 0))
						{
							perror("run_irc (pipe)");
						}
						else if ((game_pid = fork()) < 0)
						{
							perror("run_irc (fork)");
						}
						else
						{
							if (game_pid == 0)
							{
								/* BEGIN child code (game process) */
								signal(SIGQUIT, SIG_DFL);
								signal(SIGTERM, SIG_DFL);
								if ((close(r_pipe[0]) < 0) || 
									(close(out_pipe[0]) < 0) ||
									(close(in_pipe[1]) < 0))
								{
									perror("run_irc (close)");
								}
								int ret = skat_child(tnr, r, true, in_pipe[0],
									out_pipe[1], r_pipe[1], pub.keyid(5));
								sleep(1);
								if ((close(r_pipe[1]) < 0) || 
									(close(out_pipe[1]) < 0) ||
									(close(in_pipe[0]) < 0))
								{
									perror("run_irc (close)");
								}
								exit(ret);
								/* END child code (game process) */
							}
							else
							{
								if ((close(r_pipe[1]) < 0) || 
									(close(out_pipe[1]) < 0) ||
									(close(in_pipe[0]) < 0))
								{
									perror("run_irc (close)");
								}
								games_pid2tnr[game_pid] = tnr;
								games_tnr2pid[tnr] = game_pid;
								games_rnkpipe[game_pid] = r_pipe[0];
								games_opipe[game_pid] = out_pipe[0];
								games_ipipe[game_pid] = in_pipe[1];
								join_irc(irc, tnr); // join that table
							}
						}
					}
					else
					{
						std::cout << X << _("wrong number of rounds") <<
							" <r> = " << trr << std::endl;
					}
				}
				else
				{
					std::cout << X << _("table") << " <nr> = \"" << tnr <<
						"\" " << _("already exists") << std::endl;
				}
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
							int r_pipe[2], in_pipe[2], out_pipe[2];
							if ((pipe(r_pipe) < 0) || (pipe(in_pipe) < 0) ||
								(pipe(out_pipe) < 0))
							{
								perror("run_irc (pipe)");
							}
							else if ((game_pid = fork()) < 0)
							{
								perror("run_irc (fork)");
							}
							else
							{
								if (game_pid == 0)
								{
									/* BEGIN child code (game process) */
									signal(SIGQUIT, SIG_DFL);
									signal(SIGTERM, SIG_DFL);
									if ((close(r_pipe[0]) < 0) || 
										(close(out_pipe[0]) < 0) ||
										(close(in_pipe[1]) < 0))
									{
										perror("run_irc (close)");
									}
									int ret = skat_child(tnr, tables_r[tnr],
										false, in_pipe[0], out_pipe[1],
										r_pipe[1], tables_o[tnr]);
									sleep(1);
									if ((close(r_pipe[1]) < 0) || 
										(close(out_pipe[1]) < 0) ||
										(close(in_pipe[0]) < 0))
									{
										perror("run_irc (close)");
									}
									exit(ret);
									/* END child code (game process) */
								}
								else
								{
									if ((close(r_pipe[1]) < 0) || 
										(close(out_pipe[1]) < 0) ||
										(close(in_pipe[0]) < 0))
									{
										perror("run_irc (close)");
									}
									games_pid2tnr[game_pid] = tnr;
									games_tnr2pid[tnr] = game_pid;
									games_rnkpipe[game_pid] = r_pipe[0];
									games_opipe[game_pid] = out_pipe[0];
									games_ipipe[game_pid] = in_pipe[1];
									join_irc(irc, tnr); // join that table
									who_irc(irc, tnr); // request status
								}
							}
						}
						else
						{
							std::cout << X << _("player") << " \"" <<
								pub.name << "\" " << _("is already on table") <<
								" <nr> = " << tnr << std::endl;
						}
					}
					else
					{
						std::cout << X << _("table") << " <nr> = " << tnr <<
							" " << _("is completely occupied") << std::endl;
					}
				}
				else
				{
					std::cout << X << _("table") << " <nr> = " << tnr << " " <<
						_("don't exists (yet)") << std::endl;
				}
			}
			else
			{
				std::cout << X << _("wrong number of arguments") << ": " <<
					cmd_argc << std::endl <<
					X << _("/help shows the list of commands") << std::endl;
			}
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
						{
							perror("run_irc (pipe)");
						}
						else if ((ballot_pid = fork()) < 0)
						{
							perror("run_irc (fork)");
						}
						else
						{
							if (ballot_pid == 0)
							{
								/* BEGIN child code (ballot process) */
								signal(SIGQUIT, SIG_DFL);
								signal(SIGTERM, SIG_DFL);
								if ((close(out_pipe[0]) < 0) ||
									(close(in_pipe[1]) < 0))
								{
									perror("run_irc (close)");
								}
								int ret = ballot_child(tnr, b, true,
									in_pipe[0], out_pipe[1], pub.keyid(5));
#ifndef NDEBUG
std::cerr << "ballot_child() = " << ret << std::endl;
#endif
								sleep(1);
								if ((close(out_pipe[1]) < 0) ||
									(close(in_pipe[0]) < 0))
								{
									perror("run_irc (close)");
								}
								exit(ret);
								/* END child code (ballot process) */
							}
							else
							{
								if ((close(out_pipe[1]) < 0) ||
									(close(in_pipe[0]) < 0))
								{
									perror("run_irc (close)");
								}
								games_pid2tnr[ballot_pid] = tnr;
								games_tnr2pid[tnr] = ballot_pid;
								games_rnkpipe[ballot_pid] = -1;
								games_opipe[ballot_pid] = out_pipe[0];
								games_ipipe[ballot_pid] = in_pipe[1];
								join_irc(irc, tnr); // join that room
							}
						}
					}
					else
					{
						std::cout << X << _("wrong number of bits") <<
							" <bits> = " << tbb << std::endl;
					}
				}
				else
				{
					std::cout << X << _("room") << " <nr> = \"" << tnr <<
						"\" " << _("already exists") << std::endl;
				}
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
							{
								perror("run_irc (pipe)");
							}
							else if ((ballot_pid = fork()) < 0)
							{
								perror("run_irc (fork)");
							}
							else
							{
								if (ballot_pid == 0)
								{
									/* BEGIN child code (ballot process) */
									signal(SIGQUIT, SIG_DFL);
									signal(SIGTERM, SIG_DFL);
									if ((close(out_pipe[0]) < 0) ||
										(close(in_pipe[1]) < 0))
									{
										perror("run_irc (close)");
									}
									int ret = ballot_child(tnr, -tables_r[tnr],
										false, in_pipe[0], out_pipe[1],
										tables_o[tnr]);
#ifndef NDEBUG
std::cerr << "ballot_child() = " << ret << std::endl;
#endif
									sleep(1);
									if ((close(out_pipe[1]) < 0) ||
										(close(in_pipe[0]) < 0))
									{
										perror("run_irc (close)");
									}
									exit(ret);
									/* END child code (ballot process) */
								}
								else
								{
									if ((close(out_pipe[1]) < 0) ||
										(close(in_pipe[0]) < 0))
									{
										perror("run_irc (close)");
									}
									games_pid2tnr[ballot_pid] = tnr;
									games_tnr2pid[tnr] = ballot_pid;
									games_rnkpipe[ballot_pid] = -1;
									games_opipe[ballot_pid] = out_pipe[0];
									games_ipipe[ballot_pid] = in_pipe[1];
									join_irc(irc, tnr); // join that room
									who_irc(irc, tnr); // request status
								}
							}
						}
						else
						{
							std::cout << X << _("voter") << " \"" << pub.name <<
								"\" " << _("is already in room") <<
								" <nr> = " << tnr << std::endl;
						}
					}
					else
					{
						std::cout << X << _("room") << " <nr> = " << tnr <<
							" " << _("is closed") << std::endl;
					}
				}
				else
				{
					std::cout << X << _("room") << " <nr> = " << tnr << " " <<
						_("don't exists (yet)") << std::endl;
				}
			}
			else
			{
				std::cout << X << _("wrong number of arguments") << ": " <<
					cmd_argc << std::endl <<
					X << _("/help shows the list of commands") << std::endl;
			}
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
						std::cout << X << _("opening file") << " " <<
							cmd_argv[1] << " " << _("failed") << std::endl;
					}
				}
				catch (std::ofstream::failure& e)
				{
					std::cout << X << _("writing file") << " " << cmd_argv[1] << 
						" " << _("failed") << ": " << e.what() << std::endl;
				}
			}
			else
			{
				std::cout << X << _("wrong number of arguments") << ": " << 
					(cmd_argc-1) << " " << _("instead of") << " 1" << std::endl;
			}
		}
		else if (cmd_argv[0] == "import")
		{
			if (cmd_argc == 2)
			{
				std::ifstream ifs;
				ifs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
				char *buffer = new char[KEY_SIZE];
				if (buffer != NULL)
				{

					try
					{
						ifs.open(cmd_argv[1].c_str(), std::ifstream::in);
						if (ifs.is_open())
						{
							ifs.getline(buffer, KEY_SIZE);
							ifs.close();
							TMCG_PublicKey apkey;
							if (!apkey.import(buffer))
							{
								std::cout << X <<
									_("TMCG: public key corrupted") <<
									std::endl;
							}
							else if ((nick_key.find(apkey.keyid(5)) !=
								nick_key.end()) ||
								(apkey.keyid(5) == pub.keyid(5)))
							{
								std::cout << X <<
									_("public key already present") <<
									std::endl;
							}
							else
							{
								std::cout << X << _("Checking the key") <<
									" \"" << apkey.keyid(5) << "\". " <<
									_("Please wait") << "..." << std::endl;
								if (!apkey.check())
								{
									std::cout << X <<
										_("TMCG: invalid public key") <<
										std::endl;
								}
								else
								{
									nick_key[apkey.keyid(5)] = apkey; // import
									std::cout << X << "PKI " << _("imports") << 
										" \"" << apkey.keyid(5) << "\" " <<
										"aka \"" << apkey.name << "\" <" <<
										apkey.email << ">" << std::endl;
								}
							}
						}
						else
						{
							std::cout << X << _("opening file") << " " <<
								cmd_argv[1] << " " << _("failed") << std::endl;
						}
					}
					catch (std::ifstream::failure& e)
					{
						std::cout << X << _("reading file") << " " <<
							cmd_argv[1] << " " << _("failed") << ": " <<
							e.what() << std::endl;
					}
					delete [] buffer;
				}
				else
				{
					std::cout << X << _("out of memory") << std::endl;
				}
			}
			else
			{
				std::cout << X << _("wrong number of arguments") << ": " << 
					(cmd_argc-1) << " " << _("instead of") << " 1" << std::endl;
			}
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
				_("create the room <nr> for voting between 2^<b> values") <<
				std::endl;
			std::cout << XX << _("/ballot") << " <nr> -- " << 
				_("join the voting in room <nr>") << std::endl;
			std::cout << XXX << "/<nr> open -- " << 
				_("open the voting process in room <nr> (only owner)") <<
				std::endl;
			std::cout << XXX << "/<nr> vote <r> -- " << 
				_("vote in room <nr> for value <r>") << std::endl;
			std::cout << XX << "/skat <nr> <r> -- " << 
				_("create the table <nr> for playing <r> rounds") << std::endl;
			std::cout << XX << "/skat <nr> -- " << 
				_("join the game on table <nr>") << std::endl;
			std::cout << XX << "/<nr> <cmd> -- " << 
				_("execute the command <cmd> on table <nr>") << std::endl;
			std::cout << XXX << "/<nr> " << _("view") << " --- " << 
				_("show your own cards and additional information") <<
				std::endl;
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
			for (m_ci_string_pid_t gi = games_tnr2pid.begin();
				gi != games_tnr2pid.end(); ++gi)
			{
				if (cmd_argv[0] == gi->first)
				{
					found = true;
					opipestream *npipe =
						new opipestream(games_ipipe[gi->second]);
					*npipe << "CMD ";
					for (size_t gj = 1; gj < cmd_argc; gj++)
						*npipe << cmd_argv[gj] << " ";
					*npipe << std::endl << std::flush;
					delete npipe;
				}
			}
			if (!found)
			{
				std::cout << X << _("unknown command") << ": \"/" <<
					cmd_argv[0] << "\"" << std::endl <<
					X << _("/help shows the list of commands") << std::endl;
			}
		}
	}
	else
	{
		if ((s != NULL) && (strlen(s) > 0))
		{
			// sign and send PRIVMSG message (regular chat at main channel)
			*irc << "PRIVMSG " << MAIN_CHANNEL << " :" << s << "~~~" << 
				sec.sign(s) << std::endl << std::flush;
			std::cout << "<" << pub.name << "> " << s << std::endl;
		}
	}
	free(line);
}

void run_irc
	(const std::string &hostname)
{
    bool first_command = true, first_entry = false, entry_ok = false;
    fd_set rfds;                    // set of read descriptors
	int mfds = 0;                   // highest-numbered descriptor
	struct timeval tv;              // timeout structure for select(2)
	char irc_readbuf[32768];        // read buffer
	size_t irc_readed = 0;          // read pointer
	unsigned long ann_counter = 0;  // announcement counter
	unsigned long clr_counter = 0;  // clear tables counter
#ifdef AUTOJOIN
	unsigned long atj_counter = 0;  // autojoin counter
#endif
		
	while (irc->good() && !irc_quit)
	{
		// select(2) -- initialize file descriptors
		FD_ZERO(&rfds);
#ifndef NOHUP
		MFD_SET(fileno(stdin), &rfds);
#endif
		if (irc_handle < FD_SETSIZE)
		{
			MFD_SET(irc_handle, &rfds);
		}
		else
		{
			std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
			break;
		}
		if (pki7771_handle < FD_SETSIZE)
		{
			MFD_SET(pki7771_handle, &rfds);
		}
		else
			std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
		if (rnk7773_handle < FD_SETSIZE)
		{
			MFD_SET(rnk7773_handle, &rfds);
		}
		else
			std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
		if (rnk7774_handle < FD_SETSIZE)
		{
			MFD_SET(rnk7774_handle, &rfds);
		}
		else
			std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
		// PKI pipes from childs
		for (m_ci_pid_t_int pi = nick_pipe.begin();	pi != nick_pipe.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				MFD_SET(pi->second, &rfds);
			}
			else
				std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
		}
		// RNK pipes from childs
		for (m_ci_pid_t_int pi = rnk_pipe.begin(); pi != rnk_pipe.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				MFD_SET(pi->second, &rfds);
			}
			else
				std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
		}
		// RNK pipes from game childs
		for (m_ci_pid_t_int pi = games_rnkpipe.begin();
			pi != games_rnkpipe.end(); ++pi)
		{
			if (pi->second < 0)
				continue;
			if (pi->second < FD_SETSIZE)
			{
				MFD_SET(pi->second, &rfds);
			}
			else
				std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
		}
		// OUT pipes from game childs
		for (m_ci_pid_t_int pi = games_opipe.begin();
			pi != games_opipe.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				MFD_SET(pi->second, &rfds);
			}
			else
			{
				std::cerr << _("ERROR: FD_SETSIZE exceeded") << std::endl;
				irc_quit = 1; // simple 'break' does not help here
			}
		}
		
		// select(2) -- initialize timeout
		tv.tv_sec = 1L;			// seconds
		tv.tv_usec = 0L;		// microseconds
		
		// select(2) -- do everything with asynchronous I/O
		int ret = select(mfds + 1, &rfds, NULL, NULL, &tv);
		
		// error occured
		if (ret < 0)
		{
			if (errno != EINTR)
			{
				perror("run_irc (select)");
				break;
			}
			else
				continue;
		}
		
		// anything happend in any descriptor set
		if (ret > 0)
		{
			// input: RNK pipes from children
			read_after_select(rfds, rnk_pipe, 1);
			// input: RNK pipes from game children
			read_after_select(rfds, games_rnkpipe, 1);
			// input: OUT pipes from game children
			read_after_select(rfds, games_opipe, 2);
			// input: PKI pipes from children
			read_after_select(rfds, nick_pipe, 3);
			// output: RNK (export rank list on port 7773)
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
					for (m_ci_string pi = rnk.begin(); pi != rnk.end(); ++pi)
						*rnk_io << pi->first << std::endl << std::flush;
					delete rnk_io;
					if (close(client_handle) < 0)
						perror("run_irc (close)");
				}
			}
			// output: PKI (export public key on port 7771)
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
			// output: RNK (get rank entry on port 7774)
			if (FD_ISSET(rnk7774_handle, &rfds))
			{
				struct sockaddr_in client_in;
				socklen_t client_len = sizeof(client_in);
				int client_handle = accept(rnk7774_handle,
					(struct sockaddr*) &client_in, &client_len);
				if (client_handle < 0)
				{
					perror("run_irc (accept)");
				}
				else if (rnkrpl_pid.size() >= RNK_CHILDS)
				{
					// too many RNK childs
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
							/* BEGIN child code (ranking data) */
							signal(SIGQUIT, SIG_DFL);
							signal(SIGTERM, SIG_DFL);
							iosocketstream *client_ios =
								new iosocketstream(client_handle);
							char *tmp = new char[100000L];
							client_ios->getline(tmp, 100000L);
							if (rnk.find(tmp) != rnk.end())
							{
								*client_ios << rnk[tmp] << std::endl <<
									std::flush;
							}
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
			// input: read from stdin
			if (FD_ISSET(fileno(stdin), &rfds))
			{
				rl_callback_read_char();
			}
#endif
			// input: read from IRC connection
			if (FD_ISSET(irc_handle, &rfds))
			{
				ssize_t num = read(irc_handle, irc_readbuf + irc_readed,
					sizeof(irc_readbuf) - irc_readed);
				if (num <= 0)
				{
					if (errno != EINTR)
					{
						std::cerr <<
							_("IRC ERROR: connection with server collapsed") <<
							" [errno=" << errno << "]" << std::endl;
						break;
					}
				}
				else
					irc_readed += num;
			}
		}

		// input: process from IRC connection			
		if (irc_readed > 0)
		{
			std::vector<size_t> pos_delim;
			size_t cnt_delim = 0, cnt_pos = 0, pos = 0;
			for (size_t i = 0; i < irc_readed; i++)
			{
				if (irc_readbuf[i] == '\n')
					cnt_delim++, pos_delim.push_back(i);
				if (irc_readbuf[i] == '\015')
					irc_readbuf[i] = '\n', cnt_delim++, 
				pos_delim.push_back(i);
			}
			while (cnt_delim >= 1)
			{
				char tmp[65536];
				memset(tmp, 0, sizeof(tmp));
				memcpy(tmp, irc_readbuf + cnt_pos,
					pos_delim[pos] - cnt_pos);
				--cnt_delim, cnt_pos = pos_delim[pos] + 1, pos++;
				std::string irc_reply = tmp;
				if (!irc_process(irc, irc_reply, entry_ok, first_entry,
					irc_stat, pub.keyid(5), public_prefix, games_tnr2pid,
					games_ipipe, nick_key, nick_players, nick_sl, nick_p7771,
					nick_p7772, nick_p7773, nick_p7774,	nick_package,
					tables, tables_r, tables_p, tables_u, tables_o))
				{
					irc_quit = 1;
					break;
				}
			}
			char tmp[65536];
			memset(tmp, 0, sizeof(tmp));
			irc_readed -= cnt_pos;
			memcpy(tmp, irc_readbuf + cnt_pos, irc_readed);
			memcpy(irc_readbuf, tmp, irc_readed);
		}
		
		// the timeout occured
		if (ret == 0)
		{
			// We use signal blocking for serializing access (a serious hack!).
			raise(SIGUSR1);
			
			// re-install signal handlers, because some unices do not restore
			// them properly
			signal(SIGINT, sig_handler_quit);
			signal(SIGQUIT, sig_handler_quit);
			signal(SIGTERM, sig_handler_quit);
			signal(SIGPIPE, sig_handler_pipe);
			signal(SIGCHLD, sig_handler_chld);
#ifdef NOHUP
			signal(SIGHUP, SIG_IGN);
#else
            signal(SIGHUP, sig_handler_quit);
#endif
			signal(SIGUSR1, sig_handler_usr1);
			
			// do other delayed stuff, i.e., register at IRC server and join
			if (first_command)
			{
				// create basic information record of this instance
				char ptmp[1024];
				if (hostname == "undefined")
				{
					snprintf(ptmp, sizeof(ptmp), "|%d~%d!%d#%d?%d/",
						pki7771_port, 0, rnk7773_port, rnk7774_port, 80);
				}
				else
				{
					snprintf(ptmp, sizeof(ptmp), "|%d~%d!%d#%d?%d/%s*",
						pki7771_port, 0, rnk7773_port, rnk7774_port, 80,
						hostname.c_str());
				}
				std::string uname = pub.keyid(5);
				// create a somehow "unique" username based on the nickname
				if (uname.length() > 4)
				{
					std::string uname2 = "os"; // prefix
					for (size_t ic = 4; ic < uname.length(); ic++)
					{
						if (islower(uname[ic]))
						{
							uname2 += uname[ic];
						}
						else if (isdigit(uname[ic]))
						{
							uname2 += "d"; // sign for decimal digit
							uname2 += ('a' + (uname[ic] - 0x30));
						}
						else if (isupper(uname[ic]))
						{
							uname2 += "u"; // sign for upper case letter
							uname2 += ('a' + (uname[ic] - 0x41));
						}
					}
					uname = uname2;
				}
				else
					uname = "unknown";
				// register the instance at IRC server
				*irc << "USER " << uname << " 0 0 :" << PACKAGE_STRING <<
					ptmp << std::endl << std::flush;
				first_command = false;
			}
			else if (first_entry)
			{
				// join the main channel and request status
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
					for (l_ci_string t = tables.begin(); t != tables.end(); ++t)
					{
						// if not already joined, do AUTOJOIN (greedy behaviour)
						if (games_tnr2pid.find(*t) == games_tnr2pid.end())
						{
							char *command = (char*)malloc(500);
							if (command == NULL)
							{
								std::cerr << _("MALLOC ERROR: out of memory") <<
									std::endl;
								irc_quit = 1;
							}
							memset(command, 0, 500);
							strncat(command, "/skat ", 25);
							strncat(command, t->c_str(), 475);
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
					for (m_ci_pid_t_int pi = games_ipipe.begin();
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
			
			// send SIGQUIT to all PKI processes -- PKI TIMEMOUT exceeded
			for (l_ci_pid_t p = nick_pids.begin(); p != nick_pids.end(); ++p)
			{
				if (nick_ncnt[nick_nick[*p]] > PKI_TIMEOUT)
				{
					if (kill(*p, SIGQUIT) < 0)
						perror("run_irc (kill)");
				}
			}
			
			// send SIGQUIT to all RNK processes -- RNK TIMEMOUT exceeded
			for (l_ci_pid_t p = rnk_pids.begin(); p != rnk_pids.end(); ++p)
			{
				if (nick_rnkcnt[rnk_nick[*p]] > RNK_TIMEOUT)
				{
					if (kill(*p, SIGQUIT) < 0)
						perror("run_irc (kill)");
				}
			}
			
			// start RNK or PKI processes
			for (m_ci_string ni = nick_players.begin();
				ni != nick_players.end(); ++ni)
			{
				std::string nick = ni->first, host = ni->second;
				// RNK (obtain ranking data from other players by gossip)
				if (nick_rcnt.find(nick) == nick_rcnt.end())
					nick_rcnt[nick] = RNK_TIMEOUT;
				else
					nick_rcnt[nick] += 1;
				if (nick_rnkcnt.find(nick) != nick_rnkcnt.end())
					nick_rnkcnt[nick] += 1;
				if ((nick_rcnt[nick] > RNK_TIMEOUT) &&
					(nick_rnkcnt.find(nick) == nick_rnkcnt.end()))
				{
#ifndef NDEBUG
std::cerr << "RNK gossip started [nick=" << nick << "]" << std::endl;
#endif
					// start RNK gossip
					nick_rcnt[nick] = 0;
					int fd_pipe[2];
					if (pipe(fd_pipe) < 0)
					{
						perror("run_irc (pipe)");
					}
					else if ((rnk_pid = fork()) < 0)
					{
						perror("run_irc (fork)");
					}
					else
					{
						if (rnk_pid == 0)
						{
							/* BEGIN child code (ranking data gossip) */
							signal(SIGQUIT, SIG_DFL);
							signal(SIGTERM, SIG_DFL);
							sleep(1);
							if (close(fd_pipe[0]) < 0)
							{
								perror("run_irc [RNK/child] (close)");
								exit(-1);
							}
							opipestream *npipe = new opipestream(fd_pipe[1]);
							// create TCP/IP connection to p7773
							int nick_handle = ConnectToHost(host.c_str(),
								nick_p7773[nick]);
							if (nick_handle < 0)
							{
								std::cerr << "run_irc [RNK/child]" << 
									" (ConnectToHost)" << std::endl;
								*npipe << "EOF" << std::endl << std::flush;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [RNK/child] (close)");
								exit(-1);
							}
							iosocketstream *n = new iosocketstream(nick_handle);
							// get RNK list
							char *tmp = new char[RNK_SIZE];
							if (tmp == NULL)
							{
								std::cerr << _("RNK ERROR: out of memory") <<
									std::endl;
								*npipe << "EOF" << std::endl << std::flush;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [RNK/child] (close)");
								exit(-1);
							}
							char num[32];
							memset(num, 0, sizeof(num));
							n->getline(num, sizeof(num) - 1);
							size_t rnk_idsize = strtoul(num, NULL, 10);
							std::vector<std::string> rnk_idlist;
							for (size_t i = 0; i < rnk_idsize; i++)
							{
								memset(tmp, 0, RNK_SIZE);
								n->getline(tmp, RNK_SIZE);
								if (rnk.find(tmp) == rnk.end())
									rnk_idlist.push_back(tmp);
							}
							// close TCP/IP connection
							delete n;
							if (close(nick_handle) < 0)
								perror("run_irc [RNK/child] (close)");
							// iterate through unknown entries of RNK list
							for (v_ci_string ri = rnk_idlist.begin();
								ri != rnk_idlist.end(); ++ri)
							{
								// create TCP/IP connection to p7774
								int rhd = ConnectToHost(host.c_str(),
									nick_p7774[nick]);
								if (rhd < 0)
								{
									std::cerr << "run_irc [RNK/child]" <<
										" (ConnectToHost)" << std::endl;
									delete [] tmp;
									*npipe << "EOF" << std::endl << std::flush;
									delete npipe;
									if (close(fd_pipe[1]) < 0)
										perror("run_irc [RNK/child] (close)");
									exit(-1);
								}
								iosocketstream *nrpl = new iosocketstream(rhd);
								// get RNK data and send it to storing parent
								*nrpl << *ri << std::endl << std::flush;
								memset(tmp, 0, RNK_SIZE);
								nrpl->getline(tmp, RNK_SIZE);
								*npipe << *ri << std::endl << std::flush;
								*npipe << tmp << std::endl << std::flush;
								// close TCP/IP connection
								delete nrpl;
								if (close(rhd) < 0)
									perror("run_irc [RNK/child] (close)");
							}
							*npipe << "EOF" << std::endl << std::flush;
							delete [] tmp;
							delete npipe;
							if (close(fd_pipe[1]) < 0)
								perror("run_irc (close)");
							exit(0);
							/* END child code (ranking data gossip) */
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
				// PKI (obtain and verify public keys of other players)
				if ((nick_key.find(nick) == nick_key.end()) &&
					(std::find(nick_ninf.begin(), nick_ninf.end(), nick) ==
					nick_ninf.end()))
				{
#ifndef NDEBUG
std::cerr << "PKI key exchange started [nick=" << nick << "]" << std::endl;
#endif
					int fd_pipe[2];
					if (pipe(fd_pipe) < 0)
					{
						perror("run_irc (pipe)");
					}
					if ((nick_pid = fork()) < 0)
					{
						perror("run_irc (fork)");
					}
					else
					{
						if (nick_pid == 0)
						{
							/* BEGIN child code (public key exchange) */
							signal(SIGQUIT, SIG_DFL);
							signal(SIGTERM, SIG_DFL);
							sleep(1);
							if (close(fd_pipe[0]) < 0)
							{
								perror("run_irc [PKI/child] (close)");
								exit(-1);
							}
							opipestream *npipe = new opipestream(fd_pipe[1]);
							// create the TCP/IP connection
							int nick_handle = ConnectToHost(host.c_str(),
								nick_p7771[nick]);
							if (nick_handle < 0)
							{
								std::cerr << "run_irc [PKI/child]" <<
									" (ConnectToHost)" << std::endl;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [PKI/child] (close)");
								exit(-1);
							}
							iosocketstream *n = new iosocketstream(nick_handle);
							// get the public key
							char *tmp = new char[KEY_SIZE];
							if (tmp == NULL)
							{
								std::cerr << _("PKI ERROR: out of memory") <<
									std::endl;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [PKI/child] (close)");
								exit(-1);
							}
							memset(tmp, 0, KEY_SIZE);
							n->getline(tmp, KEY_SIZE);
							std::string public_key = tmp;
							// close the TCP/IP connection
							delete n;
							delete [] tmp;
							if (close(nick_handle) < 0)
								perror("run_irc [PKI/child] (close)");
							// import the public key
							TMCG_PublicKey pkey;
							if (!pkey.import(public_key))
							{
								std::cerr << _("TMCG: public key corrupted") <<
									std::endl;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [PKI/child] (close)");
								exit(-2);
							}
							// check the keyID
							if (nick != pkey.keyid(5))
							{
								std::cerr << _("TMCG: wrong public key") <<
									std::endl;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [PKI/child] (close)");
								exit(-3);
							}
							// check the self-signature and NIZK
							if (!pkey.check())
							{
								std::cerr << _("TMCG: invalid public key") <<
									std::endl;
								delete npipe;
								if (close(fd_pipe[1]) < 0)
									perror("run_irc [PKI/child] (close)");
								exit(-4);
							}
							// send the valid public key to our parent
							*npipe << nick << std::endl << std::flush;
							*npipe << public_key << std::endl << std::flush;
							delete npipe;
							if (close(fd_pipe[1]) < 0)
								perror("run_irc [child] (close)");
							exit(0);
							/* END child code (public key exchange) */
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
				else if (std::find(nick_ninf.begin(), nick_ninf.end(), nick) !=
					nick_ninf.end())
				{
					nick_ncnt[nick] += 1;
				}
			}
		}
	}

    // check whether the IRC connection still exists
    if (!irc->good())
	{
        std::cerr << _("IRC ERROR: connection with server collapsed") <<
			std::endl;
	}

    // free the previously allocated memory (read buffers)
    for (m_ci_int rbi = readbuf.begin(); rbi != readbuf.end(); ++rbi)
		delete [] rbi->second;
}

void cleanup
	()
{
    // send SIGQUIT to all child processes and wait for them
    for (m_ci_pid_t p = games_pid2tnr.begin(); p != games_pid2tnr.end(); ++p)
    {
        if (kill(p->first, SIGQUIT) < 0)
            perror("cleanup (kill)");
        waitpid(p->first, NULL, 0);
    }
    games_pid2tnr.clear(), games_tnr2pid.clear();
    for (l_ci_pid_t p = nick_pids.begin(); p != nick_pids.end(); ++p)
    {
        if (kill(*p, SIGQUIT) < 0)
            perror("cleanup (kill)");
        waitpid(*p, NULL, 0);
    }
    nick_pids.clear(), nick_nick.clear(), nick_host.clear();
    nick_ninf.clear(), nick_ncnt.clear(), nick_players.clear();
    for (l_ci_pid_t p = rnkrpl_pid.begin(); p != rnkrpl_pid.end(); ++p)
    {
        if (kill(*p, SIGQUIT) < 0)
            perror("cleanup (kill)");
        waitpid(*p, NULL, 0);
    }
    rnkrpl_pid.clear();
}

void init_term
	(struct termios &old_term)
{
    struct termios new_term;
    
    // save the old terminal settings
    if (tcgetattr(fileno(stdin), &old_term) < 0)
    {
        perror("init_term (tcgetattr)");
        exit(-1);
    }
    // set the new terminal settings
    new_term = old_term;
    new_term.c_lflag &= ~ICANON, new_term.c_cc[VTIME] = 1;
    if (tcsetattr(fileno(stdin), TCSANOW, &new_term) < 0)
    {
        perror("init_term (tcsetattr)");
        exit(-1);
    }
    // install readline callback handler
    rl_readline_name = "SecureSkat";
#ifdef _RL_FUNCTION_TYPEDEF
    rl_callback_handler_install(NULL, (rl_vcpfunc_t*)process_line);
#else
    rl_callback_handler_install(NULL, (VFunction*)process_line);
#endif
}

void done_term
	(struct termios &old_term)
{
    // remove readline callback handler
    rl_callback_handler_remove();
    // restore old terminal settings
    if (tcsetattr(fileno(stdin), TCSANOW, &old_term) < 0)
        perror("done_term (tcsetattr)");
}

int main
	(int argc, char* argv[], char* envp[])
{
	char *home = NULL, *althost = NULL;
	std::string homedir = "", hostname = "undefined";
	std::cout << PACKAGE_STRING <<
		", (c) 2019  Heiko Stamer <HeikoStamer@gmx.net>, License: GPLv2" <<
		std::endl;
	
#ifdef ENABLE_NLS
	// set the locales
#ifdef HAVE_LC_MESSAGES
	setlocale(LC_TIME, "");
	setlocale(LC_MESSAGES, "");
#else
	setlocale(LC_ALL, "");
#endif
	// enable the native language support
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	std::cout << "++ " << _("Internationalization support") << ": " <<
		LOCALEDIR << std::endl;
#endif
	
	// evaluate the environment variable HOME
	home = getenv("HOME");
	if (home != NULL)
		homedir = home, homedir += "/.SecureSkat/";
	else
		homedir = "~/.SecureSkat/";
	std::cout << "++ " << _("PKI/RNK database directory") << ": " <<
		homedir << std::endl;

	// evaluate the environment variable ALTHOST
	althost = getenv("ALTHOST");
	if (althost != NULL)
	{
		hostname = althost;
		std::cout << "++ " << _("Alternative hostname") << ": " <<
			hostname << std::endl;
	}
    
	// check existance and permissions of the home directory
	struct stat stat_buffer;
	if (stat(homedir.c_str(), &stat_buffer))
	{
		if (errno == ENOENT)
		{
			// create directory, if it doesn't exist
			if (mkdir(homedir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR))
			{
				std::cerr << _("Can't create directory!") << " (" <<
					strerror(errno) << ")" << std::endl;
				return EXIT_FAILURE;
			}
		}
		else
		{
			// print error message
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
			std::cerr << _("Missing permissions for directory!") << std::endl;
			return EXIT_FAILURE;
		}
	}
	
	// process the command line arguments
	if (((argc == 4) && isdigit(argv[2][0])) ||
		((argc == 3) && isdigit(argv[2][0])) ||
		(argc == 2))
	{
		struct termios old_term;
		int irc_port = 0;

		// set the default values
		irc_port = 6667;
		game_ctl = "";
		game_env = NULL;

		// evaluate the provided command switches to override the defaults
		switch (argc)
		{
			case 4:
				game_ctl = argv[3];
				game_env = envp;
				irc_port = atoi(argv[2]);
				break;
			case 3:
				irc_port = atoi(argv[2]);
				break;
		}

		// initialize LibTMCG
		if (!init_libTMCG())
		{
			std::cerr << _("Initialization of LibTMCG failed!") << std::endl;
			return EXIT_FAILURE;
		}
		// display version of LibTMCG
		std::cout << "++ " << _("Initialization of LibTMCG version") << " " <<
			version_libTMCG() << std::endl;

		// key management		
		get_secret_key(homedir + "SecureSkat.skr", sec, public_prefix);
		pub = TMCG_PublicKey(sec); // extract the public part of the secret key
		std::cout << _("Your key fingerprint") << ": " <<
			pub.fingerprint() << std::endl;
		get_public_keys(homedir + "SecureSkat.pkr", nick_key); // load pub keys
		
		create_pki(pki7771_port, pki7771_handle);
		create_rnk(rnk7773_port, rnk7774_port, rnk7773_handle, rnk7774_handle);
		load_rnk(homedir + "SecureSkat.rnk", rnk); // load ranking data
        
		// open an IRC connection
		irc_handle = create_irc(argv[1], irc_port, &irc);

		// install several signal handlers
		signal(SIGINT, sig_handler_quit);
		signal(SIGQUIT, sig_handler_quit);
		signal(SIGTERM, sig_handler_quit);
		signal(SIGPIPE, sig_handler_pipe);
		signal(SIGCHLD, sig_handler_chld);
#ifdef NOHUP
		signal(SIGHUP, SIG_IGN);
#else
		signal(SIGHUP, sig_handler_quit);
#endif
		signal(SIGUSR1, sig_handler_usr1);

		init_irc(irc, pub.keyid(5));
		std::cout << _("Usage") << ": " <<
			_("type /help for the command list or read the file README") <<
			std::endl;
#ifndef NOHUP
		init_term(old_term);
#endif
		run_irc(hostname); // main loop
#ifndef NOHUP
		done_term(old_term);
#endif
    
		// ignore the remaining signals
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, SIG_IGN);

		// stop and release everything
		done_irc(irc);
		cleanup(); // kill, wait, and reload^Hclear
		release_irc(irc_handle, irc); // close IRC connection
		save_rnk(homedir + "SecureSkat.rnk", rnk); // save ranking data
		release_rnk(rnk7773_handle, rnk7774_handle);
		release_pki(pki7771_handle);
		set_public_keys(homedir + "SecureSkat.pkr", nick_key); // save pub keys
		
		return EXIT_SUCCESS;
	}

	// print a short usage message and exit with failure
	std::cout << _("Usage") << ": " << argv[0] <<
		" IRC_SERVER<string> [ IRC_PORT<int> [ CTRL_PROGRAM<string> ] ]" <<
		std::endl;
	return EXIT_FAILURE;
}
