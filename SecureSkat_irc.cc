/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2009, 2017, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#include "SecureSkat_irc.hh"

int create_irc
	(const std::string &server, short int port, iosocketstream **irc)
{
	int irc_handle;
    
	// establish a TCP/IP connection to a given IRC server
	irc_handle = ConnectToHost(server.c_str(), port);
	if (irc_handle < 0)
		exit(irc_handle); // abort with an appropriate error code
	*irc = new iosocketstream(irc_handle);
    
	return irc_handle;
}

void init_irc
	(iosocketstream *irc, const std::string &nickname)
{
	// send the NICK message to the IRC server
	*irc << "NICK " << nickname << std::endl << std::flush;
}

void join_irc
	(iosocketstream *irc, const std::string &c)
{
	// join an IRC channel that represents an unique table for playing
	*irc << "JOIN " << MAIN_CHANNEL_UNDERSCORE << c << std::endl << std::flush;
}

void who_irc
	(iosocketstream *irc, const std::string &c)
{
	// request status of an IRC channel that is used for playing
	*irc << "WHO " << MAIN_CHANNEL_UNDERSCORE << c << std::endl << std::flush;
}

// strip leading spaces (0x20) from the input
void irc_strip
	(std::string &input)
{
	while (input.find(" ") == 0)
		input = input.substr(1, input.length() - 1);
}

// factor an IRC message into prefix, command and params according to RFC1459
void irc_factor
	(std::string input, std::string &prefix, std::string &command,
	std::string &params)
{
	// prefix
	if (input.find(":") == 0)
	{
		std::string::size_type spos = input.find(" ");
		if (spos == input.npos)
		{
			prefix = input;
			command = "";
			params = "";
			return;	
		}
		prefix = input.substr(1, spos - 1);
		input = input.substr(spos + 1, input.length() - spos - 1);
	}
	else
		prefix = "";
	// strip spaces
	irc_strip(input);
	// command
	if (input.find(" ") != input.npos)
	{
		std::string::size_type spos = input.find(" ");
		command = input.substr(0, spos);
		input = input.substr(spos + 1, input.length() - spos - 1);
	}
	else
	{
		command = input;
		params = "";
		return;
	}
	// strip spaces
	irc_strip(input);
	// params
	params = input;
}

// return the prefix of an IRC message
std::string irc_prefix
	(const std::string &input)
{
	std::string prefix, command, params;

	irc_factor(input, prefix, command, params);
	return std::string(prefix);
}

// return the command of an IRC message
std::string irc_command
	(const std::string &input)
{
	std::string prefix, command, params;
    
	irc_factor(input, prefix, command, params);    
	return std::string(command);
}

// return the arguments of an IRC message
std::string irc_params
	(const std::string &input)
{
	std::string prefix, command, params;
    
	irc_factor(input, prefix, command, params);    
	return std::string(params);
}

// construct a vector containing the arguments of an IRC message
size_t irc_paramvec
	(std::string input, std::vector<std::string> &v)
{
	v.clear(); // clear the vector that will contain the arguments
	while (input != "")
	{
		// strip spaces
		irc_strip(input);
		// found escape sequence, i.e. last token
		if (input.find(":") == 0)
		{ 
			v.push_back(input.substr(1, input.length() - 1));
			break;
		}
		else if (input.find(" ") != input.npos) // next token
		{
			std::string::size_type spos = input.find(" ");
			v.push_back(input.substr(0, spos));
			input = input.substr(spos + 1, input.length() - spos);
		}
		else // last token (without escape character) 
		{
			if (input != "")
				v.push_back(input);
			break;
		}
	}
	return v.size(); // return the size of v, i.e. number of arguments
}

bool irc_command_cmp
	(const std::string &input, const std::string &cmd)
{
	if (strncasecmp(irc_command(input).c_str(), cmd.c_str(), cmd.length()))
		return false;
	else
		return true;
}

void pipe_irc
	(iosocketstream *irc, const std::string &irc_message,
	 const TMCG_SecretKey &sec, const std::string &keyid,
	 const std::map<std::string, std::string> &nick_players,
	 std::list<std::string> &tables,
	 std::map<std::string, int> &tables_r,
	 std::map<std::string, int> &tables_p,
	 std::map<std::string, std::string> &tables_u,
	 std::map<std::string, std::string> &tables_o)
{
    std::vector<std::string> irc_parvec;
    if (irc_command_cmp(irc_message, "PRIVMSG"))
    {
        if (irc_paramvec(irc_params(irc_message), irc_parvec) >= 2)
        {
            if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
                (irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
            {
                // send the signed message to the chat channel
                *irc << "PRIVMSG " << irc_parvec[0] << " :" << irc_parvec[1] << 
                    "~~~" << sec.sign(irc_parvec[1]) << std::endl <<std::flush;
            }
            else if (irc_parvec[0] == MAIN_CHANNEL)
            {
                for (m_ci_string ni = nick_players.begin();
					ni != nick_players.end(); ++ni)
                {
                    // First of all, send the announcement to each player.
                    *irc << "PRIVMSG " << ni->first << " :" << irc_parvec[1] << 
                        std::endl << std::flush;
                }
				// Additionally, send the announcement to the main channel,
				// because some IRC servers (e.g. freenode.net) may block
				// private messages of unregistered users.
                *irc << "PRIVMSG " << MAIN_CHANNEL << " :" << irc_parvec[1] << 
                    "~+~" << std::endl << std::flush;			
                // Finally, process the announcement PRIVMSG internally.
                size_t ti1 = irc_parvec[1].find("|", 0);
                size_t ti2 = irc_parvec[1].find("~", 0);
                size_t ti3 = irc_parvec[1].find("!", 0);
                if ((ti1 != irc_parvec[1].npos) &&
                    (ti2 != irc_parvec[1].npos) &&
                    (ti3 != irc_parvec[1].npos) && 
                    (ti1 < ti2) && (ti2 < ti3))
                {
                    std::string tm1 = irc_parvec[1].substr(0, ti1);
                    std::string tm2 = irc_parvec[1].substr(ti1 + 1, ti2-ti1-1);
                    std::string tm3 = irc_parvec[1].substr(ti2 + 1, ti3-ti2-1);	
                    if ((std::find(tables.begin(), tables.end(), tm1) ==
						tables.end()) && (tm2 != "0"))
                    {
                        // create a new table
                        tables.push_back(tm1);
                        tables_p[tm1] = atoi(tm2.c_str());
                        tables_r[tm1] = atoi(tm3.c_str());
                        tables_u[tm1] = tm3;
                        tables_o[tm1] = keyid;
                    }
                    else
                    {
                        if (tm2 == "0")
                        {
                            // remove a table
                            tables_p.erase(tm1);
							tables_r.erase(tm1);
                            tables_u.erase(tm1);
							tables_o.erase(tm1);
                            tables.remove(tm1);
                        }
                        else
                        {
                            // update a table
                            tables_p[tm1] = atoi(tm2.c_str());
                            tables_r[tm1] = atoi(tm3.c_str());
                            tables_u[tm1] = tm3;
                        }
                    }
                }
            }
            else
                *irc << irc_message << std::endl << std::flush;
        }
        else
            *irc << irc_message << std::endl << std::flush;
    }
    else
        *irc << irc_message << std::endl << std::flush;
}

bool irc_process
	(iosocketstream *irc, const std::string &irc_reply, bool &entry_ok,
	 bool &first_entry, bool &irc_stat, const std::string &keyid,
	 const std::string &public_prefix,
	 std::map<std::string, pid_t> &games_tnr2pid,
	 std::map<pid_t, int> &games_ipipe,
	 std::map<std::string, TMCG_PublicKey> &nick_key,
	 std::map<std::string, std::string> &nick_players,
	 std::map<std::string, int> &nick_sl,
	 std::map<std::string, int> &nick_p7771,
	 std::map<std::string, int> &nick_p7772,
	 std::map<std::string, int> &nick_p7773,
	 std::map<std::string, int> &nick_p7774,
	 std::map<std::string, std::string> &nick_package,
	 std::list<std::string> &tables,
	 std::map<std::string, int> &tables_r,
	 std::map<std::string, int> &tables_p,
	 std::map<std::string, std::string> &tables_u,
	 std::map<std::string, std::string> &tables_o)
{
	// parse NICK and HOST from IRC prefix
	std::string pfx = irc_prefix(irc_reply);
	std::string nick = "?", host = "?";
	if ((pfx.find("!", 0) != pfx.npos) && (pfx.find("@", 0) != pfx.npos))
	{
		nick = pfx.substr(0, pfx.find("!", 0));
		host = pfx.substr(pfx.find("@", 0) + 1, 
			pfx.length() - pfx.find("@", 0) - 1);
	}
				
	// process the IRC messages
	std::vector<std::string> irc_parvec;
	if (irc_command_cmp(irc_reply, "PING"))
	{
		*irc << "PONG " << irc_params(irc_reply) << std::endl << std::flush;
	} // USER success reply
	else if (irc_command_cmp(irc_reply, "001"))
	{
		entry_ok = true, first_entry = true;
	} // NICK and USER error replies
	else if (irc_command_cmp(irc_reply, "432") ||
		irc_command_cmp(irc_reply, "433") ||
		irc_command_cmp(irc_reply, "436") ||
		irc_command_cmp(irc_reply, "462") ||
		irc_command_cmp(irc_reply, "463") ||
		irc_command_cmp(irc_reply, "464") ||
		irc_command_cmp(irc_reply, "465") ||
		irc_command_cmp(irc_reply, "466") ||
		irc_command_cmp(irc_reply, "468"))
	{
		std::cerr << _("IRC ERROR: not registered at IRC server") << std::endl;
		std::cerr << irc_reply << std::endl;
		return false;
	}
	else if (irc_command_cmp(irc_reply, "JOIN"))
	{
		if (irc_paramvec(irc_params(irc_reply), irc_parvec) >= 1)
		{
			if (irc_parvec[0] == MAIN_CHANNEL)
			{
				if (nick.find(keyid, 0) == 0)
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
					{
						std::cout << X << _("observer") << " \"" << nick <<
							"\" (" << host << ") " << _("joins channel") <<
							" " << irc_parvec[0] << std::endl;
					}
				}
			}
			else if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
				(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
			{
				std::string tb = 
					irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
					irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
				if (nick.find(keyid, 0) == 0)
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
					std::cout << X << _("observer") << " \"" << nick << "\"" <<
						" (" << host << ") " << _("joins") << " " << tb <<
						std::endl;
				}
			}
		}
	}
	else if (irc_command_cmp(irc_reply, "471") ||
		irc_command_cmp(irc_reply, "473") ||
		irc_command_cmp(irc_reply, "474") ||
		irc_command_cmp(irc_reply, "403") ||
		irc_command_cmp(irc_reply, "405") ||
		irc_command_cmp(irc_reply, "475"))
	{
		std::cerr << _("IRC ERROR: join to channel failed") << std::endl;
		std::cerr << irc_reply << std::endl;
	}
	else if (irc_command_cmp(irc_reply, "PART"))
	{
		if (irc_paramvec(irc_params(irc_reply), irc_parvec) >= 1)
		{
			if (irc_parvec[0] == MAIN_CHANNEL)
			{
				if (nick.find(keyid, 0) == 0)
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
					{
						std::cout << X << _("player") << " \"" << nick <<
							"\" (" << host << ") " << _("leaves channel") <<
							" " << irc_parvec[0] << std::endl;
					}
				}
				else
				{
					if (irc_stat)
					{
						std::cout << X << _("observer") << " \"" << nick <<
							"\" (" << host << ") " << _("leaves channel") <<
							" " << irc_parvec[0] << std::endl;
					}
				}
			}
			else if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) && 
				(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
			{
				std::string tb = 
					irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
					irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
				if (nick.find(keyid, 0) == 0)
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
					std::cout << X << _("observer") << " \"" << nick << "\"" <<
						" (" << host << ") " << _("leaves") << " " << tb <<
						std::endl;
				}
			}
		}
	}
	else if (irc_command_cmp(irc_reply, "KICK"))
	{
		int pvs = irc_paramvec(irc_params(irc_reply), irc_parvec);
		if (pvs >= 2)
		{
			if (irc_parvec[0] == MAIN_CHANNEL)
			{
				if (irc_parvec[1].find(keyid, 0) == 0)
				{
					std::cout << X << _("you kicked from channel") << " " << 
						irc_parvec[0] << " " << _("by operator") << " " << 
						nick << std::endl;
					if (pvs == 3)
					{
						std::cout << X << _("reason") << ": " <<
							irc_parvec[2] << std::endl;
					}
					return false;
				}
				else if (irc_parvec[1].find(public_prefix, 0) == 0)
				{
					nick_players.erase(irc_parvec[1]), nick_sl.erase(nick);
					nick_p7771.erase(nick),	nick_p7772.erase(nick);
					nick_p7773.erase(nick),	nick_p7774.erase(nick);
					if (nick_key.find(irc_parvec[1]) != nick_key.end())
						host = nick_key[irc_parvec[1]].name;
					if (irc_stat)
					{
						std::cout << X << _("player") << " \"" << host <<
							"\" " << _("kicked from channel") << " " <<
							irc_parvec[0] << " " << _("by operator") << " " <<
							nick << std::endl;
					}
					if (irc_stat && (pvs == 3))
					{
						std::cout << X << _("reason") << ": " <<
							irc_parvec[2] << std::endl;
					}
				}
				else
				{
					if (irc_stat)
					{
						std::cout << X << _("observer") << " \"" << host <<
							"\" " << _("kicked from channel") << " " <<
							irc_parvec[0] << " " << _("by operator") << " " <<
							nick << std::endl;
					}
					if (irc_stat && (pvs == 3))
					{
						std::cout << X << _("reason") << ": " <<
							irc_parvec[2] << std::endl;
					}
				}
			}
			else if ((irc_parvec[0].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) &&
				(irc_parvec[0].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
			{
				std::string tb = 
					irc_parvec[0].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
					irc_parvec[0].length() - strlen(MAIN_CHANNEL_UNDERSCORE));
				if (irc_parvec[1].find(keyid, 0) == 0)
				{
					if (games_tnr2pid.find(tb) != games_tnr2pid.end())
					{
						opipestream *npipe = 
							new opipestream(games_ipipe[games_tnr2pid[tb]]);
						*npipe << "!KICK" << std::endl << std::flush;
						delete npipe;
					}
					std::cout << X << _("you kicked from") << " " << tb <<
						std::endl;
					if (pvs == 3)
					{
						std::cout << X << _("reason") << ": " <<
							irc_parvec[2] << std::endl;
					}
				}
				else if (irc_parvec[1].find(public_prefix, 0) == 0)
				{
					if (games_tnr2pid.find(tb) != games_tnr2pid.end())
					{
						opipestream *npipe = 
							new opipestream(games_ipipe[games_tnr2pid[tb]]);
						*npipe << "KICK " << irc_parvec[1] << std::endl <<
							std::flush;
						delete npipe;
					}
					if (nick_key.find(irc_parvec[1]) != nick_key.end())
						nick = nick_key[irc_parvec[1]].name;
					std::cout << X << _("player") << " \"" << nick << "\" " <<
						_("kicked from") << " " << tb << std::endl;
					if (pvs == 3)
					{
						std::cout << X << _("reason") << ": " <<
							irc_parvec[2] << std::endl;
					}
				}
				else
				{
					std::cout << X << _("observer") << " \"" << irc_parvec[1] << 
						"\" " << _("kicked from") << " " << tb << std::endl;
					if (pvs == 3)
					{
						std::cout << X << _("reason") << ": " <<
							irc_parvec[2] << std::endl;
					}
				}
			}
		}
	}
	else if (irc_command_cmp(irc_reply, "QUIT"))
	{
		if (nick.find(keyid, 0) == 0)
		{
			std::cout << X << _("you quit SecureSkat") << std::endl;
		}
		else if (nick.find(public_prefix, 0) == 0)
		{
			nick_players.erase(nick),nick_sl.erase(nick);
			nick_p7771.erase(nick), nick_p7772.erase(nick);
			nick_p7773.erase(nick), nick_p7774.erase(nick);
			for (m_ci_string_pid_t gi = games_tnr2pid.begin();
				gi != games_tnr2pid.end(); ++gi)
			{
				opipestream *npipe = 
					new opipestream(games_ipipe[gi->second]);
				*npipe << "QUIT " << nick << std::endl << std::flush;
				delete npipe;
			}
			if (nick_key.find(nick) != nick_key.end())
				nick = nick_key[nick].name;
			if (irc_stat)
			{
				std::cout << X << _("player") << " \"" << nick << "\" (" <<
					host << ") " << _("quits SecureSkat") << std::endl;
			}
		}
		else
		{
			if (irc_stat)
			{
				std::cout << X << _("observer") << " \"" << nick << "\" (" <<
					host << ") " << _("quits IRC client") << std::endl;
			}
		}
	}
	else if (irc_command_cmp(irc_reply, "352"))
	{
		if (irc_paramvec(irc_params(irc_reply), irc_parvec) >= 8)
		{
			if (irc_parvec[5] != keyid)
			{
				if (irc_parvec[1] == MAIN_CHANNEL)
				{
					if (irc_parvec[5].find(public_prefix, 0) == 0)
					{
						if ((irc_stat) && (irc_parvec[3] == "localhost"))
						{
							std::cerr << _("WARNING: host of player") <<
								" \"" << irc_parvec[5] << "\" " << 
								_("has unqualified domain (no FQDN)") <<
								std::endl;
						}
						std::string tmp = irc_parvec[7], package = "unknown";
						int p7771 = 0, p7772 = 0, p7773 = 0, p7774 = 0, sl = 0;
						std::string ahostname = "undefined";
						size_t a0 = tmp.find(" ", 0);
						size_t ai = tmp.find("|", 0), bi = tmp.find("~", 0);
						size_t ci = tmp.find("!", 0), di = tmp.find("#", 0);
						size_t ei = tmp.find("?", 0), fi = tmp.find("/", 0);
						size_t gi = tmp.find("*", 0);
						if ((a0 != tmp.npos) && (ai != tmp.npos) && 
							(bi != tmp.npos) && (ci != tmp.npos) && 
							(di != tmp.npos) && (ei != tmp.npos) && 
							(fi != tmp.npos) && (a0 < ai) && (ai < bi) && 
							(bi < ci) && (ci < di) && (di < ei) && (ei < fi))
						{
							package = tmp.substr(a0 + 1, ai - a0 - 1);
							std::string pt1 = tmp.substr(ai + 1, bi - ai - 1);
							std::string pt2 = tmp.substr(bi + 1, ci - bi - 1);
							std::string pt3 = tmp.substr(ci + 1, di - ci - 1);
							std::string pt4 = tmp.substr(di + 1, ei - di - 1);
							std::string slt = tmp.substr(ei + 1, fi - ei - 1);
							p7771 = atoi(pt1.c_str());
							p7772 = atoi(pt2.c_str());
							p7773 = atoi(pt3.c_str());
							p7774 = atoi(pt4.c_str());
							sl = atoi(slt.c_str());
							// exctract alternative hostname (e.g. onion address)
							if ((gi != tmp.npos) && (fi < gi))
								ahostname = tmp.substr(fi + 1, gi - fi - 1);
						}
						nick_package[irc_parvec[5]] = package;
						nick_p7771[irc_parvec[5]] = p7771;
						nick_p7772[irc_parvec[5]] = p7772;
						nick_p7773[irc_parvec[5]] = p7773;
						nick_p7774[irc_parvec[5]] = p7774;
						nick_sl[irc_parvec[5]] = sl;
#ifndef NDEBUG
std::cerr << "tmp (IRC realname) = " << tmp << std::endl;
std::cerr << "ahostname = " << ahostname << std::endl;
#endif
						if (ahostname == "undefined")
							nick_players[irc_parvec[5]] = irc_parvec[3];
						else
							nick_players[irc_parvec[5]] = ahostname;
						if (nick_key.find(irc_parvec[5]) != nick_key.end())
							irc_parvec[5] = nick_key[irc_parvec[5]].name;
						if (irc_stat)
						{
							std::cout << X << _("player") << " \"" <<
								irc_parvec[5] << "\" (" << irc_parvec[3] <<
								") " << _("is in channel") << " " <<
								irc_parvec[1] << std::endl;
						}
					}
					else
					{
						if (irc_stat)
						{
							std::cout << X << _("observer") << " \"" <<
								irc_parvec[5] << "\" (" << irc_parvec[3] <<
								") " << _("is in channel") << " " <<
								irc_parvec[1] << std::endl;
						}
					}
				}
				else if ((irc_parvec[1].find(MAIN_CHANNEL_UNDERSCORE, 0) == 0) &&
					(irc_parvec[1].length() > strlen(MAIN_CHANNEL_UNDERSCORE)))
				{
					std::string tb = 
						irc_parvec[1].substr(strlen(MAIN_CHANNEL_UNDERSCORE), 
						irc_parvec[1].length()-strlen(MAIN_CHANNEL_UNDERSCORE));
					if (irc_parvec[5].find(public_prefix, 0) == 0)
					{
						if (games_tnr2pid.find(tb) != games_tnr2pid.end())
						{
							opipestream *npipe = 
								new opipestream(games_ipipe[games_tnr2pid[tb]]);
							*npipe << "WHO " << irc_parvec[5] << std::endl <<
								std::flush;
							delete npipe;
						}
						if (nick_key.find(irc_parvec[5]) != nick_key.end())
							irc_parvec[5] = nick_key[irc_parvec[5]].name;
						if (irc_stat)
						{
							std::cout << X << _("player") << " \"" <<
								irc_parvec[5] << "\" (" << irc_parvec[3] <<
								") " << _("is at") << " " << irc_parvec[1] <<
								std::endl;
						}
					}
				}
			}
		}	
	} // MOTD start line and end line
	else if (irc_command_cmp(irc_reply, "375") ||
		irc_command_cmp(irc_reply, "376"))
	{
		std::cout << std::endl;
	} // MOTD text line
	else if (irc_command_cmp(irc_reply, "372"))
	{
		if (irc_paramvec(irc_params(irc_reply), irc_parvec) >= 2)
		{
			std::string tms = irc_parvec[1].substr(1, irc_parvec[1].length()-1);
			std::cout << X << tms << std::endl;
		}
	} // PRIVMSG
	else if (irc_command_cmp(irc_reply, "PRIVMSG"))
	{
		if (irc_paramvec(irc_params(irc_reply), irc_parvec) >= 2)
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
					std::string fullmsg = irc_parvec[1];
					size_t tei = fullmsg.find("~~~");
					if (tei != fullmsg.npos)
					{
						std::string realmsg = fullmsg.substr(0, tei);
						std::string sig = fullmsg.substr(tei + 3,
							fullmsg.length() - realmsg.length() - 3);
						if (nick_key.find(nick) != nick_key.end())
						{
							if (nick_key[nick].verify(realmsg, sig))
							{
								pid_t tp = games_tnr2pid[tb];
								opipestream *npipe =
									new opipestream(games_ipipe[tp]);
								*npipe << "MSG " << nick << " " << realmsg <<
									std::endl << std::flush;
								delete npipe;
							}
							else
							{
								std::cerr << _("TMCG: verify() failed") <<
									std::endl;
								std::cerr << "MSG: " << realmsg << std::endl;
								std::cerr << "SIG: " << sig << std::endl;
								std::cerr << "NICK: " << nick << std::endl;
							}
						}
						else
						{
							std::cerr << _("TMCG: no public key available") <<
								std::endl;
						}
					}
				}
			}
			// announce and no channel messages
			if (((irc_parvec[1].find("~+~") != irc_parvec[1].npos) &&
				(irc_parvec[0] == MAIN_CHANNEL)) ||
					((irc_parvec[0] != MAIN_CHANNEL) &&
						(nick.find(public_prefix, 0) == 0) &&
						((irc_parvec[0] == keyid) && (nick != keyid))))
			{
				size_t ti1 = irc_parvec[1].find("|", 0);
				size_t ti2 = irc_parvec[1].find("~", 0);
				size_t ti3 = irc_parvec[1].find("!", 0);
				if ((ti1 != irc_parvec[1].npos) &&
					(ti2 != irc_parvec[1].npos) &&
					(ti3 != irc_parvec[1].npos) && 
					(ti1 < ti2) && (ti2 < ti3))
				{
					std::string tm1 = irc_parvec[1].substr(0, ti1);
					std::string tm2 = irc_parvec[1].substr(ti1 + 1, ti2-ti1-1);
					std::string tm3 = irc_parvec[1].substr(ti2 + 1, ti3-ti2-1);	
					if ((std::find(tables.begin(), tables.end(), tm1) ==
						tables.end()) && (tm2 != "0"))
					{
						// new table
						tables.push_back(tm1);
						tables_p[tm1] = atoi(tm2.c_str());
						tables_r[tm1] = atoi(tm3.c_str());
						tables_u[tm1] = tm3;
						tables_o[tm1] = nick;
					}	
					else
					{
						// check ownership
						if (nick == tables_o[tm1])
						{
							if (tm2 == "0")
							{
								// remove table
								tables_p.erase(tm1);
								tables_r.erase(tm1);
								tables_u.erase(tm1);
								tables_o.erase(tm1);
								tables.remove(tm1);
							}
							else
							{
								// update table
								tables_p[tm1] = atoi(tm2.c_str());
								tables_r[tm1] = atoi(tm3.c_str());
								tables_u[tm1] = tm3;
							}
						}
						else
						{
							std::cout << XX << _("player") << " \"" << nick << 
								"\" (" << host << ") " << 
								_("announces unauthorized session") << " " <<
								tm1 << std::endl;
						}
					}
				}
				else if (irc_stat)
				{
					if (nick_key.find(nick) != nick_key.end())
						nick = nick_key[nick].name;
					std::cout << ">" << nick << "< " << irc_parvec[1] <<
						std::endl;
				}
			} // chat messages
			else if (irc_stat && (irc_parvec[0] == MAIN_CHANNEL))
			{
				std::string fullmsg = irc_parvec[1];
				size_t tei = fullmsg.find("~~~");
				if ((nick.find(public_prefix, 0) == 0) &&
					(nick_key.find(nick) != nick_key.end()) &&
					(tei != fullmsg.npos))
				{
					std::string realmsg = fullmsg.substr(0, tei);
					std::string sig = fullmsg.substr(tei + 3,
						fullmsg.length() - realmsg.length() - 3);
					if (nick_key[nick].verify(realmsg, sig))
					{
						nick = nick_key[nick].name;
						std::cout << "<" << nick << "> " << realmsg <<
							std::endl;
					}
					else
					{
						std::cerr << _("TMCG: verify() failed") << std::endl;
						std::cerr << "MSG: " << realmsg << std::endl;
						std::cerr << "SIG: " << sig << std::endl;
						std::cerr << "NICK: " << nick << std::endl;
					}
				}
				else
					std::cout << "<?" << nick << "?> " << fullmsg << std::endl;
			} // other messages
			else if (irc_stat && ((irc_parvec[0] == keyid) && (nick != keyid)))
			{
				std::cout << ">?" << nick << "?< " << irc_parvec[1] <<
					std::endl;
			}
		}
	}
	else if (irc_command_cmp(irc_reply, "NOTICE") || 
		irc_command_cmp(irc_reply, "020"))
	{
		if (irc_paramvec(irc_params(irc_reply), irc_parvec) >= 2)
		{
			std::cout << "[NOTICE] " << irc_parvec[1] << std::endl;
		}
	}
	else if (irc_command_cmp(irc_reply, "ERROR"))
	{
		std::cerr << "[ERROR] " << irc_reply << std::endl;
	}
	else
	{
		// unparsed IRC-message -- ignore it
//std::cerr << "[UNPARSED]" << irc_reply << std::endl;
	}
	return true;
}

void done_irc
	(iosocketstream *irc)
{
	// leave the main channel and send a QUIT message
	*irc << "PART " << MAIN_CHANNEL << std::endl << std::flush;
	*irc << "QUIT :SecureSkat rulez!" << std::endl << std::flush;	
}

void release_irc
	(int irc_handle, iosocketstream *irc)
{
	delete irc;
	CloseHandle(irc_handle);
}
