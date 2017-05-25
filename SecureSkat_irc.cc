/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2009, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
