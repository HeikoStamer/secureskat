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

#include "SecureSkat_rnk.hh"

void load_rnk
	(const std::string &filename, std::map<std::string, std::string> &rnk)
{
	datum key, nextkey, data;
	GDBM_FILE rnk_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (rnk_db != NULL)
	{
		key = gdbm_firstkey(rnk_db);
		while (key.dptr)
		{
			data = gdbm_fetch(rnk_db, key);
			rnk[key.dptr] = data.dptr;
			nextkey = gdbm_nextkey(rnk_db, key);
			free(data.dptr);
			free(key.dptr);
			key = nextkey;
		}
		gdbm_close(rnk_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_rnk::load_rnk (gdbm_open)");
		exit(-1);
	}
}

void save_rnk
	(const std::string &filename, std::map<std::string, std::string> rnk)
{
	datum key, data;
	GDBM_FILE rnk_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (rnk_db != NULL)
	{	
		for (std::map<std::string, std::string>::iterator pi = rnk.begin();
			pi != rnk.end(); pi++)
		{
			std::string rnk_id = pi->first, rnk_data = pi->second;
			key.dptr = (char*)rnk_id.c_str();
			key.dsize = rnk_id.length() + 1;
			if (!gdbm_exists(rnk_db, key))
			{
				data.dptr = (char*)rnk_data.c_str();
				data.dsize = rnk_data.length() + 1;
				gdbm_store(rnk_db, key, data, GDBM_INSERT);
			}
		}
		gdbm_close(rnk_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_rnk::save_rnk (gdbm_open)");
		exit(-1);
	}
}

void create_rnk
	(int &rnk7773_port, int &rnk7774_port,
	int &rnk7773_handle, int &rnk7774_handle)
{
	long socket_option = 1;
	struct sockaddr_in sin7773;
	sin7773.sin_addr.s_addr = htonl(INADDR_ANY);
	sin7773.sin_family = AF_INET;
	struct sockaddr_in sin7774;
	sin7774.sin_addr.s_addr = htonl(INADDR_ANY);
	sin7774.sin_family = AF_INET;
	
	if ((rnk7773_handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (socket)");
		exit(-1);
	}
	if (setsockopt(rnk7773_handle, SOL_SOCKET, SO_REUSEADDR, &socket_option,
		sizeof(socket_option)) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (setsockopt)");
		exit(-1);
	}
	rnk7773_port = BindEmptyPort(7771);
	sin7773.sin_port = htons(rnk7773_port);
	if (bind(rnk7773_handle, (struct sockaddr*)&sin7773, sizeof(sin7773)) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (bind)");
		exit(-1);
	}
	if (listen(rnk7773_handle, SOMAXCONN) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (listen)");
		exit(-1);
	}
	if ((rnk7774_handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (socket)");
		exit(-1);
	}
	if (setsockopt(rnk7774_handle, SOL_SOCKET, SO_REUSEADDR, &socket_option,
		sizeof(socket_option)) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (setsockopt)");
		exit(-1);
	}
	rnk7774_port = BindEmptyPort(7771);
	sin7774.sin_port = htons(rnk7774_port);	
	if (bind(rnk7774_handle, (struct sockaddr*)&sin7774, sizeof(sin7774)) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (bind)");
		exit(-1);
	}
	if (listen(rnk7774_handle, SOMAXCONN) < 0)
	{
		perror("SecureSkat_rnk::create_rnk (listen)");
		exit(-1);
	}
}

void release_rnk
	(int rnk7773_handle, int rnk7774_handle)
{
	if (close(rnk7773_handle) < 0)
		perror("SecureSkat_rnk::release_rnk (close)");
	if (close(rnk7774_handle) < 0)
		perror("SecureSkat_rnk::release_rnk (close)");
}
