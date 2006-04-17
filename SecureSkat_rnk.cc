/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2006  Heiko Stamer <stamer@gaos.org>

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
	rnk7773_port = BindEmptyPort(7771);
	if ((rnk7773_handle = ListenToPort(rnk7773_port)) < 0)
		exit(-1);
	rnk7774_port = BindEmptyPort(7771);
	if ((rnk7774_handle = ListenToPort(rnk7774_port)) < 0)
		exit(-1);
}

void release_rnk
	(int rnk7773_handle, int rnk7774_handle)
{
	CloseHandle(rnk7773_handle);
	CloseHandle(rnk7774_handle);
}
