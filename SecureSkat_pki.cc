/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004 Heiko Stamer, <stamer@gaos.org>

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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include "SecureSkat_pki.hh"

void get_secret_key
	(const std::string &filename, TMCG_SecretKey &sec, std::string &prefix)
{
	std::ostringstream ost;
	datum key, data;
	GDBM_FILE sec_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (sec_db != NULL)
	{
		key = gdbm_firstkey(sec_db);
		if (key.dptr)
		{
			data = gdbm_fetch(sec_db, key);
			ost << data.dptr;
			free(data.dptr);
			free(key.dptr);
		}
		else
		{
			std::string name, email, keyid, osttmp;
			std::cout << _("Your nickname") << ": ";
			std::getline(std::cin, name);
			std::cout << _("Your electronic mail address") << ": ";
			std::getline(std::cin, email);
			while (1)
			{
				TMCG_SecretKey tmpsec(name, email);
				if (tmpsec.check())
				{
					sec = tmpsec;
					break;
				}
				else
					std::cerr << "." << std::flush;
			}
			ost << sec;
			keyid = sec.keyid();
			key.dptr = (char*)keyid.c_str();
			key.dsize = keyid.length() + 1;
			osttmp = ost.str();
			data.dptr = (char*)osttmp.c_str();
			data.dsize = osttmp.length() + 1;
			gdbm_store(sec_db, key, data, GDBM_INSERT);
			std::cout << _("PKI: cryptographic key") << " \"" << keyid <<
				"\" " << _("created and stored") << std::endl;
		}
		gdbm_close(sec_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_pki::get_secret_key (gdbm_open)");
		exit(-1);
	}
	
	if (!sec.import(ost.str()))
	{
		std::cerr << _("PKI ERROR: secret key corrupted") << std::endl;
		exit(-1);
	}
	
	prefix = sec.keyid();
	size_t ei = prefix.find("^", 0);
	if (ei == prefix.npos)
	{
		std::cerr << _("PKI ERROR: identification prefix unknown") << std::endl;
		exit(-1);
	}
	else
		prefix = prefix.substr(0, ei + 1);
}

void get_public_keys
	(const std::string &filename, std::map<std::string, TMCG_PublicKey> &keys)
{
	datum key, nextkey, data;
	GDBM_FILE pub_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (pub_db != NULL)
	{
		key = gdbm_firstkey(pub_db);
		while (key.dptr)
		{
			TMCG_PublicKey pkey;
			data = gdbm_fetch(pub_db, key);
			if (pkey.import(data.dptr))
				keys[key.dptr] = pkey;
			else
				std::cerr << _("PKI ERROR: public key corrupted") <<
					std::endl;
			nextkey = gdbm_nextkey(pub_db, key);
			free(data.dptr);
			free(key.dptr);
			key = nextkey;
		}
		gdbm_close(pub_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_pki::get_public_keys (gdbm_open)");
		exit(-1);
	}
}

void set_public_keys
	(const std::string &filename,
	const std::map<std::string, TMCG_PublicKey> &keys)
{
	datum key, data;
	GDBM_FILE pub_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (pub_db != NULL)
	{
		for (std::map<std::string, TMCG_PublicKey>::const_iterator
			pi = keys.begin(); pi != keys.end(); pi++)
		{
			key.dptr = (char*)(pi->first).c_str();
			key.dsize = (pi->first).length() + 1;
			if (!gdbm_exists(pub_db, key))
			{
				std::ostringstream ost;
				ost << pi->second;
				std::string osttmp = ost.str();
				data.dptr = (char*)osttmp.c_str();
				data.dsize = osttmp.length() + 1;
				gdbm_store(pub_db, key, data, GDBM_INSERT);
			}
		}
		gdbm_close(pub_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_pki::set_public_keys (gdbm_open)");
		exit(-1);
	}
}

void create_pki
	(int &pki7771_port, int &pki7771_handle)
{
	long socket_option = 1;
	struct sockaddr_in sin7771;
	sin7771.sin_addr.s_addr = htonl(INADDR_ANY);
	sin7771.sin_family = AF_INET;
	
	if ((pki7771_handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_pki::create_pki (socket)");
		exit(-1);
	}
	if (setsockopt(pki7771_handle, SOL_SOCKET, SO_REUSEADDR, &socket_option,
		sizeof(socket_option)) < 0)
	{
		perror("SecureSkat_pki::create_pki (setsockopt)");
		exit(-1);
	}
	pki7771_port = BindEmptyPort(7771);
	sin7771.sin_port = htons(pki7771_port);
	if (bind(pki7771_handle, (struct sockaddr*)&sin7771, sizeof(sin7771)) < 0)
	{
		perror("SecureSkat_pki::create_pki (bind)");
		exit(-1);
	}
	if (listen(pki7771_handle, SOMAXCONN) < 0)
	{
		perror("SecureSkat_pki::create_pki (listen)");
		exit(-1);
	}
}

void release_pki
	(int pki7771_handle)
{
	if (close(pki7771_handle) < 0)
		perror("SecureSkat_pki::release_pki (close)");
}
