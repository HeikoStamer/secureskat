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

#ifndef INCLUDED_SecureSkat_pki_HH
	#define INCLUDED_SecureSkat_pki_HH
	
	// autoconf header
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <cstdio>
	#include <unistd.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <sys/socket.h>
	#include <sys/stat.h>
	#include <clocale>
	#include <libintl.h>
	
	#include <string>
	#include <sstream>
	#include <map>
	
	#include <gdbm.h>
	#include <gcrypt.h>
	#include <termios.h>
	
	#include <libTMCG.hh>
	#include "SecureSkat_misc.hh"
	
	#ifdef ENABLE_NLS
		#define _(String) gettext(String)
	#else
		#define _(String) String
	#endif
	
	void get_secret_key
		(const std::string &filename, TMCG_SecretKey &sec, std::string &prefix);
	void get_public_keys
		(const std::string &filename,
		std::map<std::string, TMCG_PublicKey> &keys);
	void set_public_keys
		(const std::string &filename,
		const std::map<std::string, TMCG_PublicKey> &keys);
	void create_pki
		(int &pki7771_port, int &pki7771_handle);
	void release_pki
		(int pki7771_handle);
#endif
