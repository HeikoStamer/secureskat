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

#ifndef INCLUDED_SecureSkat_rnk_HH
	#define INCLUDED_SecureSkat_rnk_HH
	
	// autoconf header
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <cstdio>
	#include <unistd.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <sys/socket.h>
	#include <sys/stat.h>
	#include <gdbm.h>
	#include <clocale>
	#include <libintl.h>
	
	#include <string>
	#include <iostream>
	#include <map>
	
	#include "SecureSkat_misc.hh"
	
	#ifdef ENABLE_NLS
		#define _(String) gettext(String)
	#else
		#define _(String) String
	#endif
	
	void load_rnk
		(const std::string &filename, std::map<std::string, std::string> &rnk);
	void save_rnk
		(const std::string &filename, std::map<std::string, std::string> rnk);
	void create_rnk
		(int &rnk7773_port, int &rnk7774_port,
		int &rnk7773_handle, int &rnk7774_handle);
	void release_rnk
		(int rnk7773_handle, int rnk7774_handle);
#endif
