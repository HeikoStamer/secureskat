/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004 Heiko Stamer, <stamer@gaos.org>

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

#ifndef INCLUDED_TMCG_PublicKey_HH
	#define INCLUDED_TMCG_PublicKey_HH

	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif

	// C++/STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <sstream>
	#include <iostream>
	#include <vector>
	
	// GNU multiple precision library
	#include <gmp.h>

	#include "mpz_srandom.h"
	#include "parse_helper.hh"

struct TMCG_PublicKey
{
	std::string						name, email, type, nizk, sig;
	mpz_t							m, y;
	
	TMCG_PublicKey
		();
	
	TMCG_PublicKey
		(const TMCG_SecretKey &skey);
	
	TMCG_PublicKey
		(std::string s);
	
	bool check
		() const;
	
	std::string selfid
		() const;
	
	std::string keyid
		() const;
	
	std::string sigid
		(std::string s) const;
	
	bool import
		(std::string s);
	
	std::string encrypt
		(const char *value) const;
	
	bool verify
		(const std::string &data, std::string s) const;
	
	~TMCG_PublicKey
		();
};

std::ostream& operator<< 
	(std::ostream &out, const TMCG_PublicKey &key)
{
	return out << "pub|" << key.name << "|" << key.email << "|" << key.type <<
		"|" << key.m << "|" << key.y << "|" << key.nizk << "|" << key.sig;
}

#endif
