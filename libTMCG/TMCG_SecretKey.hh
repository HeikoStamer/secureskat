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

#ifndef INCLUDED_TMCG_SecretKey_HH
	#define INCLUDED_TMCG_SecretKey_HH

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
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "TMCG.def"
	
	#include "mpz_srandom.h"
	#include "mpz_sqrtm.h"
	#include "mpz_helper.hh"
	#include "parse_helper.hh"
	#include "mpz_shash.hh"

struct TMCG_SecretKey
{
	std::string				name, email, type, nizk, sig;
	mpz_t							m, y, p, q;
	// below this line are non-persistent values (pre-computation)
	mpz_t							y1, m1pq, gcdext_up, gcdext_vq, pa1d4, qa1d4;
	int								ret;
	char							encval[rabin_s0];
	
	TMCG_SecretKey
		();
	
	TMCG_SecretKey
		(unsigned long int keysize, const std::string &n, const std::string &e);
	
	TMCG_SecretKey
		(const std::string& s);
	
	TMCG_SecretKey
		(const TMCG_SecretKey& that);
	
	TMCG_SecretKey& operator =
		(const TMCG_SecretKey& that);
	
	void precompute
		();
	
	bool import
		(std::string s);
	
	bool check
		() const;
	
	std::string selfid
		() const;
	
	std::string keyid
		() const;
	
	std::string sigid
		(std::string s) const;
	
	const char* decrypt
		(std::string value) const;
	
	std::string sign
		(const std::string &data) const;
	
	std::string encrypt
		(const char *value) const;
	
	bool verify
		(const std::string &data, std::string s) const;
	
	~TMCG_SecretKey
		();
};

std::ostream& operator<< 
	(std::ostream &out, const TMCG_SecretKey &key);

#endif
