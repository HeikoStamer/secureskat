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

#ifndef INCLUDED_TMCG_Card_HH
	#define INCLUDED_TMCG_Card_HH

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
	#include <algorithm>
	#include <functional>
	
	// GNU multiple precision library
	#include <gmp.h>

	#include "mpz_srandom.h"
	#include "parse_helper.hh"

struct TMCG_Card
{
	size_t					Players, TypeBits;
	mpz_t					z[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS];
	
	TMCG_Card
		()
	{
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_init(z[k][w]);
	}
	
	TMCG_Card
		(const TMCG_Card& that) :
		Players(that.Players), TypeBits(that.TypeBits)
	{
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_init_set(z[k][w], that.z[k][w]);
	}
	
	TMCG_Card& operator =
		(const TMCG_Card& that)
	{
		Players = that.Players, TypeBits = that.TypeBits;
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_set(z[k][w], that.z[k][w]);
		return *this;
	}
	
	bool operator ==
		(const TMCG_Card& that)
	{
		if ((Players != that.Players) || (TypeBits != that.TypeBits))
			return false;
		for (size_t k = 0; k < Players; k++)
			for (size_t w = 0; w < TypeBits; w++)
				if (mpz_cmp(z[k][w], that.z[k][w]))
					return false;
		return true;
	}
	
	bool operator !=
		(const TMCG_Card& that)
	{
		return !(*this == that);
	}
	
	bool import
		(string s)
	{
		char *ec;
		
		try
		{
			// check magic
			if (!cm(s, "crd", '|'))
				throw false;
			
			// card description
			if (gs(s, '|') == NULL)
				throw false;
			Players = strtoul(gs(s, '|'), &ec, 10);
			if ((*ec != '\0') || (Players <= 0) ||
				(Players > TMCG_MAX_PLAYERS) || (!nx(s, '|')))
					throw false;
			if (gs(s, '|') == NULL)
				throw false;
			TypeBits = strtoul(gs(s, '|'), &ec, 10);
			if ((*ec != '\0') || (TypeBits <= 0) ||
				(TypeBits > TMCG_MAX_TYPEBITS) || (!nx(s, '|')))
					throw false;
			
			// card data
			for (size_t k = 0; k < Players; k++)
			{
				for (size_t w = 0; w < TypeBits; w++)
				{
					// z_ij
					if ((mpz_set_str(z[k][w], gs(s, '|'), TMCG_MPZ_IO_BASE) < 0) ||
						(!nx(s, '|')))
							throw false;
				}
			}
			throw true;
		}
		catch (bool return_value)
		{
			return return_value;
		}
	}
	
	~TMCG_Card
		()
	{
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_clear(z[k][w]);
	}
};

friend ostream& operator<< 
	(ostream &out, const TMCG_Card &card)
{
	out << "crd|" << card.Players << "|" << card.TypeBits << "|";
	for (size_t k = 0; k < card.Players; k++)
		for (size_t w = 0; w < card.TypeBits; w++)
			out << card.z[k][w] << "|";
	return out;
}

#endif
