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

#include "TMCG_CardSecret.hh"

TMCG_CardSecret::TMCG_CardSecret
	()
{
	for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
		for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
			mpz_init(r[k][w]), mpz_init(b[k][w]);
}

TMCG_CardSecret::TMCG_CardSecret
	(const TMCG_CardSecret& that) :
	Players(that.Players), TypeBits(that.TypeBits)
{
	for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
		for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
			mpz_init_set(r[k][w], that.r[k][w]),
			mpz_init_set(b[k][w], that.b[k][w]);
}

TMCG_CardSecret& TMCG_CardSecret::operator =
	(const TMCG_CardSecret& that)
{
	Players = that.Players, TypeBits = that.TypeBits;
	for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
		for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
			mpz_set(r[k][w], that.r[k][w]), mpz_set(b[k][w], that.b[k][w]);
	return *this;
}

bool TMCG_CardSecret::import
	(std::string s)
{
	char *ec;
	
	try
	{
		// check magic
		if (!cm(s, "crs", '|'))
			throw false;
		
		// public card data
		if (gs(s, '|').length() == 0)
			throw false;
		Players = strtoul(gs(s, '|').c_str(), &ec, 10);
		if ((*ec != '\0') || (Players <= 0) ||
			(Players > TMCG_MAX_PLAYERS) || (!nx(s, '|')))
				throw false;
		if (gs(s, '|').length() == 0)
			throw false;
		TypeBits = strtoul(gs(s, '|').c_str(), &ec, 10);
		if ((*ec != '\0') || (TypeBits <= 0) ||
			(TypeBits > TMCG_MAX_TYPEBITS) || (!nx(s, '|')))
				throw false;
		
		// secret card data
		for (size_t k = 0; k < Players; k++)
		{
			for (size_t w = 0; w < TypeBits; w++)
			{
				// r_ij
				if ((mpz_set_str(r[k][w], gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
					(!nx(s, '|')))
						throw false;
						
				// b_ij
				if ((mpz_set_str(b[k][w], gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
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

TMCG_CardSecret::~TMCG_CardSecret
	()
{
	for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
		for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
			mpz_clear(r[k][w]), mpz_clear(b[k][w]);
}

std::ostream& operator<< 
	(std::ostream &out, const TMCG_CardSecret &cardsecret)
{
	out << "crs|" << cardsecret.Players << "|" << cardsecret.TypeBits << "|";
	for (size_t k = 0; k < cardsecret.Players; k++)
		for (size_t w = 0; w < cardsecret.TypeBits; w++)
			out << cardsecret.r[k][w] << "|" << cardsecret.b[k][w] << "|";
	return out;
}
