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

#ifndef INCLUDED_TMCG_OpenStack_HH
	#define INCLUDED_TMCG_OpenStack_HH

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
	
	#include "TMCG.def"

template <typename CardType> struct TMCG_OpenStack
{
	std::vector<std::pair<size_t, CardType> >	stack;
	
	struct eq_first_component : public std::binary_function<
		std::pair<size_t, CardType>, std::pair<size_t, CardType>, bool>
	{
		bool operator() 
			(const std::pair<size_t, CardType>& p1, 
			const std::pair<size_t, CardType>& p2) const
		{
			return (p1.first == p2.first);
		}
	};
	
	TMCG_OpenStack
		();
	
	TMCG_OpenStack& operator =
		(const TMCG_OpenStack& that);
	
	bool operator ==
		(const TMCG_OpenStack& that);
	
	bool operator !=
		(const TMCG_OpenStack& that);
	
	const std::pair<size_t, CardType>& operator []
		(size_t n) const;
	
	std::pair<size_t, CardType>& operator []
		(size_t n);
	
	size_t size
		() const;
	
	void push
		(size_t type, const CardType& c);
	
	void push
		(const TMCG_OpenStack& s);
	
	size_t pop
		(CardType& c);
	
	void clear
		();
	
	bool find
		(size_t type) const;
	
	bool remove
		(size_t type);
	
	size_t removeAll
		(size_t type);
	
	bool move
		(size_t type, TMCG_Stack<CardType>& s);
	
	~TMCG_OpenStack
		();
};

#endif
