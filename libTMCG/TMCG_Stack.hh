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

#ifndef INCLUDED_TMCG_Stack_HH
	#define INCLUDED_TMCG_Stack_HH

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

template <typename CardType> struct TMCG_OpenStack;			// forward

template <typename CardType> struct TMCG_Stack
{
	std::vector<CardType>	stack;
	
	TMCG_Stack
		();
	
	TMCG_Stack& operator =
		(const TMCG_Stack& that);
	
	bool operator ==
		(const TMCG_Stack& that);
	
	bool operator !=
		(const TMCG_Stack& that);
	
	const CardType& operator []
		(size_t n) const;
	
	CardType& operator []
		(size_t n);
	
	size_t size
		() const;
	
	void push
		(const CardType& c);
	
	void push
		(const TMCG_Stack& s);
	
	void push
		(const TMCG_OpenStack<CardType>& s);
	
	bool pop
		(CardType& c);
	
	void clear
		();
	
	bool find
		(const CardType& c) const;
	
	bool remove
		(const CardType& c);
	
	size_t removeAll
		(const CardType& c);
	
	bool import
		(std::string s);
	
	~TMCG_Stack
		();
};

template<typename CardType> std::ostream& operator<<
	(std::ostream &out, const TMCG_Stack<CardType> &s);

#endif
