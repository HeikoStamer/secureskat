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

#include "TMCG_StackSecret.hh"

TMCG_StackSecret::TMCG_StackSecret
	()
{
}

TMCG_StackSecret& TMCG_StackSecret::operator =
	(const TMCG_StackSecret<CardSecretType>& that)
{
	stack.clear();
	stack = that.stack;
	return *this;
}

const std::pair<size_t, CardSecretType>& TMCG_StackSecret::operator []
	(size_t n) const
{
	return stack[n];
}

std::pair<size_t, CardSecretType>& TMCG_StackSecret::operator []
	(size_t n)
{
	return stack[n];
}

size_t TMCG_StackSecret::size
	() const
{
	return stack.size();
}

void TMCG_StackSecret::push
	(size_t index, const CardSecretType& cs)
{
	stack.push_back(std::pair<size_t, CardSecretType>(index, cs));
}

void TMCG_StackSecret::clear
	()
{
	stack.clear();
}

bool TMCG_StackSecret::find
	(size_t index)
{
	return (std::find_if(stack.begin(), stack.end(),
		std::bind2nd(eq_first_component(),
			std::pair<size_t, CardSecretType>(index, CardSecretType())))
				!= stack.end());
}

bool TMCG_StackSecret::import
	(std::string s)
{
	size_t size = 0;
	char *ec;
	
	try
	{
		// check magic
		if (!cm(s, "sts", '^'))
			throw false;
		
		// size of stack
		if (gs(s, '^') == NULL)
			throw false;
		size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (size <= 0) || (!nx(s, '^')))
			throw false;
		
		// cards on stack
		for (size_t i = 0; i < size; i++)
		{
			std::pair<size_t, CardSecretType> lej;
			
			// permutation index
			if (gs(s, '^') == NULL)
				throw false;
			lej.first = (size_t)strtoul(gs(s, '^'), &ec, 10);
			if ((*ec != '\0') || (lej.first < 0) || (lej.first >= size) ||
				(!nx(s, '^')))
					throw false;
			
			// card secret
			if (gs(s, '^') == NULL)
				throw false;
			if ((!lej.second.import(gs(s, '^'))) || (!nx(s, '^')))
				throw false;
			
			// store pair
			stack.push_back(lej);
		}
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

TMCG_StackSecret::~TMCG_StackSecret
	()
{
	stack.clear();
}

template<typename CardSecretType> std::ostream& operator<<
	(std::ostream &out, const TMCG_StackSecret<CardSecretType> &ss)
{
	out << "sts^" << ss.size() << "^";
	for (size_t i = 0; i < ss.size(); i++)
		out << ss[i].first << "^" << ss[i].second << "^";
	return out;
}
