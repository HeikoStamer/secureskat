/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2002-2004 Heiko Stamer, <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
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

#include "mpz_helper.hh"

// friendly iostream operators 
// FIXME: currently << and >> are insufficent defined by <gmpxx.h>
std::ostream& operator<< 
	(std::ostream &out, mpz_srcptr value)
{
	char *tmp = new char[10000];
	out << mpz_get_str(tmp, TMCG_MPZ_IO_BASE, value);
	delete [] tmp;
	return out;
}

std::istream& operator>> 
	(std::istream &in, mpz_ptr value)
{
	char *tmp = new char[10000];
	in.getline(tmp, 10000);
	if (mpz_set_str(value, tmp, TMCG_MPZ_IO_BASE) < 0)
		mpz_set_ui(value, 0L);
	delete [] tmp;
	return in;
}