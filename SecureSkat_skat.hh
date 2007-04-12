/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2007  Heiko Stamer <stamer@gaos.org>

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_SecureSkat_skat_HH
    #define INCLUDED_SecureSkat_skat_HH
	
    #include "SecureSkat_defs.hh"
    #include "SecureSkat_misc.hh"
    #include "SecureSkat_game.hh"

    int skat_child
	(const std::string &nr, int r, bool neu, int ipipe, int opipe, 
	int hpipe, const std::string &master);
	
#endif
