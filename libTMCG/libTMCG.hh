/*******************************************************************************
   libTMCG.hh, general header of the |T|oolbox for |M|ental |C|ard |G|ames

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

#ifndef INCLUDED_libTMCG_HH
	#define INCLUDED_libTMCG_HH

	#ifndef LIBGCRYPT_VERSION
		/* Define appropriate version number of libgcrypt */
		#define LIBGCRYPT_VERSION "1.2.0"
	#endif

	#ifndef TMCG_MPZ_IO_BASE
		/* Define input/ouput base encoding of iostream operators */
		#define TMCG_MPZ_IO_BASE 36
	#endif
	
	#ifndef TMCG_GCRY_MD_ALGO
		/* Define message digest algorithm for signatures and FS-heuristic */
		#define TMCG_GCRY_MD_ALGO GCRY_MD_RMD160
	#endif

	#include <VTMF_Card.hh>
	#include <VTMF_CardSecret.hh>
	#include <TMCG_Card.hh>
	#include <TMCG_CardSecret.hh>
	template <typename CardType> struct TMCG_OpenStack;
	#include <TMCG_Stack.hh>
	#include <TMCG_OpenStack.hh>
	#include <TMCG_StackSecret.hh>
	
	#include <SchindelhauerTMCG.hh>
#endif
