/*******************************************************************************
   SchindelhauerTMCG.hh, cryptographic |T|oolbox for |M|ental |C|ard |G|ames

     Christian Schindelhauer: 'A Toolbox for Mental Card Games',
     Medizinische Universit\"at L\"ubeck, 17. September 1998

     Rosario Gennaro, Daniele Micciancio, Tal Rabin: 
     'An Efficient Non-Interactive Statistical Zero-Knowledge 
     Proof System for Quasi-Safe Prime Products', 1997

     Mihir Bellare, Phillip Rogaway: 'The Exact Security of Digital
     Signatures -- How to Sign with RSA and Rabin', 1996

     Dan Boneh: 'Simplified OAEP for the RSA and Rabin Functions', 2002

 Copyright (C) 2002, 2003, 2004 Heiko Stamer, <stamer@gaos.org>

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

#ifndef INCLUDED_SchindelhauerTMCG_HH
	#define INCLUDED_SchindelhauerTMCG_HH

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
	
	// GNU crypto library
	#include <gcrypt.h> 
	
	// GNU multiple precision library
	#include <gmp.h>

#include "TMCG.def"

#include <TMCG_SecretKey.hh>
#include <TMCG_PublicKey.hh>
#include <TMCG_PublicKeyRing.hh>
#include <VTMF_Card.hh>
#include <VTMF_CardSecret.hh>
#include <TMCG_Card.hh>
#include <TMCG_CardSecret.hh>
template <typename CardType> struct TMCG_OpenStack;
#include <TMCG_Stack.hh>
#include <TMCG_OpenStack.hh>
#include <TMCG_StackSecret.hh>

#include "BarnettSmartVTMF_dlog.hh"
#include "mpz_srandom.h"

class SchindelhauerTMCG
{
	private:
		int										ret;
	
	public:
		unsigned long int		TMCG_SecurityLevel;			// iterations
		size_t					TMCG_Players, TMCG_TypeBits, TMCG_MaxCardType;
		
		SchindelhauerTMCG 
			(unsigned long int security, size_t players, size_t typebits)
		{
			assert(players <= TMCG_MAX_PLAYERS);
			assert(typebits <= TMCG_MAX_TYPEBITS);
			
			TMCG_SecurityLevel = security;
			TMCG_Players = players, TMCG_TypeBits = typebits, TMCG_MaxCardType = 1;
			for (unsigned long int i = 0; i < TMCG_TypeBits; i++)
				TMCG_MaxCardType *= 2;
			
			if (!gcry_check_version(LIBGCRYPT_VERSION))
			{
				std::cerr << "libgcrypt: need library version >= " <<
					LIBGCRYPT_VERSION << std::endl;
				exit(-1);
			}
			gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
			gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
			if (gcry_md_test_algo(TMCG_GCRY_MD_ALGO))
			{
				std::cerr << "libgcrypt: algorithm " << TMCG_GCRY_MD_ALGO <<
					" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) <<
					"] not available" << std::endl;
				exit(-1);
			}
		}
		
		// zero-knowledge proofs on values
		void TMCG_ProofQuadraticResidue
			(const TMCG_SecretKey &key, mpz_srcptr t,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyQuadraticResidue
			(const TMCG_PublicKey &key, mpz_srcptr t,
			std::istream &in, std::ostream &out);
		void TMCG_ProofNonQuadraticResidue
			(const TMCG_SecretKey &key, mpz_srcptr t, std::istream &in, std::ostream &out);
		bool TMCG_VerifyNonQuadraticResidue
			(const TMCG_PublicKey &key, mpz_srcptr t, std::istream &in, std::ostream &out);
		void TMCG_ProofMaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz, mpz_srcptr r,
			mpz_srcptr b, std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz,
			std::istream &in, std::ostream &out);
		void TMCG_ProofMaskOne
			(const TMCG_PublicKey &key, mpz_srcptr r, mpz_srcptr b,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskOne
			(const TMCG_PublicKey &key, mpz_srcptr t, std::istream &in, std::ostream &out);
		void TMCG_ProofNonQuadraticResidue_PerfectZeroKnowledge
			(const TMCG_SecretKey &key, std::istream &in, std::ostream &out);
		bool TMCG_VerifyNonQuadraticResidue_PerfectZeroKnowledge
			(const TMCG_PublicKey &key, std::istream &in, std::ostream &out);
		
		// operations on values
		void TMCG_MaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_ptr zz,
			mpz_srcptr r, mpz_srcptr b);
		
		// operations and proofs on cards
		void TMCG_CreateOpenCard
			(TMCG_Card &c, const TMCG_PublicKeyRing &ring, size_t type);
		void TMCG_CreateOpenCard
			(VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf, size_t type);
		void TMCG_CreatePrivateCard
			(TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
			size_t index, size_t type);
		void TMCG_CreatePrivateCard
			(VTMF_Card &c, VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf,
			size_t type);
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring, size_t index);
		void TMCG_CreateCardSecret
			(VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, mpz_srcptr r, unsigned long int b);
		void TMCG_MaskCard
			(const TMCG_Card &c, TMCG_Card &cc, const TMCG_CardSecret &cs,
			const TMCG_PublicKeyRing &ring);
		void TMCG_MaskCard
			(const VTMF_Card &c, VTMF_Card &cc, const VTMF_CardSecret &cs,
			BarnettSmartVTMF_dlog *vtmf);
		void TMCG_ProofMaskCard
			(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_CardSecret &cs,
			const TMCG_PublicKeyRing &ring, std::istream &in, std::ostream &out);
		void TMCG_ProofMaskCard
			(const VTMF_Card &c, const VTMF_Card &cc, const VTMF_CardSecret &cs,
			BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskCard
			(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_PublicKeyRing &ring,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskCard
			(const VTMF_Card &c, const VTMF_Card &cc, BarnettSmartVTMF_dlog *vtmf,
			std::istream &in, std::ostream &out);
		void TMCG_ProofPrivateCard
			(const TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyPrivateCard
			(const TMCG_Card &c, const TMCG_PublicKeyRing &ring,
			std::istream &in, std::ostream &out);
		void TMCG_ProofCardSecret
			(const TMCG_Card &c, const TMCG_SecretKey &key, size_t index,
			std::istream &in, std::ostream &out);
		void TMCG_ProofCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyCardSecret
			(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKey &key,
			size_t index, std::istream &in, std::ostream &out);
		bool TMCG_VerifyCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
			std::istream &in, std::ostream &out);
		void TMCG_SelfCardSecret
			(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_SecretKey &key,
			size_t index);
		void TMCG_SelfCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf);
		size_t TMCG_TypeOfCard
			(const TMCG_CardSecret &cs);
		size_t TMCG_TypeOfCard
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf);
		
		// operations and proofs on stacks
		size_t TMCG_CreateStackSecret
			(TMCG_StackSecret<TMCG_CardSecret> &ss, bool cyclic,
			const TMCG_PublicKeyRing &ring, size_t index, size_t size);
		size_t TMCG_CreateStackSecret
			(TMCG_StackSecret<VTMF_CardSecret> &ss, bool cyclic, size_t size,
			BarnettSmartVTMF_dlog *vtmf);
		void TMCG_MixStack
			(const TMCG_Stack<TMCG_Card> &s, TMCG_Stack<TMCG_Card> &s2,
			const TMCG_StackSecret<TMCG_CardSecret> &ss, const TMCG_PublicKeyRing &ring);
		void TMCG_MixStack
			(const TMCG_Stack<VTMF_Card> &s, TMCG_Stack<VTMF_Card> &s2,
			const TMCG_StackSecret<VTMF_CardSecret> &ss, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_GlueStackSecret
			(const TMCG_StackSecret<TMCG_CardSecret> &sigma,
			TMCG_StackSecret<TMCG_CardSecret> &pi, const TMCG_PublicKeyRing &ring);
		void TMCG_GlueStackSecret
			(const TMCG_StackSecret<VTMF_CardSecret> &sigma,
			TMCG_StackSecret<VTMF_CardSecret> &pi, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_ProofStackEquality
			(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2,
			const TMCG_StackSecret<TMCG_CardSecret> &ss, bool cyclic,
			const TMCG_PublicKeyRing &ring, size_t index, std::istream &in, std::ostream &out);
		void TMCG_ProofStackEquality
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			const TMCG_StackSecret<VTMF_CardSecret> &ss, bool cyclic,
			BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2, bool cyclic,
			const TMCG_PublicKeyRing &ring, std::istream &in, std::ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2, bool cyclic,
			BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out);
		void TMCG_MixOpenStack
			(const TMCG_OpenStack<TMCG_Card> &os, TMCG_OpenStack<TMCG_Card> &os2,
			const TMCG_StackSecret<TMCG_CardSecret> &ss, const TMCG_PublicKeyRing &ring);
		void TMCG_MixOpenStack
			(const TMCG_OpenStack<VTMF_Card> &os, TMCG_OpenStack<VTMF_Card> &os2,
			const TMCG_StackSecret<VTMF_CardSecret> &ss, BarnettSmartVTMF_dlog *vtmf);
		
		~SchindelhauerTMCG 
			()
		{
		}
};

#endif
