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

	#include "BarnettSmartVTMF_dlog.hh"
	#include "mpz_srandom.h"

using namespace std;
typedef unsigned long int		mpz_ui;
typedef ostringstream				TMCG_DataStream;
typedef string							TMCG_KeyString,		TMCG_DataString;
typedef string							TMCG_CipherValue,	TMCG_Signature;
typedef const char*					TMCG_PlainValue;	// allocate rabin_s0 octets

struct TMCG_PublicKey
{
	string										name, email, type, nizk;
	mpz_t											m, y;
	TMCG_Signature						sig;
};

struct TMCG_SecretKey
{
	string										name, email, type, nizk;
	mpz_t											m, y, p, q;
	TMCG_Signature						sig;
	// below this line are non-persistent values (due to pre-computation)
	mpz_t											y1, m1pq, gcdext_up, gcdext_vq, pa1d4, qa1d4;
};

#define							TMCG_MAX_PLAYERS			32L
#define							TMCG_MAX_CARDS				32L
#define							TMCG_MAX_TYPEBITS			8L
#define							TMCG_MAX_KEYBITS			2048L

#define							TMCG_MAX_VALUE_CHARS		\
	(TMCG_MAX_KEYBITS / 2L)
#define							TMCG_MAX_CARD_CHARS			\
	(TMCG_MAX_PLAYERS * TMCG_MAX_TYPEBITS * TMCG_MAX_VALUE_CHARS)
#define							TMCG_MAX_STACK_CHARS		\
	(TMCG_MAX_CARDS * TMCG_MAX_CARD_CHARS)

struct TMCG_PublicKeyRing
{
	TMCG_PublicKey							key[TMCG_MAX_PLAYERS];
};

struct TMCG_Card
{
	size_t	Players, TypeBits;
	mpz_t	z[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS];
};

struct TMCG_CardSecret
{
	size_t	Players, TypeBits;
	mpz_t	r[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS],
		b[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS];
};

typedef vector<TMCG_Card*>													TMCG_Stack;
typedef vector<pair<size_t, TMCG_Card*> >						TMCG_OpenStack;
typedef vector<pair<size_t, TMCG_CardSecret*> >			TMCG_StackSecret;

class SchindelhauerTMCG
{
	private:
		static const int			gcrypt_md_algorithm = GCRY_MD_RMD160;
		
		static const size_t		bcs_size = 1024;			// random bits
		static const size_t		rabin_k0 = 20;				// SAEP octets
		static const size_t		rabin_s0 = 20;				// SAEP octets

																								// soundness error
		static const size_t		nizk_stage1 = 16;			// d^{-nizk_stage1}
		static const size_t		nizk_stage2 = 128;		// 2^{-nizk_stage2}
		static const size_t		nizk_stage3 = 128;		// 2^{-nizk_stage3}

		string								str, str2, str3;
		char									encval[rabin_s0];
		int										ret;

	public:
		static const size_t		TMCG_KeyIDSize = 5;			// octets
		mpz_ui								TMCG_SecurityLevel;			// iterations
		size_t								TMCG_Players, TMCG_TypeBits, TMCG_MaxCards;

		SchindelhauerTMCG 
			(mpz_ui security, size_t players, size_t typebits)
		{
			assert (players <= TMCG_MAX_PLAYERS);
			assert (typebits <= TMCG_MAX_TYPEBITS);
			
			TMCG_SecurityLevel = security;
			TMCG_Players = players, TMCG_TypeBits = typebits, TMCG_MaxCards = 1;
			for (mpz_ui i = 0; i < TMCG_TypeBits; i++)
				TMCG_MaxCards *= 2;
			
			if (!gcry_check_version (LIBGCRYPT_VERSION))
			{
				cerr << "libgcrypt: need library version >= " << 
				    LIBGCRYPT_VERSION << endl;
				exit(-1);
			}
			gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
			gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
			if (gcry_md_test_algo (gcrypt_md_algorithm))
			{
				cerr << "libgcrypt: hash algorithm " << gcrypt_md_algorithm << 
					" [" << gcry_md_algo_name (gcrypt_md_algorithm) << 
					"] not available" << endl;
				exit(-1);
			}
		}

		// methods for parsing
		bool cm
			(string &s, const string &c, char p)
		{
			size_t ei;
			if ((ei = s.find(p, 0)) != s.npos)
			{
				if (s.substr(0, ei) != c)
					return false;
				else
					s = s.substr(ei + 1, s.length() - ei - 1);
			}
			else
				return false;
			return true;
		}

		bool nx
			(string &s, char p)
		{	
			size_t ei;
			if ((ei = s.find(p, 0)) != s.npos)
				s = s.substr(ei + 1, s.length() - ei - 1);
			else
				return false;
			return true;
		}		
		
		const char *gs
			(const string &s, char p)
		{
			size_t ei;
			if ((ei = s.find(p, 0)) != s.npos)
			{
				if (p == '|')
				{
					str = s.substr(0, ei);
					return str.c_str();
				}
				else if (p == '^')
				{
					str2 = s.substr(0, ei);
					return str2.c_str();
				}
				else
				{
					str3 = s.substr(0, ei);
					return str3.c_str();
				}
			}
			else
				return NULL;
		}
		
		// hash functions h() and g() [Random Oracles are practical]
		void h
			(char *output, const char *input, size_t size)
		{
			gcry_md_hash_buffer (gcrypt_md_algorithm, output, input, size);
		}

		void g
			(char *output, size_t osize, const char *input, size_t isize)
		{
			size_t mdsize = gcry_md_get_algo_dlen (gcrypt_md_algorithm);
			size_t times = (osize / mdsize) + 1;
			char *out = new char[times * mdsize];
			for (size_t i = 0; i < times; i++)
			{
				char *data = new char[6 + isize];
				snprintf (data, 6 + isize, "TMCG%02x", (unsigned int)i);
				memcpy (data + 6, input, isize);
				h(out + (i * mdsize), data, 6 + isize);
				delete [] data;
			}
			memcpy (output, out, osize);
			delete [] out;
		}
		
		// export operators
		friend ostream& operator<< 
			(ostream &out, const TMCG_SecretKey &key)
		{
			return
				out << "sec|" << key.name << "|" << key.email << "|" << key.type << 
					"|" << key.m << "|" << key.y << "|" << key.p << "|" << key.q << 
					"|" << key.nizk << "|" << key.sig;
		}
		friend ostream& operator<< 
			(ostream &out, const TMCG_PublicKey &key)
		{
			return
				out << "pub|" << key.name << "|" << key.email << "|" << key.type <<
					"|" << key.m << "|" << key.y << "|" << key.nizk << "|" << key.sig;
		}
		friend ostream& operator<< 
			(ostream &out, const TMCG_Card &card)
		{
			out << "crd|";
			for (size_t k = 0; k < card.Players; k++)
				for (size_t w = 0; w < card.TypeBits; w++)
					out << card.z[k][w] << "|";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const VTMF_Card &card)
		{
			out << "crd|" << card.c_1 << "|" << card.c_2 << "|";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const TMCG_CardSecret &cardsecret)
		{
			out << "crs|";
			for (size_t k = 0; k < cardsecret.Players; k++)
				for (size_t w = 0; w < cardsecret.TypeBits; w++)
					out << cardsecret.r[k][w] << "|" << cardsecret.b[k][w] << "|";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const VTMF_CardSecret &cardsecret)
		{
			out << "crs|" << cardsecret.r << "|";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const TMCG_Stack &stack)
		{
			out << "stk^" << stack.size() << "^";
			for (TMCG_Stack::const_iterator si = stack.begin(); 
				si != stack.end(); si++)
					out << *(*si) << "^";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const VTMF_Stack &stack)
		{
			out << "stk^" << stack.size() << "^";
			for (VTMF_Stack::const_iterator si = stack.begin(); 
				si != stack.end(); si++)
					out << *(*si) << "^";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const TMCG_StackSecret &stacksecret)
		{
			out << "sts^" << stacksecret.size() << "^";
			for (TMCG_StackSecret::const_iterator si = stacksecret.begin(); 
				si != stacksecret.end(); si++)
					out << si->first << "^" << *(si->second) << "^";
			return out;
		}
		friend ostream& operator<< 
			(ostream &out, const VTMF_StackSecret &stacksecret)
		{
			out << "sts^" << stacksecret.size() << "^";
			for (VTMF_StackSecret::const_iterator si = stacksecret.begin(); 
				si != stacksecret.end(); si++)
					out << si->first << "^" << *(si->second) << "^";
			return out;
		}

		// methods for key management
		void TMCG_CreateKey
			(TMCG_SecretKey &key, mpz_ui keysize, 
			const string &name, const string &email);
		void TMCG_CreateKey
			(TMCG_PublicKey &pkey, const TMCG_SecretKey &skey) const;
		bool TMCG_CheckKey
			(const TMCG_PublicKey &pkey);
		void TMCG_ReleaseKey
			(TMCG_SecretKey &key) const;
		void TMCG_ReleaseKey
			(TMCG_PublicKey &key) const;
		const char *TMCG_ExportKeyID
			(const TMCG_SecretKey &key);
		const char *TMCG_ExportKeyID
			(const TMCG_PublicKey &key);
		const char *TMCG_ExportKeyID
			(const TMCG_Signature &sig);
		const char *TMCG_ExportSigID
			(const TMCG_Signature &sig);
		bool TMCG_ImportKey
			(TMCG_SecretKey &key, const TMCG_KeyString &import);
		bool TMCG_ImportKey
			(TMCG_PublicKey &key, const TMCG_KeyString &import);
	
		// methods for encryption and authentification
		const char *TMCG_EncryptValue
			(const TMCG_PublicKey &key, const TMCG_PlainValue &value);
		const char *TMCG_DecryptValue
			(const TMCG_SecretKey &key, TMCG_CipherValue value);
		const char *TMCG_SignData
			(const TMCG_SecretKey &key, const TMCG_DataString &data);
		bool TMCG_VerifyData
			(const TMCG_PublicKey &key, const TMCG_DataString &data,
			const TMCG_Signature &sig);

		// zero-knowledge proofs on values
		void TMCG_ProofQuadraticResidue
			(const TMCG_SecretKey &key, mpz_srcptr t, istream &in, ostream &out);
		bool TMCG_VerifyQuadraticResidue
			(const TMCG_PublicKey &key, mpz_srcptr t, istream &in, ostream &out);
		void TMCG_ProofNonQuadraticResidue
			(const TMCG_SecretKey &key, mpz_srcptr t, istream &in, ostream &out);
		bool TMCG_VerifyNonQuadraticResidue
			(const TMCG_PublicKey &key, mpz_srcptr t, istream &in, ostream &out);
		void TMCG_ProofMaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz, mpz_srcptr r,
			mpz_srcptr b, istream &in, ostream &out);
		bool TMCG_VerifyMaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz,
			istream &in, ostream &out);
		void TMCG_ProofMaskOne
			(const TMCG_PublicKey &key, mpz_srcptr r, mpz_srcptr b, 
			istream &in, ostream &out);
		bool TMCG_VerifyMaskOne
			(const TMCG_PublicKey &key, mpz_srcptr t, istream &in, ostream &out);
		void TMCG_ProofNonQuadraticResidue_PerfectZeroKnowledge
			(const TMCG_SecretKey &key, istream &in, ostream &out);
		bool TMCG_VerifyNonQuadraticResidue_PerfectZeroKnowledge
			(const TMCG_PublicKey &key, istream &in, ostream &out);
		
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
		void TMCG_ReleaseCard
			(TMCG_Card &c);
		bool TMCG_ImportCard
			(TMCG_Card &c, const string &import);
		bool TMCG_ImportCard
			(VTMF_Card &c, const string &import);
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring, size_t index);
		void TMCG_CreateCardSecret
			(VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, mpz_srcptr r, mpz_ui b);
		void TMCG_ReleaseCardSecret
			(TMCG_CardSecret &cs);
		void TMCG_CopyCardSecret
			(const TMCG_CardSecret &cs, TMCG_CardSecret &cs2);
		void TMCG_CopyCardSecret
			(const VTMF_CardSecret &cs, VTMF_CardSecret &cs2);
		bool TMCG_ImportCardSecret
			(TMCG_CardSecret &cs, const string &import);
		bool TMCG_ImportCardSecret
			(VTMF_CardSecret &cs, const string &import);
		void TMCG_MaskCard
			(const TMCG_Card &c, TMCG_Card &cc, const TMCG_CardSecret &cs,
			const TMCG_PublicKeyRing &ring);
		void TMCG_MaskCard
			(const VTMF_Card &c, VTMF_Card &cc, const VTMF_CardSecret &cs,
			BarnettSmartVTMF_dlog *vtmf);
		bool TMCG_EqualCard
			(const TMCG_Card &c, const TMCG_Card &cc);
		bool TMCG_EqualCard
			(const VTMF_Card &c, const VTMF_Card &cc);
		void TMCG_CopyCard
			(const TMCG_Card &c, TMCG_Card &cc);
		void TMCG_CopyCard
			(const VTMF_Card &c, VTMF_Card &cc);
		void TMCG_ProofMaskCard
			(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_CardSecret &cs,
			const TMCG_PublicKeyRing &ring, istream &in, ostream &out);
		void TMCG_ProofMaskCard
			(const VTMF_Card &c, const VTMF_Card &cc, const VTMF_CardSecret &cs,
			BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out);
		bool TMCG_VerifyMaskCard
			(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_PublicKeyRing &ring,
			istream &in, ostream &out);
		bool TMCG_VerifyMaskCard
			(const VTMF_Card &c, const VTMF_Card &cc, BarnettSmartVTMF_dlog *vtmf,
			istream &in, ostream &out);
		void TMCG_ProofPrivateCard
			(const TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
			istream &in, ostream &out);
		bool TMCG_VerifyPrivateCard
			(const TMCG_Card &c, const TMCG_PublicKeyRing &ring,
			istream &in, ostream &out);
		void TMCG_ProofCardSecret
			(const TMCG_Card &c, const TMCG_SecretKey &key, size_t index, 
			istream &in, ostream &out);
		void TMCG_ProofCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
			istream &in, ostream &out);
		bool TMCG_VerifyCardSecret
			(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKey &key,
			size_t index, istream &in, ostream &out);
		bool TMCG_VerifyCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
			istream &in, ostream &out);
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
			(TMCG_StackSecret &ss, bool cyclic, const TMCG_PublicKeyRing &ring,
			size_t index, size_t size);
		size_t TMCG_CreateStackSecret
			(VTMF_StackSecret &ss, bool cyclic, size_t size,
			BarnettSmartVTMF_dlog *vtmf);
		void TMCG_ReleaseStackSecret
			(TMCG_StackSecret &ss);
		void TMCG_ReleaseStackSecret
			(VTMF_StackSecret &ss);
		bool TMCG_ImportStackSecret
			(TMCG_StackSecret &ss, const string &import);
		bool TMCG_ImportStackSecret
			(VTMF_StackSecret &ss, const string &import);
		void TMCG_PushToStack
			(TMCG_Stack &s, const TMCG_Card &c);
		void TMCG_PushToStack
			(VTMF_Stack &s, const VTMF_Card &c);
		void TMCG_PushStackToStack
			(TMCG_Stack &s, const TMCG_Stack &s2);
		void TMCG_PushStackToStack
			(VTMF_Stack &s, const VTMF_Stack &s2);
		bool TMCG_PopFromStack
			(TMCG_Stack &s, TMCG_Card &c);
		bool TMCG_PopFromStack
			(VTMF_Stack &s, VTMF_Card &c);
		bool TMCG_IsInStack
			(const TMCG_Stack &s, const TMCG_Card &c);
		bool TMCG_IsInStack
			(const VTMF_Stack &s, const VTMF_Card &c);
		void TMCG_RemoveFirstFromStack
			(TMCG_Stack &s, const TMCG_Card &c);
		void TMCG_RemoveFirstFromStack
			(VTMF_Stack &s, const VTMF_Card &c);
		void TMCG_RemoveAllFromStack
			(TMCG_Stack &s, const TMCG_Card &c);
		void TMCG_RemoveAllFromStack
			(VTMF_Stack &s, const VTMF_Card &c);
		void TMCG_ReleaseStack
			(TMCG_Stack &s);
		void TMCG_ReleaseStack
			(VTMF_Stack &s);
		bool TMCG_ImportStack
			(TMCG_Stack &s, const string &import);
		bool TMCG_ImportStack
			(VTMF_Stack &s, const string &import);
		void TMCG_CopyStack
			(const TMCG_Stack &s, TMCG_Stack &s2);
		void TMCG_CopyStack
			(const VTMF_Stack &s, VTMF_Stack &s2);
		bool TMCG_EqualStack
			(const TMCG_Stack &s, const TMCG_Stack &s2);
		bool TMCG_EqualStack
			(const VTMF_Stack &s, const VTMF_Stack &s2);
		void TMCG_MixStack
			(const TMCG_Stack &s, TMCG_Stack &s2, const TMCG_StackSecret &ss,
			const TMCG_PublicKeyRing &ring);
		void TMCG_MixStack
			(const VTMF_Stack &s, VTMF_Stack &s2, const VTMF_StackSecret &ss,
			BarnettSmartVTMF_dlog *vtmf);
		void TMCG_GlueStackSecret
			(const TMCG_StackSecret &sigma, TMCG_StackSecret &pi,
			const TMCG_PublicKeyRing &ring);
		void TMCG_GlueStackSecret
			(const VTMF_StackSecret &sigma, VTMF_StackSecret &pi,
			BarnettSmartVTMF_dlog *vtmf);
		void TMCG_ProofStackEquality
			(const TMCG_Stack &s, const TMCG_Stack &s2, const TMCG_StackSecret &ss,
			bool cyclic, const TMCG_PublicKeyRing &ring, size_t index,
			istream &in, ostream &out);
		void TMCG_ProofStackEquality
			(const VTMF_Stack &s, const VTMF_Stack &s2, const VTMF_StackSecret &ss,
			bool cyclic, BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack &s, const TMCG_Stack &s2, bool cyclic,
			const TMCG_PublicKeyRing &ring, istream &in, ostream &out);
		bool TMCG_VerifyStackEquality
			(const VTMF_Stack &s, const VTMF_Stack &s2, bool cyclic,
			BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out);
		void TMCG_PushToOpenStack
			(TMCG_OpenStack &os, const TMCG_Card &c, size_t type);
		void TMCG_PushToOpenStack
			(VTMF_OpenStack &os, const VTMF_Card &c, size_t type);
		void TMCG_PushOpenStackToOpenStack 
			(TMCG_OpenStack &os, const TMCG_OpenStack &os2);
		void TMCG_PushOpenStackToOpenStack 
			(VTMF_OpenStack &os, const VTMF_OpenStack &os2);
		size_t TMCG_PopFromOpenStack
			(TMCG_OpenStack &os, TMCG_Card &c);
		size_t TMCG_PopFromOpenStack
			(VTMF_OpenStack &os, VTMF_Card &c);
		bool TMCG_IsInOpenStack
			(const TMCG_OpenStack &os, size_t check_type);
		bool TMCG_IsInOpenStack
			(const VTMF_OpenStack &os, size_t check_type);
		void TMCG_MoveFromOpenStackToStack
			(TMCG_OpenStack &os, TMCG_Stack &s, size_t check_type);
		void TMCG_MoveFromOpenStackToStack
			(VTMF_OpenStack &os, VTMF_Stack &s, size_t check_type);
		void TMCG_ReleaseOpenStack
			(TMCG_OpenStack &os);
		void TMCG_ReleaseOpenStack
			(VTMF_OpenStack &os);
		void TMCG_CopyOpenStack
			(const TMCG_OpenStack &os, TMCG_OpenStack &os2);
		void TMCG_CopyOpenStack
			(const VTMF_OpenStack &os, VTMF_OpenStack &os2);
		void TMCG_MixOpenStack
			(const TMCG_OpenStack &os, TMCG_OpenStack &os2,
			const TMCG_StackSecret &ss, const TMCG_PublicKeyRing &ring);
		void TMCG_MixOpenStack
			(const VTMF_OpenStack &os, VTMF_OpenStack &os2,
			const VTMF_StackSecret &ss, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_ExtractStack
			(const TMCG_OpenStack &os, TMCG_Stack &s);
		void TMCG_ExtractStack
			(const VTMF_OpenStack &os, VTMF_Stack &s);
		~SchindelhauerTMCG 
			()
		{
		}
};

#endif
