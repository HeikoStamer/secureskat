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
	#include <algorithm>
	#include <functional>
	
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
	mpz_t		z[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS];
	
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
		try
		{
			// check magic
			if (!cm(s, "crd", '|'))
				throw false;
			
			// card description
// FIXME: read from string
			Players = 0, TypeBits = 0;
			
			// card data
			for (size_t k = 0; k < Players; k++)
			{
				for (size_t w = 0; w < TypeBits; w++)
				{
					// z_ij
					if ((mpz_set_str(z[k][w], gs(s, '|'), MPZ_IO_BASE) < 0) ||
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

struct TMCG_CardSecret
{
	size_t	Players, TypeBits;
	mpz_t		r[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS],
					b[TMCG_MAX_PLAYERS][TMCG_MAX_TYPEBITS];
	
	TMCG_CardSecret
		()
	{
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_init(r[k][w]), mpz_init(b[k][w]);
	}
	
	TMCG_CardSecret
		(const TMCG_CardSecret& that) :
		Players(that.Players), TypeBits(that.TypeBits)
	{
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_init_set(r[k][w], that.r[k][w]),
				mpz_init_set(b[k][w], that.b[k][w]);
	}
	
	TMCG_CardSecret& operator =
		(const TMCG_CardSecret& that)
	{
		Players = that.Players, TypeBits = that.TypeBits;
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_set(r[k][w], that.r[k][w]), mpz_set(b[k][w], that.b[k][w]);
		return *this;
	}
	
	bool import
		(string s)
	{
		try
		{
			// check magic
			if (!cm(s, "crs", '|'))
				throw false;
			
			// public card data
// FIXME: read from string
			Players = 0, TypeBits = 0;
			
			// secret card data
			for (size_t k = 0; k < Players; k++)
			{
				for (size_t w = 0; w < TypeBits; w++)
				{
					// r_ij
					if ((mpz_set_str(r[k][w], gs(s, '|'), MPZ_IO_BASE) < 0) ||
						(!nx(s, '|')))
							throw false;
							
					// b_ij
					if ((mpz_set_str(b[k][w], gs(s, '|'), MPZ_IO_BASE) < 0) ||
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
	
	~TMCG_CardSecret
		()
	{
		for (size_t k = 0; k < TMCG_MAX_PLAYERS; k++)
			for (size_t w = 0; w < TMCG_MAX_TYPEBITS; w++)
				mpz_clear(r[k][w]), mpz_clear(b[k][w]);
	}
};

template <typename CardType> struct TMCG_OpenStack;

template <typename CardType> struct TMCG_Stack
{
	vector<CardType>	stack;
	
	TMCG_Stack
		()
	{
	}
	
	TMCG_Stack& operator =
		(const TMCG_Stack& that)
	{
		clear();
		stack = that.stack;
	}
	
	bool operator ==
		(const TMCG_Stack& that)
	{
		if (stack.size() != that.stack.size())
			return false;
		return std::equal(stack.begin(), stack.end(), that.stack.begin());
	}
	
	bool operator !=
		(const TMCG_Stack& that)
	{
		return !(*this == that);
	}
	
	const CardType& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	CardType& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	size_t size
		() const
	{
		return stack.size();
	}
	
	void push
		(const CardType& c)
	{
		stack.push_back(c);
	}
	
	void push
		(const TMCG_Stack& s)
	{
		std::copy(s.stack.begin(), s.stack.end(), back_inserter(stack));
	}
	
	void push
		(const TMCG_OpenStack<CardType>& s)
	{
		for (typename vector<pair<size_t, CardType> >::const_iterator
			si = s.stack.begin(); si != si.end(); si++)
				stack.push_back(si->second);
	}
	
	bool pop
		(CardType& c)
	{
		if (stack.empty())
			return false;
		
		c = *(stack.back());
		stack.pop_back();
		return true;
	}
	
	void clear
		()
	{
		stack.clear();
	}
	
	bool find
		(const CardType& c) const
	{
		return (std::find(stack.begin(), stack.end(), c) != stack.end());
	}
	
	bool remove
		(const CardType& c)
	{
		typename vector<CardType>::iterator si =
			std::find(stack.begin(), stack.end(), c);
		
		if (si != stack.end())
		{
			stack.erase(si);
			return true;
		}
		return false;
	}
	
	size_t removeAll
		(const CardType& c)
	{
		size_t counter = 0;
		while (remove(c))
			counter++;
		return counter;
	}
	
	bool import
		(string s)
	{
		size_t size = 0;
		char *ec;
		
		try
		{
			// check magic
			if (!cm(s, "stk", '^'))
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
				CardType c;
				
				if (gs(s, '^') == NULL)
					throw false;
				if ((!c.import(gs(s, '^'))) || (!nx(s, '^')))
					throw false;
				stack.push_back(c);
			}
			
			throw true;
		}
		catch (bool return_value)
		{
			return return_value;
		}
	}
	
	~TMCG_Stack
		()
	{
		stack.clear();
	}
};

template <typename CardType> struct TMCG_OpenStack
{
	vector<pair<size_t, CardType> >	stack;
	
	struct eq_first_component : public binary_function<
		pair<size_t, CardType>, pair<size_t, CardType>, bool>
	{
		bool operator() 
			(const pair<size_t, CardType>& p1, const pair<size_t, CardType>& p2)
		{
			return (p1.first == p2.first);
		}
	};
	
	TMCG_OpenStack
		()
	{
	}
	
	TMCG_OpenStack& operator =
		(const TMCG_OpenStack& that)
	{
		clear();
		stack = that.stack;
	}
	
	bool operator ==
		(const TMCG_OpenStack& that)
	{
		if (stack.size() != that.stack.size())
			return false;
		return std::equal(stack.begin(), stack.end(), that.stack.begin());
	}
	
	bool operator !=
		(const TMCG_OpenStack& that)
	{
		return !(*this == that);
	}
	
	const pair<size_t, CardType>& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	pair<size_t, CardType>& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	size_t size
		() const
	{
		return stack.size();
	}
	
	void push
		(size_t type, const CardType& c)
	{
		stack.push_back(pair<size_t, CardType>(type, c));
	}
	
	void push
		(const TMCG_OpenStack& s)
	{
		std::copy(s.stack.begin(), s.stack.end(), back_inserter(stack));
	}
	
	size_t pop
		(CardType& c)
	{
		size_t type = (1 << TMCG_MAX_TYPEBITS);		// set 'error code'
		
		if (stack.empty())
			return type;
		
		type = (stack.back())->first;
		c = (stack.back())->second;
		stack.pop_back();
		return type;
	}
	
	void clear
		()
	{
		stack.clear();
	}
	
	bool find
		(size_t type) const
	{
		return (std::find_if(stack.begin(), stack.end(),
			std::bind2nd(eq_first_component(), pair<size_t, CardType>
				(type, CardType()))) != stack.end());
	}
	
	bool remove
		(size_t type)
	{
		typename vector<pair<size_t, CardType> >::iterator si =
			std::find_if(stack.begin(), stack.end(),
				std::bind2nd(eq_first_component(), pair<size_t, CardType>
					(type, CardType())));
		
		if (si != stack.end())
		{
			stack.erase(si);
			return true;
		}
		return false;
	}
	
	size_t removeAll
		(size_t type)
	{
		size_t counter = 0;
		while (remove(type))
			counter++;
		return counter;
	}
	
	bool move
		(size_t type, TMCG_Stack<CardType>& s)
	{
		typename vector<pair<size_t, CardType> >::iterator si =
			std::find_if(stack.begin(), stack.end(),
				std::bind2nd(eq_first_component(), pair<size_t, CardType>
					(type, CardType())));
		
		if (si != stack.end())
		{
			s.push(si->second);
			stack.erase(si);
			return true;
		}
		return false;
	}
	
	~TMCG_OpenStack
		()
	{
		stack.clear();
	}
};

template <typename CardSecretType> struct TMCG_StackSecret
{
	vector<pair<size_t, CardSecretType> >	stack;
	
	struct eq_first_component : public binary_function<
		pair<size_t, CardSecretType>, pair<size_t, CardSecretType>, bool>
	{
		bool operator() 
			(const pair<size_t, CardSecretType>& p1,
			 const pair<size_t, CardSecretType>& p2) const
		{
			return (p1.first == p2.first);
		}
	};
	
	TMCG_StackSecret
		()
	{
	}
	
	TMCG_StackSecret& operator =
		(const TMCG_StackSecret<CardSecretType>& that)
	{
		stack.clear();
		stack = that.stack;
	}
	
	const pair<size_t, CardSecretType>& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	pair<size_t, CardSecretType>& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	size_t size
		() const
	{
		return stack.size();
	}
	
	void push
		(size_t index, const CardSecretType& cs)
	{
		stack.push_back(pair<size_t, CardSecretType>(index, cs));
	}
	
	void clear
		()
	{
		stack.clear();
	}
	
	bool find
		(size_t index)
	{
		return (std::find_if(stack.begin(), stack.end(),
			std::bind2nd(eq_first_component(),
				pair<size_t, CardSecretType>(index, CardSecretType()))) != stack.end());
	}
	
	bool import
		(string s)
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
				pair<size_t, CardSecretType> lej;
				
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
	
	~TMCG_StackSecret
		()
	{
		stack.clear();
	}
};

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
		size_t								TMCG_Players, TMCG_TypeBits, TMCG_MaxCardType;
		
		SchindelhauerTMCG 
			(mpz_ui security, size_t players, size_t typebits)
		{
			assert (players <= TMCG_MAX_PLAYERS);
			assert (typebits <= TMCG_MAX_TYPEBITS);
			
			TMCG_SecurityLevel = security;
			TMCG_Players = players, TMCG_TypeBits = typebits, TMCG_MaxCardType = 1;
			for (mpz_ui i = 0; i < TMCG_TypeBits; i++)
				TMCG_MaxCardType *= 2;
			
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
		template<typename CardType> friend ostream& operator<<
			(ostream &out, const TMCG_Stack<CardType> &s)
		{
			out << "stk^" << s.size() << "^";
			for (size_t i = 0; i < s.size(); i++)
				out << s[i] << "^";
			return out;
		}
		template<typename CardSecretType> friend ostream& operator<<
			(ostream &out, const TMCG_StackSecret<CardSecretType> &ss)
		{
			out << "sts^" << ss.size() << "^";
			for (size_t i = 0; i < ss.size(); i++)
				out << ss[i].first << "^" << ss[i].second << "^";
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
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring, size_t index);
		void TMCG_CreateCardSecret
			(VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, mpz_srcptr r, mpz_ui b);
		void TMCG_MaskCard
			(const TMCG_Card &c, TMCG_Card &cc, const TMCG_CardSecret &cs,
			const TMCG_PublicKeyRing &ring);
		void TMCG_MaskCard
			(const VTMF_Card &c, VTMF_Card &cc, const VTMF_CardSecret &cs,
			BarnettSmartVTMF_dlog *vtmf);
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
			const TMCG_PublicKeyRing &ring, size_t index, istream &in, ostream &out);
		void TMCG_ProofStackEquality
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			const TMCG_StackSecret<VTMF_CardSecret> &ss, bool cyclic,
			BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2, bool cyclic,
			const TMCG_PublicKeyRing &ring, istream &in, ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2, bool cyclic,
			BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out);
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
