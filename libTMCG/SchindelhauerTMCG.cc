/*******************************************************************************
   SchindelhauerTMCG.cc, cryptographic |T|oolbox for |M|ental |C|ard |G|ames

     Christian Schindelhauer: 'A Toolbox for Mental Card Games',
     Medizinische Universit? L?eck, 17. September 1998

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

#include "SchindelhauerTMCG.hh"
#include "mpz_sqrtm.h"

void SchindelhauerTMCG::TMCG_CreateKey 
	(TMCG_SecretKey &key, mpz_ui keysize, const string &name, const string &email)
{
	mpz_t	foo, bar;
	mpz_init (foo), mpz_init (bar);
	
	// sanity check, set maximum keysize
	if (keysize > TMCG_MAX_KEYBITS)
		keysize = TMCG_MAX_KEYBITS;
	
	// initalize personal key information
	TMCG_DataStream type;
	type << "TMCG/RABIN_" << keysize << "_NIZK";
	key.name = name, key.email = email, key.type = type.str();
	
	// generate appropriate primes for RABIN encryption with OAEP/SAEP
	mpz_init (key.p), mpz_init (key.q), mpz_init (key.m);
	do
	{
		// choose random p \in Z, but with fixed size (n/2 + 1) bit
		do
		{
			mpz_ssrandomb (key.p, NULL, (keysize / 2L) + 1L);
		}
		while (mpz_sizeinbase (key.p, 2L) < ((keysize / 2L) + 1L));
		
		// if p is even, increment p by 1L
		if (mpz_even_p (key.p))
			mpz_add_ui (key.p, key.p, 1L);
		
		// while p is not probable prime and congruent 3 (mod 4)
		while (!mpz_congruent_ui_p (key.p, 3L, 4L) ||
			!mpz_probab_prime_p (key.p, 25))
		{
			mpz_add_ui (key.p, key.p, 2L);
		}
		assert (!mpz_congruent_ui_p (key.p, 1L, 8L));
		
		// choose random q \in Z, but with fixed size (n/2 + 1) bit
		do
		{
			mpz_ssrandomb (key.q, NULL, (keysize / 2L) + 1L);
		}
		while (mpz_sizeinbase (key.q, 2L) < ((keysize / 2L) + 1L));
		
		// if q is even, increment q by 1L
		if (mpz_even_p (key.q))
			mpz_add_ui (key.q, key.q, 1L);
		
		// while q is not probable prime and congruent 3 (mod 4)
		mpz_set_ui (foo, 8L);
		while (!mpz_congruent_ui_p (key.q, 3L, 4L) ||
			!mpz_probab_prime_p (key.q, 25) ||
			mpz_congruent_p (key.p, key.q, foo))
		{
			mpz_add_ui (key.q, key.q, 2L);
		}
		assert (!mpz_congruent_ui_p (key.q, 1L, 8L));
		
		// compute modulus: m = p * q
		mpz_mul (key.m, key.p, key.q);
		
		// compute upper bound 2^{n+1} + 2^n
		mpz_set_ui (foo, 1L);
		mpz_mul_2exp (foo, foo, keysize);
		mpz_mul_2exp (bar, foo, 1L);
		mpz_add (bar, bar, foo);
	}
	while ((mpz_sizeinbase (key.m, 2L) < (keysize + 1L)) ||
		(mpz_cmp (key.m, bar) >= 0));
	
	// choose random y \in NQR? for TMCG
	mpz_init (key.y);
	do
	{
		mpz_srandomm (key.y, NULL, key.m);
	}
	while ((mpz_jacobi (key.y, key.m) != 1) || 
		mpz_qrmn_p (key.y, key.p, key.q, key.m));
	
	// pre-compute non-persistent values
	mpz_init (key.y1);
	ret = mpz_invert (key.y1, key.y, key.m);
	assert (ret);
	mpz_init (key.m1pq);
	mpz_sub (foo, key.m, key.p);
	mpz_sub (foo, foo, key.q);
	mpz_add_ui (foo, foo, 1L);
	ret = mpz_invert (key.m1pq, key.m, foo);
	assert (ret);
	mpz_init (key.gcdext_up), mpz_init (key.gcdext_vq);
	mpz_init (key.pa1d4), mpz_init (key.qa1d4);
	mpz_gcdext (foo, key.gcdext_up, key.gcdext_vq, key.p, key.q);
	assert (mpz_cmp_ui (foo, 1L) == 0);
	mpz_mul (key.gcdext_up, key.gcdext_up, key.p);
	mpz_mul (key.gcdext_vq, key.gcdext_vq, key.q);
	mpz_set (key.pa1d4, key.p), mpz_set (key.qa1d4, key.q);
	mpz_add_ui (key.pa1d4, key.pa1d4, 1L);
	mpz_add_ui (key.qa1d4, key.qa1d4, 1L);
	mpz_fdiv_q_2exp (key.pa1d4, key.pa1d4, 2L);
	mpz_fdiv_q_2exp (key.qa1d4, key.qa1d4, 2L);
	
	// compute NIZK-proofs (STAGE1+2: m = p^i * q^j    STAGE3: y \in NQR?)
	TMCG_DataStream nizk, input;
	input << key.m << "^" << key.y,	nizk << "nzk^";
	size_t mnsize = mpz_sizeinbase (key.m, 2L) / 8;
	char *mn = new char[mnsize];
	
	// STAGE1: m Square Free, soundness error probability = d^{-nizk_stage1}
	nizk << nizk_stage1 << "^";
	for (size_t stage1 = 0; stage1 < nizk_stage1; stage1++)
	{
		// common random number foo \in Z*m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import (foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod (foo, foo, key.m);
			mpz_gcd (bar, foo, key.m);
			input << foo;
		}
		while (mpz_cmp_ui (bar, 1L));
		
		// compute bar = foo^m1pq mod m
		mpz_powm (bar, foo, key.m1pq, key.m);
		
		// update NIZK-proof stream
		nizk << bar << "^"; 
	}
	
	// STAGE2: m Prime Power Product, soundness error prob. = 2^{-nizk_stage2}
	nizk << nizk_stage2 << "^";
	for (size_t stage2 = 0; stage2 < nizk_stage2; stage2++)
	{
		// common random number foo \in Z*m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import (foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod (foo, foo, key.m);
			mpz_gcd (bar, foo, key.m);
			input << foo;
		}
		while (mpz_cmp_ui (bar, 1L));
		
		// compute square root of +-foo or +-2foo mod m
		if (mpz_qrmn_p (foo, key.p, key.q, key.m))
			mpz_sqrtmn_r (bar, foo, key.p, key.q, key.m, NULL);
		else
		{
			mpz_neg (foo, foo);
			if (mpz_qrmn_p (foo, key.p, key.q, key.m))
				mpz_sqrtmn_r (bar, foo, key.p, key.q, key.m, NULL);
			else
			{
				mpz_mul_2exp (foo, foo, 1L);
				if (mpz_qrmn_p (foo, key.p, key.q, key.m))
					mpz_sqrtmn_r (bar, foo, key.p, key.q, key.m, NULL);
				else
				{
					mpz_neg (foo, foo);
					if (mpz_qrmn_p (foo, key.p, key.q, key.m))
						mpz_sqrtmn_r (bar, foo, key.p, key.q, key.m, NULL);
					else
						mpz_set_ui (bar, 0L);
				}
			}
		}
		
		// update NIZK-proof stream
		nizk << bar << "^";
	}
	
	// STAGE3: y \in NQR?, soundness error probability = 2^{-nizk_stage3}
	nizk << nizk_stage3 << "^";
	for (size_t stage3 = 0; stage3 < nizk_stage3; stage3++)
	{
		// common random number foo \in Z? (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import (foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod (foo, foo, key.m);
			input << foo;
		}
		while (mpz_jacobi (foo, key.m) != 1);
		
		// compute square root
		if (!mpz_qrmn_p (foo, key.p, key.q, key.m))
		{
			mpz_mul (foo, foo, key.y);
			mpz_mod (foo, foo, key.m);
		}
		mpz_sqrtmn_r (bar, foo, key.p, key.q, key.m, NULL);
		
		// update NIZK-proof stream
		nizk << bar << "^";
	}
	
	key.nizk = nizk.str();
	delete [] mn, mpz_clear (foo), mpz_clear (bar);
	
	// compute self-signature
	TMCG_DataStream data, repl;
	data << key.name << "|" << key.email << "|" << key.type << "|" <<
		key.m << "|" << key.y << "|" << key.nizk << "|";
	key.sig = TMCG_SignData(key, data.str());
	repl << "ID" << TMCG_KeyIDSize << "^";
	(key.sig).replace((key.sig).find(repl.str()), (repl.str()).length() +  
		TMCG_KeyIDSize, TMCG_ExportKeyID(key));
}

void SchindelhauerTMCG::TMCG_CreateKey 
	(TMCG_PublicKey &pkey, const TMCG_SecretKey &skey) const
{
	pkey.name = skey.name, pkey.email = skey.email, pkey.type = skey.type;
	mpz_init_set (pkey.m, skey.m);
	mpz_init_set (pkey.y, skey.y);
	pkey.nizk = skey.nizk, pkey.sig = skey.sig;
}

bool SchindelhauerTMCG::TMCG_CheckKey
	(const TMCG_PublicKey &pkey)
{
	mpz_t foo, bar;
	string s = pkey.nizk;
	size_t stage1_size = 0, stage2_size = 0, stage3_size = 0;
	size_t mnsize = mpz_sizeinbase (pkey.m, 2L) / 8;
	char *ec, *mn = new char[mnsize];
	
	mpz_init (foo), mpz_init (bar);
	try
	{
		// sanity check, if y \in Z?
		if (mpz_jacobi (pkey.y, pkey.m) != 1)
			throw false;
		
		// sanity check, if m \in ODD (odd numbers)
		if (!(mpz_get_ui (pkey.m) & 1L))
			throw false;
		
		// sanity check, if m \in P (prime)
		// (here is a very small probability of false-negativ behaviour,
		//  FIX: give a short witness in public key)
		if (mpz_probab_prime_p (pkey.m, 500))
			throw false;
		
		// check self-signature
		TMCG_DataStream data;
		data << pkey.name << "|" << pkey.email << "|" << pkey.type << "|" << 
			pkey.m << "|" << pkey.y << "|" << pkey.nizk << "|";
		if (!TMCG_VerifyData(pkey, data.str(), pkey.sig))
			throw false;
		
		// check, that m \not\in FP (fermat primes: m = 2^k + 1)
		mpz_set (foo, pkey.m);
		mpz_sub_ui (foo, foo, 1L);
		mpz_ui k = mpz_sizeinbase (pkey.m, 2L);
		mpz_set_ui (bar, 2L);
		mpz_pow_ui (bar, bar, k);
		if (mpz_cmp (foo, bar) == 0)
		{
			// check, if k is power of two
			mpz_set_ui (foo, k);
			mpz_ui l = mpz_sizeinbase (foo, 2L);
			mpz_set_ui (bar, 2L);
			mpz_pow_ui (bar, bar, l);
			if (mpz_cmp (foo, bar) == 0)
			{
				// check, if m equal 5L
				mpz_set_ui (foo, 5L);
				if (mpz_cmp (foo, pkey.m) == 0)
					throw false;
				
				// check, if 5^2^(k/2) = -1 mod m [Pepin's prime test]
				mpz_set_ui (foo, 2L);
				mpz_powm_ui (foo, foo, (k / 2), pkey.m);
				mpz_set_ui (bar, 5L);
				mpz_powm (foo, bar, foo, pkey.m);
				mpz_set_si (bar, -1L);
				if (mpz_congruent_p (foo, bar, pkey.m))
					throw false;
			}
		}
		
		// check magic of NIZK
		if (!cm(s, "nzk", '^'))
			throw false;
		
		// initalize NIZK proof input
		TMCG_DataStream input;
		input << pkey.m << "^" << pkey.y;
		
		// get security parameter of STAGE1
		if (gs(s, '^') == NULL)
			throw false;
		stage1_size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (stage1_size <= 0) || (!nx(s, '^')))
			throw false;
		
		// check security parameter of STAGE1
		if (stage1_size < nizk_stage1)
			throw false;
		
		// STAGE1: m is Square Free
		for (size_t i = 0; i < stage1_size; i++)
		{
			// common random number foo \in Z*m (build from hash function g)
			do
			{
				g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
				mpz_import (foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod (foo, foo, pkey.m);
				mpz_gcd (bar, foo, pkey.m);
				input << foo;
			}
			while (mpz_cmp_ui (bar, 1L));
			
			// read NIZK proof
			if (gs(s, '^') == NULL)
				throw false;
			if ((mpz_set_str(bar, gs(s, '^'), MPZ_IO_BASE) < 0) || (!nx(s, '^')))
				throw false;
			
			// check, if bar^m = foo mod m
			mpz_powm (bar, bar, pkey.m, pkey.m);
			if (mpz_cmp (foo, bar) != 0)
				throw false;
		}
		
		// get security parameter of STAGE2
		if (gs(s, '^') == NULL)
			throw false;
		stage2_size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (stage2_size <= 0) || (!nx(s, '^')))
			throw false;
		
		// check security parameter of STAGE2
		if (stage2_size < nizk_stage2)
			throw false;
		
		// STAGE2: m is Prime Power Product
		for (size_t i = 0; i < stage2_size; i++)
		{
			// common random number foo \in Z*m (build from hash function g)
			do
			{
				g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
				mpz_import (foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod (foo, foo, pkey.m);
				mpz_gcd (bar, foo, pkey.m);
				input << foo;
			}
			while (mpz_cmp_ui (bar, 1L));
			
			// read NIZK proof
			if (gs(s, '^') == NULL)
				throw false;
			if ((mpz_set_str (bar, gs(s, '^'), MPZ_IO_BASE) < 0) || (!nx(s, '^')))
				throw false;
			
			// check, if bar^2 = +-foo or +-2foo mod m
			mpz_mul (bar, bar, bar);
			mpz_mod (bar, bar, pkey.m);
			if (!mpz_congruent_p (bar, foo, pkey.m))
			{
				mpz_neg (foo, foo);
				if (!mpz_congruent_p (bar, foo, pkey.m))
				{
					mpz_mul_2exp (foo, foo, 1L);
					if (!mpz_congruent_p (bar, foo, pkey.m))
					{
						mpz_neg (foo, foo);
						if (!mpz_congruent_p (bar, foo, pkey.m))
							throw false;
					}
				}
			}
		}
		
		// get security parameter of STAGE3
		if (gs(s, '^') == NULL)
			throw false;
		stage3_size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (stage3_size <= 0) || (!nx(s, '^')))
			throw false;
		
		// check security parameter of STAGE3
		if (stage3_size < nizk_stage3)
			throw false;
		
		// STAGE3: y \in NQR?
		for (size_t i = 0; i < stage3_size; i++)
		{
			// common random number foo \in Z? (build from hash function g)
			do
			{
				g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
				mpz_import (foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod (foo, foo, pkey.m);
				input << foo;
			}
			while (mpz_jacobi (foo, pkey.m) != 1);
			
			// read NIZK proof
			if (gs(s, '^') == NULL)
				throw false;
			if ((mpz_set_str (bar, gs(s, '^'), MPZ_IO_BASE) < 0) || (!nx(s, '^')))
				throw false;
			
			// check congruence [Goldwasser-Micali NIZK proof for NQR]
			mpz_mul (bar, bar, bar);
			mpz_mod (bar, bar, pkey.m);
			if (!mpz_congruent_p (bar, foo, pkey.m))
			{
				mpz_mul (foo, foo, pkey.y);
				mpz_mod (foo, foo, pkey.m);
				if (!mpz_congruent_p (bar, foo, pkey.m))
					throw false;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		delete [] mn, mpz_clear (foo), mpz_clear (bar);
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ReleaseKey
	(TMCG_SecretKey &key) const
{
	mpz_clear (key.m);
	mpz_clear (key.y);
	mpz_clear (key.p);
	mpz_clear (key.q);
	// release non-persistent values
	mpz_clear (key.y1), mpz_clear (key.m1pq);
	mpz_clear (key.gcdext_up), mpz_clear (key.gcdext_vq);
	mpz_clear (key.pa1d4), mpz_clear (key.qa1d4);
}

void SchindelhauerTMCG::TMCG_ReleaseKey
	(TMCG_PublicKey &key) const
{
	mpz_clear (key.m);
	mpz_clear (key.y);
}

const char *SchindelhauerTMCG::TMCG_ExportKeyID
	(const TMCG_SecretKey &key)
{
	TMCG_DataStream data;
	string tmp = TMCG_ExportSigID(key.sig);
	data << "ID" << TMCG_KeyIDSize << "^" << tmp.substr(tmp.length() - 
		((TMCG_KeyIDSize < tmp.length()) ? TMCG_KeyIDSize : tmp.length()),
		(TMCG_KeyIDSize < tmp.length()) ? TMCG_KeyIDSize : tmp.length());
	str = data.str();
	return str.c_str();
}

const char *SchindelhauerTMCG::TMCG_ExportKeyID
	(const TMCG_PublicKey &key)
{
	TMCG_DataStream data;
	string tmp = TMCG_ExportSigID(key.sig);
	data << "ID" << TMCG_KeyIDSize << "^" << tmp.substr(tmp.length() - 
		((TMCG_KeyIDSize < tmp.length()) ? TMCG_KeyIDSize : tmp.length()),
		(TMCG_KeyIDSize < tmp.length()) ? TMCG_KeyIDSize : tmp.length());
	str = data.str();
	return str.c_str();
}

const char *SchindelhauerTMCG::TMCG_ExportKeyID
	(const TMCG_Signature &sig)
{
	string s = sig;
	
	// check magic
	if (!cm(s, "sig", '|'))
		return NULL;
	
	// get keyID
	return gs(s, '|');
}

const char *SchindelhauerTMCG::TMCG_ExportSigID
	(const TMCG_Signature &sig)
{
	string s = sig;
	
	// maybe self signature
	if (sig == "")
		return "SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG";
	
	// check magic
	if (!cm(s, "sig", '|'))
		return NULL;
	
	// skip keyID
	if (!nx(s, '|'))
		return NULL;
	
	// get sigID
	return gs(s, '|');
}

bool SchindelhauerTMCG::TMCG_ImportKey
	(TMCG_SecretKey &key, const TMCG_KeyString &import)
{
	string s = import;
	mpz_init (key.m),	mpz_init (key.y),	mpz_init (key.p),	mpz_init (key.q);
	
	try
	{
		// check magic
		if (!cm(s, "sec", '|'))
			throw false;
		
		// name
		key.name = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// email
		key.email = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// type
		key.type = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// m
		if ((mpz_set_str (key.m, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// y
		if ((mpz_set_str (key.y, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// p
		if ((mpz_set_str (key.p, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// q
		if ((mpz_set_str (key.q, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// NIZK
		key.nizk = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// sig
		key.sig = s;
		
		// pre-compute non-persistent values
		mpz_t foo;
		mpz_init (key.y1);
		ret = mpz_invert (key.y1, key.y, key.m);
		assert (ret);
		mpz_init (key.m1pq);
		mpz_init (foo);
		mpz_sub (foo, key.m, key.p);
		mpz_sub (foo, foo, key.q);
		mpz_add_ui (foo, foo, 1L);
		ret = mpz_invert (key.m1pq, key.m, foo);
		assert (ret);
		mpz_init (key.gcdext_up), mpz_init (key.gcdext_vq);
		mpz_init (key.pa1d4), mpz_init (key.qa1d4);
		mpz_gcdext (foo, key.gcdext_up, key.gcdext_vq, key.p, key.q);
		assert (mpz_cmp_ui (foo, 1L) == 0);
		mpz_mul (key.gcdext_up, key.gcdext_up, key.p);
		mpz_mul (key.gcdext_vq, key.gcdext_vq, key.q);
		mpz_clear (foo);
		mpz_set (key.pa1d4, key.p), mpz_set (key.qa1d4, key.q);
		mpz_add_ui (key.pa1d4, key.pa1d4, 1L);
		mpz_add_ui (key.qa1d4, key.qa1d4, 1L);
		mpz_fdiv_q_2exp (key.pa1d4, key.pa1d4, 2L);
		mpz_fdiv_q_2exp (key.qa1d4, key.qa1d4, 2L);
		
		return true;
	}
	catch (bool return_value)
	{
		mpz_clear (key.m), mpz_clear (key.y), mpz_clear (key.p), mpz_clear (key.q);
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_ImportKey
	(TMCG_PublicKey &key, const TMCG_KeyString &import)
{
	string s = import;
	mpz_init (key.m),	mpz_init (key.y);
	
	try
	{
		// check magic
		if (!cm(s, "pub", '|'))
			throw false;
		
		// name
		key.name = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// email
		key.email = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// type
		key.type = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// m
		if ((mpz_set_str (key.m, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// y
		if ((mpz_set_str (key.y, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// NIZK
		key.nizk = gs(s, '|');
		if ((gs(s, '|') == NULL) || (!nx(s, '|')))
			throw false;
		
		// sig
		key.sig = s;
		
		return true;
	}
	catch (bool return_value)
	{
		mpz_clear	(key.m), mpz_clear (key.y);
		return return_value;
	}
}

const char *SchindelhauerTMCG::TMCG_EncryptValue
	(const TMCG_PublicKey &key, const TMCG_PlainValue &value)
{
	mpz_t vdata;
	size_t rabin_s2 = 2 * rabin_s0;
	size_t rabin_s1 = (mpz_sizeinbase (key.m, 2L) / 8) - rabin_s2;

	assert (rabin_s2 < (mpz_sizeinbase (key.m, 2L) / 16));
	assert (rabin_s2 < rabin_s1);
	assert (rabin_s0 < (mpz_sizeinbase (key.m, 2L) / 32));

	char *r = new char[rabin_s1];
	gcry_randomize ((unsigned char*)r, rabin_s1, GCRY_STRONG_RANDOM);
		
	char *Mt = new char[rabin_s2], *g12 = new char[rabin_s2];
	memcpy (Mt, value, rabin_s0),	memset (Mt + rabin_s0, 0, rabin_s0);
	g(g12, rabin_s2, r, rabin_s1);

	for (size_t i = 0; i < rabin_s2; i++)
		Mt[i] ^= g12[i];
	
	char *y = new char[rabin_s2 + rabin_s1];
	memcpy (y, Mt, rabin_s2),	memcpy (y + rabin_s2, r, rabin_s1);
	mpz_init (vdata), mpz_import (vdata, 1, -1, rabin_s2 + rabin_s1, 1, 0, y);
	delete [] y, delete [] g12, delete [] Mt, delete [] r;

	// apply RABIN function vdata = vdata^2 mod m
	mpz_mul (vdata, vdata, vdata);
	mpz_mod (vdata, vdata, key.m);

	TMCG_DataStream ost;
	ost << "enc|" << TMCG_ExportKeyID(key) << "|" << vdata << "|";
	mpz_clear (vdata);
	
	str2 = ost.str();
	return str2.c_str();
}

const char *SchindelhauerTMCG::TMCG_DecryptValue
	(const TMCG_SecretKey &key, TMCG_CipherValue value)
{
	mpz_t vdata, vroot[4];
	size_t rabin_s2 = 2 * rabin_s0;
	size_t rabin_s1 = (mpz_sizeinbase (key.m, 2L) / 8) - rabin_s2;

	assert (rabin_s2 < (mpz_sizeinbase (key.m, 2L) / 16));
	assert (rabin_s2 < rabin_s1);
	assert (rabin_s0 < (mpz_sizeinbase (key.m, 2L) / 32));

	char *y = new char[rabin_s2 + rabin_s1 + 1024], *r = new char[rabin_s1];
	char *Mt = new char[rabin_s2], *g12 = new char[rabin_s2];
	mpz_init (vdata), mpz_init (vroot[0]), mpz_init (vroot[1]),
		mpz_init (vroot[2]), mpz_init (vroot[3]);
	try
	{
		// check magic
		if (!cm(value, "enc", '|'))
			throw false;
		
		// check keyID
		if (!cm(value, TMCG_ExportKeyID(key), '|'))
			throw false;
					
		// vdata
		if ((mpz_set_str (vdata, gs(value, '|'), MPZ_IO_BASE) < 0) || 
			(!nx(value, '|')))
				throw false;

		// decrypt value, compute modular square roots
		if (!mpz_qrmn_p (vdata, key.p, key.q, key.m))
			throw false;
		mpz_sqrtmn_fast_all (vroot[0], vroot[1], vroot[2], vroot[3], vdata, 
			key.p, key.q, key.m, key.gcdext_up, key.gcdext_vq, key.pa1d4, key.qa1d4);
		for (size_t k = 0; k < 4; k++)
		{
			if ((mpz_sizeinbase (vroot[k], 2L) / 8) <= (rabin_s1 + rabin_s2))
			{
				size_t cnt = 1;
				mpz_export (y, &cnt, -1, rabin_s2 + rabin_s1, 1, 0, vroot[k]);
				memcpy (Mt, y, rabin_s2), memcpy (r, y + rabin_s2, rabin_s1);
				g(g12, rabin_s2, r, rabin_s1);

				for (size_t i = 0; i < rabin_s2; i++)
					Mt[i] ^= g12[i];
			
				memset (g12, 0, rabin_s0);
				if (memcmp (Mt + rabin_s0, g12, rabin_s0) == 0)
				{
					memcpy (encval, Mt, rabin_s0);
					throw true;
				}
			}
		}
		throw false;
	}
	catch (bool success)
	{
		delete [] y, delete [] g12, delete [] Mt, delete [] r;
		mpz_clear (vdata), mpz_clear(vroot[0]), mpz_clear(vroot[1]),
			mpz_clear(vroot[2]), mpz_clear(vroot[3]);
		if (success)
			return encval;
		else
			return NULL;
	}
}

const char *SchindelhauerTMCG::TMCG_SignData
	(const TMCG_SecretKey &key, const TMCG_DataString &data)
{
	size_t mdsize = gcry_md_get_algo_dlen (gcrypt_md_algorithm);
	size_t mnsize = mpz_sizeinbase (key.m, 2L) / 8;
	mpz_t foo, foo_sqrt[4];
	mpz_init (foo), mpz_init (foo_sqrt[0]), mpz_init (foo_sqrt[1]),
		mpz_init (foo_sqrt[2]), mpz_init (foo_sqrt[3]);
	
	// check that y \in Z*m
	assert (mpz_sizeinbase (key.m, 2L) > (mnsize * 8));
	assert (mnsize > (mdsize + rabin_k0));

	// WARNING: only a probabilistic algorithm (Rabin's signature scheme)
	// PRab from [Bellare, Rogaway: The Exact Security of Digital Signatures]
	do
	{
		char *r = new char[rabin_k0];
		gcry_randomize ((unsigned char*)r, rabin_k0, GCRY_STRONG_RANDOM);
		
		char *Mr = new char[data.length() + rabin_k0];
		memcpy (Mr, data.c_str(), data.length());
		memcpy (Mr + data.length(), r, rabin_k0);

		char *w = new char[mdsize];
		h(w, Mr, data.length() + rabin_k0);

		char *g12 = new char[mnsize];
		g(g12, mnsize - mdsize, w, mdsize);

		for (size_t i = 0; i < rabin_k0; i++)
			r[i] ^= g12[i];
		
		char *y = new char[mnsize];
		memcpy (y, w, mdsize);
		memcpy (y + mdsize, r, rabin_k0);
		memcpy (y + mdsize + rabin_k0,	g12 + rabin_k0,
			mnsize - mdsize - rabin_k0);
		mpz_import (foo, 1, -1, mnsize, 1, 0, y);

		delete [] y, delete [] g12, delete [] w, delete [] Mr, delete [] r;
	}
	while (!mpz_qrmn_p (foo, key.p, key.q, key.m));
	mpz_sqrtmn_fast_all (foo_sqrt[0], foo_sqrt[1], foo_sqrt[2], foo_sqrt[3], foo,
		key.p, key.q, key.m, key.gcdext_up, key.gcdext_vq, key.pa1d4, key.qa1d4);

	// choose square root randomly (one of four)
	mpz_srandomb (foo, NULL, 2L);

	TMCG_DataStream ost;
	ost << "sig|" << TMCG_ExportKeyID(key) << 
		"|" << foo_sqrt[mpz_get_ui (foo) % 4] << "|";
	mpz_clear (foo), mpz_clear (foo_sqrt[0]), mpz_clear (foo_sqrt[1]),
		mpz_clear (foo_sqrt[2]), mpz_clear (foo_sqrt[3]);

	str2 = ost.str();
	return str2.c_str();
}

bool SchindelhauerTMCG::TMCG_VerifyData
	(const TMCG_PublicKey &key, const TMCG_DataString &data,
	const TMCG_Signature &sig)
{
	mpz_t foo;
	string s = sig;
	
	mpz_init (foo);
	try
	{
		// check magic
		if (!cm(s, "sig", '|'))
			throw false;
		
		// check keyID
		if (!cm(s, TMCG_ExportKeyID(key), '|'))
			throw false;
		
		// value
		if ((mpz_set_str (foo, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		// verify signature
		size_t mdsize = gcry_md_get_algo_dlen (gcrypt_md_algorithm);
		size_t mnsize = mpz_sizeinbase (key.m, 2L) / 8;

		// check that y \in Z*m
		assert (mpz_sizeinbase (key.m, 2L) > (mnsize * 8));
		assert (mnsize > (mdsize + rabin_k0));
		
		mpz_mul (foo, foo, foo);
		mpz_mod (foo, foo, key.m);

		char *w = new char[mdsize], *r = new char[rabin_k0];
		char *gamma = new char[mnsize - mdsize - rabin_k0];
		char *y = new char[mnsize + 1024];
		size_t cnt = 1;
		mpz_export (y, &cnt, -1, mnsize, 1, 0, foo);
		memcpy (w, y, mdsize);
		memcpy (r, y + mdsize, rabin_k0);
		memcpy (gamma, y + mdsize + rabin_k0, mnsize - mdsize - rabin_k0);
		
		char *g12 = new char[mnsize];
		g(g12, mnsize - mdsize, w, mdsize);
		
		for (size_t i = 0; i < rabin_k0; i++)
			r[i] ^= g12[i];
		
		char *Mr = new char[data.length() + rabin_k0];
		memcpy (Mr, data.c_str(),	data.length());
		memcpy (Mr + data.length(),	r, rabin_k0);
		
		char *w2 = new char[mdsize];
		h(w2, Mr, data.length() + rabin_k0);
		
		bool ok = (memcmp (w, w2, mdsize) == 0) && 
			(memcmp (gamma, g12 + rabin_k0, mnsize - mdsize - rabin_k0) == 0);
		delete [] y, delete [] w, delete [] r, delete [] gamma, 
			delete [] g12, delete [] Mr, delete [] w2;
	
		throw ok;
	}		
	catch (bool return_value)
	{
		mpz_clear (foo);
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProofQuadraticResidue
	(const TMCG_SecretKey &key, mpz_srcptr t, istream &in, ostream &out)
{
	vector<mpz_ptr> rr, ss;
	mpz_t foo, bar, lej, t_sqrt;
	mpz_ui security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');

	mpz_init (foo), mpz_init (bar), mpz_init (lej);
	mpz_init (t_sqrt);
	try
	{
		// compute mpz_sqrtmn of t
		assert (mpz_qrmn_p (t, key.p, key.q, key.m));
		mpz_sqrtmn_fast (t_sqrt, t, key.p, key.q, key.m,
			key.gcdext_up, key.gcdext_vq, key.pa1d4, key.qa1d4);

		// phase (P2)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			mpz_ptr r = new mpz_t(), s = new mpz_t();
			mpz_init (r),	mpz_init (s);
			
			// choose random number r \in Z*m
			do
			{
				mpz_srandomm (r, NULL, key.m);
				mpz_gcd (lej, r, key.m);
			}
			while (mpz_cmp_ui (lej, 1L) || !mpz_cmp_ui (r, 1L));
			
			// compute s = t_sqrt * r_i^{-1} (mod m)
			ret = mpz_invert (s, r, key.m);
			assert(ret);
			mpz_mul (s, s, t_sqrt);
			mpz_mod (s, s, key.m);
			assert(mpz_cmp_ui (s, 1L));
			
			// compute R_i = r_i^2 (mod m), S_i = s_i^2 (mod m)
			mpz_mul (foo, r, r);
			mpz_mod (foo, foo, key.m);
			mpz_mul (bar, s, s);
			mpz_mod (bar, bar, key.m);
			
			// check congruence R_i * S_i \cong t (mod m)
			#ifndef NDEBUG
				mpz_mul (lej, foo, bar);
				mpz_mod (lej, lej, key.m);
				assert(mpz_congruent_p (t, lej, key.m));
			#endif

			// store r_i, s_i and send R_i, S_i to prover
			rr.push_back(r), ss.push_back(s);
			out << foo << endl, out << bar << endl;
		}
		
		// phase (P4)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			// receive R/S-question from verifier
			in >> foo;
			
			// send proof to verifier
			if (mpz_get_ui (foo) & 1L)
				out << rr[i] << endl;
			else
				out << ss[i] << endl;
		}
		
		// finish
		throw true;
	}
	catch (bool exception)
	{
		mpz_clear (foo), mpz_clear (bar), mpz_clear (lej);
		mpz_clear (t_sqrt);
		for (vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (vector<mpz_ptr>::iterator si = ss.begin(); si != ss.end(); si++)
			mpz_clear(*si), delete *si;
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyQuadraticResidue
	(const TMCG_PublicKey &key, mpz_srcptr t, istream &in, ostream &out)
{
	vector<mpz_ptr> RR, SS;
	mpz_t foo, bar, lej;
	out << TMCG_SecurityLevel << endl;
	
	// check for positive jacobi symbol	(t \in Z?)
	if (mpz_jacobi (t, key.m) != 1)
		return false;
	
	mpz_init (foo),	mpz_init (bar),	mpz_init (lej);
	try
	{
		// phase (V3)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			mpz_ptr R = new mpz_t(), S = new mpz_t();
			mpz_init (R), mpz_init (S);
			
			// receive R_i, S_i from prover and store values
			in >> R, in >> S;
			RR.push_back(R), SS.push_back(S);
			
			// check congruence R_i * S_i \cong t (mod m)
			mpz_mul (foo, S, R);
			mpz_mod (foo, foo, key.m);
			if (!mpz_congruent_p (t, foo, key.m))
				throw false;
		}
		
		// phase (V4)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			// send R/S-question to prover
			mpz_srandomb (foo, NULL, 1L);
			out << foo << endl;

			// receive proof
			in >> bar;
			
			// verify proof R_i = r_i^2 (mod m)  or  S_i = s_i^2 (mod m)
			mpz_mul (lej, bar, bar);
			mpz_mod (lej, lej, key.m);
			if (((mpz_get_ui (foo) & 1L) && 
				(mpz_cmp (lej, RR[i]) || !mpz_cmp_ui (bar, 1L))) ||
				(!(mpz_get_ui (foo) & 1L) && 
				(mpz_cmp (lej, SS[i]) || !mpz_cmp_ui (bar, 1L))))
					throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear (foo);
		mpz_clear (bar);
		mpz_clear (lej);
		for (vector<mpz_ptr>::iterator ri = RR.begin(); ri != RR.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (vector<mpz_ptr>::iterator si = SS.begin(); si != SS.end(); si++)
			mpz_clear(*si), delete *si;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProofNonQuadraticResidue
	(const TMCG_SecretKey &key, mpz_srcptr t, istream &in, ostream &out)
{
	mpz_t bar;
	mpz_init (bar);

	// compute bar = t * y^{-1} (mod m) and send it to verifier
	mpz_set (bar, t);
	mpz_mul (bar, bar, key.y1);
	mpz_mod (bar, bar, key.m);
	out << bar << endl;
	
	// QR-proof
	TMCG_ProofQuadraticResidue(key, bar, in, out);
	
	mpz_clear (bar);
	return;
}

bool SchindelhauerTMCG::TMCG_VerifyNonQuadraticResidue
	(const TMCG_PublicKey &key, mpz_srcptr t, istream &in, ostream &out)
{
	mpz_t foo, bar;
	
	mpz_init (foo);
	mpz_init (bar);
	try
	{
		// receive bar from prover
		in >> bar;
		
		// check congruence bar * y \cong t (mod m)
		mpz_mul (foo, bar, key.y);
		mpz_mod (foo, foo, key.m); 
		if (!mpz_congruent_p (t, foo, key.m))
			throw false;

		// verify QR-proof
		if (!TMCG_VerifyQuadraticResidue(key, bar, in, out))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear (foo);
		mpz_clear (bar);
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_MaskValue
	(const TMCG_PublicKey &key, mpz_srcptr z, mpz_ptr zz, 
	mpz_srcptr r, mpz_srcptr b)
{
	// compute zz = z * r^2 * y^b (mod m)
	mpz_mul (zz, r, r);
	mpz_mod (zz, zz, key.m);
	mpz_mul (zz, zz, z);
	mpz_mod (zz, zz, key.m);
	if (mpz_get_ui (b) & 1L)
	{
		mpz_mul (zz, zz, key.y);
		mpz_mod (zz, zz, key.m);
	}
	return;
}

void SchindelhauerTMCG::TMCG_ProofMaskValue
	(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz, 
	mpz_srcptr r, mpz_srcptr b, istream &in, ostream &out)
{
	vector<mpz_ptr> rr, bb;
	mpz_t foo, bar;
	mpz_ui security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');

	mpz_init (foo), mpz_init (bar);
	try
	{
		// phase (P2)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			mpz_ptr r2 = new mpz_t(), b2 = new mpz_t();
			mpz_init (r2), mpz_init (b2);
	
			// choose random number r_i \in Z*m and b_i \in {0,1}
			do
			{
				mpz_srandomm (r2, NULL, key.m);
				mpz_srandomb (b2, NULL, 1L);
				mpz_gcd (bar, r2, key.m);
			}
			while (mpz_cmp_ui (bar, 1L) || !mpz_cmp_ui(r2, 1L));
			rr.push_back(r2),	bb.push_back(b2);
			
			// compute foo = zz * r2^2 * y^b2 (mod m)
			mpz_mul (foo, r2, r2);
			mpz_mod (foo, foo, key.m);
			mpz_mul (foo, foo, zz);
			mpz_mod (foo, foo, key.m);
			if (mpz_get_ui (b2) & 1L)
			{
				mpz_mul (foo, foo, key.y);
				mpz_mod (foo, foo, key.m);
			}
			
			// send foo to verifier
			out << foo << endl;
		}

		// phase (P4)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			// receive Z/Z'-question from verifier
			in >> foo;
			
			// send proof to verifier
			if (mpz_get_ui (foo) & 1L)
			{
				out << rr[i] << endl, out << bb[i] << endl;
			}
			else
			{
				mpz_mul (foo, r, rr[i]);
				mpz_mod (foo, foo, key.m);
				if ((mpz_get_ui (b) & 1L) && (mpz_get_ui (bb[i]) & 1L))
				{
					mpz_mul (foo, foo, key.y);
					mpz_mod (foo, foo, key.m);
				}
				mpz_add (bar, b, bb[i]);
				if (!(mpz_get_ui (bar) & 1L))
					mpz_set_ui (bar, 0L);
				out << foo << endl, out << bar << endl;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool excpetion)
	{
		mpz_clear (foo), mpz_clear (bar);
		for (vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (vector<mpz_ptr>::iterator bi = bb.begin(); bi != bb.end(); bi++)
			mpz_clear(*bi), delete *bi;
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyMaskValue
	(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz,
	istream &in, ostream &out)
{
	vector<mpz_ptr> T;
	mpz_t foo, bar, lej;
	
	// send security parameter
	out << TMCG_SecurityLevel << endl;
	
	mpz_init (foo), mpz_init (bar), mpz_init (lej);
	try
	{
		// phase (V3)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			mpz_ptr t = new mpz_t();
			mpz_init (t);
			
			// receive t_i from prover and store value
			in >> t;
			T.push_back(t);
		}

		// phase (V4)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			// send Z/Z'-question to prover
			mpz_srandomb (foo, NULL, 1L);
			out << foo << endl;

			// receive proof (r, b)
			in >> bar, in >> lej;
			
			// verify proof, store result of TMCG_MaskValue() in foo
			if (mpz_get_ui (foo) & 1L)
				TMCG_MaskValue(key, zz, foo, bar, lej);
			else
				TMCG_MaskValue(key, z, foo, bar, lej);
			if (mpz_cmp (foo, T[i]) || !mpz_cmp_ui (bar, 1L))
				throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear (foo), mpz_clear (bar), mpz_clear (lej);
		for (vector<mpz_ptr>::iterator ti = T.begin(); ti != T.end(); ti++)
			mpz_clear(*ti), delete *ti;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProofMaskOne
	(const TMCG_PublicKey &key, mpz_srcptr r, mpz_srcptr b,
	istream &in, ostream &out)
{
	vector<mpz_ptr> rr, ss, bb, cc;
	mpz_t y1m, foo, bar;
	mpz_ui security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	// compute y1m = y^{-1} mod m
	mpz_init (y1m);
	ret = mpz_invert (y1m, key.y, key.m);
	assert (ret);
	
	mpz_init (foo), mpz_init (bar);
	try
	{
		// phase (P2)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			mpz_ptr r3 = new mpz_t(), s = new mpz_t(), 
				b3 = new mpz_t(), c = new mpz_t();
			mpz_init (r3),	mpz_init (s),	mpz_init (b3),	mpz_init (c);
			
			// choose random number r_i \in Z*m and b \in {0,1}
			do
			{
				mpz_srandomm (r3, NULL, key.m);
				mpz_srandomb (b3, NULL, 1L);
				mpz_gcd (foo, r3, key.m);
			}
			while (mpz_cmp_ui (foo, 1L) || !mpz_cmp_ui (r3, 1L));
			rr.push_back(r3), bb.push_back(b3);
			
			// compute c_i
			if (mpz_cmp (b, b3) == 0)
				mpz_set_ui (c, 0L);
			else
				mpz_set_ui (c, 1L);
			
			// compute s_i
			if ((mpz_cmp_ui (b, 0L) == 0) && (mpz_cmp_ui (b3, 1L) == 0))
			{
				ret = mpz_invert (s, r3, key.m);
				assert (ret);
				mpz_mul (s, s, y1m);
				mpz_mod (s, s, key.m);
				mpz_mul (s, s, r);
				mpz_mod (s, s, key.m);
			}
			else
			{
				ret = mpz_invert (s, r3, key.m);
				assert (ret);
				mpz_mul (s, s, r);
				mpz_mod (s, s, key.m);
			}
			
			// store s_i, c_i
			ss.push_back(s), cc.push_back(c);
			
			// compute R_i = {r_i}^2 * y^b (mod m), S_i = {s_i}^2 * y^{c_i} (mod m)
			mpz_mul (foo, r3, r3);
			mpz_mod (foo, foo, key.m);
			if (mpz_get_ui (b3) & 1L)
			{
				mpz_mul (foo, foo, key.y);
				mpz_mod (foo, foo, key.m);
			}
			mpz_mul (bar, s, s);
			mpz_mod (bar, bar, key.m);
			if (mpz_get_ui (c) & 1L)
			{
				mpz_mul (bar, bar, key.y);
				mpz_mod (bar, bar, key.m);
			}
			
			// check congruence R_i * S_i \cong t (mod m)
			#ifndef NDEBUG
				mpz_t lej, t;
				mpz_init (lej), mpz_init (t);
				mpz_mul (t, r, r);
				mpz_mod (t, t, key.m);
				if (mpz_get_ui (b) & 1L)
				{
					mpz_mul (t, t, key.y);
					mpz_mod (t, t, key.m);
				}
				mpz_mul (lej, foo, bar);
				mpz_mod (lej, lej, key.m);
				assert (mpz_congruent_p (t, lej, key.m));
				mpz_clear (lej), mpz_clear (t);
			#endif
			
			// send R_i, S_i to verifier
			out << foo << endl, out << bar << endl;
		}
		
		// phase (P4)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			// receive R/S-question from verifier
			in >> foo;

			// send proof to verifier
			if (mpz_get_ui (foo) & 1L)
				out << rr[i] << endl, out << bb[i] << endl;
			else
				out << ss[i] << endl, out << cc[i] << endl;	
		}
		
		// finish
		throw true;
	}
	catch (bool exception)
	{
		mpz_clear (y1m), mpz_clear (foo), mpz_clear (bar);
		for (vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (vector<mpz_ptr>::iterator bi = bb.begin(); bi != bb.end(); bi++)
			mpz_clear(*bi), delete *bi;
		for (vector<mpz_ptr>::iterator si = ss.begin(); si != ss.end(); si++)
			mpz_clear(*si), delete *si;
		for (vector<mpz_ptr>::iterator ci = cc.begin(); ci != cc.end(); ci++)
			mpz_clear(*ci), delete *ci;
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyMaskOne
	(const TMCG_PublicKey &key, mpz_srcptr t, istream &in, ostream &out)
{
	vector<mpz_ptr> RR, SS;
	mpz_t foo, bar, lej;

	// send security parameter
	out << TMCG_SecurityLevel << endl;
	
	mpz_init (foo), mpz_init (bar), mpz_init (lej);
	try
	{
		// phase (V3)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			mpz_ptr R = new mpz_t(), S = new mpz_t();
			mpz_init (R), mpz_init (S);
			
			// receive R_i, S_i from prover and store values
			in >> R, in >> S;
			RR.push_back(R), SS.push_back(S);

			// check congruence R_i * S_i \cong t (mod m)
			mpz_mul (foo, R, S);
			mpz_mod (foo, foo, key.m);
			if (!mpz_congruent_p (t, foo, key.m))
				throw false;
		}
		
		// phase (V4)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			// send R/S-question to prover
			mpz_srandomb (foo, NULL, 1L);
			out << foo << endl;
			
			// receive proof (r, b)
			in >> bar, in >> lej;
			
			// verify proof
			mpz_mul (lej, bar, bar);
			mpz_mod (lej, lej, key.m);
			if (mpz_get_ui (lej) & 1L)
			{
				mpz_mul (lej, lej, key.y);
				mpz_mod (lej, lej, key.m);
			}
			if (((mpz_get_ui (foo) & 1L) && 
				(mpz_cmp (lej, RR[i]) || !mpz_cmp_ui (bar, 1L))) ||
				(!(mpz_get_ui (foo) & 1L) && 
				(mpz_cmp (lej, SS[i]) || !mpz_cmp_ui (bar, 1L))))
					throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{	
		mpz_clear (foo), mpz_clear (bar), mpz_clear (lej);
		for (vector<mpz_ptr>::iterator ri = RR.begin(); ri != RR.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (vector<mpz_ptr>::iterator si = SS.begin(); si != SS.end(); si++)
			mpz_clear(*si), delete *si;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProofNonQuadraticResidue_PerfectZeroKnowledge
	(const TMCG_SecretKey &key, istream &in, ostream &out)
{
	TMCG_PublicKey key2;
	mpz_t foo, bar;
	mpz_ui security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	// extract public key
	TMCG_CreateKey(key2, key);

	mpz_init (foo), mpz_init (bar);
	try
	{
		// phase (P2) and (P3)
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			// receive question
			in >> foo;
			
			// verify proof of mask knowledge 1->foo
			if (TMCG_VerifyMaskOne(key2, foo, in, out))
			{
				if (mpz_qrmn_p (foo, key.p, key.q, key.m))
					mpz_set_ui (bar, 1L);
				else
					mpz_set_ui (bar, 0L);
				
				// send proof
				out << bar << endl;
			}
			else
				throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool exception)
	{
		TMCG_ReleaseKey(key2);
		mpz_clear (foo), mpz_clear (bar);
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyNonQuadraticResidue_PerfectZeroKnowledge
	(const TMCG_PublicKey &key, istream &in, ostream &out)
{	
	mpz_t foo, bar, r, b;
	
	// send security parameter
	out << TMCG_SecurityLevel << endl;
	
	mpz_init (foo), mpz_init (bar), mpz_init (r), mpz_init (b);
	try
	{
		// phase (V2) and (V3)
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			// choose random number r \in Z*m and b \in {0,1}
			do
			{
				mpz_srandomm (r, NULL, key.m);
				mpz_srandomb (b, NULL, 1L);
				mpz_gcd (foo, r, key.m);
			}
			while (mpz_cmp_ui (foo, 1L));
			
			// compute foo = r^2 * y^b (mod m)
			mpz_mul (foo, r, r);
			mpz_mod (foo, foo, key.m);
			if (mpz_get_ui (b) & 1L)
			{
				mpz_mul (foo, foo, key.y);
				mpz_mod (foo, foo, key.m);
			}
			
			// send question to prover
			out << foo << endl;
		
			// proof of mask knowledge 1->foo
			TMCG_ProofMaskOne(key, r, b, in, out);

			// receive proof
			in >> bar;
			
			// verify proof
			if (((mpz_get_ui (b) & 1L) && (mpz_get_ui (bar) & 1L)) ||
				(!(mpz_get_ui (b) & 1L) && !(mpz_get_ui (bar) & 1L)))
					throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear (foo), mpz_clear (bar),	mpz_clear (r), mpz_clear (b);
		return return_value;
	}
}	

// ============================================================================

void SchindelhauerTMCG::TMCG_CreateOpenCard
	(TMCG_Card &c, const TMCG_PublicKeyRing &ring, size_t type)
{
	c.Players = TMCG_Players, c.TypeBits = TMCG_TypeBits;
	for (size_t w = 0; w < TMCG_TypeBits; w++)
	{
		if (type & 1)
		{
			mpz_init_set (c.z[0][w], ring.key[0].y);
			--type, type /= 2;
		}
		else
		{
			mpz_init_set_ui (c.z[0][w], 1L);
			type /= 2;
		}
	}
	
	for (size_t k = 1; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_init_set_ui (c.z[k][w], 1L);
}

void SchindelhauerTMCG::TMCG_CreateOpenCard
(VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf, size_t type)
{
	mpz_set_ui(c.c_1, 1L);
	vtmf->IndexElement(c.c_2, type);
cerr << c.c_2 << endl;
cerr << "type = " << type << " mpz_jacobi = " << mpz_jacobi(c.c_2, vtmf->p) <<
	" bzw. mod q = " << mpz_jacobi(c.c_2, vtmf->q) << endl;
}

void SchindelhauerTMCG::TMCG_CreatePrivateCard
	(TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
	size_t index, size_t type)
{
	TMCG_Card oc;
	TMCG_CreateOpenCard(oc, ring, type);
	TMCG_CreateCardSecret(cs, ring, index);
	TMCG_MaskCard(oc, c, cs, ring);
	TMCG_ReleaseCard(oc);
}

void SchindelhauerTMCG::TMCG_CreatePrivateCard
	(VTMF_Card &c, VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf,
	size_t type)
{
	mpz_t m;

	mpz_init(m);
	vtmf->IndexElement(m, type);
cerr << m << endl;
	vtmf->VerifiableMaskingProtocol_Mask(m, c.c_1, c.c_2, cs.r);
cerr << "after mask -- type = " << type << " mpz_jacobi = " << mpz_jacobi(c.c_2, vtmf->p) <<
	" bzw. mod q = " << mpz_jacobi(c.c_2, vtmf->q) << endl;
	mpz_clear(m);
}

void SchindelhauerTMCG::TMCG_ReleaseCard
	(TMCG_Card &c)
{
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_clear(c.z[k][w]);
}

bool SchindelhauerTMCG::TMCG_ImportCard
	(TMCG_Card &c, const string &import)
{
	string s = import;

	try
	{
		// check magic
		if (!cm(s, "crd", '|'))
			throw false;

		// card description
		c.Players = TMCG_Players, c.TypeBits = TMCG_TypeBits;

		// card data
		for (size_t k = 0; k < TMCG_Players; k++)
		{
			for (size_t w = 0; w < TMCG_TypeBits; w++)
			{
				// z_ij
				if ((mpz_init_set_str (c.z[k][w], gs(s, '|'), MPZ_IO_BASE) < 0) || 
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

bool SchindelhauerTMCG::TMCG_ImportCard
	(VTMF_Card &c, const string &import)
{
	string s = import;

	try
	{
		// check magic
		if (!cm(s, "crd", '|'))
			throw false;
		
		// card data
		if ((mpz_set_str(c.c_1, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		if ((mpz_set_str(c.c_2, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_CreateCardSecret
	(TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring, size_t index)
{
	mpz_t foo;

	mpz_init (foo);
	cs.Players = TMCG_Players, cs.TypeBits = TMCG_TypeBits;
	for (size_t k = 0; k < TMCG_Players; k++)
	{
		for (size_t w = 0; w < TMCG_TypeBits; w++)
		{
			mpz_init (cs.r[k][w]), mpz_init (cs.b[k][w]);
			
			// choose random number r \in Z*m
			do
			{
				mpz_srandomm (cs.r[k][w], NULL, ring.key[k].m);
				mpz_gcd (foo, cs.r[k][w], ring.key[k].m);
			}
			while (mpz_cmp_ui (foo, 1L));
			
			// choose random bit b \in {0,1} or set it initially to zero
			if (k != index)
				mpz_srandomb (cs.b[k][w], NULL, 1L);
			else
				mpz_set_ui (cs.b[index][w], 0L);
		}
	}
	mpz_clear (foo);

	// XOR b_ij with i \neq index (keep type of card)
	for (size_t k = 0; k < TMCG_Players; k++)
	{
		for (size_t w = 0; (k != index) && (w < TMCG_TypeBits); w++)
		{
			if (mpz_get_ui (cs.b[index][w]) & 1L)
			{
				if (mpz_get_ui (cs.b[k][w]) & 1L)
					mpz_set_ui (cs.b[index][w], 0L);
				else
					mpz_set_ui (cs.b[index][w], 1L);
			}
			else
			{
				if (mpz_get_ui (cs.b[k][w]) & 1L)
					mpz_set_ui (cs.b[index][w], 1L);
				else
					mpz_set_ui (cs.b[index][w], 0L);
			}
		}
	}
}

void SchindelhauerTMCG::TMCG_CreateCardSecret
	(VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf)
{
	vtmf->VerifiableRemaskingProtocol_RemaskValue(cs.r);
}

void SchindelhauerTMCG::TMCG_CreateCardSecret
	(TMCG_CardSecret &cs, mpz_srcptr r, mpz_ui b)
{
	cs.Players = TMCG_Players, cs.TypeBits = TMCG_TypeBits;
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_init_set(cs.r[k][w], r), mpz_init_set_ui(cs.b[k][w], b);
}

void SchindelhauerTMCG::TMCG_ReleaseCardSecret
	(TMCG_CardSecret &cs)
{
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_clear(cs.r[k][w]), mpz_clear(cs.b[k][w]);
}

void SchindelhauerTMCG::TMCG_CopyCardSecret
	(const TMCG_CardSecret &cs, TMCG_CardSecret &cs2)
{
	cs2.Players = TMCG_Players, cs2.TypeBits = TMCG_TypeBits;
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_init_set (cs2.r[k][w], cs.r[k][w]),
			mpz_init_set (cs2.b[k][w], cs.b[k][w]);
}

void SchindelhauerTMCG::TMCG_CopyCardSecret
	(const VTMF_CardSecret &cs, VTMF_CardSecret &cs2)
{
	mpz_set(cs2.r, cs.r);
}

bool SchindelhauerTMCG::TMCG_ImportCardSecret
	(TMCG_CardSecret &cs, const string &import)
{
	string s = import;

	try
	{
		// check magic
		if (!cm(s, "crs", '|'))
			throw false;
		
		// public card data
		cs.Players = TMCG_Players, cs.TypeBits = TMCG_TypeBits;
		
		// secret card data
		for (size_t k = 0; k < TMCG_Players; k++)
		{
			for (size_t w = 0; w < TMCG_TypeBits; w++)
			{
				// r_ij
				if ((mpz_init_set_str (cs.r[k][w], gs(s, '|'), MPZ_IO_BASE) < 0) ||
					(!nx(s, '|')))
						throw false;
						
				// b_ij
				if ((mpz_init_set_str (cs.b[k][w], gs(s, '|'), MPZ_IO_BASE) < 0) ||
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

bool SchindelhauerTMCG::TMCG_ImportCardSecret
	(VTMF_CardSecret &cs, const string &import)
{
	string s = import;

	try
	{
		// check magic
		if (!cm(s, "crs", '|'))
			throw false;
		
		// secret card data
		if ((mpz_set_str(cs.r, gs(s, '|'), MPZ_IO_BASE) < 0) || (!nx(s, '|')))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_MaskCard
	(const TMCG_Card &c, TMCG_Card &cc, const TMCG_CardSecret &cs,
	const TMCG_PublicKeyRing &ring)
{
	cc.Players = TMCG_Players, cc.TypeBits = TMCG_TypeBits;
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_init (cc.z[k][w]), TMCG_MaskValue(ring.key[k],
				c.z[k][w], cc.z[k][w], cs.r[k][w], cs.b[k][w]);
}

void SchindelhauerTMCG::TMCG_MaskCard
	(const VTMF_Card &c, VTMF_Card &cc, const VTMF_CardSecret &cs,
	BarnettSmartVTMF_dlog *vtmf)
{
	vtmf->VerifiableRemaskingProtocol_Remask(c.c_1, c.c_2, cc.c_1, cc.c_2, cs.r);
cerr << "mask3 -- type = ? mpz_jacobi = " << mpz_jacobi(c.c_2, vtmf->p) <<
	" bzw. mod q = " << mpz_jacobi(c.c_2, vtmf->q) << endl;
}

bool SchindelhauerTMCG::TMCG_EqualCard
	(const TMCG_Card &c, const TMCG_Card &cc)
{
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			if (mpz_cmp(c.z[k][w], cc.z[k][w]) != 0)
				return false;
	return true;
}

bool SchindelhauerTMCG::TMCG_EqualCard
	(const VTMF_Card &c, const VTMF_Card &cc)
{
	if ((mpz_cmp(c.c_1, cc.c_1) != 0) || (mpz_cmp(c.c_2, cc.c_2) != 0))
		return false;
	return true;
}

void SchindelhauerTMCG::TMCG_CopyCard
	(const TMCG_Card &c, TMCG_Card &cc)
{
	cc.Players = TMCG_Players, cc.TypeBits = TMCG_TypeBits;
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			mpz_init_set(cc.z[k][w], c.z[k][w]);
}

void SchindelhauerTMCG::TMCG_CopyCard
	(const VTMF_Card &c, VTMF_Card &cc)
{
	mpz_set(cc.c_1, c.c_1), mpz_set(cc.c_2, c.c_2);
}

void SchindelhauerTMCG::TMCG_ProofMaskCard
	(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_CardSecret &cs,
	const TMCG_PublicKeyRing &ring,
	istream &in, ostream &out)
{
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			TMCG_ProofMaskValue(ring.key[k], c.z[k][w], cc.z[k][w],
				cs.r[k][w], cs.b[k][w], in, out);
}

void SchindelhauerTMCG::TMCG_ProofMaskCard
	(const VTMF_Card &c, const VTMF_Card &cc, const VTMF_CardSecret &cs,
	BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out)
{
	vtmf->VerifiableRemaskingProtocol_Prove(c.c_1, c.c_2, cc.c_1, cc.c_2,
		cs.r, out);
}

bool SchindelhauerTMCG::TMCG_VerifyMaskCard
	(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_PublicKeyRing &ring,
	istream &in, ostream &out)
{
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			if (!TMCG_VerifyMaskValue(ring.key[k], c.z[k][w], cc.z[k][w], in, out))
				return false;
	return true;
}

bool SchindelhauerTMCG::TMCG_VerifyMaskCard
	(const VTMF_Card &c, const VTMF_Card &cc, BarnettSmartVTMF_dlog *vtmf,
	istream &in, ostream &out)
{
	if (!vtmf->VerifiableRemaskingProtocol_Verify(c.c_1, c.c_2, cc.c_1,
		cc.c_2, in))
			return false;
	return true;
}

void SchindelhauerTMCG::TMCG_ProofPrivateCard
	(const TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
	istream &in, ostream &out)
{
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			TMCG_ProofMaskOne(ring.key[k], cs.r[k][w], cs.b[k][w], in, out);
	return;
}

bool SchindelhauerTMCG::TMCG_VerifyPrivateCard
	(const TMCG_Card &c, const TMCG_PublicKeyRing &ring,
	istream &in, ostream &out)
{	
	for (size_t k = 0; k < TMCG_Players; k++)
		for (size_t w = 0; w < TMCG_TypeBits; w++)
			if (!TMCG_VerifyMaskOne(ring.key[k], c.z[k][w], in, out))
				return false;
	return true;
}

void SchindelhauerTMCG::TMCG_ProofCardSecret
	(const TMCG_Card &c, const TMCG_SecretKey &key, size_t index,
	istream &in, ostream &out)
{
	mpz_t foo;

	mpz_init (foo);
	for (size_t w = 0; w < TMCG_TypeBits; w++)
	{
		if (mpz_qrmn_p(c.z[index][w], key.p, key.q, key.m))
		{
			mpz_set_ui(foo, 0L),	out << foo << endl;
			TMCG_ProofQuadraticResidue(key, c.z[index][w], in, out);
		}
		else
		{
			mpz_set_ui(foo, 1L),	out << foo << endl;
			TMCG_ProofNonQuadraticResidue(key, c.z[index][w], in, out);
		}
	}
	mpz_clear(foo);
}

void SchindelhauerTMCG::TMCG_ProofCardSecret
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
	istream &in, ostream &out)
{
	vtmf->VerifiableDecryptionProtocol_Prove(c.c_1, out);
}

bool SchindelhauerTMCG::TMCG_VerifyCardSecret
	(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKey &key,
	size_t index, istream &in, ostream &out)
{
	cs.Players = TMCG_Players, cs.TypeBits = TMCG_TypeBits;
	try
	{
		for (size_t w = 0; w < TMCG_TypeBits; w++)
		{
			mpz_init(cs.b[index][w]), in >> cs.b[index][w];
			mpz_init_set_ui(cs.r[index][w], 0L);
			if (mpz_get_ui(cs.b[index][w]) & 1L)
			{
				if (!TMCG_VerifyNonQuadraticResidue(key, c.z[index][w], in, out))
					throw false;
			}
			else
			{
				if (!TMCG_VerifyQuadraticResidue(key, c.z[index][w], in, out))
					throw false;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyCardSecret
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
	istream &in, ostream &out)
{
	if (!vtmf->VerifiableDecryptionProtocol_Verify_Update(c.c_1, in))
		return false;
	return true;
}

void SchindelhauerTMCG::TMCG_SelfCardSecret
	(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_SecretKey &key,
	size_t index)
{
	cs.Players = TMCG_Players, cs.TypeBits = TMCG_TypeBits;
	for (size_t w = 0; w < TMCG_TypeBits; w++)
	{
		mpz_init_set_ui(cs.r[index][w], 0L);
		if (mpz_qrmn_p(c.z[index][w], key.p, key.q, key.m))
			mpz_init_set_ui(cs.b[index][w], 0L);
		else
			mpz_init_set_ui(cs.b[index][w], 1L);
	}
}

void SchindelhauerTMCG::TMCG_SelfCardSecret
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf)
{
	vtmf->VerifiableDecryptionProtocol_Verify_Initalize(c.c_1);
}

size_t SchindelhauerTMCG::TMCG_TypeOfCard
	(const TMCG_CardSecret &cs)
{
	size_t type = 0, p2 = 1;
	for (size_t w = 0; w < TMCG_TypeBits; w++)
	{
		bool bit = false;
		for (size_t k = 0; k < TMCG_Players; k++)
		{
			if (mpz_get_ui(cs.b[k][w]) & 1L)
				bit = !bit;
		}
		if (bit)
			type += p2;
		p2 *= 2;
	}
	return type;
}

size_t SchindelhauerTMCG::TMCG_TypeOfCard
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf)
{
	size_t type = TMCG_MaxCards;
	mpz_t m, a;

	mpz_init_set_ui(m, 0L), mpz_init(a);
	vtmf->VerifiableDecryptionProtocol_Verify_Finalize(c.c_2, m);
	for (size_t t = 0; t < TMCG_MaxCards; t++)
	{
		vtmf->IndexElement(a, t);
		if (!mpz_cmp(a, m))
		{
			type = t;
			break;
		}	
	}
	mpz_clear(m), mpz_clear(a);

cerr << "TOC -- type = " << type << " mpz_jacobi = " << mpz_jacobi(c.c_2, vtmf->p) <<
	" bzw. mod q = " << mpz_jacobi(c.c_2, vtmf->q) << endl;

	return type;
}

// ============================================================================

size_t SchindelhauerTMCG::TMCG_CreateStackSecret
	(TMCG_StackSecret &ss, bool cyclic, const TMCG_PublicKeyRing &ring,
	size_t index, size_t size)
{
	if (size > TMCG_MAX_CARDS)
		return 0;

	size_t cyc = 0;
	mpz_t foo, bar;
	mpz_init (foo),	mpz_init_set_ui (bar, size);
	if (cyclic)
	{
		mpz_t cy;
		mpz_init (cy);
		mpz_srandomm (cy, NULL, bar);
		cyc = (size_t)mpz_get_ui (cy);
		mpz_clear (cy);
	}
	for (size_t i = 0; i < size; i++)
	{
		pair<size_t, TMCG_CardSecret*> lej;
		TMCG_CardSecret *cs = new TMCG_CardSecret();
		TMCG_CreateCardSecret(*cs, ring, index);
		
		// only cyclic shift
		if (cyclic)
		{
			mpz_set_ui (foo, i);
			mpz_add_ui (foo, foo, (mpz_ui)cyc);
			mpz_mod (foo, foo, bar);
		}
		// full permutation
		else
		{
			bool pi_ok;
			do
			{
				pi_ok = true;
				mpz_srandomm (foo, NULL, bar);
				for (TMCG_StackSecret::const_iterator ssi = ss.begin(); 
					ssi != ss.end(); ssi++)
						if (ssi->first == (size_t)(mpz_get_ui (foo)))
							pi_ok = false;
			}
			while (!pi_ok);
		}
		lej.first = (size_t)mpz_get_ui (foo), lej.second = cs;
		ss.push_back(lej);
	}
	mpz_clear (foo), mpz_clear (bar);
	return cyc;
}

size_t SchindelhauerTMCG::TMCG_CreateStackSecret
	(VTMF_StackSecret &ss, bool cyclic, size_t size, BarnettSmartVTMF_dlog *vtmf)
{
	if (size > TMCG_MAX_CARDS)
		return 0;

	size_t cyc = 0;
	mpz_t foo, bar;
	mpz_init(foo), mpz_init_set_ui(bar, size);
	if (cyclic)
	{
		mpz_t cy;
		mpz_init(cy);
		mpz_srandomm(cy, NULL, bar);
		cyc = (size_t)mpz_get_ui(cy);
		mpz_clear(cy);
	}
	for (size_t i = 0; i < size; i++)
	{
		pair<size_t, VTMF_CardSecret*> lej;
		VTMF_CardSecret *cs = new VTMF_CardSecret();
		TMCG_CreateCardSecret(*cs, vtmf);
		
		// only cyclic shift
		if (cyclic)
		{
			mpz_set_ui(foo, i);
			mpz_add_ui(foo, foo, (mpz_ui)cyc);
			mpz_mod(foo, foo, bar);
		}
		// full permutation
		else
		{
			bool pi_ok;
			do
			{
				pi_ok = true;
				mpz_srandomm(foo, NULL, bar);
				for (VTMF_StackSecret::const_iterator ssi = ss.begin(); 
					ssi != ss.end(); ssi++)
						if (ssi->first == (size_t)(mpz_get_ui(foo)))
							pi_ok = false;
			}
			while (!pi_ok);
		}
		lej.first = (size_t)mpz_get_ui(foo), lej.second = cs;
		ss.push_back(lej);
	}
	mpz_clear(foo), mpz_clear(bar);
	return cyc;
}

void SchindelhauerTMCG::TMCG_ReleaseStackSecret
	(TMCG_StackSecret &ss)
{
	for (TMCG_StackSecret::const_iterator si = ss.begin(); si != ss.end(); si++)
		TMCG_ReleaseCardSecret(*(si->second)), delete si->second;
	ss.clear();
}

void SchindelhauerTMCG::TMCG_ReleaseStackSecret
	(VTMF_StackSecret &ss)
{
	for (VTMF_StackSecret::const_iterator si = ss.begin(); si != ss.end(); si++)
		delete si->second;
	ss.clear();
}

bool SchindelhauerTMCG::TMCG_ImportStackSecret
	(TMCG_StackSecret &ss, const string &import)
{
	string s = import;
	size_t size = 0;
	char *ec;
	
	TMCG_ReleaseStackSecret(ss);
	try
	{
		// check magic
		if (!cm(s, "sts", '^'))
			throw false;
	
		// size of stack
		if (gs(s, '^') == NULL)
			throw false;
		size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (size <= 0) || (size > TMCG_MAX_CARDS) || 
			(!nx(s, '^')))
				throw false;
				
		// cards on stack
		for (size_t i = 0; i < size; i++)
		{
			// permutation index
			if (gs(s, '^') == NULL)
				throw false;
			size_t pi = (size_t)strtoul(gs(s, '^'), &ec, 10);
			if ((*ec != '\0') || (pi < 0) || (pi >= size) || (!nx(s, '^')))
				throw false;
			
			// card secret
			TMCG_CardSecret *cs = new TMCG_CardSecret();
			if (gs(s, '^') == NULL)
				throw false;
			if ((!TMCG_ImportCardSecret(*cs, gs(s, '^'))) || (!nx(s, '^')))
				throw false;
			
			pair<size_t, TMCG_CardSecret*> lej;
			lej.first = pi, lej.second = cs;
			ss.push_back(lej);
		}
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_ImportStackSecret
	(VTMF_StackSecret &ss, const string &import)
{
	string s = import;
	size_t size = 0;
	char *ec;
	
	TMCG_ReleaseStackSecret(ss);
	try
	{
		// check magic
		if (!cm(s, "sts", '^'))
			throw false;
		
		// size of stack
		if (gs(s, '^') == NULL)
			throw false;
		size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (size <= 0) || (size > TMCG_MAX_CARDS) || 
			(!nx(s, '^')))
				throw false;
		
		// cards on stack
		for (size_t i = 0; i < size; i++)
		{
			// permutation index
			if (gs(s, '^') == NULL)
				throw false;
			size_t pi = (size_t)strtoul(gs(s, '^'), &ec, 10);
			if ((*ec != '\0') || (pi < 0) || (pi >= size) || (!nx(s, '^')))
				throw false;
			
			// card secret
			VTMF_CardSecret *cs = new VTMF_CardSecret();
			if (gs(s, '^') == NULL)
				throw false;
			if ((!TMCG_ImportCardSecret(*cs, gs(s, '^'))) || (!nx(s, '^')))
				throw false;
			
			pair<size_t, VTMF_CardSecret*> lej;
			lej.first = pi, lej.second = cs;
			ss.push_back(lej);
		}
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_PushToStack
	(TMCG_Stack &s, const TMCG_Card &c)
{
	if (s.size() < TMCG_MAX_CARDS)
	{
		TMCG_Card *c2 = new TMCG_Card();
		TMCG_CopyCard(c, *c2);
		s.push_back(c2);
	}
}

void SchindelhauerTMCG::TMCG_PushToStack
	(VTMF_Stack &s, const VTMF_Card &c)
{
	if (s.size() < TMCG_MAX_CARDS)
	{
		VTMF_Card *c2 = new VTMF_Card();
		TMCG_CopyCard(c, *c2);
		s.push_back(c2);
	}
}

void SchindelhauerTMCG::TMCG_PushStackToStack
	(TMCG_Stack &s, const TMCG_Stack &s2)
{
	if ((s.size() + s2.size()) <= TMCG_MAX_CARDS)
	{
		for (TMCG_Stack::const_iterator si = s2.begin(); si != s2.end(); si++)
		{
			TMCG_Card *c2 = new TMCG_Card();
			TMCG_CopyCard(*(*si), *c2);
			s.push_back(c2);
		}
	}
}

void SchindelhauerTMCG::TMCG_PushStackToStack
	(VTMF_Stack &s, const VTMF_Stack &s2)
{
	if ((s.size() + s2.size()) <= TMCG_MAX_CARDS)
	{
		for (VTMF_Stack::const_iterator si = s2.begin(); si != s2.end(); si++)
		{
			VTMF_Card *c2 = new VTMF_Card();
			TMCG_CopyCard(*(*si), *c2);
			s.push_back(c2);
		}
	}
}

bool SchindelhauerTMCG::TMCG_PopFromStack
	(TMCG_Stack &s, TMCG_Card &c)
{
	if (!s.empty())
	{
		TMCG_CopyCard(*(s.back()), c);
		delete s.back();
		s.pop_back();
		return true;
	}
	else
		return false;
}

bool SchindelhauerTMCG::TMCG_PopFromStack
	(VTMF_Stack &s, VTMF_Card &c)
{
	if (!s.empty())
	{
		TMCG_CopyCard(*(s.back()), c);
		delete s.back();
		s.pop_back();
		return true;
	}
	else
		return false;
}

bool SchindelhauerTMCG::TMCG_IsInStack
	(const TMCG_Stack &s, const TMCG_Card &c)
{
	for (TMCG_Stack::const_iterator si = s.begin(); si != s.end(); si++)
		if (TMCG_EqualCard(*(*si), c))
			return true;
	return false;
}

bool SchindelhauerTMCG::TMCG_IsInStack
	(const VTMF_Stack &s, const VTMF_Card &c)
{
	for (VTMF_Stack::const_iterator si = s.begin(); si != s.end(); si++)
		if (TMCG_EqualCard(*(*si), c))
			return true;
	return false;
}

void SchindelhauerTMCG::TMCG_RemoveFirstFromStack
	(TMCG_Stack &s, const TMCG_Card &c)
{
	for (TMCG_Stack::iterator si = s.begin(); si != s.end(); si++)
	{
		// remove first card equal to c from stack s
		if (TMCG_EqualCard(*(*si), c))
		{
			TMCG_ReleaseCard(*(*si)),	delete *si;
			s.erase(si);
			return;
		}
	}
}

void SchindelhauerTMCG::TMCG_RemoveFirstFromStack
	(VTMF_Stack &s, const VTMF_Card &c)
{
	for (VTMF_Stack::iterator si = s.begin(); si != s.end(); si++)
	{
		// remove first card equal to c from stack s
		if (TMCG_EqualCard(*(*si), c))
		{
			delete *si;
			s.erase(si);
			return;
		}
	}
}

void SchindelhauerTMCG::TMCG_RemoveAllFromStack
	(TMCG_Stack &s, const TMCG_Card &c)
{
	TMCG_Stack::iterator si = s.begin();
	while (si != s.end())
	{
		// remove all cards equal to c from stack s
		if (TMCG_EqualCard(*(*si), c))
		{
			TMCG_ReleaseCard(*(*si)),	delete *si;
			si = s.erase(si);
		}
		else
			si++;
	}
}

void SchindelhauerTMCG::TMCG_RemoveAllFromStack
	(VTMF_Stack &s, const VTMF_Card &c)
{
	VTMF_Stack::iterator si = s.begin();
	while (si != s.end())
	{
		// remove all cards equal to c from stack s
		if (TMCG_EqualCard(*(*si), c))
		{
			delete *si;
			si = s.erase(si);
		}
		else
			si++;
	}
}

void SchindelhauerTMCG::TMCG_ReleaseStack
	(TMCG_Stack &s)
{
	for (TMCG_Stack::const_iterator si = s.begin(); si != s.end(); si++)
		TMCG_ReleaseCard(*(*si)), delete *si;
	s.clear();
}

void SchindelhauerTMCG::TMCG_ReleaseStack
	(VTMF_Stack &s)
{
	for (VTMF_Stack::const_iterator si = s.begin(); si != s.end(); si++)
		delete *si;
	s.clear();
}

bool SchindelhauerTMCG::TMCG_ImportStack
	(TMCG_Stack &s2, const string &import)
{
	string s = import;
	size_t size = 0;
	char *ec;
	
	TMCG_ReleaseStack(s2);
	try
	{
		// check magic
		if (!cm(s, "stk", '^'))
			throw false;
		
		// size of stack
		if (gs(s, '^') == NULL)
			throw false;
		size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (size <= 0) || (size > TMCG_MAX_CARDS) || 
			(!nx(s, '^')))
				throw false;
				
		// cards on stack
		for (size_t i = 0; i < size; i++)
		{
			TMCG_Card *c = new TMCG_Card();
			if (gs(s, '^') == NULL)
				throw false;
			if ((!TMCG_ImportCard(*c, gs(s, '^'))) || (!nx(s, '^')))
				throw false;
			s2.push_back(c);
		}
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_ImportStack
	(VTMF_Stack &s2, const string &import)
{
	string s = import;
	size_t size = 0;
	char *ec;
	
	TMCG_ReleaseStack(s2);
	try
	{
		// check magic
		if (!cm(s, "stk", '^'))
			throw false;
		
		// size of stack
		if (gs(s, '^') == NULL)
			throw false;
		size = strtoul(gs(s, '^'), &ec, 10);
		if ((*ec != '\0') || (size <= 0) || (size > TMCG_MAX_CARDS) || 
			(!nx(s, '^')))
				throw false;
		
		// cards on stack
		for (size_t i = 0; i < size; i++)
		{
			VTMF_Card *c = new VTMF_Card();
			if (gs(s, '^') == NULL)
				throw false;
			if ((!TMCG_ImportCard(*c, gs(s, '^'))) || (!nx(s, '^')))
				throw false;
			s2.push_back(c);
		}
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_CopyStack 
	(const TMCG_Stack &s, TMCG_Stack &s2)
{
	TMCG_ReleaseStack(s2);
	for (TMCG_Stack::const_iterator si = s.begin(); si != s.end(); si++)
		TMCG_PushToStack(s2, *(*si));
}

void SchindelhauerTMCG::TMCG_CopyStack 
	(const VTMF_Stack &s, VTMF_Stack &s2)
{
	TMCG_ReleaseStack(s2);
	for (VTMF_Stack::const_iterator si = s.begin(); si != s.end(); si++)
		TMCG_PushToStack(s2, *(*si));
}

bool SchindelhauerTMCG::TMCG_EqualStack
	(const TMCG_Stack &s, const TMCG_Stack &s2)
{
	if (s.size() != s2.size())
		return false;
	for (size_t i = 0; i < s.size(); i++)
		if (!TMCG_EqualCard(*(s[i]), *(s2[i])))
			return false;
	return true;
}

bool SchindelhauerTMCG::TMCG_EqualStack
	(const VTMF_Stack &s, const VTMF_Stack &s2)
{
	if (s.size() != s2.size())
		return false;
	for (size_t i = 0; i < s.size(); i++)
		if (!TMCG_EqualCard(*(s[i]), *(s2[i])))
			return false;
	return true;
}

void SchindelhauerTMCG::TMCG_MixStack
	(const TMCG_Stack &s, TMCG_Stack &s2, const TMCG_StackSecret &ss,
	const TMCG_PublicKeyRing &ring)
{
	assert (s.size() != 0), assert (s.size() == ss.size());
	
	// mask all cards, mix and build new stack
	TMCG_ReleaseStack(s2);
	for (size_t i = 0; i < s.size(); i++)
	{
		TMCG_Card *c = new TMCG_Card();
		TMCG_MaskCard(*(s[ss[i].first]), *c, *(ss[ss[i].first].second), ring);
		s2.push_back(c);
	}
}

void SchindelhauerTMCG::TMCG_MixStack
	(const VTMF_Stack &s, VTMF_Stack &s2, const VTMF_StackSecret &ss,
	BarnettSmartVTMF_dlog *vtmf)
{
	assert(s.size() != 0), assert(s.size() == ss.size());
	
	// mask all cards, mix and build new stack
	TMCG_ReleaseStack(s2);
	for (size_t i = 0; i < s.size(); i++)
	{
		VTMF_Card *c = new VTMF_Card();
		TMCG_MaskCard(*(s[ss[i].first]), *c, *(ss[ss[i].first].second), vtmf);
		s2.push_back(c);
	}
}

void SchindelhauerTMCG::TMCG_GlueStackSecret
	(const TMCG_StackSecret &sigma, TMCG_StackSecret &pi,
	const TMCG_PublicKeyRing &ring)
{
	assert (sigma.size() == pi.size());

	TMCG_StackSecret ss3;
	for (size_t i = 0; i < sigma.size(); i++)
	{
		pair<size_t, TMCG_CardSecret*> lej;
		TMCG_CardSecret *cs = new TMCG_CardSecret();
		TMCG_CreateCardSecret(*cs, ring, 0);
		size_t sigma_idx = i, pi_idx = 0;
		for (size_t j = 0; j < pi.size(); j++)
			if (sigma[j].first == i)
				pi_idx = j;
		for (size_t k = 0; k < TMCG_Players; k++)
		{
			for (size_t w = 0; w < TMCG_TypeBits; w++)
			{
				// compute r
				mpz_mul (cs->r[k][w], (sigma[sigma_idx].second)->r[k][w], 
					(pi[pi_idx].second)->r[k][w]);
				mpz_mod (cs->r[k][w], cs->r[k][w], ring.key[k].m);
				if ((mpz_get_ui((sigma[sigma_idx].second)->b[k][w]) & 1L) &&
					(mpz_get_ui((pi[pi_idx].second)->b[k][w]) & 1L))
				{
					mpz_mul (cs->r[k][w], cs->r[k][w], ring.key[k].y);
					mpz_mod (cs->r[k][w], cs->r[k][w], ring.key[k].m);
				}
				
				// XOR
				if (mpz_get_ui((sigma[sigma_idx].second)->b[k][w]) & 1L)
				{
					if (mpz_get_ui((pi[pi_idx].second)->b[k][w]) & 1L)
						mpz_set_ui (cs->b[k][w], 0L);
					else
						mpz_set_ui (cs->b[k][w], 1L);
				}
				else
				{
					if (mpz_get_ui((pi[pi_idx].second)->b[k][w]) & 1L)
						mpz_set_ui (cs->b[k][w], 1L);
					else
						mpz_set_ui (cs->b[k][w], 0L);
				}
			}
		}	
		lej.first = sigma[pi[i].first].first,	lej.second = cs;
		ss3.push_back(lej);
	}	
	TMCG_ReleaseStackSecret(pi);
	for (size_t i = 0; i < ss3.size(); i++)
		pi.push_back(ss3[i]);
}

void SchindelhauerTMCG::TMCG_GlueStackSecret
	(const VTMF_StackSecret &sigma, VTMF_StackSecret &pi,
	BarnettSmartVTMF_dlog *vtmf)
{
	assert(sigma.size() == pi.size());

	VTMF_StackSecret ss3;
	for (size_t i = 0; i < sigma.size(); i++)
	{
		pair<size_t, VTMF_CardSecret*> lej;
		VTMF_CardSecret *cs = new VTMF_CardSecret();
		size_t sigma_idx = i, pi_idx = 0;
		for (size_t j = 0; j < pi.size(); j++)
			if (sigma[j].first == i)
				pi_idx = j;
		mpz_add(cs->r, (sigma[sigma_idx].second)->r, (pi[pi_idx].second)->r);
		mpz_mod(cs->r, cs->r, vtmf->q);
		lej.first = sigma[pi[i].first].first,	lej.second = cs;
		ss3.push_back(lej);
	}	
	TMCG_ReleaseStackSecret(pi);
	for (size_t i = 0; i < ss3.size(); i++)
		pi.push_back(ss3[i]);
}

void SchindelhauerTMCG::TMCG_ProofStackEquality
	(const TMCG_Stack &s, const TMCG_Stack &s2, const TMCG_StackSecret &ss,
	bool cyclic, const TMCG_PublicKeyRing &ring, size_t index,
	istream &in, ostream &out)
{
	assert (s.size() == s2.size()),	assert (s.size() == ss.size());

	mpz_t foo;
	mpz_ui security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init (foo);
	try
	{
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			TMCG_Stack s3;
			TMCG_StackSecret ss2;
			
			// create and mix stack
			TMCG_CreateStackSecret(ss2, cyclic, ring, index, s.size());
			TMCG_MixStack(s2, s3, ss2, ring);
			
			// send stack
			out << s3 << endl;
			
			// receive question
			in >> foo;
			
			// send proof
			if (!(mpz_get_ui (foo) & 1L))
				TMCG_GlueStackSecret(ss, ss2, ring);
			out << ss2 << endl;
			
			// release stack
			TMCG_ReleaseStack(s3);
			TMCG_ReleaseStackSecret(ss2);
		}
		
		// finish
		throw true;
	}
	catch (bool exception)
	{
		mpz_clear (foo);
		return;
	}
}

void SchindelhauerTMCG::TMCG_ProofStackEquality
	(const VTMF_Stack &s, const VTMF_Stack &s2, const VTMF_StackSecret &ss,
	bool cyclic, BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out)
{
	assert(s.size() == s2.size()), assert(s.size() == ss.size());

	mpz_t foo;
	mpz_ui security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init (foo);
	try
	{
		for (mpz_ui i = 0; i < security_desire; i++)
		{
			VTMF_Stack s3;
			VTMF_StackSecret ss2;
			
			// create and mix stack
			TMCG_CreateStackSecret(ss2, cyclic, s.size(), vtmf);
			TMCG_MixStack(s2, s3, ss2, vtmf);
			
			// send stack
			out << s3 << endl;
			
			// receive question
			in >> foo;
			
			// send proof
			if (!(mpz_get_ui(foo) & 1L))
				TMCG_GlueStackSecret(ss, ss2, vtmf);
			out << ss2 << endl;
			
			// release stack
			TMCG_ReleaseStack(s3);
			TMCG_ReleaseStackSecret(ss2);
		}
		
		// finish
		throw true;
	}
	catch (bool exception)
	{
		mpz_clear(foo);
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyStackEquality
	(const TMCG_Stack &s, const TMCG_Stack &s2, bool cyclic,
	const TMCG_PublicKeyRing &ring, istream &in, ostream &out)
{
	mpz_t foo;

	out << TMCG_SecurityLevel << endl;

	if (s.size() != s2.size())
		return false;
		
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	mpz_init (foo);
	try
	{
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			TMCG_Stack s3, s4;
			TMCG_StackSecret ss;
			mpz_srandomb (foo, NULL, 1L);
			
			// receive stack
			in.getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!TMCG_ImportStack(s3, tmp))
			{
				TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
				TMCG_ReleaseStackSecret(ss);
				throw false;
			}
			
			// send R/S-question to prover
			out << foo << endl;
			
			// receive proof
			in.getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!TMCG_ImportStackSecret(ss, tmp))
			{
				TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
				TMCG_ReleaseStackSecret(ss);
				throw false;
			}
			
			// verify equality proof
			if (mpz_get_ui (foo) & 1L)
				TMCG_MixStack(s2, s4, ss, ring);
			else
				TMCG_MixStack(s, s4, ss, ring);
			if (!TMCG_EqualStack(s3, s4))
			{
				TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
				TMCG_ReleaseStackSecret(ss);
				throw false;
			}
			
			// verify cyclic shift
			if (cyclic)
			{
				size_t cy = ss[0].first;
				for (size_t j = 1; j < ss.size(); j++)
					if (((++cy) % ss.size()) != ss[j].first)
						throw false;
			}
			
			// free
			TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
			TMCG_ReleaseStackSecret(ss);
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear (foo);
		delete [] tmp;
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyStackEquality
	(const VTMF_Stack &s, const VTMF_Stack &s2, bool cyclic,
	BarnettSmartVTMF_dlog *vtmf, istream &in, ostream &out)
{
	mpz_t foo;

	out << TMCG_SecurityLevel << endl;
	
	if (s.size() != s2.size())
		return false;
	
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	mpz_init(foo);
	try
	{
		for (mpz_ui i = 0; i < TMCG_SecurityLevel; i++)
		{
			VTMF_Stack s3, s4;
			VTMF_StackSecret ss;
			mpz_srandomb(foo, NULL, 1L);
			
			// receive stack (commitment)
			in.getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!TMCG_ImportStack(s3, tmp))
			{
				TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
				TMCG_ReleaseStackSecret(ss);
				throw false;
			}
			
			// send R/S-question to prover (challenge)
			out << foo << endl;
			
			// receive proof (response)
			in.getline(tmp, TMCG_MAX_STACK_CHARS);
			if (!TMCG_ImportStackSecret(ss, tmp))
			{
				TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
				TMCG_ReleaseStackSecret(ss);
				throw false;
			}
			
			// verify equality proof
			if (mpz_get_ui(foo) & 1L)
				TMCG_MixStack(s2, s4, ss, vtmf);
			else
				TMCG_MixStack(s, s4, ss, vtmf);
			if (!TMCG_EqualStack(s3, s4))
			{
				TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
				TMCG_ReleaseStackSecret(ss);
				throw false;
			}
			
			// verify cyclic shift
			if (cyclic)
			{
				size_t cy = ss[0].first;
				for (size_t j = 1; j < ss.size(); j++)
					if (((++cy) % ss.size()) != ss[j].first)
						throw false;
			}
			
			// release stacks
			TMCG_ReleaseStack(s4), TMCG_ReleaseStack(s3);
			TMCG_ReleaseStackSecret(ss);
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		delete [] tmp;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_PushToOpenStack
	(TMCG_OpenStack &os, const TMCG_Card &c, size_t type)
{
	if (os.size() < TMCG_MAX_CARDS)
	{
		pair<size_t, TMCG_Card*> lej;
		TMCG_Card *c2 = new TMCG_Card();
		
		TMCG_CopyCard(c, *c2);
		lej.first = type, lej.second = c2;
		os.push_back(lej);
	}
}

void SchindelhauerTMCG::TMCG_PushToOpenStack
	(VTMF_OpenStack &os, const VTMF_Card &c, size_t type)
{
	if (os.size() < TMCG_MAX_CARDS)
	{
		pair<size_t, VTMF_Card*> lej;
		VTMF_Card *c2 = new VTMF_Card();
		
		TMCG_CopyCard(c, *c2);
		lej.first = type, lej.second = c2;
		os.push_back(lej);
	}
}

void SchindelhauerTMCG::TMCG_PushOpenStackToOpenStack
	(TMCG_OpenStack &os, const TMCG_OpenStack &os2)
{
	for (TMCG_OpenStack::const_iterator oi = os2.begin(); oi != os2.end(); oi++)
	{
		pair<size_t, TMCG_Card*> lej;
		TMCG_Card *c2 = new TMCG_Card();
		
		TMCG_CopyCard(*(oi->second), *c2);
		lej.first = oi->first, lej.second = c2;
		os.push_back(lej);
	}
}

void SchindelhauerTMCG::TMCG_PushOpenStackToOpenStack
	(VTMF_OpenStack &os, const VTMF_OpenStack &os2)
{
	for (VTMF_OpenStack::const_iterator oi = os2.begin(); oi != os2.end(); oi++)
	{
		pair<size_t, VTMF_Card*> lej;
		VTMF_Card *c2 = new VTMF_Card();
		
		TMCG_CopyCard(*(oi->second), *c2);
		lej.first = oi->first, lej.second = c2;
		os.push_back(lej);
	}
}

size_t SchindelhauerTMCG::TMCG_PopFromOpenStack
	(TMCG_OpenStack &os, TMCG_Card &c)
{
	if (!os.empty())
	{
		size_t type = (os.back()).first;
		
		TMCG_CopyCard(*((os.back()).second), c);
		delete (os.back()).second;
		os.pop_back();
		return type;
	}
	// return 'error code'
	return (1 << TMCG_TypeBits);
}

size_t SchindelhauerTMCG::TMCG_PopFromOpenStack
	(VTMF_OpenStack &os, VTMF_Card &c)
{
	if (!os.empty())
	{
		size_t type = (os.back()).first;
		
		TMCG_CopyCard(*((os.back()).second), c);
		delete (os.back()).second;
		os.pop_back();
		return type;
	}
	// return 'error code'
	return (1 << TMCG_TypeBits);
}

bool SchindelhauerTMCG::TMCG_IsInOpenStack
	(const TMCG_OpenStack &os, size_t check_type)
{
	for (TMCG_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		if (oi->first == check_type)
			return true;
	return false;
}

bool SchindelhauerTMCG::TMCG_IsInOpenStack
	(const VTMF_OpenStack &os, size_t check_type)
{
	for (VTMF_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		if (oi->first == check_type)
			return true;
	return false;
}

void SchindelhauerTMCG::TMCG_MoveFromOpenStackToStack
	(TMCG_OpenStack &os, TMCG_Stack &s, size_t check_type)
{
	for (TMCG_OpenStack::iterator oi = os.begin(); oi != os.end(); oi++)
	{
		if (oi->first == check_type)
		{
			TMCG_PushToStack(s, *(oi->second));
			TMCG_ReleaseCard(*(oi->second));
			delete oi->second;
			os.erase(oi);
			return;
		}
	}
}

void SchindelhauerTMCG::TMCG_MoveFromOpenStackToStack
	(VTMF_OpenStack &os, VTMF_Stack &s, size_t check_type)
{
	for (VTMF_OpenStack::iterator oi = os.begin(); oi != os.end(); oi++)
	{
		if (oi->first == check_type)
		{
			TMCG_PushToStack(s, *(oi->second));
			delete oi->second;
			os.erase(oi);
			return;
		}
	}
}

void SchindelhauerTMCG::TMCG_ReleaseOpenStack
	(TMCG_OpenStack &os)
{
	for (TMCG_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		TMCG_ReleaseCard(*(oi->second)), delete oi->second;
	os.clear();
}

void SchindelhauerTMCG::TMCG_ReleaseOpenStack
	(VTMF_OpenStack &os)
{
	for (VTMF_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		delete oi->second;
	os.clear();
}

void SchindelhauerTMCG::TMCG_CopyOpenStack 
	(const TMCG_OpenStack &os, TMCG_OpenStack &os2)
{
	TMCG_ReleaseOpenStack(os2);
	for (TMCG_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		TMCG_PushToOpenStack(os2, *(oi->second), oi->first);
}

void SchindelhauerTMCG::TMCG_CopyOpenStack 
	(const VTMF_OpenStack &os, VTMF_OpenStack &os2)
{
	TMCG_ReleaseOpenStack(os2);
	for (VTMF_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		TMCG_PushToOpenStack(os2, *(oi->second), oi->first);
}

void SchindelhauerTMCG::TMCG_MixOpenStack
	(const TMCG_OpenStack &os, TMCG_OpenStack &os2,
	const TMCG_StackSecret &ss, const TMCG_PublicKeyRing &ring)
{
	assert (os.size() != 0), assert (os.size() == ss.size());

	// mask all cards, mix and build new open stack
	TMCG_ReleaseOpenStack(os2);
	for (size_t i = 0; i < os.size(); i++)
	{
		pair<size_t, TMCG_Card*> lej;
		TMCG_Card *c = new TMCG_Card();
		
		TMCG_MaskCard(*(os[ss[i].first].second), *c, 
			*(ss[ss[i].first].second), ring);
		lej.first = os[ss[i].first].first, lej.second = c;
		os2.push_back(lej);
	}
}

void SchindelhauerTMCG::TMCG_MixOpenStack
	(const VTMF_OpenStack &os, VTMF_OpenStack &os2,
	const VTMF_StackSecret &ss, BarnettSmartVTMF_dlog *vtmf)
{
	assert(os.size() != 0), assert(os.size() == ss.size());

	// mask all cards, mix and build new open stack
	TMCG_ReleaseOpenStack(os2);
	for (size_t i = 0; i < os.size(); i++)
	{
		pair<size_t, VTMF_Card*> lej;
		VTMF_Card *c = new VTMF_Card();
		
		TMCG_MaskCard(*(os[ss[i].first].second), *c, 
			*(ss[ss[i].first].second), vtmf);
		lej.first = os[ss[i].first].first, lej.second = c;
		os2.push_back(lej);
	}
}

void SchindelhauerTMCG::TMCG_ExtractStack
	(const TMCG_OpenStack &os, TMCG_Stack &s)
{
	TMCG_ReleaseStack(s);
	for (TMCG_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		TMCG_PushToStack(s, *(oi->second));
}

void SchindelhauerTMCG::TMCG_ExtractStack
	(const VTMF_OpenStack &os, VTMF_Stack &s)
{
	TMCG_ReleaseStack(s);
	for (VTMF_OpenStack::const_iterator oi = os.begin(); oi != os.end(); oi++)
		TMCG_PushToStack(s, *(oi->second));
}
