/*******************************************************************************
   BarnettSmartVTMF_dlog.hh, Verifiable l-out-of-l Threshold Masking Function

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
             Statements about Discrete Logarithms', technical report, 1997

     [CS00]  Ronald Cramer, Victor Shoup: 'Signature schemes based on the
             strong RSA assumption', ACM Transactions on Information and
             System Security, Vol.3(3), pp. 161--185, 2000

     [RS00]  Jean-Francois Raymond, Anton Stiglic: 'Security Issues in the
             Diffie-Hellman Key Agreement Protocol', ZKS technical report
             http://citeseer.ist.psu.edu/455251.html

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

#ifndef INCLUDED_BarnettSmartVTMF_dlog_HH
	#define INCLUDED_BarnettSmartVTMF_dlog_HH

	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif

	// C and STL header
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
	
	#include "mpz_srandom.h"

class BarnettSmartVTMF_dlog
{
	private:
		static const int		gcrypt_md_algorithm = GCRY_MD_RMD160;
		
		static const unsigned long int		group_size = 1024;
		static const unsigned long int		exponent_size = 160;
		
	public:
		mpz_t								p, q, g;
		mpz_t								x_i, h_i, h, d;
		
		BarnettSmartVTMF_dlog
			();
		BarnettSmartVTMF_dlog
			(std::istream &in);
		bool CheckGroup
			();
		void PublishGroup
			(std::ostream &out);
		void RandomElement
			(mpz_ptr a);
		void IndexElement
			(mpz_ptr a, std::size_t index);
		void KeyGenerationProtocol_GenerateKey
			();
		void KeyGenerationProtocol_PublishKey
			(std::ostream &out);
		bool KeyGenerationProtocol_UpdateKey
			(std::istream &in);
		void CP_Prove
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
			mpz_srcptr alpha, std::ostream &out);
		bool CP_Verify
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
			std::istream &in);
		void VerifiableMaskingProtocol_Mask
			(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r);
		void VerifiableMaskingProtocol_Prove
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr r,
			std::ostream &out);
		bool VerifiableMaskingProtocol_Verify
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, std::istream &in);
		void VerifiableRemaskingProtocol_Mask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_ptr r);
		void VerifiableRemaskingProtocol_RemaskValue
			(mpz_ptr r);
		void VerifiableRemaskingProtocol_Remask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_srcptr r);
		void VerifiableRemaskingProtocol_Prove
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
			mpz_srcptr r, std::ostream &out);
		bool VerifiableRemaskingProtocol_Verify
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
			std::istream &in);
		void VerifiableDecryptionProtocol_Prove
			(mpz_srcptr c_1, std::ostream &out);
		void VerifiableDecryptionProtocol_Verify_Initalize
			(mpz_srcptr c_1);
		bool VerifiableDecryptionProtocol_Verify_Update
			(mpz_srcptr c_1, std::istream &in);
		void VerifiableDecryptionProtocol_Verify_Finalize
			(mpz_srcptr c_2, mpz_ptr m);
		~BarnettSmartVTMF_dlog
			();

		// friendly iostream operators 
		// FIXME: currently << and >> are insufficent defined by <gmpxx.h>
		friend std::ostream& operator<< 
			(std::ostream &out, mpz_srcptr value)
		{
			char *tmp = new char[10000];
			out << mpz_get_str(tmp, MPZ_IO_BASE, value);
			delete [] tmp;
			return out;
		}

		friend std::istream& operator>> 
			(std::istream &in, mpz_ptr value)
		{
			char *tmp = new char[10000];
			in.getline(tmp, 10000);
			if (mpz_set_str(value, tmp, MPZ_IO_BASE) < 0)
				mpz_set_ui(value, 0L);
			delete [] tmp;
			return in;
		}
};

#endif
