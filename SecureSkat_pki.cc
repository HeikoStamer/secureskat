/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#include "SecureSkat_pki.hh"

std::string get_passphrase
	(const std::string &prompt)
{
	std::string pass_phrase;
	struct termios old_term, new_term;
	
	// disable echo on stdin
	if (tcgetattr(fileno(stdin), &old_term) < 0)
	{
		perror("SecureSkat_pki::get_passphrase (tcgetattr)");
		exit(-1);
	}
	new_term = old_term;
	new_term.c_lflag &= ~(ECHO | ISIG);
	new_term.c_lflag |= ECHONL;
	if (tcsetattr(fileno(stdin), TCSANOW, &new_term) < 0)
	{
		perror("SecureSkat_pki::get_passphrase (tcsetattr)");
		exit(-1);
	}
	// read pass phrase
	std::cout << prompt.c_str() << ": ";
	std::getline(std::cin, pass_phrase);
	// enable echo on stdin
	if (tcsetattr(fileno(stdin), TCSANOW, &old_term) < 0)
	{
		perror("SecureSkat_pki::get_passphrase (tcsetattr)");
		exit(-1);
	}
	
	return std::string(pass_phrase);
}

void decrypt_secret_key
	(datum data, unsigned char *key)
{
	gcry_cipher_hd_t handle;
	gcry_error_t err = 0;
	
	err = gcry_cipher_open(&handle, GCRY_CIPHER_BLOWFISH, 
		GCRY_CIPHER_MODE_CFB, 0);
	if (err)
	{
		std::cerr << "SecureSkat_pki::decrypt_secret_key (gcry_cipher_open): "
			<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
		exit(-1);
	}
	
	err = gcry_cipher_setkey(handle, key, 16);
	if (err)
	{
		std::cerr << "SecureSkat_pki::decrypt_secret_key (gcry_cipher_setkey): "
			<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
		exit(-1);
	}
	
	err = gcry_cipher_decrypt(handle, (unsigned char*)data.dptr, 
		data.dsize, NULL, 0);
	if (err)
	{
		std::cerr << "SecureSkat_pki::decrypt_secret_key (gcry_cipher_decrypt): "
			<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
		exit(-1);
	}
	
	gcry_cipher_close(handle);
}

void encrypt_secret_key
	(datum data, unsigned char *key)
{
	gcry_cipher_hd_t handle;
	gcry_error_t err = 0;
	
	err = gcry_cipher_open(&handle, GCRY_CIPHER_BLOWFISH, 
		GCRY_CIPHER_MODE_CFB, 0);
	if (err)
	{
		std::cerr << "SecureSkat_pki::encrypt_secret_key (gcry_cipher_open): "
			<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
		exit(-1);
	}
	
	err = gcry_cipher_setkey(handle, key, 16);
	if (err)
	{
		std::cerr << "SecureSkat_pki::encrypt_secret_key (gcry_cipher_setkey): "
			<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
		exit(-1);
	}
	
	err = gcry_cipher_encrypt(handle, (unsigned char*)data.dptr, 
		data.dsize, NULL, 0);
	if (err)
	{
		std::cerr << "SecureSkat_pki::encrypt_secret_key (gcry_cipher_encrypt): "
				<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
		exit(-1);
	}
	
	gcry_cipher_close(handle);
}

void get_secret_key
	(const std::string &filename, TMCG_SecretKey &sec, std::string &prefix)
{
	assert(gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO));
	assert(gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO) >= 
		gcry_cipher_get_algo_keylen(GCRY_CIPHER_BLOWFISH));
	
	std::string key_str;
	std::ostringstream ost;
	datum key, data;
	
	// open GDBM file where the secret key is stored
	GDBM_FILE sec_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (sec_db != NULL)
	{
		// key is stored at the first entry of the GDBM file
		key = gdbm_firstkey(sec_db);
		if (key.dptr)
		{
			// fetch entry from GDBM file
			data = gdbm_fetch(sec_db, key);
			// get the salt value
			key_str = key.dptr;
			
			// check whether the entry is encrypted
			std::string pass_phrase = "";
			if (memcmp(data.dptr, "sec", 3))
			    pass_phrase =
				get_passphrase(_("Enter the pass phrase to unlock your key"));
						
			// decrypt entry with a pass phrase supplied by the user
			if (pass_phrase != "")
			{
				unsigned int dlen = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
				unsigned char *pass_digest = new unsigned char[dlen];
				
				// key derivation function PBKDF1 from RCF2898
				// compute T_1 = hash(password || salt)
				unsigned char *T_i = new unsigned char[dlen];
				std::string input = pass_phrase + key_str;
				gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, T_i,
					input.c_str(), input.length());
				// use PBKDF1 with iteration count = 7000
				// compute T_2, ..., T_7000
				for (size_t i = 1; i < 7000; i++)
				{
				    gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, pass_digest, 
					T_i, dlen);
				    memcpy(T_i, pass_digest, dlen);
				}
				decrypt_secret_key(data, pass_digest);
				delete [] T_i;
				delete [] pass_digest;
			}
			
			// convert (decrypted) entry for importing as key
			ost << data.dptr;
			
			free(data.dptr);
			free(key.dptr);
		}
		else
		{
			// sync GDBM file physically
			gdbm_sync(sec_db);
			
			// create a secret key
			std::string name, email, keyid, osttmp;
			std::cout << _("Your nickname") << ": ";
			std::getline(std::cin, name);
			std::cout << _("Your electronic mail address") << ": ";
			std::getline(std::cin, email);
			std::cerr << _("Creating your key.") << " " <<
				_("Please wait") << std::flush;
			while (1)
			{
				// create a 1024-bit non-NIZK TMCG key
				TMCG_SecretKey tmpsec(name, email, 1024, false);
				if (tmpsec.check())
				{
					sec = tmpsec;
					break;
				}
			}
			ost << sec;
			
			// set pointers of the new entry
			keyid = sec.keyid(5);
			key.dptr = (char*)keyid.c_str(); // salt value
			key.dsize = keyid.length() + 1;
			osttmp = ost.str();
			data.dptr = (char*)osttmp.c_str();
			data.dsize = osttmp.length() + 1;
			
			// encrypt secret key with a pass phrase supplied by the user
			std::string pass_phrase, pass_retyped;
			do
			{
				pass_phrase = 
					get_passphrase(_("Enter a pass phrase to protect your secret key"));
				if (pass_phrase == "")
				{
					std::cerr << _("Empty pass phrase. Key protection disabled!") <<
						std::endl;
					break;
				}
				pass_retyped =
					get_passphrase(_("Repeat your pass phrase"));
				if (pass_phrase != pass_retyped)
					std::cerr << _("Your pass phrases differ.") << " " <<
						_("Please repeat carefully!") << std::endl;
			}
			while (pass_phrase != pass_retyped);
			
			// use key derivation function PBKDF1 from RCF2898
			if (pass_phrase != "")
			{
				unsigned int dlen = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
				unsigned char *pass_digest = new unsigned char[dlen];
				// compute T_1 = hash(password || salt)
				unsigned char *T_i = new unsigned char[dlen];
				std::string input = pass_phrase + keyid;
				gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, T_i, 
				    input.c_str(), input.length());
				// use PBKDF1 with iteration count = 7000
				// compute T_2, ..., T_7000
				for (size_t i = 1; i < 7000; i++)
				{
					gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, pass_digest, 
						T_i, dlen);
					memcpy(T_i, pass_digest, dlen);
				}
				delete [] T_i;
				encrypt_secret_key(data, pass_digest);
				delete [] pass_digest;
			}
			
			// store (encrypted) entry in GDBM file at the first position
			gdbm_store(sec_db, key, data, GDBM_INSERT);
			std::cout << _("PKI: cryptographic key") << " \"" << keyid <<
				"\" " << _("created and stored") << std::endl;
		}
		gdbm_close(sec_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_pki::get_secret_key (gdbm_open)");
		exit(-1);
	}
	
	if (!sec.import(ost.str()))
	{
		std::cerr << _("PKI ERROR: secret key corrupted") << 
			" [" << key_str << "]" << std::endl;
		exit(-1);
	}
	else
	{
#ifndef NDEBUG
		std::cout << _("PKI: secret key successfully loaded") << 
			" [" << key_str << "]" << std::endl;
#endif
	}
	
	prefix = sec.keyid(5);
	size_t ei = prefix.find("^", 0);
	if (ei == prefix.npos)
	{
		std::cerr << _("PKI ERROR: identification prefix unknown") << std::endl;
		exit(-1);
	}
	else
		prefix = prefix.substr(0, ei + 1);
}

void get_public_keys
	(const std::string &filename, std::map<std::string, TMCG_PublicKey> &keys)
{
	datum key, nextkey, data;
	GDBM_FILE pub_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (pub_db != NULL)
	{
		key = gdbm_firstkey(pub_db);
		while (key.dptr)
		{
			TMCG_PublicKey pkey;
			data = gdbm_fetch(pub_db, key);
			if (pkey.import(data.dptr))
				keys[key.dptr] = pkey;
			else
				std::cerr << _("PKI ERROR: public key corrupted") <<
					" [" << key.dptr << "]" << std::endl;
			nextkey = gdbm_nextkey(pub_db, key);
			free(data.dptr);
			free(key.dptr);
			key = nextkey;
		}
		gdbm_close(pub_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_pki::get_public_keys (gdbm_open)");
		exit(-1);
	}
}

void set_public_keys
	(const std::string &filename,
	const std::map<std::string, TMCG_PublicKey> &keys)
{
	datum key, data;
	GDBM_FILE pub_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (pub_db != NULL)
	{
		for (std::map<std::string, TMCG_PublicKey>::const_iterator
			pi = keys.begin(); pi != keys.end(); pi++)
		{
			key.dptr = (char*)(pi->first).c_str();
			key.dsize = (pi->first).length() + 1;
			if (!gdbm_exists(pub_db, key))
			{
				std::ostringstream ost;
				ost << pi->second;
				std::string osttmp = ost.str();
				data.dptr = (char*)osttmp.c_str();
				data.dsize = osttmp.length() + 1;
				gdbm_store(pub_db, key, data, GDBM_INSERT);
			}
		}
		gdbm_close(pub_db);
	}
	else
	{
		std::cerr << _("GDBM ERROR") << ": " << gdbm_strerror(gdbm_errno) <<
			std::endl;
		perror("SecureSkat_pki::set_public_keys (gdbm_open)");
		exit(-1);
	}
}

void create_pki
	(int &pki7771_port, int &pki7771_handle)
{
	pki7771_port = BindEmptyPort(7771);
	if ((pki7771_handle = ListenToPort(pki7771_port)) < 0)
		exit(-1);
}

void release_pki
	(int pki7771_handle)
{
	CloseHandle(pki7771_handle);
}
