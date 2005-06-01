/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2005  Heiko Stamer <stamer@gaos.org>

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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include "SecureSkat_pki.hh"

std::string get_passphrase
	(const std::string &prompt)
{
	std::string pass_phrase;
	struct termios old_term, new_term;
	
	if (tcgetattr(fileno(stdin), &old_term) < 0)
	{
		perror("SecureSkat_pki::get_passphrase (tcgetattr)");
		exit(-1);
	}
	new_term = old_term;
	new_term.c_lflag &= ~(ECHO|ISIG);
	if (tcsetattr(fileno(stdin), TCSANOW, &new_term) < 0)
	{
		perror("SecureSkat_pki::get_passphrase (tcsetattr)");
		exit(-1);
	}
	std::cout << prompt.c_str() << ": ";
	std::getline(std::cin, pass_phrase);
	std::cout << std::endl;
	if (tcsetattr(fileno(stdin), TCSANOW, &old_term) < 0)
	{
		perror("SecureSkat_pki::get_passphrase (tcsetattr)");
		exit(-1);
	}
	
	return std::string(pass_phrase);
}

void get_secret_key
	(const std::string &filename, TMCG_SecretKey &sec, std::string &prefix)
{
	std::string key_str;
	std::ostringstream ost, ost2;
	datum key, data;
	GDBM_FILE sec_db = 
		gdbm_open((char*)filename.c_str(), 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, 0);
	if (sec_db != NULL)
	{
		key = gdbm_firstkey(sec_db);
		if (key.dptr)
		{
			// fetch secret key from the GDBM file (first entry)
			data = gdbm_fetch(sec_db, key);
			
			// encrypted?
			std::string pass_phrase = "";
			ost2 << data.dptr;
			if (!sec.import(ost2.str()))
			{
				pass_phrase =
					get_passphrase(_("Enter the pass phrase to unlock your key"));
			}
			
			// decrypt the secret key with a pass phrase entered by the user
			if (pass_phrase != "")
			{
				assert(gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO));
				char *pass_digest = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
				gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, pass_digest,
					pass_phrase.c_str(), pass_phrase.length());
				
				gcry_cipher_hd_t handle;
				gcry_error_t err = 0;
				
				err = gcry_cipher_open(&handle, GCRY_CIPHER_BLOWFISH,
					GCRY_CIPHER_MODE_CFB, 0);
				if (err)
				{
					std::cerr << "SecureSkat_pki::get_secret_key (gcry_cipher_open): "
						<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
					exit(-1);
				}
				
				err = gcry_cipher_setkey(handle, pass_digest, 16);
				if (err)
				{
					std::cerr << "SecureSkat_pki::get_secret_key (gcry_cipher_setkey): "
						<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
					exit(-1);
				}
				
				err = gcry_cipher_decrypt(handle, (unsigned char*)data.dptr,
					data.dsize, NULL, 0);
				if (err)
				{
					std::cerr << "SecureSkat_pki::get_secret_key (gcry_cipher_decrypt): "
						<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
					exit(-1);
				}
				
				gcry_cipher_close(handle);
				delete [] pass_digest;
			}
			
			// convert (decrypted) secret key for importing
			ost << data.dptr;
			key_str = key.dptr;
			
			free(data.dptr);
			free(key.dptr);
		}
		else
		{
			// sync the GDBM file physically
			gdbm_sync(sec_db);
			
			// create a fresh secret key
			std::string name, email, keyid, osttmp;
			std::cout << _("Your nickname") << ": ";
			std::getline(std::cin, name);
			std::cout << _("Your electronic mail address") << ": ";
			std::getline(std::cin, email);
			std::cerr << _("Creating your key. Please wait") << std::flush;
			while (1)
			{
				TMCG_SecretKey tmpsec(name, email);
				if (tmpsec.check())
				{
					sec = tmpsec;
					break;
				}
				else
					std::cerr << "*" << std::flush;
			}
			ost << sec;
			
			keyid = sec.keyid();
			key.dptr = (char*)keyid.c_str();
			key.dsize = keyid.length() + 1;
			osttmp = ost.str();
			data.dptr = (char*)osttmp.c_str();
			data.dsize = osttmp.length() + 1;
			
			// encrypt the secret key with a pass phrase entered by the user
			std::string pass_phrase, pass_retyped;
			do
			{
				pass_phrase = 
					get_passphrase(_("Enter a pass phrase to protect your secret key"));
				if (pass_phrase == "")
				{
					std::cerr << _("Empty pass phrase. Encryption disabled!") <<
						std::endl;
					break;
				}
				pass_retyped =
					get_passphrase(_("Retype your pass phrase"));
				if (pass_phrase != pass_retyped)
					std::cerr << _("Your pass phrases differ.") << " " <<
						_("Please repeat carefully!") << std::endl;
			}
			while (pass_phrase != pass_retyped);
			
			if (pass_phrase != "")
			{
				assert(gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO));
				char *pass_digest = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
				gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, pass_digest,
					pass_phrase.c_str(), pass_phrase.length());
				
				gcry_cipher_hd_t handle;
				gcry_error_t err = 0;
				
				err = gcry_cipher_open(&handle, GCRY_CIPHER_BLOWFISH,
					GCRY_CIPHER_MODE_CFB, 0);
				if (err)
				{
					std::cerr << "SecureSkat_pki::get_secret_key (gcry_cipher_open): "
						<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
					exit(-1);
				}
				
				err = gcry_cipher_setkey(handle, pass_digest, 16);
				if (err)
				{
					std::cerr << "SecureSkat_pki::get_secret_key (gcry_cipher_setkey): "
						<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
					exit(-1);
				}
				
				err = gcry_cipher_encrypt(handle, (unsigned char*)data.dptr,
					data.dsize, NULL, 0);
				if (err)
				{
					std::cerr << "SecureSkat_pki::get_secret_key (gcry_cipher_decrypt): "
						<< gcry_strsource(err) << "/" << gcry_strerror(err) << std::endl;
					exit(-1);
				}
				
				gcry_cipher_close(handle);
				delete [] pass_digest;
			}
			
			// store the encrypted secret key in the GDBM file (first entry)
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
	
	prefix = sec.keyid();
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
	long socket_option = 1;
	struct sockaddr_in sin7771;
	sin7771.sin_addr.s_addr = htonl(INADDR_ANY);
	sin7771.sin_family = AF_INET;
	
	if ((pki7771_handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_pki::create_pki (socket)");
		exit(-1);
	}
	if (setsockopt(pki7771_handle, SOL_SOCKET, SO_REUSEADDR, &socket_option,
		sizeof(socket_option)) < 0)
	{
		perror("SecureSkat_pki::create_pki (setsockopt)");
		exit(-1);
	}
	pki7771_port = BindEmptyPort(7771);
	sin7771.sin_port = htons(pki7771_port);
	if (bind(pki7771_handle, (struct sockaddr*)&sin7771, sizeof(sin7771)) < 0)
	{
		perror("SecureSkat_pki::create_pki (bind)");
		exit(-1);
	}
	if (listen(pki7771_handle, SOMAXCONN) < 0)
	{
		perror("SecureSkat_pki::create_pki (listen)");
		exit(-1);
	}
}

void release_pki
	(int pki7771_handle)
{
	if (close(pki7771_handle) < 0)
		perror("SecureSkat_pki::release_pki (close)");
}
