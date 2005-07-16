/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 1999, 2000 Kevin Birch <kbirch@pobox.com>,
               2002, 2004 Heiko Stamer <stamer@gaos.org>

   SecureSkat is free software; you can redistribute it and/or modify
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

#ifndef INCLUDED_securesocketstream_HH
	#define INCLUDED_securesocketstream_HH

/*!
 * @module securesocketstream
 * @author Kevin Birch <kbirch@pobox.com>, Heiko Stamer <stamer@gaos.org>
 * @version 1.0, 11/05/02
 * This C++ class is designed to allow the use of BSD-style socket 
 * descriptors (with encryption/compression) by iostream applications.
 */

/*!
 * @struct securesocketbuf_traits
 * This structure defines the behavior of the socketstream class.<P>
 * If you wish to modify the behavior of socketstream, you should 
 * subclass this struct and change the return values of its methods.
 * @method buffer_output
 * @return true of output is buffered
 * @method o_write_sz
 * @return maximum size in bytes of the temporary write buffer (send)
 * (o_write_sz should be greater than 0.1% o_buffer_sz plus 12 byte)
 * @method o_buffer_sz
 * @return maximum size in bytes of the output buffer
 * @method i_read_sz
 * @return maximum size in bytes of the temporary read buffer (recv)
 * @method i_buffer_sz
 * @return maximum size in bytes of the input buffer 
 * (i_buffer_sz should be greater than decompressed data from the
 * temporary buffer of recv)
 * @method putback_sz
 * @return size in bytes of the putback area (input buffer), used by unget
 */

struct securesocketbuf_traits
{
	static inline bool buffer_output()
	{
		return true;
	}
	static inline size_t o_write_sz()
	{
		return 1024;
	}
	static inline size_t o_buffer_sz()
	{
		return 512;
	}
	static inline size_t i_read_sz()
	{
		return 512;
	}
	static inline size_t i_buffer_sz()
	{
		return 8192;
	}
	static inline size_t putback_sz()
	{
		return 4;
	}
};

/*!
 * @typedef int_type
 * used by basic_socketbuf to comply with streambuf
 */
typedef int int_type;

/*!
 * @class basic_socketbuf
 * This is the class that drives the ability to attach a socket to an iostream.
 * It handles input and output buffers, and reading from and writing to the
 * network
 */
template <class traits = securesocketbuf_traits>
	class basic_securesocketbuf : public std::streambuf 
{
	protected:
		int mSocket;				/*! @member mSocket the socket to operate on */
		char *mRBuffer;				/*! @member mRBuffer the read buffer */
		char *mWBuffer;				/*! @member mWBuffer the write buffer */
		gcry_cipher_hd_t chd_in;	/*! @member chd_in cipher handle for reading */
		gcry_cipher_hd_t chd_out;	/*! @member chd_out cipher handle for writing */
		gcry_error_t err;			/*! @member err the gcry error return code */
		z_stream zs_out;			/*! @member zs_out zlib compression stream */
		z_stream zs_in;				/*! @member zs_in zlib uncompression stream */
		int zerr;					/*! @member zerr the zlib error return code */

	public:
		typedef traits traits_type;	/*! @typedef traits_type for clients */

		/*! @method basic_securesocketbuf
		 * The primary constructor, which takes an open socket as first argument
		 * @param iSocket an open and connected socket
		 */
		basic_securesocketbuf(int iSocket, 
			const char *key_in, size_t size_in, const char *key_out, size_t size_out
		) : mSocket(iSocket) 
		{
			err = gcry_cipher_open(&chd_in,
				GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB, 0);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_cipher_open() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				exit(-1);
			}
			
			err = gcry_cipher_setkey(chd_in, key_in, size_in);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_cipher_setkey() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				exit(-1);
			}
			
			err = gcry_cipher_open(&chd_out,
				GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB, 0);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_cipher_open() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				exit(-1);
			}
			
			err = gcry_cipher_setkey(chd_out, key_out, size_out);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_cipher_setkey() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				exit(-1);
			}
			
			static const char* myZlibVersion = ZLIB_VERSION;
			if (zlibVersion()[0] != myZlibVersion[0])
			{
				std::cerr << "zlib: incompatible zlib version" << std::endl;
				exit(-1);
			}
			else if (std::strcmp(zlibVersion(), ZLIB_VERSION) != 0)
				std::cerr << "zlib: WARNING -- different zlib version" << std::endl;
			
			zs_in.zalloc = (alloc_func)0, zs_out.zalloc = (alloc_func)0;
			zs_in.zfree = (free_func)0, zs_out.zfree = (free_func)0;
			zs_in.opaque = (voidpf)0, zs_out.opaque = (voidpf)0;
			
			zerr = deflateInit(&zs_out, Z_DEFAULT_COMPRESSION);
			if (zerr)
			{
				std::cerr << "zlib: deflateInit() failed with error " << zerr
					<< std::endl;
				exit(-1);
			}
			
			zerr = inflateInit(&zs_in);
			if (zerr)
			{
				std::cerr << "zlib: inflateInit() failed with error " << zerr
					<< std::endl;
				exit(-1);
			}
			
			mRBuffer = new char[traits_type::i_buffer_sz()];
			mWBuffer = new char[traits_type::o_buffer_sz()];
			if(traits_type::buffer_output()) 
				setp(mWBuffer, mWBuffer + (traits_type::o_buffer_sz() - 1));
			char *pos = mRBuffer + traits_type::putback_sz();
			setg(pos, pos, pos);
		}
		
		/*! @method ~basic_securesocketbuf()
		 * The destructor
		 */
		~basic_securesocketbuf() 
		{
		  deflateEnd(&zs_out), inflateEnd(&zs_in);
			gcry_cipher_close(chd_in), gcry_cipher_close(chd_out);
			delete [] mRBuffer, delete [] mWBuffer;
			sync();
		}
	
	protected:
		/*! @method flushOutput
		 * flushes the write buffer to the network, and resets the write buffer 
		 * head pointer
		 * @return number of bytes written to the network
		 */
		int flushOutput() 
		{
			int num = pptr() - pbase();
			
			if (num == 0)
				return 0;
			
			Byte *cbuf = new Byte[traits_type::o_write_sz()];
			uLong clen = zs_out.total_out;
			zs_out.next_in  = (Bytef*)mWBuffer;
			zs_out.avail_in = (uInt)num;
			zs_out.next_out = cbuf;
			zs_out.avail_out = (uInt)traits_type::o_write_sz();
			zerr = deflate(&zs_out, Z_SYNC_FLUSH);
			if (zerr || (zs_out.avail_in != 0) || (zs_out.avail_out == 0))
			{
				std::cerr << "zlib: deflate() failed with error " << zerr
					<< std::endl;
				exit(-1);
			}
			clen = zs_out.total_out - clen;
			
			err = gcry_cipher_encrypt(chd_out, (unsigned char*)cbuf, clen, NULL, 0);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_cipher_encrypt() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				exit(-1);
			}
			
			int ret = send(mSocket, (unsigned char*)cbuf, clen, 0);
			delete [] cbuf;
			if ((unsigned int)ret != clen)
				return EOF;
			pbump(-num);
			return num;
		}
		
		/*! @method overflow
		 * called by std::streambuf when the write buffer is full
		 * @param c the character that overflowed the write buffer
		 * @return the character that overflowed the write buffer
		 */
		virtual int_type overflow(int_type c)
		{
			if (traits_type::buffer_output())
			{
				*pptr() = c;
				pbump(1);
				if (flushOutput() == EOF)
					return EOF;
				return c;
			}
			else 
				return EOF;
		}
		
		/*! @method sync
		 * called by std::strambuf when the endl or flush operators are used
		 * @return -1 if the write buffer flush failed
		 */
		virtual int sync()
		{
			if (flushOutput() == EOF)
				return -1;
			return 0;
		}
		
		/*! @method xsputn
		 * called by std::streambuf to write a buffer to the output device
		 * @param s the buffer to be written
		 * @param num the size of s
		 * @return the number of bytes written
		 */
		virtual std::streamsize xsputn(const char *s, std::streamsize num) 
		{
			if (num <= 0)
				return 0;
			
			size_t bufsiz = traits_type::o_write_sz();
			if ((size_t)(num + 12) >= traits_type::o_write_sz())
				bufsiz += num;
			Byte *cbuf = new Byte[bufsiz];
			uLong clen = zs_out.total_out;
			zs_out.next_in  = (Bytef*)s;
			zs_out.avail_in = (uInt)num;
			zs_out.next_out = (Byte*)cbuf;
			zs_out.avail_out = (uInt)bufsiz;
			zerr = deflate(&zs_out, Z_SYNC_FLUSH);
			if (zerr || (zs_out.avail_in != 0) || (zs_out.avail_out == 0))
			{
				std::cerr << "zlib: deflate() failed with error " << zerr
					<< std::endl;
				exit(-1);
			}
			clen = zs_out.total_out - clen;
			
			err = gcry_cipher_encrypt(chd_out, (unsigned char*)cbuf, clen, NULL, 0);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_cipher_encrypt() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				exit(-1);
			}
			
			int ret = send(mSocket, (unsigned char*)cbuf, clen, 0);
			delete [] cbuf;
			if ((unsigned int)ret != clen)
				return ret;
			return num;
		}
		
		/*! @method underflow
		 * called by std::streambuf when the read buffer is empty
		 * @return the next character to be read or EOF on failure
		 */
		virtual int_type underflow()
		{
			if (gptr() < egptr())
				return *gptr();
			
			size_t numPutBack = gptr() - eback();
			if (numPutBack > traits_type::putback_sz())
				numPutBack = traits_type::putback_sz();
			std::memcpy(mRBuffer + (traits_type::putback_sz() - numPutBack),
				gptr() - numPutBack, numPutBack);
			
			int count = 0;
			while (1)
			{
				Byte *cbuf = new Byte[traits_type::i_read_sz()];
				count = recv(mSocket, 
					(unsigned char*)cbuf, traits_type::i_read_sz(), 0);
				
				if ((count == 0) || (count == -1))
				{
					delete [] cbuf;
					if ((count == -1) && (errno == EAGAIN || errno == EINTR))
						continue;
					return EOF;
				}
				else
				{
					err = gcry_cipher_decrypt(chd_in,
						(unsigned char*)cbuf, count, NULL, 0);
					if (err)
					{
						std::cerr << "libgcrypt: gcry_cipher_decrypt() failed"
							<< std::endl << gcry_strerror(err) << std::endl;
						exit(-1);
					}
					
					uLong clen = zs_in.total_out;
					zs_in.next_in = (Bytef*)cbuf;
					zs_in.avail_in = (uInt)count;
					zs_in.next_out = (Byte*)(mRBuffer + traits_type::putback_sz());
					zs_in.avail_out = (uInt)(traits_type::i_buffer_sz() - 
						traits_type::putback_sz());
					zerr = inflate(&zs_in, Z_SYNC_FLUSH);
					if (zerr)
					{
						std::cerr << "zlib: inflate() failed with error " << zerr
							<< std::endl;
						exit(-1);
					}
					count = zs_in.total_out - clen;
					delete [] cbuf;
					
					if (count == 0)
						continue;
					else
						break;
				}
			}
			setg(mRBuffer + (traits_type::putback_sz() - numPutBack), 
				mRBuffer + traits_type::putback_sz(), 
				mRBuffer + traits_type::putback_sz() + count);
			return *gptr();
		}
};

/*! @typedef socketbuf
 * make the name socketbuf a basic_socketbuf with the default traits
 */
typedef basic_securesocketbuf<> securesocketbuf;

/*! @class isecuresocketstream
 * An istream subclass that uses a socketbuf. Create one if you wish to
 * have a read-only socket attached to an istream.
 */
class isecuresocketstream : public std::istream
{
	protected:
		securesocketbuf buf; /*! @member buf the securesocketbuf */
	
	public:
		/*! @method isecuresocktream
		 * The primary constructor, which takes an open socket as first argument
		 * @param iSocket an open and connected socket
		 */
		isecuresocketstream
			(int iSocket, const char *key_in, size_t size_in,
			const char *key_out, size_t size_out):
				std::istream(&buf), buf(iSocket, key_in, size_in, key_out, size_out)
		{
		}
};

/*! @class osecuresocketstream
 * An ostream subclass that uses a socketbuf. Create one if you wish to
 * have a write-only socket attached to an ostream.
 */
class osecuresocketstream : public std::ostream
{
	protected:
		securesocketbuf buf; /*! @member buf the securesocketbuf */
	
	public:
		/*! @method osecuresocktream
		 * The primary constructor, which takes an open socket as first argument
		 * @param iSocket an open and connected socket
		 */
		osecuresocketstream
			(int iSocket, const char *key_in, size_t size_in,
			const char *key_out, size_t size_out):
				std::ostream(&buf), buf(iSocket, key_in, size_in, key_out, size_out)
		{
		}
};

/*! @class iosocketstream
 * An iostream subclass that uses a socketbuf. Create one if you wish to
 * have a read/write socket attached to an iostream.
 */
class iosecuresocketstream : public std::iostream
{
	protected:
		securesocketbuf buf; /*! @member buf the securesocketbuf */
	
	public:
		/*! @method iosecuresocktream
		 * The primary constructor, which takes an open socket as first argument
		 * @param iSocket an open and connected socket
		 */
		iosecuresocketstream
			(int iSocket, const char *key_in, size_t size_in,
			const char *key_out, size_t size_out):
				std::iostream(&buf), buf(iSocket, key_in, size_in, key_out, size_out)
		{
		}
};

#endif
