#ifndef INCLUDED_socketstream_HH
	#define INCLUDED_socketstream_HH

/*!
 * @module socketstream
 * @author Kevin Birch <kbirch@pobox.com>
 * @version 1.0, 01/15/00
 * This C++ class is designed to allow the use of BSD-style
 * socket descriptors by applications that use iostreams.
 */

/*!
 * @struct socketbuf_traits
 * This structure defines the behavior of the socketstream class.<P>
 * If you wish to modify the behavior of socketstream, you should subclass
this struct
 * and change the return values of its methods.
 * @method buffer_output
 * @return true of output is buffered
 * @method o_buffer_sz
 * @return maximum size in bytes of the output buffer
 * @method i_buffer_sz
 * @return maximum size in bytes of the input buffer
 * @method putback_sz
 * @return size in bytes of the putback area of the input buffer, used by
unget
 */
struct socketbuf_traits {
    static inline bool buffer_output() { return false; }
    static inline size_t o_buffer_sz() { return 512; }
    static inline size_t i_buffer_sz() { return 1024; }
    static inline size_t putback_sz() { return 4; }
};

/*!
 * @typedef int_type
 * used by basic_socketbuf to comply with streambuf
 */
typedef int int_type;

/*!
 * @class basic_socketbuf
 * This is the class that drives the ability to attach a socket to an
iostream.  It
 * handles input and output buffers, and reading from and writing to the
 * network
 */
template <class traits = socketbuf_traits>
class basic_socketbuf : public std::streambuf {
protected:
    int mSocket;    /*! @member mSocket The socket to operate on */
    char *mRBuffer; /*! @member mRBuffer the read buffer */
    char *mWBuffer; /*! @member mWBuffer the write buffer */
    
public:
    typedef traits traits_type; /*! @typedef traits_type a convenience for
                                 * clients */

        /*! @method basic_socketbuf
         * The primary constructor, which takes an open socket as its only
         * argument
         * @param iSocket an open and connected socket
         */
    basic_socketbuf(int iSocket) : mSocket(iSocket) {
        mRBuffer = new char[traits_type::i_buffer_sz()];
        mWBuffer = new char[traits_type::o_buffer_sz()];
        if(traits_type::buffer_output()) {
            setp(mWBuffer, mWBuffer+(traits_type::o_buffer_sz()-1));
        }
        char *pos = mRBuffer+traits_type::putback_sz();
        setg(pos, pos, pos);
    }

        /*! @method ~basic_socketbuf()
         * The destructor
         */
    ~basic_socketbuf() {
        delete [] mRBuffer;
        delete [] mWBuffer;
        sync();
    }
    
protected:
        /*! @method flushOutput
         * flushes the write buffer to the network, and resets the write
buffer head
         * pointer
         * @return number of bytes written to the network
         */
    int flushOutput() {
        int num = pptr()-pbase();
        if(send(mSocket, mWBuffer, num, 0) != num) {
            return EOF;
        }
        pbump(-num);
        return(num);
    }

    /*! @method overflow
         * called by std::streambuf when the write buffer is full
         * @param c the character that overflowed the write buffer
         * @return the character that overflowed the write buffer
         */
    virtual int_type overflow(int_type c) {
        if(traits_type::buffer_output()) {
            *pptr() = c;
            pbump(1);
            
            if(flushOutput() == EOF) {
                return EOF;
            }
            return c;
        } else {
            if(c != EOF) {
                char z = c;
                if(send(mSocket, &z, 1, 0) != 1) {
                    return EOF;
                }
            }
            return c;
        }
    }

        /*! @method sync
         * called by std::strambuf when the endl or flush operators are used
         * @return -1 if the write buffer flush failed
         */
    virtual int sync() {
        if(flushOutput() == EOF) {
            return -1;
        }
        return 0;
    }

    /*! @method xsputn
         * called by std::streambuf to write a buffer to the output device
         * @param s the buffer to be written
         * @param num the size of s
         * @return the number of bytes written
         */
    virtual std::streamsize xsputn(const char *s, std::streamsize num) {
        return(send(mSocket, s, num, 0));
    }

        /*! @method underflow
         * called by std::streambuf when the read buffer is empty
         * @return the next character to be read or EOF on failure
         */
    virtual int_type underflow() {
        if(gptr() < egptr()) {
            return *gptr();
        }
        
        size_t numPutBack = gptr() - eback();
        if(numPutBack > traits_type::putback_sz()) {
            numPutBack = traits_type::putback_sz();
        }
        
        std::memcpy(mRBuffer+(traits_type::putback_sz()-numPutBack),
gptr()-numPutBack, 
                    numPutBack);
        
        size_t bufsiz = traits_type::i_buffer_sz() -
traits_type::putback_sz();
        int count;
        while(1) {
            count = recv(mSocket, mRBuffer+traits_type::putback_sz(),
bufsiz, 0);
            if(count == 0) {
                return EOF;
            } else if(count == -1) {
                if(errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    return EOF;
            } else {
                break;
            }
        }
        
        setg(mRBuffer+(traits_type::putback_sz()-numPutBack), 
             mRBuffer+traits_type::putback_sz(), 
             mRBuffer+traits_type::putback_sz()+count);
        
        return *gptr();
    } 
};

/*! @typedef socketbuf
 * make the name socketbuf a basic_socketbuf with the default traits
 */
typedef basic_socketbuf<> socketbuf;

/*! @class isocketstream
 * An istream subclass that uses a socketbuf.  Create one if you wish to
have
 * a read-only socket attached to an istream.
 */
class isocketstream : public std::istream {
protected:
    socketbuf buf; /*! @member buf the socketbuf */
    
public:
        /*! @method isocktream
         * The primary constructor, which takes an open socket as its only
argument
         * @param iSocket an open and connected socket
         */
    isocketstream(int iSocket) : std::istream(&buf), buf(iSocket) {}

};

/*! @class osocketstream
 * An ostream subclass that uses a socketbuf.  Create one if you wish to
have
 * a write-only socket attached to an ostream.
 */
class osocketstream : public std::ostream {
protected:
    socketbuf buf; /*! @member buf the socketbuf */
    
public:
        /*! @method osocktream
         * The primary constructor, which takes an open socket as its only
argument
         * @param iSocket an open and connected socket
         */
    osocketstream(int iSocket) : std::ostream(&buf), buf(iSocket) {}
};

/*! @class iosocketstream
 * An iostream subclass that uses a socketbuf.  Create one if you wish to
have
 * a read/write socket attached to an iostream.
 */
class iosocketstream : public std::iostream {
protected:
    socketbuf buf; /*! @member buf the socketbuf */
    
public:
        /*! @method iosocktream
         * The primary constructor, which takes an open socket as its only
argument
         * @param iSocket an open and connected socket
         */
    iosocketstream(int iSocket) : std::iostream(&buf), buf(iSocket) {}

};

#endif
