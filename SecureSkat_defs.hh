/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2007, 2009, 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_SecureSkat_defs_HH
    #define INCLUDED_SecureSkat_defs_HH

    // C and C++ header
    #include <arpa/inet.h>
    #include <cassert>
    #include <cctype>
    #include <cerrno>
    #include <csignal>
    #include <cstdio>
    #include <cstdlib>
    #include <cstdarg>
    #include <cstring>
    #include <ctime>
    
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>

    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <termios.h>
    #include <unistd.h>
    
    // STL classes
    #include <algorithm>
    #include <fstream>
    #include <iostream>
    #include <list>
    #include <map>
    #include <sstream>
    #include <string>
    #include <vector>

    // zlib
    #include <zlib.h>

    // GNU database manager
    #include <gdbm.h>

    // GNU crypto library
    #include <gcrypt.h> 

    // GNU multiple precision library
    #include <gmp.h>
    
    // GNU readline
    #include <readline/readline.h>
    #include <readline/history.h>

    // LibTMCG
    #include <libTMCG.hh>

    // autoconf header
    #ifdef HAVE_CONFIG_H
        #include "config.h"
    #endif

    // Internationalization
    #ifdef ENABLE_NLS
        #include <clocale>
        #include <libintl.h>
	
        #ifndef _
            #define _(Foo) gettext(Foo)
        #endif
    #else
        #ifndef _
            #define _(Bar) Bar
        #endif
    #endif

    // SecureSkat: mutated iostream classes
    #include "socketstream.hh"
    #include "securesocketstream.hh"
    #include "pipestream.hh"
    
    // define RETSIGTYPE
    #ifndef RETSIGTYPE
        #define RETSIGTYPE void
    #endif

    // define helper macro for select(2)
    #define MFD_SET(fd, where) { FD_SET(fd, where);\
                mfds = (fd > mfds) ? fd : mfds; }

    // define different sizes (in characters)
    #define KEY_SIZE                    1000000L
    #define RNK_SIZE                    1000000L

    // define different timeouts (in seconds)
    #define PKI_TIMEOUT                 1500
    #define RNK_TIMEOUT                 500
    #define ANNOUNCE_TIMEOUT            5
    #define CLEAR_TIMEOUT               30
    #define AUTOJOIN_TIMEOUT            75

    // define different limits (number of child processes)
    #define PKI_CHILDS                  10
    #define RNK_CHILDS                  5

    // define names of used IRC channels
    #define MAIN_CHANNEL                "#openSkat"
    #define MAIN_CHANNEL_UNDERSCORE     "#openSkat_"

#endif
