/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004 Heiko Stamer, <stamer@gaos.org>

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

#ifndef INCLUDED_SecureSkat_misc_HH
	#define INCLUDED_SecureSkat_misc_HH
	
	#include <cstdio>
	#include <cstdlib>
	#include <unistd.h>
	#include <cstring>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <sys/socket.h>
	
	#include <readline/readline.h>
	
	int BindEmptyPort
		(int start_port);
	int ListenToPort
		(int port);
	int ConnectToHost
		(const char *host, int port);
	char *stripwhite
		(char *str);
#endif
