/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2006  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_SecureSkat_misc_HH
	#define INCLUDED_SecureSkat_misc_HH
	
	// autoconf header
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <cstdio>
	#include <cstdlib>
	#include <unistd.h>
	#include <cstring>
	#include <ctime>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <sys/socket.h>
	
	int BindEmptyPort
		(int start_port);
	int ListenToPort
		(int port);
	int CloseHandle
		(int handle);
	int ConnectToHost
		(const char *host, int port);
	char *stripwhite
		(char *str);
	void start_clock
		(void);
	void stop_clock
		(void);
	char *elapsed_time
		(void);
#endif
