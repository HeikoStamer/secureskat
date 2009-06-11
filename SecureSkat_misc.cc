/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2006, 2007, 2009 Heiko Stamer <stamer@gaos.org>

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

#include "SecureSkat_misc.hh"

int BindEmptyPort
	(int start_port)
{
	int current_port = start_port;
	while (1)
	{
		int socket_handle;
		long socket_option = 1;
		struct sockaddr_in sin;
		sin.sin_port = htons(current_port), sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		if ((socket_handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("SecureSkat_misc::BindEmptyPort (socket)");
			return -1;
		}
		if (setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, &socket_option,
			sizeof(socket_option)) < 0)
		{
			perror("SecureSkat_misc::BindEmptyPort (setsockopt)");
			return -2;
		}
		if (bind(socket_handle, (struct sockaddr*)&sin, sizeof(sin)) < 0)
		{
			current_port++;
		}
		else
		{
			if (close(socket_handle) < 0)
			{
				perror("SecureSkat_misc::BindEmptyPort (close)");
				return -3;
			}
			break;
		}
	}
	return current_port;
}

int ListenToPort
	(int port)
{
	int handle;
	long socket_option = 1;
	struct sockaddr_in sin;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = AF_INET;
	if ((handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (socket)");
		return -1;
	}
	if (setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &socket_option,
		sizeof(socket_option)) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (setsockopt)");
		return -2;
	}
	sin.sin_port = htons(port);
	if (bind(handle, (struct sockaddr*)&sin, sizeof(sin)) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (bind)");
		return -3;
	}
	if (listen(handle, SOMAXCONN) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (listen)");
		return -4;
	}
	return handle;
}

int CloseHandle
	(int handle)
{
	if (close(handle) < 0)
	{
		perror("SecureSkat_misc::CloseHandle (close)");
		return -1;
	}
	return 0;
}

int ConnectToHost
	(const char *host, int port)
{
	int handle;
	struct hostent *hostinf;
	struct sockaddr_in sin;
	sin.sin_port = htons(port), sin.sin_family = AF_INET;
	if ((hostinf = gethostbyname(host)) != NULL)
	{
		memcpy((char*)&sin.sin_addr, hostinf->h_addr, hostinf->h_length);
	}
	else
	{
		perror("SecureSkat_misc::ConnectToHost (gethostbyname)");
		return -1;
	}
	if ((handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_misc::ConnectToHost (socket)");
		return -2;
	}
	if ((connect(handle, (struct sockaddr*)&sin, sizeof(sin))) < 0)
	{
		perror("SecureSkat_misc::ConnectToHost (connect)");
		return -3;
	}
	return handle;
}

char *stripwhite(char *str)
{
	register char *s, *t;
	
	for (s = str; ((*s == ' ') || (*s == '\t')); s++)
		;
	
	if (*s == 0)
		return s;
	
	t = s + strlen(s) - 1;
	while (t > s && ((*t == ' ') || (*t == '\t')))
		t--;
	*++t = '\0';
	
	return s;
}

clock_t start_time, stop_time;
char time_buffer[100];

void start_clock
	(void)
{
	start_time = stop_time = clock();
}

void stop_clock
	(void)
{
	stop_time = clock();
}

char *elapsed_time
	(void)
{
	snprintf(time_buffer, sizeof(time_buffer), "%8.0fms",
		(((double) (stop_time - start_time)) / CLOCKS_PER_SEC) * 1000);
	return time_buffer;
}
