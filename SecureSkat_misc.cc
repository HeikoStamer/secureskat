/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2006, 2007, 2009
                                       2017 Heiko Stamer <HeikoStamer@gmx.net>

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
	const int max_ports = 100;
	int current_port = start_port + (mpz_wrandom_ui() % (max_ports / 2));
	while (current_port < (start_port + max_ports))
	{
		int sockfd;
		long socket_option = 1;
		struct sockaddr_in sin = { 0 };
		sin.sin_port = htons(current_port);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("SecureSkat_misc::BindEmptyPort (socket)");
			return -1;
		}
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option)) < 0)
		{
			perror("SecureSkat_misc::BindEmptyPort (setsockopt)");
			if (close(sockfd) < 0)
				perror("SecureSkat_misc::BindEmptyPort (close)");
			return -2;
		}
		if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
		{
			current_port++;
		}
		else
		{
			if (close(sockfd) < 0)
			{
				perror("SecureSkat_misc::BindEmptyPort (close)");
				return -3;
			}
			break;
		}
		if (close(sockfd) < 0)
		{
			perror("SecureSkat_misc::BindEmptyPort (close)");
			return -3;
		}
	}
	if (current_port == (start_port + max_ports))
		return -4;
	return current_port;
}

int ListenToPort
	(int port)
{
	int sockfd;
	long socket_option = 1;
	struct sockaddr_in sin = { 0 };
	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (socket)");
		return -1;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option)) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (setsockopt)");
		if (close(sockfd) < 0)
			perror("SecureSkat_misc::ListenToPort (close)");
		return -2;
	}
	if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (bind)");
		if (close(sockfd) < 0)
			perror("SecureSkat_misc::ListenToPort (close)");
		return -3;
	}
	if (listen(sockfd, SOMAXCONN) < 0)
	{
		perror("SecureSkat_misc::ListenToPort (listen)");
		if (close(sockfd) < 0)
			perror("SecureSkat_misc::ListenToPort (close)");
		return -4;
	}
	return sockfd;
}

int CloseHandle
	(int sockfd)
{
	if (close(sockfd) < 0)
	{
		perror("SecureSkat_misc::CloseHandle (close)");
		return -1;
	}
	return 0;
}

int ConnectToHost
	(const char *host, int port)
{
	int sockfd;
	struct hostent *hostinf;
	struct sockaddr_in sin = { 0 };
	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;
	if ((hostinf = gethostbyname(host)) != NULL)
	{
		memcpy((char*)&sin.sin_addr, hostinf->h_addr, hostinf->h_length);
	}
	else
	{
		perror("SecureSkat_misc::ConnectToHost (gethostbyname)");
		return -1;
	}
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("SecureSkat_misc::ConnectToHost (socket)");
		return -2;
	}
	if ((connect(sockfd, (struct sockaddr*)&sin, sizeof(sin))) < 0)
	{
		perror("SecureSkat_misc::ConnectToHost (connect)");
		if (close(sockfd) < 0)
			perror("SecureSkat_misc::ConnectToHost (close)");
		return -3;
	}
	return sockfd;
}

char *stripwhite(char *str)
{
	register char *s = str, *t = NULL;
	
	while ((*s == ' ') || (*s == '\t'))
		s++;
	if (*s == 0)
		return s;
	t = s + strlen(s) - 1;
	while ((t > s) && ((*t == ' ') || (*t == '\t')))
		t--;
	*++t = '\0';
	
	return s;
}

clock_t start_time, stop_time;
char time_buffer[128];

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
