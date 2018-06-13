/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 2002, 2003, 2004, 2006, 2007, 2009,
               2017, 2018 Heiko Stamer <HeikoStamer@gmx.net>

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
	int current_port = start_port + (tmcg_mpz_wrandom_ui() % (max_ports / 4));
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
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socket_option,
			sizeof(socket_option)) < 0)
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
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socket_option,
		sizeof(socket_option)) < 0)
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
	(const char *host, uint16_t port)
{
	struct addrinfo hints = { 0 }, *res, *rp;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
	std::stringstream ports;
	int ret;
	ports << port;
	if ((ret = getaddrinfo(host, (ports.str()).c_str(), &hints, &res)) != 0)
	{
		if (ret == EAI_SYSTEM)
			perror("SecureSkat_misc::ConnectToHost (getaddrinfo)");
		else
			std::cerr << "ERROR: " << gai_strerror(ret) << std::endl;
		return -1;
	}
	for (rp = res; rp != NULL; rp = rp->ai_next)
	{
		int sockfd;
		if ((sockfd = socket(rp->ai_family, rp->ai_socktype,
			rp->ai_protocol)) < 0)
		{
			perror("SecureSkat_misc::ConnectToHost (socket)");
			continue; // try next address
		}
		if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) < 0)
		{
			if (errno != ECONNREFUSED)
				perror("SecureSkat_misc::ConnectToHost (connect)");					
			if (close(sockfd) < 0)
				perror("SecureSkat_misc::ConnectToHost (close)");
			continue; // try next address
		}
		else
		{
			freeaddrinfo(res);
			return sockfd;
		}
	}
	freeaddrinfo(res);
	return -2;
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

