/*
    sockaddr.h -- sockaddr handling

    Copyright (C) 2003-2004 Guus Sliepen <guus@tinc-vpn.org>,

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#ifndef __SOCKADDR_H__
#define __SOCKADDR_H__

#define AF_UNKNOWN 255

struct sockaddr_unknown {
	uint16_t family;
	uint16_t pad1;
	uint32_t pad2;
	char *address;
	char *port;
};

#define sa(s) ((struct sockaddr *)(s))
#ifdef SA_LEN
#define sa_len(s) SA_LEN((struct sockaddr *)(s))
#else
#define sa_len(s) (((struct sockaddr *)(s))->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

#define sa_family(s) (((struct sockaddr *)(s))->sa_family)

#define sa_unmap(s) ({if(((struct sockaddr *)(s))->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)(s))->sin6_addr)) { \
		((struct sockaddr_in *)(s))->sin_addr.s_addr = ((struct sockaddr_in6 *)(s))->sin6_addr.s6_addr32[3]; \
		((struct sockaddr *)(s))->sa_family = AF_INET; \
} \
s;})

#endif
