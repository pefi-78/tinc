/*
    subnet.h -- subnet handling

    Copyright (C) 2003-2004 Guus Sliepen <guus@tinc-vpn.org>,
                  2003-2004 Ivo Timmermans <ivo@tinc-vpn.org>

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

#ifndef __SUBNET_H__
#define __SUBNET_H__

#include "rt/node.h"
#include "support/avl.h"

typedef struct mac {
        uint8_t x[6];
} mac_t;

typedef struct ipv4 {
        uint8_t x[4];
} ipv4_t;

typedef struct ipv6 {
        uint16_t x[8];
} ipv6_t;

typedef enum subnet_type {
	SUBNET_TYPE_MAC,
	SUBNET_TYPE_IPV4,
	SUBNET_TYPE_IPV6,
} subnet_type_t;

typedef struct subnet_mac {
	mac_t address;
} subnet_mac_t;

typedef struct subnet_ipv4 {
	ipv4_t address;
	int prefixlength;
} subnet_ipv4_t;

typedef struct subnet_ipv6 {
	ipv6_t address;
	int prefixlength;
} subnet_ipv6_t;

typedef struct subnet {
	struct node *owner;
	struct timeval expires;

	enum subnet_type type;

	union net {
		struct subnet_mac mac;
		struct subnet_ipv4 ipv4;
		struct subnet_ipv6 ipv6;
	} net;
} subnet_t;

extern subnet_t *subnet_new(void) __attribute__ ((__malloc__));
extern void subnet_free(struct subnet *);
extern bool subnet_init(void);
extern bool subnet_exit(void);
extern avl_tree_t *subnet_tree_new(void) __attribute__ ((__malloc__));
extern void subnet_tree_free(avl_tree_t *);
extern void subnet_add(struct subnet *);
extern void subnet_del(struct subnet *);
extern char *net2str(const struct subnet *);
extern struct subnet *str2net(const char *);
extern struct subnet *subnet_get(const struct subnet *);
extern struct subnet *subnet_get_mac(const struct mac *);
extern struct subnet *subnet_get_ipv4(const struct ipv4 *);
extern struct subnet *subnet_get_ipv6(const struct ipv6 *);

#endif
