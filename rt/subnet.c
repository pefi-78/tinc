/*
    subnet.c -- subnet handling

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

#include "system.h"

#include "cfg/cfg.h"
#include "logger/logger.h"
#include "rt/node.h"
#include "rt/subnet.h"
#include "support/avl.h"
#include "support/xalloc.h"

avl_tree_t *subnets;
/* Subnet mask handling */

static int maskcmp(const void *va, const void *vb, int masklen, int len) {
	int i, m, result;
	const char *a = va;
	const char *b = vb;

	for(m = masklen, i = 0; m >= 8; m -= 8, i++) {
		result = a[i] - b[i];
		if(result)
			return result;
	}

	return m ? (a[i] & (0x100 - (1 << (8 - m)))) - (b[i] & (0x100 - (1 << (8 - m)))) : 0;
}

static void mask(void *va, int masklen, int len) {
	int i;
	char *a = va;

	i = masklen / 8;
	masklen %= 8;

	if(masklen)
		a[i++] &= (0x100 - (1 << masklen));

	for(; i < len; i++)
		a[i] = 0;
}

static void maskcpy(void *va, const void *vb, int masklen, int len) {
	int i, m;
	char *a = va;
	const char *b = vb;

	for(m = masklen, i = 0; m >= 8; m -= 8, i++)
		a[i] = b[i];

	if(m) {
		a[i] = b[i] & (0x100 - (1 << m));
		i++;
	}

	for(; i < len; i++)
		a[i] = 0;
}

static bool maskcheck(const void *va, int masklen, int len) {
	int i;
	const char *a = va;

	i = masklen / 8;
	masklen %= 8;

	if(masklen && a[i++] & (0xff >> masklen))
		return false;

	for(; i < len; i++)
		if(a[i] != 0)
			return false;

	return true;
}

/* Cache handling */

struct {
	subnet_t key;
	subnet_t *subnet;
} *cache;

int cache_bits;
int cache_size;
uint32_t cache_mask;

static void cache_flush(void) {
	memset(cache, 0, sizeof *cache * cache_size);
}

static void cache_init(void) {
	cache_bits = 8;
	cache_size = 1 << 8;
	cache_mask = cache_size - 1;

	dim(cache, cache_size);

	cache_flush();
}

static void cache_exit(void) {
	free(cache);
}

static uint32_t subnet_hash(const subnet_t *subnet) {
	uint32_t hash;
	int i;

	hash = subnet->type;

	for(i = 0; i < sizeof subnet->net / sizeof(uint32_t); i++)
		hash ^= ((uint32_t *)&subnet->net)[i];

	hash ^= hash >> 16;
	hash ^= hash >> 8;
	
	return hash & cache_mask;
}

static subnet_t *cache_get(subnet_t *subnet) {
	uint32_t hash = subnet_hash(subnet);

	if(cache[hash].subnet && memcmp(&cache[hash].key, subnet, sizeof *subnet))
		return cache[hash].subnet;
	else
		return NULL;
}

static void cache_add(subnet_t *key, subnet_t *subnet) {
	uint32_t hash = subnet_hash(subnet);

	cache[hash].key = *key;
	cache[hash].subnet = subnet;
}

/* Subnet tree handling */

static int subnet_compare_mac(const subnet_t *a, const subnet_t *b) {
	return memcmp(&a->net.mac.address, &b->net.mac.address, sizeof(mac_t))
		?: (a->owner && b->owner) ? strcmp(a->owner->name, b->owner->name) : 0;
}

static int subnet_compare_ipv4(const subnet_t *a, const subnet_t *b) {
	return memcmp(&a->net.ipv4.address, &b->net.ipv4.address, sizeof(ipv4_t))
		?: (a->net.ipv4.prefixlength - b->net.ipv4.prefixlength)
		?: (a->owner && b->owner) ? strcmp(a->owner->name, b->owner->name) : 0;
}

static int subnet_compare_ipv6(const subnet_t *a, const subnet_t *b) {
	return memcmp(&a->net.ipv6.address, &b->net.ipv6.address, sizeof(ipv6_t))
		?: (a->net.ipv6.prefixlength - b->net.ipv6.prefixlength)
		?: (a->owner && b->owner) ? strcmp(a->owner->name, b->owner->name) : 0;
}

static int subnet_compare(const subnet_t *a, const subnet_t *b) {
	int result;

	result = a->type - b->type;

	if(result)
		return result;

	switch (a->type) {
		case SUBNET_TYPE_MAC:
			return subnet_compare_mac(a, b);
		case SUBNET_TYPE_IPV4:
			return subnet_compare_ipv4(a, b);
		case SUBNET_TYPE_IPV6:
			return subnet_compare_ipv6(a, b);
		default:
			logger(LOG_ERR, _("rt: subnet_compare() was called with unknown subnet type %d, exitting!"), a->type);
			exit(1);
	}
}

avl_tree_t *subnet_tree_new(void) {
	return avl_tree_new((avl_compare_t)subnet_compare, NULL);
}

void subnet_tree_free(avl_tree_t *subnets) {
	avl_tree_free(subnets);
}

subnet_t *subnet_new(void) {
	subnet_t *subnet;

	return clear(new(subnet));
}

void subnet_free(subnet_t *subnet) {
	free(subnet);
}

void subnet_add(subnet_t *subnet) {
	avl_add(subnets, subnet);
	avl_add(subnet->owner->subnets, subnet);
	cache_flush();
}

void subnet_del(subnet_t *subnet) {
	avl_del(subnet->owner->subnets, subnet);
	avl_del(subnets, subnet);
	cache_flush();
}

bool subnet_init(void) {
	cache_init();
	subnets = avl_tree_new((avl_compare_t)subnet_compare, (avl_action_t)subnet_free);

	return true;
}

bool subnet_exit(void) {
	avl_tree_del(subnets);
	cache_exit();

	return true;
}

subnet_t *str2net(const char *subnetstr) {
	int i, l;
	subnet_t subnet = {0};
	uint16_t x[8];

	if(sscanf(subnetstr, "%hu.%hu.%hu.%hu/%d",
			  &x[0], &x[1], &x[2], &x[3], &l) == 5) {
		subnet.type = SUBNET_TYPE_IPV4;
		subnet.net.ipv4.prefixlength = l;

		for(i = 0; i < 4; i++)
			subnet.net.ipv4.address.x[i] = x[i];

		return copy(&subnet);
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7],
			  &l) == 9) {
		subnet.type = SUBNET_TYPE_IPV6;
		subnet.net.ipv6.prefixlength = l;

		for(i = 0; i < 8; i++)
			subnet.net.ipv6.address.x[i] = htons(x[i]);

		return copy(&subnet);
	}

	if(sscanf(subnetstr, "%hu.%hu.%hu.%hu", &x[0], &x[1], &x[2], &x[3]) == 4) {
		subnet.type = SUBNET_TYPE_IPV4;
		subnet.net.ipv4.prefixlength = 32;

		for(i = 0; i < 4; i++)
			subnet.net.ipv4.address.x[i] = x[i];

		return copy(&subnet);
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7]) == 8) {
		subnet.type = SUBNET_TYPE_IPV6;
		subnet.net.ipv6.prefixlength = 128;

		for(i = 0; i < 8; i++)
			subnet.net.ipv6.address.x[i] = htons(x[i]);

		return copy(&subnet);
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]) == 6) {
		subnet.type = SUBNET_TYPE_MAC;

		for(i = 0; i < 6; i++)
			subnet.net.mac.address.x[i] = x[i];

		return copy(&subnet);
	}

	return NULL;
}

char *net2str(const subnet_t *subnet) {
	char *netstr;

	switch (subnet->type) {
		case SUBNET_TYPE_MAC:
			asprintf(&netstr, "%hx:%hx:%hx:%hx:%hx:%hx",
					 subnet->net.mac.address.x[0],
					 subnet->net.mac.address.x[1],
					 subnet->net.mac.address.x[2],
					 subnet->net.mac.address.x[3],
					 subnet->net.mac.address.x[4],
					 subnet->net.mac.address.x[5]);
			break;

		case SUBNET_TYPE_IPV4:
			asprintf(&netstr, "%hu.%hu.%hu.%hu/%d",
					 subnet->net.ipv4.address.x[0],
					 subnet->net.ipv4.address.x[1],
					 subnet->net.ipv4.address.x[2],
					 subnet->net.ipv4.address.x[3],
					 subnet->net.ipv4.prefixlength);
			break;

		case SUBNET_TYPE_IPV6:
			asprintf(&netstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d",
					 ntohs(subnet->net.ipv6.address.x[0]),
					 ntohs(subnet->net.ipv6.address.x[1]),
					 ntohs(subnet->net.ipv6.address.x[2]),
					 ntohs(subnet->net.ipv6.address.x[3]),
					 ntohs(subnet->net.ipv6.address.x[4]),
					 ntohs(subnet->net.ipv6.address.x[5]),
					 ntohs(subnet->net.ipv6.address.x[6]),
					 ntohs(subnet->net.ipv6.address.x[7]),
					 subnet->net.ipv6.prefixlength);
			break;

		default:
			logger(LOG_ERR, _("net2str() was called with unknown subnet type %d, exiting!"), subnet->type);
			exit(0);
	}

	return netstr;
}

bool cfg_subnet(cfg_t *cfg, subnet_t **result) {
	subnet_t *subnet;

	subnet = str2net(cfg->value);

	if(!subnet) {
		logger(LOG_ERR, _("rt: invalid subnet for configuration variable %s in %s line %d"),
		   cfg->variable, cfg->file, cfg->line);
		return false;
	}

	*result = subnet;

	return true;
}

subnet_t *subnet_get(const subnet_t *subnet) {
	return subnet->owner ? avl_get(subnet->owner->subnets, subnet) : avl_get(subnets, subnet);
}

subnet_t *subnet_get_mac(const mac_t *address) {
	subnet_t *subnet, search = {0};

	search.type = SUBNET_TYPE_MAC;
	search.net.mac.address = *address;

	subnet = cache_get(&search);
	
	if(subnet)
		return subnet;

	subnet = avl_get(subnets, &search);
	
	if(subnet)
		cache_add(&search, subnet);

	return subnet;
}

subnet_t *subnet_get_ipv4(const ipv4_t *address) {
	subnet_t *subnet, search = {0};

	search.type = SUBNET_TYPE_IPV4;
	search.net.ipv4.address = *address;
	search.net.ipv4.prefixlength = 32;

	subnet = cache_get(&search);
	
	if(subnet)
		return subnet;

	while(subnet = avl_get_closest_smaller(subnets, &search)) {
		if(subnet->type != SUBNET_TYPE_IPV4)
			return NULL;

		if(!maskcmp(address, &subnet->net.ipv4.address, subnet->net.ipv4.prefixlength, sizeof(ipv4_t))) {
			cache_add(&search, subnet);
			return subnet;
		}

		search.net.ipv4.prefixlength = subnet->net.ipv4.prefixlength - 1;
		maskcpy(&search.net.ipv4.address, &subnet->net.ipv4.address, search.net.ipv4.prefixlength, sizeof(ipv4_t));
	}

	return NULL;
}

subnet_t *subnet_get_ipv6(const ipv6_t *address) {
	subnet_t *subnet, search = {0};

	search.type = SUBNET_TYPE_IPV6;
	search.net.ipv6.address = *address;
	search.net.ipv6.prefixlength = 128;

	subnet = cache_get(&search);
	
	if(subnet)
		return subnet;

	while(subnet = avl_get_closest_smaller(subnets, &search)) {
		if(subnet->type != SUBNET_TYPE_IPV6)
			return NULL;

		if(!maskcmp(address, &subnet->net.ipv6.address, subnet->net.ipv6.prefixlength, sizeof(ipv6_t))) {
			cache_add(&search, subnet);
			return subnet;
		}

		search.net.ipv6.prefixlength = subnet->net.ipv6.prefixlength - 1;
		maskcpy(&search.net.ipv6.address, &subnet->net.ipv6.address, search.net.ipv6.prefixlength, sizeof(ipv6_t));
	}

	return NULL;
}
