/*
    rt.c -- routing

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
#include "rt/edge.h"
#include "rt/node.h"
#include "rt/rt.h"
#include "rt/subnet.h"
#include "support/xalloc.h"
#include "tnl/tnl.h"
#include "vnd/vnd.h"
#include "tincd.h"

vnd_t *rt_vnd = NULL;
int rt_af = AF_UNSPEC;
int rt_macexpire = 600;
int rt_maxtimeout = 900;
rt_mode_t rt_mode = RT_MODE_ROUTER;
bool rt_priorityinheritance = false;
bool rt_hostnames = false;
bool rt_overwrite_mac = false;

avl_tree_t *rt_tnls;
avl_tree_t *rt_listeners;

static bool rt_tnl_accept(tnl_t *t) {
	
}

static bool rt_vnd_recv(vnd_t *vnd, const void *buf, int len) {
	route(myself, buf, len);
}

static bool rt_tnl_recv_packet(tnl_t *tnl, const void *buf, int len) {
	edge_t *edge = tnl->data;
	route(edge->to, buf, len);
}

static bool rt_tnl_recv_meta(tnl_t *tnl, const void *buf, int len) {
}

static void rt_outgoing(char *name) {
	tnl_t *tnl;

	clear(new(tnl));
	
}

bool rt_init(void) {
	char *bindtoaddress = NULL;
	char *bindtointerface = NULL;
	char *device = NULL;
	char *iface = NULL;
	char *port = NULL;
	cfg_t *cfg;
	subnet_t *subnet;
	struct addrinfo hint, *ai, *aip;
	int err;
	int listeners;
	char *connectto = NULL;
	
	cfg_choice_t mode_choice[] = {
		{"Router", RT_MODE_ROUTER},
		{"Switch", RT_MODE_SWITCH},
		{"Hub", RT_MODE_HUB},
	};

	cfg_choice_t af_choice[] = {
		{"IPv4", AF_INET},
		{"IPv6", AF_INET6},
		{"Any", AF_UNSPEC},
	};

	logger(LOG_INFO, _("rt: initialising"));

	if(!subnet_init() || !node_init() || !edge_init())
		return false;

	rt_tnls = avl_tree_new(NULL, NULL);
	rt_listeners = avl_tree_new(NULL, NULL);

	/* Read main configuration */

	if(!cfg_get_choice(tinc_cfg, "AddressFamily", af_choice, AF_UNSPEC, &rt_af)
			|| !cfg_get_string(tinc_cfg, "BindToAddress", NULL, &bindtoaddress)
			|| !cfg_get_string(tinc_cfg, "BindToInterface", NULL, &bindtointerface)
			|| !cfg_get_string(tinc_cfg, "Device", "/dev/net/tun", &device)
			|| !cfg_get_bool(tinc_cfg, "Hostnames", false, &rt_hostnames)
			|| !cfg_get_string(tinc_cfg, "Interface", tinc_netname, &iface)
			|| !cfg_get_period(tinc_cfg, "MACExpire", 600, &rt_macexpire)
			|| !cfg_get_period(tinc_cfg, "MaxTimeout", 3600, &rt_maxtimeout)
			|| !cfg_get_choice(tinc_cfg, "Mode", mode_choice, RT_MODE_ROUTER, &rt_mode)
			|| !cfg_get_bool(tinc_cfg, "PriorityInheritance", false, &rt_priorityinheritance))
		return false;

	/* Read host configuration for myself */
	
	if(!cfg_get_string(myself->cfg, "Port", "655", &port))
		return false;

	for(cfg = cfg_get(myself->cfg, "Subnet"); cfg; cfg = cfg_get_next(myself->cfg, cfg)) {
		if(!cfg_subnet(cfg, &subnet))
			return false;

		subnet->owner = myself;
		subnet_add(subnet);
	}

	/* Open the virtual network device */
	
	if(!cfg_get_string(tinc_cfg, "Device", "/dev/net/tun", &rt_vnd->device)
			|| !cfg_get_string(tinc_cfg, "Interface", tinc_netname, &rt_vnd->interface)
			|| !cfg_get_choice(tinc_cfg, "Mode", mode_choice, RT_MODE_ROUTER, rt_mode)) {
		vnd_free(rt_vnd);
		return false;
	}
	
	rt_vnd->mode = (rt_mode == RT_MODE_ROUTER) ? VND_MODE_TUN : VND_MODE_TAP;
	rt_vnd->recv = rt_vnd_recv;

	if(!vnd_open(rt_vnd)) {
		vnd_free(rt_vnd);
		return false;
	}
	
	/* Create listening sockets */

	hint.ai_family = rt_af;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = AI_PASSIVE;

	err = getaddrinfo(bindtoaddress, port, &hint, &ai);

	if(err || !ai) {
		logger(LOG_ERR, _("rt: system call '%s' failed: %s"), "getaddrinfo", gai_strerror(err));
		return false;
	}

	listeners = 0;

	for(aip = ai; aip; aip = aip->ai_next) {
		tnl_listen_t *listener;
		
		clear(new(listener));
		listener->local.address = *(struct sockaddr_storage *)aip->ai_addr;
		listener->local.id = myself->name;
		// listener->local.cred = ...;
		listener->accept = rt_tnl_accept;

		if(tnl_listen(listener))
			listeners++;
	}

	freeaddrinfo(ai);

	if(!listeners) {
		logger(LOG_ERR, _("rt: unable to create any listening socket!"));
		return false;
	}

	/* Setup outgoing connections */

	for(cfg = cfg_get(tinc_cfg, "ConnectTo"); cfg; cfg = cfg_get_next(tinc_cfg, cfg)) {
		if(!cfg_string(cfg, NULL, &connectto))
			return false;

		if(!node_validname(connectto)) {
			logger(LOG_ERR, _("rt: invalid name for outgoing connection in %s line %d"), cfg->file, cfg->line);
			free(connectto);
			continue;
		}

		rt_outgoing(connectto);
	}

	return true;
}

bool rt_exit(void) {
	edge_exit();
	node_exit();
	subnet_exit();

	logger(LOG_INFO, _("rt: exitting"));
}


