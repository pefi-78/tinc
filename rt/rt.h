/*
    route.h -- routing

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

#ifndef __RT_H__
#define __RT_H__

#include "rt/node.h"
#include "tnl/tnl.h"
#include "vnd/vnd.h"

#define RT_PROTOCOL 0

typedef enum rt_mode {
	RT_MODE_ROUTER,
	RT_MODE_SWITCH,
	RT_MODE_HUB,
} rt_mode_t;

extern int rt_af;
extern enum rt_mode rt_mode;
extern bool rt_hostnames;
extern bool rt_priorityinheritance;
extern int rt_macexpire;
extern int rt_maxtimeout;
extern bool rt_overwrite_mac;

extern node_t *myself;
extern vnd_t *rt_vnd;
extern avl_tree_t *rt_tnls;

extern bool rt_init(void);
extern bool rt_exit(void);

#endif
