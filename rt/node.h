/*
    node.h -- node management

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

#ifndef __NODE_H__
#define __NODE_H__

typedef int node_options_t;

#define NODE_OPTIONS_INDIRECT 1

#include "rt/edge.h"
#include "rt/subnet.h"
#include "support/avl.h"
#include "tnl/tnl.h"

typedef struct node_status {
	int active:1;
	int visited:1;
	int reachable:1;
	int indirect:1;
} node_status_t;

typedef struct node {
	char *name;

	avl_tree_t *queue;

	struct node *nexthop;
	struct node *via;

	avl_tree_t *subnets;
	avl_tree_t *edges;

	struct tnl *tnl;

	node_status_t status;
	node_options_t options;

	struct sockaddr_storage address;

	avl_tree_t *cfg;
} node_t;

extern avl_tree_t *nodes;
extern struct node *myself;

extern bool node_init(void);
extern bool node_exit(void);
extern struct node *node_new(void) __attribute__ ((__malloc__));
extern void node_free(struct node *);
extern void node_add(struct node *);
extern void node_del(struct node *);
extern struct node *node_get(char *);

#endif
