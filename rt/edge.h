/*
    edge.h -- edge management
    
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

#ifndef __EDGE_H__
#define __EDGE_H__

#include "rt/node.h"
#include "support/avl.h"
#include "tnl/tnl.h"

typedef struct edge_status {
	int visited:1;
	int mst:1;
} edge_status_t;

typedef struct edge {
	struct node *from;
	struct node *to;
	struct sockaddr_storage address;

	int weight;

	struct edge *reverse;
	struct tnl *tnl;

	edge_status_t status;
	node_options_t options;
} edge_t;

extern avl_tree_t *edges;

extern bool edge_init(void);
extern bool edge_exit(void);
extern struct edge *edge_new(void) __attribute__ ((__malloc__));
extern void edge_free(struct edge *);
extern avl_tree_t *edge_tree_new(void) __attribute__ ((__malloc__));
extern void edge_tree_free(avl_tree_t *);
extern void edge_add(struct edge *);
extern void edge_del(struct edge *);
extern struct edge *edge_get(struct node *, struct node *);

#endif
