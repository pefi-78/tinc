/*
    node.c -- node management

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
#include "support/avl.h"
#include "support/xalloc.h"
#include "tincd.h"

avl_tree_t *nodes;

node_t *myself;

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}

bool node_validname(const char *name) {
	for(; *name; name++)
		if(!isalnum(*name) && *name != '_')
			return false;

	return true;
}

bool node_init(void) {
	char *cfgfilename;

	nodes = avl_tree_new((avl_compare_t)node_compare, (avl_action_t)node_free);
	myself = node_new();

	if(!cfg_get_string(tinc_cfg, "Name", NULL, &myself->name) || !myself->name) {
		logger(LOG_ERR, _("rt: name for tinc daemon required!"));
		node_exit();
		return false;
	}

	if(!node_validname(myself->name)) {
		logger(LOG_ERR, _("rt: invalid name for myself!"));
		node_exit();
		return false;
	}

	myself->cfg = cfg_tree_new();

	asprintf(&cfgfilename, "%s/hosts/%s", tinc_confbase, myself->name);

	if(!cfg_read_file(myself->cfg, cfgfilename)) {
		free(cfgfilename);
		node_exit();
		return false;
	}

	free(cfgfilename);
	
	return true;
}

bool node_exit(void) {
	avl_tree_del(nodes);
	return true;
}

node_t *node_new(void) {
	node_t *node;

	clear(new(node));
	node->subnets = subnet_tree_new();
	node->edges = edge_tree_new();
	node->queue = avl_tree_new(NULL, (avl_action_t)free);

	return node;
}

void node_free(node_t *node) {
	if(node->queue)
		avl_tree_free(node->queue);

	if(node->subnets)
		subnet_tree_free(node->subnets);

	if(node->edges)
		edge_tree_free(node->edges);

	replace(node->name, NULL);

	free(node);
}

void node_add(node_t *node) {
	avl_add(nodes, node);
}

void node_del(node_t *node) {
	edge_t *edge;
	subnet_t *subnet;

	avl_foreach(node->subnets, subnet, subnet_del(subnet));
	avl_foreach(node->edges, edge, edge_del(edge));

	avl_del(nodes, node);
}

node_t *node_get(char *name) {
	node_t search = {0};

	search.name = name;

	return avl_get(nodes, &search);
}

