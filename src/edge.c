/*
    edge.c -- edge management

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

#include "rt/edge.h"
#include "rt/node.h"
#include "support/avl.h"
#include "support/xalloc.h"

avl_tree_t *edges;

static int edge_compare(const edge_t *a, const edge_t *b) {
	return strcmp(a->to->name, b->to->name);
}

static int edge_weight_compare(const edge_t *a, const edge_t *b) {
	return (a->weight - b->weight) ?: strcmp(a->from->name, b->from->name) ?: strcmp(a->to->name, b->to->name);
}

bool edge_init(void) {
	edges = avl_tree_new((avl_compare_t)edge_weight_compare, NULL);

	return true;
}

bool edge_exit(void) {
	avl_tree_free(edges);

	return true;
}

avl_tree_t *edge_tree_new(void) {
	return avl_tree_new((avl_compare_t)edge_compare, (avl_action_t)edge_free);
}

void edge_tree_free(avl_tree_t *edge_tree) {
	avl_tree_free(edge_tree);
}

edge_t *edge_new(void) {
	edge_t *edge;

	return clear(new(edge));
}

void edge_free(edge_t *edge) {
	free(edge);
}

void edge_add(edge_t *edge) {
	avl_add(edge->from->edges, edge);
	avl_add(edges, edge);

	edge->reverse = edge_get(edge->to, edge->from);

	if(edge->reverse)
		edge->reverse->reverse = edge;
}

void edge_del(edge_t *edge) {
	if(edge->reverse)
		edge->reverse->reverse = NULL;

	avl_del(edges, edge);
	avl_del(edge->from->edges, edge);
}

edge_t *edge_get(node_t *from, node_t *to) {
	edge_t search = {0};
	
	search.from = from;
	search.to = to;

	return avl_get(from->edges, &search);
}

