/*
    graph.c -- graph algorithms
    Copyright (C) 2001-2004 Guus Sliepen <guus@tinc-vpn.org>,
                  2001-2004 Ivo Timmermans <ivo@tinc-vpn.org>

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

/* We need to generate two trees from the graph:

   1. A minimum spanning tree for broadcasts,
   2. A single-source shortest path tree for unicasts.

   Actually, the first one alone would suffice but would make unicast packets
   take longer routes than necessary.

   For the MST algorithm we can choose from Prim's or Kruskal's. I personally
   favour Kruskal's, because we make an extra AVL tree of edges sorted on
   weights (metric). That tree only has to be updated when an edge is added or
   removed, and during the MST algorithm we just have go linearly through that
   tree, adding safe edges until #edges = #nodes - 1. The implementation here
   however is not so fast, because I tried to avoid having to make a forest and
   merge trees.

   For the SSSP algorithm Dijkstra's seems to be a nice choice. Currently a
   simple breadth-first search is presented here.

   The SSSP algorithm will also be used to determine whether nodes are directly,
   indirectly or not reachable from the source. It will also set the correct
   destination address and port of a node if possible.
*/

#include "system.h"

#include "rt/edge.h"
#include "rt/node.h"
#include "support/avl.h"
#include "support/list.h"

/* Implementation of Kruskal's algorithm.
   Running time: O(EN)
   Please note that sorting on weight is already done by add_edge().
*/

void mst_kruskal(void) {
	avl_node_t *avl, *next;
	edge_t *edge;
	node_t *node;
	int safe_edges = 0;
	bool skipped;

	/* Do we have something to do at all? */

	if(!edges->head)
		return;

	logger(LOG_DEBUG, "Running Kruskal's algorithm:");

	/* Clear MST status on edges */

	avl_foreach(edges, edge, edge->status.mst = false);

	/* Clear visited status on nodes */

	avl_foreach(nodes, node, node->status.visited = false);

	/* Starting point */

	((edge_t *) edges->head->data)->from->status.visited = true;

	/* Add safe edges */

	for(skipped = false, avl = edges->head; avl; avl = next) {
		next = avl->next;
		edge = avl->data;

		if(!edge->reverse || edge->from->status.visited == edge->to->status.visited) {
			skipped = true;
			continue;
		}

		edge->from->status.visited = true;
		edge->to->status.visited = true;
		edge->status.mst = true;
		edge->reverse->status.mst = true;

		if(skipped) {
			skipped = false;
			next = edges->head;
			continue;
		}
	}
}

/* Implementation of a simple breadth-first search algorithm.
   Running time: O(E)
*/

void sssp_bfs(void) {
	list_t *todo;
	list_node_t *todonode;
	edge_t *edge;
	node_t *node;
	bool indirect;
	char *name;
	char *address, *port;
	int i;

	todo = list_new(NULL);

	/* Clear visited status on nodes */

	avl_foreach(nodes, node, {
		node->status.visited = false;
		node->status.indirect = true;
	});

	/* Begin with myself */

	myself->status.visited = true;
	myself->status.indirect = false;
	myself->nexthop = myself;
	myself->via = myself;

	list_add_head(todo, myself);

	/* Loop while todo list is filled */

	while(todo->head) {
		list_foreach_node(todo, todonode, {
			node = todonode->data;

			avl_foreach(node->edges, edge, {
				if(!edge->reverse)
					continue;

				/* Situation:

				             /
				            /
				   ----->(node)---edge-->(edge->to)
				            \
				             \

				   node->address is set to the ->address of the edge left of node.
				   We are currently examining the edge right of node:

				   - If edge->reverse->address != node->address, then edge->to is probably
				     not reachable for the nodes left of node. We do as if the indirectdata
				     flag is set on edge.
				   - If edge provides for better reachability of edge->to, update
				     edge->to and (re)add it to the todo_tree to (re)examine the reachability
				     of nodes behind it.
				 */

				indirect = node->status.indirect || edge->options & NODE_OPTION_INDIRECT
					|| ((node != myself) && sockaddrcmp(&node->address, &edge->reverse->address));

				if(edge->to->status.visited && (!edge->to->status.indirect || indirect))
					continue;

				edge->to->status.visited = true;
				edge->to->status.indirect = indirect;
				edge->to->nexthop = (node->nexthop == myself) ? edge->to : node->nexthop;
				edge->to->via = indirect ? node->via : edge->to;
				edge->to->options = edge->options;

				list_add_head(todo, edge->to);
			});

			list_del_node(todo, todonode);
		});
	}

	list_free(todo);

	/* Check reachability status. */

	avl_foreach(nodes, node, {
		if(node->status.visited != node->status.reachable) {
			node->status.reachable = !node->status.reachable;

			if(node->status.reachable)
				logger(LOG_DEBUG, _("Node %s became reachable"), node->name);
			else
				logger(LOG_DEBUG, _("Node %s became unreachable"), node->name);

#if 0
			asprintf(&envp[0], "NETNAME=%s", netname ? : "");
			asprintf(&envp[1], "DEVICE=%s", device ? : "");
			asprintf(&envp[2], "INTERFACE=%s", iface ? : "");
			asprintf(&envp[3], "NODE=%s", n->name);
			sockaddr2str(&n->address, &address, &port);
			asprintf(&envp[4], "REMOTEADDRESS=%s", address);
			asprintf(&envp[5], "REMOTEPORT=%s", port);
			envp[6] = NULL;

			asprintf(&name,
					 n->status.reachable ? "hosts/%s-up" : "hosts/%s-down",
					 n->name);
			execute_script(name, envp);

			free(name);
			free(address);
			free(port);

			for(i = 0; i < 7; i++)
				free(envp[i]);
#endif
		}
	});
}

void graph(void)
{
	mst_kruskal();
	sssp_bfs();
}
