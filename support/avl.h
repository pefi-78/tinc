/*
    avl.h -- AVL tree management

    Copyright (C) 1998 Michael H. Buselli
                  2000-2004 Ivo Timmermans <ivo@tinc-vpn.org>,
                  2000-2004 Guus Sliepen <guus@tinc-vpn.org>
                  2000-2004 Wessel Dankers <wsl@tinc-vpn.org>

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

    Original AVL tree library by Michael H. Buselli <cosine@cosine.org>.

    Modified 2000-11-28 by Wessel Dankers <wsl@tinc-vpn.org> to use counts
    instead of depths, to add the ->next and ->prev and to generally obfuscate
    the code. Mail me if you found a bug.

    Cleaned up and incorporated some of the ideas from the red-black tree
    library for inclusion into tinc (http://www.tinc-vpn.org/) by
    Guus Sliepen <guus@tinc-vpn.org>.

    $Id$
*/


#ifndef __AVL_H__
#define __AVL_H__

#ifndef AVL_DEPTH
#ifndef AVL_COUNT
#define AVL_DEPTH
#endif
#endif

typedef uint32_t avl_count_t;
typedef uint16_t avl_depth_t;

typedef struct avl_node {
	struct avl_node *next;
	struct avl_node *prev;

	struct avl_node *parent;
	struct avl_node *left;
	struct avl_node *right;

#ifdef AVL_COUNT
	avl_count_t count;
#endif

#ifdef AVL_DEPTH
	avl_depth_t depth;
#endif

	void *data;
} avl_node_t;

typedef int (*avl_compare_t)(const void *, const void *);
typedef void (*avl_action_t)(void *);
typedef void (*avl_node_action_t)(struct avl_node *);

typedef struct avl_tree {
	struct avl_node *head;
	struct avl_node *tail;

	struct avl_node *root;

	avl_compare_t compare;
	avl_action_t free;
} avl_tree_t;

/* (De)constructors */

extern struct avl_tree *avl_tree_new(avl_compare_t, avl_action_t);
extern void avl_tree_free(struct avl_tree *);

extern struct avl_node *avl_node_new(void);
extern void avl_node_free(struct avl_tree *tree, struct avl_node *);

/* Insertion and deletion */

extern struct avl_node *avl_add(struct avl_tree *, void *);
extern struct avl_node *avl_add_node(struct avl_tree *, struct avl_node *);

extern void avl_add_top(struct avl_tree *, struct avl_node *);
extern void avl_add_before(struct avl_tree *, struct avl_node *, struct avl_node *);
extern void avl_add_after(struct avl_tree *, struct avl_node *, struct avl_node *);

extern struct avl_node *avl_unlink(struct avl_tree *, const void *);
extern void avl_unlink_node(struct avl_tree *tree, struct avl_node *);
extern bool avl_del(struct avl_tree *, void *);
extern void avl_del_node(struct avl_tree *, struct avl_node *);

/* Fast tree cleanup */

extern void avl_tree_del(struct avl_tree *);

/* Searching */

extern void *avl_get(const struct avl_tree *, const void *);
extern void *avl_get_closest(const struct avl_tree *, const void *, int *);
extern void *avl_get_closest_smaller(const struct avl_tree *, const void *);
extern void *avl_get_closest_greater(const struct avl_tree *, const void *);

extern struct avl_node *avl_get_node(const struct avl_tree *, const void *);
extern struct avl_node *avl_get_closest_node(const struct avl_tree *, const void *, int *);
extern struct avl_node *avl_get_closest_smaller_node(const struct avl_tree *, const void *);
extern struct avl_node *avl_get_closest_greater_node(const struct avl_tree *, const void *);

/* Tree walking */

#define avl_foreach(tree, object, action) {avl_node_t *_node, *_next; \
	for(_node = (tree)->head; _node; _node = _next) { \
		_next = _node->next; \
		(object) = _node->data; \
		action; \
	} \
}

#define avl_foreach_node(tree, node, action) {avl_node_t *_next; \
	for((node) = (tree)->head; (node); (node) = _next) { \
		_next = (node)->next; \
		action; \
	} \
}

#if 0
extern void avl_foreach(struct avl_tree *, avl_action_t);
extern void avl_foreach_node(struct avl_tree *, avl_node_action_t);
#endif

/* Indexing */

#ifdef AVL_COUNT
extern avl_count_t avl_count(const struct avl_tree *);
extern avl_count_t avl_index(const struct avl_node *);
extern void *avl_get_indexed(const struct avl_tree *, avl_count_t);
extern struct avl_node *avl_get_indexed_node(const struct avl_tree *, avl_count_t);
#endif
#ifdef AVL_DEPTH
extern avl_depth_t avl_depth(const struct avl_tree *);
#endif

#endif
