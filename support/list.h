/*
    list.h -- linked lists

    Copyright (C) 2000-2004 Ivo Timmermans <ivo@tinc-vpn.org>
                  2000-2004 Guus Sliepen <guus@tinc-vpn.org>

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

    $Id: list.h 1374 2004-03-21 14:21:22Z guus $
*/

#ifndef __LIST_H__
#define __LIST_H__

typedef struct list_node {
	struct list_node *prev;
	struct list_node *next;

	void *data;
} list_node_t;

typedef void (*list_action_t)(const void *);
typedef void (*list_node_action_t)(const list_node_t *);

typedef struct list {
	struct list_node *head;
	struct list_node *tail;
	int count;

	list_action_t free;
} list_t;

/* (De)constructors */

extern struct list *list_new(list_action_t) __attribute__ ((__malloc__));
extern void list_free(struct list *);
extern struct list_node *list_node_new(void);
extern void list_node_free(struct list *, struct list_node *);

/* Insertion and deletion */

extern struct list_node *list_add_head(struct list *, void *);
extern struct list_node *list_add_tail(struct list *, void *);

extern void list_unlink_node(struct list *, struct list_node *);
extern void list_node_del(struct list *, struct list_node *);

extern void list_del_head(struct list *);
extern void list_del_tail(struct list *);

/* Head/tail lookup */

extern void *list_get_head(const struct list *);
extern void *list_get_tail(const struct list *);

/* Fast list deletion */

extern void list_del(struct list *);

/* Traversing */

#define list_foreach(list, object, action) {list_node_t *_node, *_next; \
        for(_node = (list)->head; _node; _node = _next) { \
                _next = _node->next; \
                (object) = _node->data; \
                action; \
        } \
}

#define list_foreach_node(list, node, action) {list_node_t *_next; \
        for((node) = (list)->head; (node); (node) = _next) { \
                _next = (node)->next; \
                action; \
        } \
}

#endif
