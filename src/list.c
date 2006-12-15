/*
    list.c -- linked lists
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

    $Id: list.c 1374 2004-03-21 14:21:22Z guus $
*/

#include "system.h"

#include "support/list.h"
#include "support/xalloc.h"

list_t *list_new(list_action_t free) {
	list_t *list;

	clear(new(list));
	list->free = free;

	return list;
}

void list_free(list_t *list) {
	free(list);
}

list_node_t *list_node_new(void) {
	list_node_t *node;

	return clear(new(node));
}

void list_node_free(list_t *list, list_node_t *node) {
	if(node->data && list->free)
		list->free(node->data);

	free(node);
}

list_node_t *list_add_head(list_t *list, void *data) {
	list_node_t *node;

	node = list_node_new();

	node->data = data;
	node->prev = NULL;
	node->next = list->head;
	list->head = node;

	if(node->next)
		node->next->prev = node;
	else
		list->tail = node;

	list->count++;

	return node;
}

list_node_t *list_add_tail(list_t *list, void *data) {
	list_node_t *node;

	node = list_node_new();

	node->data = data;
	node->next = NULL;
	node->prev = list->tail;
	list->tail = node;

	if(node->prev)
		node->prev->next = node;
	else
		list->head = node;

	list->count++;

	return node;
}

void list_unlink_node(list_t *list, list_node_t *node) {
	if(node->prev)
		node->prev->next = node->next;
	else
		list->head = node->next;

	if(node->next)
		node->next->prev = node->prev;
	else
		list->tail = node->prev;

	list->count--;
}

void list_del_node(list_t *list, list_node_t *node) {
	list_unlink_node(list, node);
	list_node_free(list, node);
}

void list_del_head(list_t *list) {
	list_del_node(list, list->head);
}

void list_del_tail(list_t *list) {
	list_del_node(list, list->tail);
}

void *list_get_head(const list_t *list) {
	if(list->head)
		return list->head->data;
	else
		return NULL;
}

void *list_get_tail(const list_t *list) {
	if(list->tail)
		return list->tail->data;
	else
		return NULL;
}

void list_del(list_t *list) {
	list_node_t *node;

	list_foreach_node(list, node, list_node_free(list, node));
	list_free(list);
}
