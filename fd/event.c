/*
    event.c -- event queue

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

#include "support/avl.h"
#include "support/xalloc.h"
#include "fd/event.h"

avl_tree_t *events;

static event_id_t id;

static int timevalcmp(struct timeval a, struct timeval b) {
	return a.tv_sec - b.tv_sec ?: a.tv_usec - b.tv_usec;
}

static int event_compare(const event_t *a, const event_t *b) {
	return timevalcmp(a->tv, b->tv) ?: a->id - b->id;
}

bool event_init(void) {
	events = avl_tree_new((avl_compare_t)event_compare, (avl_action_t)event_free);

	return true;
}

bool event_exit(void) {
	avl_tree_del(events);

	return true;
}

event_t *event_new(void) {
	event_t *event;

	return clear(new(event));
}

void event_free(event_t *event) {
	free(event);
}

void event_set(event_t *event, struct timeval timeout, event_handler_t handler, void *data) {
	gettimeofday(&event->tv, NULL);
	event_update(event, timeout);
	event->interval = timeout;
	event->handler = handler;
	event->data = data;
}	

void event_update(event_t *event, struct timeval timeout) {
	event->tv.tv_sec += timeout.tv_sec;
	event->tv.tv_usec += timeout.tv_usec;
	event->tv.tv_sec += event->tv.tv_usec / 1000000;
	event->tv.tv_usec %= 1000000;
}	

bool event_add(event_t *event) {
	event->id = ++id;
	return avl_add(events, event);
}

bool event_del(event_t *event) {
	return avl_del(events, event);
}

void event_handle(void) {
	struct timeval now;
	event_t *event;
	avl_node_t *avl;

	gettimeofday(&now, NULL);

	avl_foreach_node(events, avl, {
		event = avl->data;
		
		if(timercmp(&event->tv, &now, <)) {
			avl_unlink_node(events, avl);
			if(event->handler(event))
				avl_add_node(events, avl);
			else
				avl_node_free(events, avl);
		} else {
			break;
		}
	});
}

struct timeval event_timeout(void) {
	struct timeval tv, now;
	event_t *event;

	gettimeofday(&now, NULL);

	if(events->head) {
		event = events->head->data;

		tv.tv_sec = event->tv.tv_sec - now.tv_sec;
		tv.tv_usec = event->tv.tv_usec - now.tv_usec;

		if(tv.tv_usec < 0) {
			tv.tv_usec += 1e6;
			tv.tv_sec--;
		}

		if(tv.tv_sec < 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		}
	} else {
		tv.tv_sec = -1;
		tv.tv_usec = -1;
	}

	return tv;
}
