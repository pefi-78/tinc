/*
    event.h -- event queue

    Copyright (C) 2003-2004 Guus Sliepen <guus@tinc-vpn.org>,

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

#ifndef __EVENT_H__
#define __EVENT_H__

typedef int event_id_t;

struct event;

typedef bool (*event_handler_t)(struct event *event);

typedef struct event {
	struct timeval tv;
	struct timeval interval;
	event_id_t id;
	event_handler_t handler;
	void *data;
} event_t;

extern bool event_init(void);
extern bool event_exit(void);
extern bool event_add(struct event *event);
extern bool event_del(struct event *event);
extern struct event *event_new(void);
extern void event_free(struct event *);
extern void event_set(struct event *, struct timeval, event_handler_t, void *);
extern void event_update(struct event *, struct timeval);
extern void event_handle(void);
extern struct timeval event_timeout(void);

#endif /* __EVENT_H__ */
