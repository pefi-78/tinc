/*
    vnd.c -- virtual network device management

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

#ifndef __VND_H__
#define __VND_H__

typedef enum vnd_mode{
	VND_MODE_TUN,
	VND_MODE_TAP,
} vnd_mode_t;

struct vnd;

typedef bool (*vnd_handler_t)(struct vnd *vnd, const void *buf, int len);

typedef struct vnd {
	char *device;
	char *interface;
	enum vnd_mode mode;
	int mtu;

	vnd_handler_t recv;
	vnd_handler_t send;

	/* Private data */

	struct fd fd;
	char *description;
} vnd_t;

extern bool vnd_init(void);
extern bool vnd_exit(void);
extern struct vnd *vnd_new(void);
extern void vnd_free(struct vnd *vnd);
extern void vnd_set(struct vnd *vnd, char *device, char *interface, vnd_mode_t mode, vnd_handler_t recv);
extern bool vnd_open(struct vnd *vnd);
extern bool vnd_close(struct vnd *vnd);

#endif /* __VND_H__ */
