/*
    fd.h -- I/O and event multiplexing

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

#ifndef __FD_H__
#define __FD_H__

enum fd_mode {
	FD_MODE_READ = 0,
	FD_MODE_WRITE,
	FD_MODE_EXCEPT,
	FD_MODES,
} fd_mode_t;

struct fd;

typedef bool (*fd_handler_t)(struct fd *);

typedef struct fd {
	int fd;
	enum fd_mode mode;
	fd_handler_t handler;
	void *data;
} fd_t;

extern bool fd_init(void);
extern bool fd_exit(void);
extern bool fd_add(struct fd *fd);
extern bool fd_del(struct fd *fd);
extern bool fd_run(void);
extern void fd_stop(void);

#endif
