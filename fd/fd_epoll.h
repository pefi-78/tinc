/*
    fd_epoll.h -- I/O and event multiplexing using epoll

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

    $Id: fd.h 1375 2004-03-22 12:30:39Z guus $
*/

#ifndef __FD_H__
#define __FD_H__

struct fd;

typedef bool (*fd_handler_t)(struct fd *);

typedef struct fd {
	int fd;
	fd_handler_t read;
	fd_handler_t write;
	fd_handler_t error;
	void *data;

	/* Private */
	
	struct epoll_event event;
} fd_t;

extern bool fd_init(void);
extern bool fd_exit(void);
extern bool fd_add(struct fd *fd);
extern bool fd_del(struct fd *fd);
extern bool fd_mod(struct fd *fd);
extern bool fd_run(void);
extern void fd_stop(void);

#endif
