/*
    fd.c -- I/O and event multiplexing

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

#include "system.h"

#include "support/avl.h"
#include "support/xalloc.h"
#include "fd/event.h"
#include "fd/fd.h"

static fd_set readset, writeset, errorset;
static int max_fd;
static avl_tree_t *fds;

volatile bool fd_running = false;

int fd_compare(struct fd *a, struct fd *b) {
	return a->fd - b->fd;
};

bool fd_init(void) {
	int i;

	FD_ZERO(&readset);
	FD_ZERO(&writeset);
	FD_ZERO(&errorset);

	fds = avl_tree_new((avl_compare_t)fd_compare, NULL);

	event_init();
}

bool fd_exit(void) {
	event_exit();

	avl_tree_del(fds);
}

bool fd_add(struct fd *fd) {
	if(!avl_add(fds, fd))
		return false;

	if(fd->read)
		FD_SET(fd->fd, &readset);

	if(fd->write)
		FD_SET(fd->fd, &writeset);

	if(fd->error)
		FD_SET(fd->fd, &errorset);
	
	if(fd->fd > max_fd)
		max_fd = fd->fd;

	return true;
};

bool fd_del(struct fd *fd) {
	FD_CLR(fd->fd, &readset);
	FD_CLR(fd->fd, &writeset);
	FD_CLR(fd->fd, &errorset);
	
	avl_del(fds, fd);

	if(fds->tail)
		max_fd = ((struct fd *)fds->tail->data)->fd;
	else
		max_fd = 0;

	return true;
};

bool fd_mod(struct fd *fd) {
	if(fd->read)
		FD_SET(fd->fd, &readset);
	else
		FD_CLR(fd->fd, &readset);

	if(fd->write)
		FD_SET(fd->fd, &writeset);
	else
		FD_CLR(fd->fd, &writeset);

	if(fd->error)
		FD_SET(fd->fd, &errorset);
	else
		FD_CLR(fd->fd, &errorset);
}	

bool fd_run(void) {
	struct timeval tv;
	int result;
	fd_set readtmp, writetmp, errortmp;

	fd_running = true;

	logger(LOG_INFO, "fd: running");
		
	while(fd_running) {
		readtmp = readset;
		writetmp = writeset;
		errortmp = errorset;

		tv = event_timeout();

		result = select(max_fd + 1, &readtmp, &writetmp, &errortmp, tv.tv_sec >= 0 ? &tv : NULL);

		if(result < 0) {
			if(errno != EINTR && errno != EAGAIN) {
				logger(LOG_ERR, _("fd: error while waiting for input: %s"), strerror(errno));
				return false;
			}

			continue;
		}

		if(result) {
			struct fd *fd;
			
			avl_foreach(fds, fd, {
				if(fd->read && FD_ISSET(fd->fd, &readtmp))
					fd->read(fd);
				if(fd->write && FD_ISSET(fd->fd, &writetmp))
					fd->write(fd);
				if(fd->error && FD_ISSET(fd->fd, &errortmp))
					fd->error(fd);
			});
		} else {
			event_handle();
		}
	}

	logger(LOG_INFO, "fd: stopping");

	return true;
}

void fd_stop(void) {
	fd_running = false;
}
