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

static fd_set fd_sets[FD_MODES];
static int max_fd;
static avl_tree_t *fds;

volatile bool fd_running = false;

int fd_compare(struct fd *a, struct fd *b) {
	return (a->fd - b->fd) ?: (a->mode - b->mode);
};

bool fd_init(void) {
	int i;

	for(i = 0; i < FD_MODES; i++)
		FD_ZERO(&fd_sets[i]);

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

	FD_SET(fd->fd, &fd_sets[fd->mode]);
	
	if(fd->fd > max_fd)
		max_fd = fd->fd;

	return true;
};

bool fd_del(struct fd *fd) {
	FD_CLR(fd->fd, &fd_sets[fd->mode]);
	
	if(fd->fd >= max_fd)
		max_fd = ((struct fd *)fds->tail)->fd;

	return avl_del(fds, fd);
};

bool fd_run(void) {
	struct timeval tv;
	int result;
	fd_set fd_cur[FD_MODES];

	fd_running = true;

	logger(LOG_INFO, "fd: running");
		
	while(fd_running) {
		memcpy(fd_cur, fd_sets, sizeof(fd_cur));
		tv = event_timeout();

		result = select(max_fd + 1, &fd_cur[0], &fd_cur[1], &fd_cur[2], tv.tv_sec >= 0 ? &tv : NULL);

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
				if(FD_ISSET(fd->fd, &fd_cur[fd->mode]))
					fd->handler(fd);
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
