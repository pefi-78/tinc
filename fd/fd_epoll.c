/*
    fd_epoll.c -- I/O and event multiplexing using epoll

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

    $Id: fd.c 1375 2004-03-22 12:30:39Z guus $
*/

#include "system.h"

#include "support/avl.h"
#include "support/xalloc.h"
#include "fd/event.h"
#include "fd/fd.h"

static int epollfd;
static avl_tree_t *fds;

volatile bool fd_running = false;

int fd_compare(struct fd *a, struct fd *b) {
	return (a->fd - b->fd) ?: (a->mode - b->mode);
};

bool fd_init(void) {
	int i;

	epollfd = epoll_create(32);

	if(epollfd == -1) {
		logger(LOG_ERR, "fd: could not open an epoll file descriptor: %s", strerror(errno));
		return false;
	}

	fds = avl_tree_new((avl_compare_t)fd_compare, NULL);

	event_init();
}

bool fd_exit(void) {
	event_exit();

	avl_tree_del(fds);

	close(epollfd);
}

bool fd_add(struct fd *fd) {
	if(!avl_add(fds, fd))
		return false;
	
	fd->event.events = 0;

	if(fd->read)
		fd->event.events |= EPOLLIN;

	if(fd->write)
		fd->event.events |= EPOLLOUT;

	if(fd->error)
		fd->event.events |= EPOLLPRI | EPOLLERR | EPOLLHUP;

	fd->event.data.ptr = fd;

	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, fd->fd, &fd->event) == -1) {
		logger(LOG_ERR, "fd: failed to add file descriptor: %s", strerror(errno));
		return false;
	}

	return true;
};

bool fd_del(struct fd *fd) {
	if(epoll_ctl(epollfd, EPOLL_CTL_DEL, fd->fd, &fd->event) == -1) {
		logger(LOG_ERR, "fd: failed to delete file descriptor: %s", strerror(errno));
		return false;
	}

	return avl_del(fds, fd);
};

bool fd_mod(struct fd *fd) {
	fd->event.events = 0;

	if(fd->read)
		fd->event.events |= EPOLLIN;

	if(fd->write)
		fd->event.events |= EPOLLOUT;

	if(fd->error)
		fd->event.events |= EPOLLPRI | EPOLLERR | EPOLLHUP;

	if(epoll_ctl(epollfd, EPOLL_CTL_MOD, fd->fd, &fd->event) == -1) {
		logger(LOG_ERR, "fd: failed to modify file descriptor: %s", strerror(errno));
		return false;
	}

	return true;
}	

bool fd_run(void) {
	struct timeval tv;
	int result;
	struct epoll_event *events[10];

	fd_running = true;

	logger(LOG_INFO, "fd: running");
		
	while(fd_running) {
		tv = event_timeout();

		result = epoll_wait(epollfd, events, sizeof events / sizeof *events, tv.tv_sec >= 0 ? tv.tv_sec * 1000 + tv.tv_usec / 1000: -1);

		if(result < 0) {
			if(errno != EINTR && errno != EAGAIN) {
				logger(LOG_ERR, _("fd: error while waiting for input: %s"), strerror(errno));
				return false;
			}

			continue;
		}

		if(result) {
			struct fd *fd;

			while(result--) {
				fd = events[result].data.ptr;

				if(events[result].events & EPOLLIN)
					fd->read(fd);

				if(events[result].events & EPOLLOUT)
					fd->write(fd);

				if(events[result].events & (EPOLLPRI | EPOLLERR | EPOLLHUP))
					fd->error(fd);
			}
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
