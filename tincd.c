/*
    tincd.c -- the main file for tincd

    Copyright (C) 2000-2004 Guus Sliepen <guus@tinc-vpn.org>

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

#include "cfg/cfg.h"
#include "fd/event.h"
#include "fd/fd.h"
#include "logger/logger.h"
#include "support/avl.h"
#include "support/sockaddr.h"
#include "support/xalloc.h"
#include "tnl/tnl.h"
#include "vnd/vnd.h"

static bool vnd_recv(struct vnd *vnd, char *buf, int len) {
	static int p = 0;
	char b[4];
	logger(LOG_DEBUG, _("Read packet of %d bytes from vnd %p"), len, vnd);
	memcpy(b, buf + 16, 4);
	memcpy(buf + 16, buf + 20, 4);
	memcpy(buf + 20, b, 4);
	vnd->send(vnd, buf, len);
	return true;
}

static bool vnd_stop(event_t *event) {
	static int i = 0;

	logger(LOG_DEBUG, "i = %d", i++);

	if(i > 5) {
		fd_stop();
		return false;
	}

	event_update(event, event->interval);
	return true;
}

int test(int argc, char **argv) {
	vnd_t *vnd;
	event_t *stop;
	tnl_listen_t *listener;
	
	//vnd_init();
	if(fd_init() && tnl_init()) {
		vnd = vnd_new();
		vnd_set(vnd, "/dev/tun", "test", VND_MODE_TUN, vnd_recv);

		stop = event_new();
		event_set(stop, (struct timeval){5, 0}, vnd_stop, NULL);
		event_add(stop);

		clear(new(listener));
		listener->type = SOCK_STREAM;
		listener->protocol = IPPROTO_TCP;
		sa(&listener->local.address)->sa_family = AF_INET;

		if(tnl_listen(listener) && vnd_open(vnd)) {
			fd_run();
			vnd_close(vnd);
			listener->close(listener);
		}

		vnd_free(vnd);

		tnl_exit();
		fd_exit();
	}
	//vnd_exit();
}

avl_tree_t *tinc_cfg = NULL;
char *tinc_netname = NULL;

int main(int argc, char **argv) {
	tnl_listen_t *listener;

	logger_init("tinc", LOGGER_MODE_STDERR);
	
	tinc_cfg = cfg_tree_new();
	
	if(!cfg_read_file(tinc_cfg, "tinc.conf"))
		return 1;

	if(fd_init() && tnl_init()) {
		clear(new(listener));
		listener->type = SOCK_STREAM;
		listener->protocol = IPPROTO_TCP;
		sa(&listener->local.address)->sa_family = AF_INET;
		((struct sockaddr_in *) &listener->local.address)->sin_port = htons(655);
		if(tnl_listen(listener)) {
			fd_run();
			listener->close(listener);
		}
		tnl_exit() && fd_exit();
	}

	return 0;
}

