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

#include "system.h"

#include <linux/if_tun.h>

#include "fd/fd.h"
#include "logger/logger.h"
#include "support/xalloc.h"

#include "vnd/vnd.h"

vnd_t *vnd_new(void) {
	vnd_t *vnd;

	return clear(new(vnd));
}

void vnd_free(vnd_t *vnd) {
	replace(vnd->device, NULL);
	replace(vnd->interface, NULL);
	replace(vnd->description, NULL);
	free(vnd);
}

void vnd_set(vnd_t *vnd, char *device, char *interface, vnd_mode_t mode, vnd_handler_t recv) {
	replace(vnd->device, device);
	replace(vnd->interface, interface);
	vnd->mode = mode;
	vnd->recv = recv;
}

static bool vnd_send(vnd_t *vnd, const void *buf, int len) {
	int result;

	result = write(vnd->fd.fd, buf, len);

	if(result == len || result < 0 && (errno == EINTR || errno == EAGAIN)) {
		logger(LOG_INFO, _("vnd: wrote packet of %d bytes to %s"), len, vnd->description);
		return true;
	}

	logger(LOG_INFO, _("vnd: error writing packet of %d bytes to %s: %s"), len, vnd->description, strerror(errno));

	return false;
}

static bool vnd_recv_handler(fd_t *fd) {
	vnd_t *vnd = fd->data;
	char buf[vnd->mtu];
	int len;

	vnd = fd->data;

	len = read(fd->fd, buf, sizeof buf);

	if(len > 0) {
		logger(LOG_INFO, _("vnd: read packet of %d bytes from %s"), len, vnd->description);
		return vnd->recv(vnd, buf, len);
	}

	if(len < 0 && (errno == EINTR || errno == EAGAIN))
		return true;

	logger(LOG_ERR, _("vnd: error reading packet from %s: %s"), vnd->description, strerror(errno));

	return false;
}

bool vnd_open(vnd_t *vnd) {
	struct ifreq ifr = {0};
	
	if(!vnd->device)
		vnd->device = xstrdup("/dev/net/tun");
	
	vnd->fd.fd = open(vnd->device, O_RDWR | O_NONBLOCK);

	if(vnd->fd.fd < 0) {
		logger(LOG_ERR, _("vnd: could not open %s: %s"), vnd->device, strerror(errno));
		return false;
	}

	if(vnd->mode == VND_MODE_TUN)
		ifr.ifr_flags = IFF_TUN;
	else
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if(vnd->interface)
		strncpy(ifr.ifr_name, vnd->interface, IFNAMSIZ);

	if(!ioctl(vnd->fd.fd, TUNSETIFF, &ifr)) {
		if(vnd->interface)
			free(vnd->interface);
		vnd->interface = xstrdup(ifr.ifr_name);
	} else {
		logger(LOG_ERR, _("vnd: %s is not a Linux tun/tap device"), vnd->device);
		return false;
	}

	if(!vnd->mtu)
		vnd->mtu = 1514;

	vnd->send = vnd_send;
	vnd->fd.read = vnd_recv_handler;
	vnd->fd.data = vnd;

	if(vnd->description)
		free(vnd->description);

	asprintf(&vnd->description, "Linux tun/tap device %s (interface %s)", vnd->device, vnd->interface);

	if(!fd_add(&vnd->fd))
		return false;

	logger(LOG_INFO, _("vnd: opened %s"), vnd->description);

	return true;
}

bool vnd_close(vnd_t *vnd) {
	fd_del(&vnd->fd);

	close(vnd->fd.fd);

	logger(LOG_INFO, _("vnd: closed %s"), vnd->description);

	return true;
}

