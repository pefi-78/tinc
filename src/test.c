/*
    test.c -- tunnel test

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

    $Id: tnl.c 1379 2004-03-27 11:59:31Z guus $
*/

#include "system.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "logger/logger.h"
#include "support/avl.h"
#include "support/sockaddr.h"
#include "support/xalloc.h"
#include "tnl/tnl.h"

static const int addressfamily = AF_UNSPEC;
static const int socktype = SOCK_STREAM;
static const int protocol = IPPROTO_TCP;

bool server_recv_meta(struct tnl *tnl, const void *buf, int len) {
	const char *in = buf;
	char out[len];

	for(int i = 0; i < len; i++) {
		if(isupper(in[i]))
			out[i] = tolower(in[i]);
		else if(islower(in[i]))
			out[i] = toupper(in[i]);
		else
			out[i] = in[i];
	}

	tnl->send_meta(tnl, out, len);

	return true;
}

bool server_accept(struct tnl *tnl) {
	logger(LOG_INFO, _("Got connection from %s"), tnl->remote.id);
	tnl->recv_meta = server_recv_meta;
	return true;
}

void server(char *port) {
	struct addrinfo *ai, hint = {0};
	int err;
	tnl_listen_t *listen = clear(new(listen));

	hint.ai_family = addressfamily;
	hint.ai_socktype = socktype;
	hint.ai_protocol = protocol;
	hint.ai_flags = AI_PASSIVE;

	err = getaddrinfo(NULL, port, &hint, &ai);

	if(err || !ai) {
		logger(LOG_WARNING, _("Error looking up port %s: %s"), port, gai_strerror(err));
		return;
	}

	if(sizeof listen->local.address < ai->ai_addrlen) {
		logger(LOG_ERR, "%d < %d!", sizeof listen->local.address, ai->ai_addrlen);
		return;
	}

	memcpy(&listen->local.address, ai->ai_addr, ai->ai_addrlen);
	listen->local.id = xstrdup("CommonA");
	listen->type = socktype;
	listen->protocol = protocol;
	listen->accept = server_accept;

	logger(LOG_DEBUG, "Nu ga ik iets doen hoor");
	if(!tnl_ep_set_x509_credentials(&listen->local, "server_key", "server_cert", "trust", NULL)) {
		logger(LOG_ERR, "Couldn't set X.509 credentials!");
		return;
	}

	if(!tnl_listen(listen)) {
		logger(LOG_ERR, _("Could not listen!"));
		return;
	}
}

bool client_stdin_handler(fd_t *fd) {
	tnl_t *tnl = fd->data;
	char buf[1024];
	int len;

	len = read(fd->fd, buf, sizeof buf);

	if(len <= 0) {
		gnutls_bye(tnl->session, GNUTLS_SHUT_WR);
		fd_del(fd);
		return false;
	}
	
	tnl->send_meta(tnl, buf, len);

	return true;
}

bool client_recv_meta(struct tnl *tnl, const void *buf, int len) {
	write(1, buf, len);
	return true;
}

bool client_error(tnl_t *tnl, int err) {
	exit(err);
}

bool client_accept(tnl_t *tnl) {
	fd_t *fd;

	logger(LOG_INFO, _("Connected to %s"), tnl->remote.id);
	tnl->recv_meta = client_recv_meta;

	clear(new(fd));
	fd->fd = 0;
	fd->read = client_stdin_handler;
	fd->data = tnl;
	fd_add(fd);

	return true;
}

void client(char *host, char *port) {
	struct addrinfo *ai, hint = {0};
	int err;
	static tnl_t *tnl;

	hint.ai_family = addressfamily;
	hint.ai_socktype = socktype;

	err = getaddrinfo(host, port, &hint, &ai);

	if(err || !ai) {
		logger(LOG_WARNING, _("Error looking up %s port %s: %s"), host, port, gai_strerror(err));
		return;
	}

	clear(new(tnl));
	memcpy(&tnl->remote.address, ai->ai_addr, ai->ai_addrlen);
	tnl->local.id = xstrdup("CommonB");
	tnl->remote.id = xstrdup("CommonA");
	tnl->type = socktype;
	tnl->protocol = protocol;
	tnl->accept = client_accept;
	tnl->error = client_error;

	if(!tnl_ep_set_x509_credentials(&tnl->local, "client_key", "client_cert", "trust", NULL)) {
		logger(LOG_ERR, "Couldn't set credentials!");
		return;
	}

	if(!tnl_connect(tnl)) {
		logger(LOG_ERR, _("Could not connect to server!"));
		return;
	}
}

int main(int argc, char **argv) {
	gnutls_global_init();
	gnutls_global_init_extra();

	fd_init();
	logger_init(argv[0], LOGGER_MODE_NULL);

	if(argc > 2)
		client(argv[1], argv[2]);
	else if(argc > 1)
		server(argv[1]);
	else {
		logger(LOG_ERR, "Usage: %s [host] port\n", argv[0]);
		return 1;
	}

	fd_run();

	return 0;
}
