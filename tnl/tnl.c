/*
    tnl.c -- tunnels

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

#include <gnutls/gnutls.h>

#include "support/avl.h"
#include "support/sockaddr.h"
#include "support/xalloc.h"
#include "tnl/tnl.h"

static bool tnl_send(tnl_t *tnl, const void *buf, int len) {
	int result;

	while(len) {
		result = gnutls_record_send(tnl->session, buf, len);
		if(result <= 0) {
			if(result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN)
				continue;

			if(result)
				logger(LOG_ERR, _("tnl: error while sending: %s"), gnutls_strerror(result));
			else
				logger(LOG_INFO, _("tnl: connection closed by peer"));

			tnl->error(tnl, result);
			tnl->close(tnl);
			return !result;
		}

		buf += result;
		len -= result;
	}

	return true;
}

static bool tnl_recv(tnl_t *tnl) {
	int result;
	tnl_record_t *record = (tnl_record_t *)tnl->buf;

	result = gnutls_record_recv(tnl->session, tnl->buf + tnl->bufread, sizeof tnl->buf - tnl->bufread);
	if(result <= 0) {
		if(result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN)
			return true;

		if(result)
			logger(LOG_ERR, _("tnl: error while receiving: %s"), gnutls_strerror(result));
		else
			logger(LOG_INFO, _("tnl: connection closed by peer"));

		tnl->error(tnl, result);
		tnl->close(tnl);
		return !result;
	}

	tnl->bufread += result;

	while(tnl->bufread >= sizeof *record && tnl->bufread - sizeof *record >= record->len) {
		switch(record->type) {
			case TNL_RECORD_META:
				tnl->recv_meta(tnl, record->data, record->len);
				break;

			case TNL_RECORD_PACKET:
				tnl->recv_packet(tnl, record->data, record->len);
				break;
				
			default:
				logger(LOG_ERR, _("tnl: error while receiving: %s"), _("unknown record type"));
				tnl->error(tnl, EINVAL);
				tnl->close(tnl);
				return false;
		}

		tnl->bufread -= sizeof *record + record->len;
		memmove(tnl->buf, record->data + record->len, tnl->bufread);
	}
}

static bool tnl_recv_handler(fd_t *fd) {
	tnl_t *tnl = fd->data;
	int result;

	result = gnutls_record_recv(tnl->session, tnl->buf + tnl->bufread, sizeof(tnl->buf) - tnl->bufread);
	if(result < 0) {
		if(gnutls_error_is_fatal(result)) {
			logger(LOG_DEBUG, _("tnl: reception failed: %s\n"), gnutls_strerror(result));
			tnl->error(tnl, result);
			tnl->close(tnl);
			return false;
		}

		return true;
	}

	tnl->bufread += result;
	return tnl_recv(tnl);
}

static bool tnl_authenticate(tnl_t *tnl) {
	gnutls_x509_crt cert;
        const gnutls_datum *certs;
        int ncerts = 0, result;
	char buf[1024], *name, *p;
	int len;

	certs = gnutls_certificate_get_peers(tnl->session, &ncerts);

	if (!certs || !ncerts) {
		logger(LOG_ERR, _("tnl: no certificates from %s"), tnl->remote.hostname);
		return false;
	}

	len = sizeof buf;
	gnutls_x509_crt_init(&cert);
	result = gnutls_x509_crt_import(cert, certs, GNUTLS_X509_FMT_DER) ?: gnutls_x509_crt_get_dn(cert, buf, &len);

	if(result) {
		logger(LOG_ERR, _("tnl: error importing certificate from %s: %s"), tnl->remote.hostname, gnutls_strerror(errno));
		gnutls_x509_crt_deinit(cert);
		return false;
	}

	name = strstr(buf, "CN=");
	if(!name) {
		logger(LOG_ERR, _("tnl: no name in certificate from %s"), tnl->remote.hostname);
		gnutls_x509_crt_deinit(cert);
		return false;
	}

	name += 3;
	for(p = name; *p && *p != ','; p++);
	*p = '\0';

	if(tnl->remote.id && strcmp(tnl->remote.id, name)) {
		logger(LOG_ERR, _("tnl: peer %s is %s instead of %s"), tnl->remote.hostname, name, tnl->remote.id);
		return false;
	}

	replace(tnl->remote.id, name);

	result = gnutls_certificate_verify_peers(tnl->session);

	if(result < 0) {
		logger(LOG_ERR, "tnl: error verifying certificate from %s (%s): %s\n", tnl->remote.id, tnl->remote.hostname, gnutls_strerror(result));
		return false;
	}

	if(result) {
		logger(LOG_ERR, "tnl: certificate from %s (%s) not good, verification result %x", tnl->remote.id, tnl->remote.hostname, result);
		return false;
	}
}

	

static bool tnl_handshake_handler(fd_t *fd) {
	char id[1024];
	tnl_t *tnl = fd->data;
	int result;

	result = gnutls_handshake(tnl->session);
	if(result < 0) {
		if(gnutls_error_is_fatal(result)) {
			logger(LOG_ERR, "tnl: handshake error: %s\n", gnutls_strerror(result));
			tnl->close(tnl);
			return false;
		}

		/* check other stuff? */
		return true;
	}
	
	logger(LOG_DEBUG, _("tnl: handshake finished"));

	if(!tnl_authenticate(tnl))
		return false;

	tnl->status == TNL_STATUS_UP;
	tnl->fd.read = tnl_recv_handler;
	tnl->accept(tnl);
	return true;
}

static bool tnl_send_meta(tnl_t *tnl, const void *buf, int len) {
	tnl_record_t record = {
		.type = TNL_RECORD_META,
		.len = len,
	};

	return tnl_send(tnl, &record, sizeof record) && tnl_send(tnl, buf, len);
}

static bool tnl_send_packet(tnl_t *tnl, const void *buf, int len) {
	tnl_record_t record = {
		.type = TNL_RECORD_PACKET,
		.len = len,
	};

	return tnl_send(tnl, &record, sizeof record) && tnl_send(tnl, buf, len);
}

static bool tnl_close(tnl_t *tnl) {
	if(tnl->session) {
		gnutls_bye(tnl->session, GNUTLS_SHUT_RDWR);
		gnutls_deinit(tnl->session);
	}
		
	fd_del(&tnl->fd);
	close(tnl->fd.fd);
	
	return true;
}

static bool tnl_accept_error(tnl_t *tnl, int errnum) {
	logger(LOG_ERR, _("tnl: error %d on accepted tunnel"));
	return true;
}

static bool tnl_accept_handler(fd_t *fd) {
	tnl_listen_t *listener = fd->data;
	tnl_t *tnl;
	struct sockaddr_storage ss;
	socklen_t len = sizeof ss;
	int sock;	
	
	sock = accept(fd->fd, sa(&ss), &len);

	if(sock == -1) {
		logger(LOG_ERR, _("tnl: could not accept incoming connection: %s"), strerror(errno));
		return false;
	}

	logger(LOG_DEBUG, _("tnl: accepted incoming connection"));

	sa_unmap(&ss);

	clear(new(tnl));
	tnl->local = listener->local;
	tnl->remote.address = ss;
	len = sizeof tnl->local.address;
	getsockname(sock, sa(&tnl->local.address), &len);
	sa_unmap(&tnl->local.address);
	tnl->type = listener->type;
	tnl->protocol = listener->protocol;
	tnl->status = TNL_STATUS_CONNECTING;
	tnl->error = tnl_accept_error;
	tnl->close = tnl_close;

	tnl->fd.fd = sock;
	tnl->fd.read = tnl_handshake_handler;
	tnl->fd.data = tnl;

	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);

	gnutls_init(&tnl->session, GNUTLS_SERVER);
	//gnutls_handshake_set_private_extensions(tnl->session, 1);
	gnutls_set_default_priority(tnl->session);
	gnutls_credentials_set(tnl->session, GNUTLS_CRD_CERTIFICATE, tnl->local.cred);
	gnutls_certificate_server_set_request(tnl->session, GNUTLS_CERT_REQUEST);
	gnutls_transport_set_ptr(tnl->session, (gnutls_transport_ptr)sock);
	gnutls_handshake(tnl->session);

	tnl->accept = listener->accept;
	
	fd_add(&tnl->fd);
	
	return true;
}	

static bool tnl_connect_handler(fd_t *fd) {
	tnl_t *tnl = fd->data;
	int result;
	socklen_t len;

	len = sizeof result;
	getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &result, &len);
	if(result) {
		logger(LOG_ERR, "tnl: error while connecting: %s", strerror(result));
		tnl->error(tnl, result);
		tnl->close(tnl);
		return false;
	}
	
	fcntl(tnl->fd.fd, F_SETFL, fcntl(tnl->fd.fd, F_GETFL) | O_NONBLOCK);

	tnl->status = TNL_STATUS_HANDSHAKE;
	gnutls_init(&tnl->session, GNUTLS_CLIENT);
	//gnutls_handshake_set_private_extensions(tnl->session, 1);
	gnutls_set_default_priority(tnl->session);
	gnutls_credentials_set(tnl->session, GNUTLS_CRD_CERTIFICATE, tnl->local.cred);
	gnutls_certificate_server_set_request(tnl->session, GNUTLS_CERT_REQUEST);
	gnutls_transport_set_ptr(tnl->session, (gnutls_transport_ptr)fd->fd);
	gnutls_handshake(tnl->session);

	tnl->fd.write = NULL;
	tnl->fd.read = tnl_handshake_handler;
	fd_mod(&tnl->fd);

	logger(LOG_DEBUG, _("tnl: connected"));
	
	return true;
}

bool tnl_connect(tnl_t *tnl) {
	int sock;

	sock = socket(sa_family(&tnl->remote.address), tnl->type, tnl->protocol);

	if(sock == -1) {
		logger(LOG_ERR, _("tnl: could not create socket: %s"), strerror(errno));
		return false;
	}
	
#if 0
	if(sa_nonzero(&tnl->local.address) && bind(sock, sa(&tnl->local.address), sa_len(&tnl->local.address)) == -1) {
		logger(LOG_ERR, _("tnl: could not bind socket: %s"), strerror(errno));
		close(sock);
		return false;
	}
#endif

	if(connect(sock, sa(&tnl->remote.address), sa_len(&tnl->remote.address)) == -1) {
		logger(LOG_ERR, _("tnl: could not connect: %s"), strerror(errno));
		close(sock);
		return false;
	}

	tnl->status = TNL_STATUS_CONNECTING;

	tnl->fd.fd = sock;
	tnl->fd.write = tnl_connect_handler;
	tnl->fd.data = tnl;

	tnl->send_packet = tnl_send_packet;
	tnl->send_meta = tnl_send_meta;
	tnl->close = tnl_close;
	
	fd_add(&tnl->fd);

	return true;
}

static bool tnl_listen_close(tnl_listen_t *listener) {
	fd_del(&listener->fd);
	close(listener->fd.fd);
	return true;
}

bool tnl_listen(tnl_listen_t *listener) {
	int sock;

	sock = socket(sa_family(&listener->local.address), listener->type, listener->protocol);

	if(sock == -1) {
		logger(LOG_ERR, _("tnl: could not create listener socket: %s"), strerror(errno));
		return false;
	}
	
	if(bind(sock, sa(&listener->local.address), sa_len(&listener->local.address)) == -1) {
		logger(LOG_ERR, _("tnl: could not bind listener socket: %s"), strerror(errno));
		return false;
	}
	
	if(listen(sock, 10) == -1) {
		logger(LOG_ERR, _("tnl: could not listen on listener socket: %s"), strerror(errno));
		return false;
	}

	listener->fd.fd = sock;
	listener->fd.read = tnl_accept_handler;
	listener->fd.data = listener;
	listener->close = tnl_listen_close;

	fd_add(&listener->fd);

	return true;
}
