/*
    tnl.h -- tunnels

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

#ifndef __TNL_H__
#define __TNL_H__

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>

#include "fd/fd.h"

#define TNL_PROTOCOL 0

#define TNL_RECORD_PACKET 0
#define TNL_RECORD_META 1
#define TNL_RECORD_HELLO 2
#define TNL_RECORD_BLA 3

typedef struct tnl_record {
	uint16_t type;
	uint16_t len;
	char data[];
} tnl_record_t;

typedef enum tnl_status {
	TNL_STATUS_DOWN,
	TNL_STATUS_CONNECTING,
	TNL_STATUS_HANDSHAKE,
	TNL_STATUS_UP,
} tnl_status_t;

typedef struct tnl_ep_credentials {
	gnutls_credentials_type type;
	union {
		gnutls_anon_client_credentials anon_client;
		gnutls_anon_server_credentials anon_server;
		gnutls_srp_client_credentials srp_client;
		gnutls_srp_server_credentials srp_server;
		gnutls_certificate_credentials certificate;
	};
} tnl_ep_credentials_t;		

typedef struct tnl_ep_cryptoparm {
} tnl_ep_cryptoparm_t;

typedef struct tnl_ep {
	struct sockaddr_storage address;
	char *id;
	char *hostname;
	struct tnl_ep_credentials cred;
	struct tnl_ep_cryptoparm parm;
} tnl_ep_t;

typedef struct tnl {
	struct tnl_ep local;
	struct tnl_ep remote;
	int type;
	int protocol;
	int mtu;
	enum tnl_status status;
	void *data;

	bool (*send_packet)(struct tnl *tnl, const void *buf, int len);
	bool (*send_meta)(struct tnl *tnl, const void *buf, int len);
	bool (*close)(struct tnl *tnl);

	bool (*recv_packet)(struct tnl *tnl, const void *buf, int len);
	bool (*recv_meta)(struct tnl *tnl, const void *buf, int len);
	bool (*accept)(struct tnl *tnl);
	bool (*error)(struct tnl *tnl, int errnum);

	/* private */
	
	gnutls_session session;
	struct fd fd;
	char buf[4096];
	int bufread;
} tnl_t;

typedef struct tnl_listen {
	struct tnl_ep local;
	int type;
	int protocol;

	bool (*accept)(struct tnl *tnl);
	bool (*close)(struct tnl_listen *listener);

	struct fd fd;
} tnl_listen_t;

extern bool tnl_listen(struct tnl_listen *listener);
extern bool tnl_connect(struct tnl *tnl);

extern bool tnl_ep_set_x509_credentials(tnl_ep_t *tnl_ep, const char *key, const char *certificate, const char *trust, const char *crl);
extern bool tnl_ep_set_openpgp_credentials(tnl_ep_t *tnl_ep, const char *privkey, const char *pubkey, const char *keyring, const char *trustdb);

#endif /* __TNL_H__ */
