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

#include "fd/fd.h"

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

typedef struct tnl_ep {
	struct sockaddr_storage address;
	char *id;
	char *hostname;
	struct tnl_ep_credentials *cred;
	struct tnl_ep_cryptoparm *parm;
} tnl_ep_t;

typedef struct tnl {
	struct tnl_ep local;
	struct tnl_ep remote;
	int type;
	int protocol;
	int mtu;
	enum tnl_status status;
	void *data;

	bool (*send_packet)(struct tnl *tnl, const char *buf, int len);
	bool (*send_meta)(struct tnl *tnl, const char *buf, int len);
	bool (*close)(struct tnl *tnl);

	bool (*recv_packet)(struct tnl *tnl, const char *buf, int len);
	bool (*recv_meta)(struct tnl *tnl, const char *buf, int len);
	bool (*accept)(struct tnl *tnl);
	bool (*error)(struct tnl *tnl, int errnum);

	/* private */
	
	struct fd fd;
	gnutls_session session;
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

extern bool tnl_init(void);
extern bool tnl_exit(void);
extern bool tnl_listen(struct tnl_listen *listener);
extern bool tnl_connect(struct tnl *tnl);

extern bool tnl_credentials_sprint(const char *buf, int len, const struct tnl_ep_credentials *cred);
extern bool tnl_credentials_sscan(const char *buf, struct tnl_ep_credentials *cred);
extern bool tnl_cryptoparm_sprint(const char *buf, int len, const struct tnl_ep_cryptoparm *parm);
extern bool tnl_cryptoparm_sscan(const char *buf, struct tnl_ep_cryptoparm *parm);
extern bool tnl_credentials_fprint(FILE *stream, const struct tnl_ep_credentials *cred);
extern bool tnl_credentials_fscan(FILE *stream, struct tnl_ep_credentials *cred);

#endif /* __TNL_H__ */
