/*
    protocol_key.c -- handle the meta-protocol, key exchange
    Copyright (C) 1999-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: protocol_key.c,v 1.1.4.26 2003/12/20 21:25:17 guus Exp $
*/

#include "system.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include "avl_tree.h"
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool mykeyused = false;

bool send_key_changed(connection_t *c, const node_t *n)
{
	cp();

	/* Only send this message if some other daemon requested our key previously.
	   This reduces unnecessary key_changed broadcasts.
	 */

	if(n == myself && !mykeyused)
		return true;

	return send_request(c, "%d %lx %s", KEY_CHANGED, random(), n->name);
}

bool key_changed_h(connection_t *c)
{
	char name[MAX_STRING_SIZE];
	node_t *n;

	cp();

	if(sscanf(c->buffer, "%*d %*x " MAX_STRING, name) != 1) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "KEY_CHANGED",
			   c->name, c->hostname);
		return false;
	}

	if(seen_request(c->buffer))
		return true;

	n = lookup_node(name);

	if(!n) {
		logger(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist"),
			   "KEY_CHANGED", c->name, c->hostname, name);
		return false;
	}

	n->status.validkey = false;
	n->status.waitingforkey = false;

	/* Tell the others */

	if(!tunnelserver)
		forward_request(c);

	return true;
}

bool send_req_key(connection_t *c, const node_t *from, const node_t *to)
{
	cp();

	return send_request(c, "%d %s %s", REQ_KEY, from->name, to->name);
}

bool req_key_h(connection_t *c)
{
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;

	cp();

	if(sscanf(c->buffer, "%*d " MAX_STRING " " MAX_STRING, from_name, to_name) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "REQ_KEY", c->name,
			   c->hostname);
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist in our connection list"),
			   "REQ_KEY", c->name, c->hostname, from_name);
		return false;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, _("Got %s from %s (%s) destination %s which does not exist in our connection list"),
			   "REQ_KEY", c->name, c->hostname, to_name);
		return false;
	}

	/* Check if this key request is for us */

	if(to == myself) {			/* Yes, send our own key back */
		mykeyused = true;
		from->received_seqno = 0;
		memset(from->late, 0, sizeof(from->late));
		send_ans_key(c, from);
	} else {
		if(tunnelserver)
			return false;

		send_req_key(to->nexthop->connection, from, to);
	}

	return true;
}

bool send_ans_key(connection_t *c, const node_t *to)
{
	char cipherkey[myself->cipherkeylen * 2 + 1];
	char digestkey[myself->digestlen * 2 + 1];

	cp();

	bin2hex(myself->cipherkey, cipherkey, myself->cipherkeylen);
	cipherkey[myself->cipherkeylen * 2] = '\0';

	bin2hex(myself->digestkey, digestkey, myself->digestlen);
	digestkey[myself->digestlen * 2] = '\0';

	return send_request(c, "%d %s %s %s %s %d %d %d %d", ANS_KEY,
						myself->name, to->name, cipherkey, digestkey,
						myself->cipher,
						myself->digest, myself->maclength,
						myself->compression);
}

bool ans_key_h(connection_t *c)
{
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char cipherkey[MAX_STRING_SIZE];
	char digestkey[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	node_t *from, *to;

	cp();

	if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %d %d",
			from_name, to_name, cipherkey, digestkey, &cipher, &digest, &maclength, &compression) != 8) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "ANS_KEY", c->name,
			   c->hostname);
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist in our connection list"),
			   "ANS_KEY", c->name, c->hostname, from_name);
		return false;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, _("Got %s from %s (%s) destination %s which does not exist in our connection list"),
			   "ANS_KEY", c->name, c->hostname, to_name);
		return false;
	}

	/* Forward it if necessary */

	if(to != myself) {
		if(tunnelserver)
			return false;

		return send_request(to->nexthop->connection, "%s", c->buffer);
	}

	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		from->cipher = cipher;
		if(!*gcry_cipher_algo_name(from->cipher)) {
			logger(LOG_ERR, _("Node %s (%s) uses unknown cipher!"), from->name,
				   from->hostname);
			return false;
		}

		from->cipherblklen = gcry_cipher_get_algo_blklen(from->cipher);
	} else {
		from->cipher = GCRY_CIPHER_NONE;
	}

	from->maclength = maclength;

	if(digest) {
		from->digest = digest;

		if(!*gcry_md_algo_name(from->digest)) {
			logger(LOG_ERR, _("Node %s (%s) uses unknown digest!"), from->name,
				   from->hostname);
			return false;
		}

		from->digestlen = gcry_md_get_algo_dlen(from->digest);
		
		if(from->maclength > from->digestlen || from->maclength < 0) {
			logger(LOG_ERR, _("Node %s (%s) uses bogus MAC length!"),
				   from->name, from->hostname);
			return false;
		}
	} else {
		from->digest = GCRY_MD_NONE;
	}

	if(compression < 0 || compression > 11) {
		logger(LOG_ERR, _("Node %s (%s) uses bogus compression level!"), from->name, from->hostname);
		return false;
	}
	
	from->compression = compression;

	/* Update our copy of the origin's packet key */

	if(from->cipherkey)
		free(from->cipherkey);

	from->cipherkeylen = strlen(cipherkey) / 2;
	from->cipherkey = xmalloc(from->cipherkeylen);
	hex2bin(cipherkey, from->cipherkey, from->cipherkeylen);

	if(from->cipherkeylen != gcry_cipher_get_algo_keylen(from->cipher)) {
		logger(LOG_ERR, _("Node %s (%s) uses wrong keylength %d instead of %d!"), from->name,
			   from->hostname, from->cipherkeylen, gcry_cipher_get_algo_keylen(from->cipher) );
		return false;
	}

	if(from->digestkey)
		free(from->digestkey);

	from->digestlen = strlen(digestkey) / 2;
	from->digestkey = xmalloc(from->digestlen);
	hex2bin(digestkey, from->digestkey, from->digestlen);
	
	if(from->cipher) {
		int result;
		result = gcry_cipher_open(&from->cipher_ctx, from->cipher, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
		gcry_cipher_setkey(from->cipher_ctx, from->cipherkey, from->cipherkeylen);
		if(result) {
			logger(LOG_ERR, _("Error during initialisation of key from %s (%s): %s"),
					from->name, from->hostname, gcry_strerror(result));
			return false;
		}
	}

	if(from->digest) {
		int result;
		result = gcry_md_open(&from->digest_ctx, from->digest, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
		gcry_md_setkey(from->digest_ctx, from->digestkey, from->digestlen);
		if(result) {
			logger(LOG_ERR, _("Error during initialisation of key from %s (%s): %s"),
					from->name, from->hostname, gcry_strerror(result));
			return false;
		}
	}

	from->status.validkey = true;
	from->status.waitingforkey = false;
	from->sent_seqno = 0;

	if(from->options & OPTION_PMTU_DISCOVERY && !from->mtuprobes)
		send_mtu_probe(from);

	flush_queue(from);

	return true;
}
