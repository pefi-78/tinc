/*
    connection.c -- connection list management
    Copyright (C) 2000-2003 Guus Sliepen <guus@sliepen.eu.org>,
                  2000-2003 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: connection.c,v 1.1.2.44 2003/08/28 21:05:10 guus Exp $
*/

#include "system.h"

#include "avl_tree.h"
#include "conf.h"
#include "list.h"
#include "logger.h"
#include "net.h"				/* Don't ask. */
#include "netutl.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *connection_tree;	/* Meta connections */
connection_t *broadcast;

static int connection_compare(const connection_t *a, const connection_t *b)
{
	return (void *)a - (void *)b;
}

void init_connections(void)
{
	cp();

	connection_tree = avl_alloc_tree((avl_compare_t) connection_compare, NULL);
	broadcast = new_connection();
	broadcast->name = xstrdup(_("everyone"));
	broadcast->hostname = xstrdup(_("BROADCAST"));
}

void exit_connections(void)
{
	cp();

	avl_delete_tree(connection_tree);
	free_connection(broadcast);
}

connection_t *new_connection(void)
{
	connection_t *c;

	cp();

	c = xmalloc_and_zero(sizeof(connection_t));

	if(!c)
		return NULL;

	gettimeofday(&c->start, NULL);

	return c;
}

void free_connection(connection_t *c)
{
	cp();

	free(c);
}

void connection_add(connection_t *c)
{
	cp();

	avl_insert(connection_tree, c);
}

void connection_del(connection_t *c)
{
	cp();

	avl_delete(connection_tree, c);
}

void dump_connections(void)
{
	avl_node_t *node;
	connection_t *c;

	cp();

	logger(LOG_DEBUG, _("Connections:"));

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		logger(LOG_DEBUG, _(" %s at %s options %lx socket %d cipher %s digest %s compression %s kx method %s status %04x"),
				c->name, c->hostname, c->options, c->socket,
				c->session ? gnutls_cipher_get_name(gnutls_cipher_get(c->session)) : "-",
				c->session ? gnutls_mac_get_name(gnutls_mac_get(c->session)) : "-",
				c->session ? gnutls_compression_get_name(gnutls_compression_get(c->session)) : "-",
				c->session ? gnutls_kx_get_name(gnutls_kx_get(c->session)) : "-",
			   *(uint32_t *)&c->status);
	}

	logger(LOG_DEBUG, _("End of connections."));
}

bool read_connection_config(connection_t *c)
{
	char *fname;
	int x;

	cp();

	asprintf(&fname, "%s/hosts/%s", confbase, c->name);
	x = read_config_file(c->config_tree, fname);
	free(fname);

	return x == 0;
}
