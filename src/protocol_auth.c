/*
    protocol_auth.c -- handle the meta-protocol, authentication
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

    $Id: protocol_auth.c,v 1.1.4.34 2003/12/22 11:04:16 guus Exp $
*/

#include "system.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool send_ack(connection_t *c)
{
	char buf[MAX_STRING_SIZE];
	size_t len;
	gnutls_x509_crt cert;
	const gnutls_datum *cert_list;
	int cert_list_size = 0, result;
	char *p, *name;

	cert_list = gnutls_certificate_get_peers(c->session, &cert_list_size);

	if (!cert_list || !cert_list_size) {
		logger(LOG_ERR, _("No certificates from %s"), c->hostname);
		return false;
	}

	len = sizeof buf;
	gnutls_x509_crt_init(&cert);
	result = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)
		?: gnutls_x509_crt_get_dn(cert, buf, &len);

	if(result) {
		logger(LOG_ERR, _("Error importing certificate from %s: %s"), c->hostname, gnutls_strerror(errno));
		gnutls_x509_crt_deinit(cert);
		return false;
	}

	name = strstr(buf, "CN=");
	if(!name) {
		logger(LOG_ERR, _("No name in certificate from %s"), c->hostname);
		gnutls_x509_crt_deinit(cert);
		return false;
	}
	name += 3;
	for(p = name; *p && *p != ','; p++);
	*p = '\0';

	if(!check_id(name)) {
		logger(LOG_ERR, _("Invalid name from %s"), c->hostname);
		return false;
	}

	if(c->name) {
		if(strcmp(c->name, name)) {
			logger(LOG_ERR, _("Peer %s is %s instead of %s"), c->hostname, name, c->hostname);
			return false;
		}
	} else {
		c->name = xstrdup(name);
	}
	
	result = gnutls_certificate_verify_peers(c->session);

	if(result) {
		if(result & GNUTLS_CERT_INVALID)
			logger(LOG_ERR, _("Certificate from %s (%s) invalid"), c->name, c->hostname);
		if(result & GNUTLS_CERT_REVOKED)
			logger(LOG_ERR, _("Certificate from %s (%s) revoked"), c->name, c->hostname);
		if(result & GNUTLS_CERT_SIGNER_NOT_FOUND)
			logger(LOG_ERR, _("Certificate from %s (%s) has no known signer"), c->name, c->hostname);
		if(result & GNUTLS_CERT_SIGNER_NOT_CA)
			logger(LOG_ERR, _("Certificate from %s (%s) has no CA as signer"), c->name, c->hostname);
	}
	
	if(!c->config_tree) {
		init_configuration(&c->config_tree);

		if(!read_connection_config(c)) {
			logger(LOG_ERR, _("Peer %s had unknown identity (%s)"), c->hostname,
				   c->name);
			return false;
		}
	}

	/* ACK message contains rest of the information the other end needs
	   to create node_t and edge_t structures. */

	struct timeval now;
	bool choice;

	cp();

	/* Estimate weight */

	gettimeofday(&now, NULL);
	c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;

	/* Check some options */

	if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &choice) && choice) || myself->options & OPTION_INDIRECT)
		c->options |= OPTION_INDIRECT;

	if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &choice) && choice) || myself->options & OPTION_TCPONLY)
		c->options |= OPTION_TCPONLY | OPTION_INDIRECT;

	if((get_config_bool(lookup_config(c->config_tree, "PMTUDiscovery"), &choice) && choice) || myself->options & OPTION_PMTU_DISCOVERY)
		c->options |= OPTION_PMTU_DISCOVERY;

	get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight);

	return send_request(c, "%d %s %d %lx", ACK, myport, c->estimated_weight, c->options);
}

static void send_everything(connection_t *c)
{
	avl_node_t *node, *node2;
	node_t *n;
	subnet_t *s;
	edge_t *e;

	/* Send all known subnets and edges */

	if(tunnelserver) {
		for(node = myself->subnet_tree->head; node; node = node->next) {
			s = node->data;
			send_add_subnet(c, s);
		}

		return;
	}

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;

		for(node2 = n->subnet_tree->head; node2; node2 = node2->next) {
			s = node2->data;
			send_add_subnet(c, s);
		}

		for(node2 = n->edge_tree->head; node2; node2 = node2->next) {
			e = node2->data;
			send_add_edge(c, e);
		}
	}
}

bool ack_h(connection_t *c)
{
	char hisport[MAX_STRING_SIZE];
	char *hisaddress, *dummy;
	int weight, mtu;
	long int options;
	node_t *n;

	cp();

	if(sscanf(c->buffer, "%*d " MAX_STRING " %d %lx", hisport, &weight, &options) != 3) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "ACK", c->name,
			   c->hostname);
		return false;
	}

	/* Check if we already have a node_t for him */

	n = lookup_node(c->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(c->name);
		node_add(n);
	} else {
		if(n->connection) {
			/* Oh dear, we already have a connection to this node. */
			ifdebug(CONNECTIONS) logger(LOG_DEBUG, _("Established a second connection with %s (%s), closing old connection"),
					   n->name, n->hostname);
			terminate_connection(n->connection, false);
			/* Run graph algorithm to purge key and make sure up/down scripts are rerun with new IP addresses and stuff */
			graph();
		}
	}

	n->connection = c;
	c->node = n;
	c->options |= options;

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu)
		n->mtu = mtu;

	if(get_config_int(lookup_config(myself->connection->config_tree, "PMTU"), &mtu) && mtu < n->mtu)
		n->mtu = mtu;

	/* Activate this connection */

	c->allow_request = ALL;
	c->status.active = true;

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, _("Connection with %s (%s) activated"), c->name,
			   c->hostname);

	/* Send him everything we know */

	send_everything(c);

	/* Create an edge_t for this connection */

	c->edge = new_edge();
	cp();
	c->edge->from = myself;
	c->edge->to = n;
	sockaddr2str(&c->address, &hisaddress, &dummy);
	c->edge->address = str2sockaddr(hisaddress, hisport);
	free(hisaddress);
	free(dummy);
	c->edge->weight = (weight + c->estimated_weight) / 2;
	c->edge->connection = c;
	c->edge->options = c->options;

	edge_add(c->edge);

	/* Notify everyone of the new edge */

	if(tunnelserver)
		send_add_edge(c, c->edge);
	else
		send_add_edge(broadcast, c->edge);

	/* Run MST and SSSP algorithms */

	graph();

	return true;
}
