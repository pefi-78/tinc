/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2003 Ivo Timmermans <ivo@o2w.nl>,
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

    $Id: net_socket.c,v 1.1.2.38 2003/12/22 11:04:16 guus Exp $
*/

#include "system.h"

#include <gnutls/gnutls.h>

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "event.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

#ifdef WSAEINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif

int addressfamily = AF_UNSPEC;
int maxtimeout = 900;
int seconds_till_retry = 5;

listen_socket_t listen_socket[MAXSOCKETS];
int listen_sockets;

int certselfunc(gnutls_session session,  const gnutls_datum *client_cert, int ncerts, const gnutls_datum* req_ca_cert, int nreqs) {
	logger(LOG_DEBUG, "Client certificate select function called with %d certs, %d requests\n", ncerts, nreqs);
	return 0;
}

int scertselfunc(gnutls_session session,  const gnutls_datum *server_cert, int ncerts) {
	logger(LOG_DEBUG, "Server certificate select function called with %d certs\n", ncerts);
	return 0;
}

/* Setup sockets */

int setup_listen_socket(const sockaddr_t *sa)
{
	int nfd;
	char *addrstr;
	int option;
	char *iface;

	cp();

	nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(nfd < 0) {
		ifdebug(STATUS) logger(LOG_ERR, _("Creating metasocket failed: %s"), strerror(errno));
		return -1;
	}

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl",
				   strerror(errno));
			return -1;
		}
	}
#endif

	/* Optimize TCP settings */

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

#if defined(SOL_TCP) && defined(TCP_NODELAY)
	setsockopt(nfd, SOL_TCP, TCP_NODELAY, &option, sizeof(option));
#endif

#if defined(SOL_IP) && defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(nfd, SOL_IP, IP_TOS, &option, sizeof(option));
#endif

	if(get_config_string
	   (lookup_config(config_tree, "BindToInterface"), &iface)) {
#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);

		if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
			closesocket(nfd);
			logger(LOG_ERR, _("Can't bind to interface %s: %s"), iface,
				   strerror(errno));
			return -1;
		}
#else
		logger(LOG_WARNING, _("BindToInterface not supported on this platform"));
#endif
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(LOG_ERR, _("Can't bind to %s/tcp: %s"), addrstr,
			   strerror(errno));
		free(addrstr);
		return -1;
	}

	if(listen(nfd, 3)) {
		closesocket(nfd);
		logger(LOG_ERR, _("System call `%s' failed: %s"), "listen",
			   strerror(errno));
		return -1;
	}

	return nfd;
}

int setup_vpn_in_socket(const sockaddr_t *sa)
{
	int nfd;
	char *addrstr;
	int option;

	cp();

	nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(nfd < 0) {
		logger(LOG_ERR, _("Creating UDP socket failed: %s"), strerror(errno));
		return -1;
	}

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl",
				   strerror(errno));
			return -1;
		}
	}
#endif

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

#if defined(SOL_IP) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
	{
		bool choice;

		if(get_config_bool(lookup_config(myself->connection->config_tree, "PMTUDiscovery"), &choice) && choice) {
			option = IP_PMTUDISC_DO;
			setsockopt(nfd, SOL_IP, IP_MTU_DISCOVER, &option, sizeof(option));
		}
	}
#endif

#if defined(SOL_IPV6) && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
	{
		bool choice;

		if(get_config_bool(lookup_config(myself->connection->config_tree, "PMTUDiscovery"), &choice) && choice) {
			option = IPV6_PMTUDISC_DO;
			setsockopt(nfd, SOL_IPV6, IPV6_MTU_DISCOVER, &option, sizeof(option));
		}
	}
#endif

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	{
		char *iface;
		struct ifreq ifr;

		if(get_config_string(lookup_config(config_tree, "BindToInterface"), &iface)) {
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);

			if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
				closesocket(nfd);
				logger(LOG_ERR, _("Can't bind to interface %s: %s"), iface,
					   strerror(errno));
				return -1;
			}
		}
	}
#endif

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(LOG_ERR, _("Can't bind to %s/udp: %s"), addrstr,
			   strerror(errno));
		free(addrstr);
		return -1;
	}

	return nfd;
}

void retry_outgoing(outgoing_t *outgoing)
{
	event_t *event;

	cp();

	outgoing->timeout += 5;

	if(outgoing->timeout > maxtimeout)
		outgoing->timeout = maxtimeout;

	event = new_event();
	event->handler = (event_handler_t) setup_outgoing_connection;
	event->time = now + outgoing->timeout;
	event->data = outgoing;
	event_add(event);

	ifdebug(CONNECTIONS) logger(LOG_NOTICE,
			   _("Trying to re-establish outgoing connection in %d seconds"),
			   outgoing->timeout);
}

void finish_connecting(connection_t *c)
{
	int result;

	cp();

	ifdebug(CONNECTIONS) logger(LOG_INFO, _("Connected to %s (%s)"), c->name, c->hostname);

	c->last_ping_time = now;

	gnutls_init(&c->session, GNUTLS_SERVER);
	gnutls_set_default_priority(c->session);
	gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, myself->connection->credentials);
	gnutls_certificate_server_set_request(c->session, GNUTLS_CERT_REQUEST);
//	gnutls_certificate_client_set_select_function(c->session, certselfunc);
//	gnutls_certificate_server_set_select_function(c->session, scertselfunc);
	gnutls_transport_set_ptr(c->session, c->socket);
}

void do_outgoing_connection(connection_t *c)
{
	char *address, *port;
	int option, result, flags;

	cp();

begin:
	if(!c->outgoing->ai) {
		if(!c->outgoing->cfg) {
			ifdebug(CONNECTIONS) logger(LOG_ERR, _("Could not set up a meta connection to %s"),
					   c->name);
			c->status.remove = true;
			retry_outgoing(c->outgoing);
			return;
		}

		get_config_string(c->outgoing->cfg, &address);

		if(!get_config_string(lookup_config(c->config_tree, "Port"), &port))
			asprintf(&port, "655");

		c->outgoing->ai = str2addrinfo(address, port, SOCK_STREAM);
		free(address);
		free(port);

		c->outgoing->aip = c->outgoing->ai;
		c->outgoing->cfg = lookup_config_next(c->config_tree, c->outgoing->cfg);
	}

	if(!c->outgoing->aip) {
		freeaddrinfo(c->outgoing->ai);
		c->outgoing->ai = NULL;
		goto begin;
	}

	memcpy(&c->address, c->outgoing->aip->ai_addr, c->outgoing->aip->ai_addrlen);
	c->outgoing->aip = c->outgoing->aip->ai_next;

	if(c->hostname)
		free(c->hostname);

	c->hostname = sockaddr2hostname(&c->address);

	ifdebug(CONNECTIONS) logger(LOG_INFO, _("Trying to connect to %s (%s)"), c->name,
			   c->hostname);

	c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(c->socket == -1) {
		ifdebug(CONNECTIONS) logger(LOG_ERR, _("Creating socket for %s failed: %s"), c->hostname,
				   strerror(errno));

		goto begin;
	}

	/* Optimize TCP settings */

#if defined(SOL_TCP) && defined(TCP_NODELAY)
	option = 1;
	setsockopt(c->socket, SOL_TCP, TCP_NODELAY, &option, sizeof(option));
#endif

#if defined(SOL_IP) && defined(IP_TOS)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, SOL_IP, IP_TOS, &option, sizeof(option));
#endif

	/* Non-blocking */

#ifdef O_NONBLOCK
	flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(LOG_ERR, _("fcntl for %s: %s"), c->hostname, strerror(errno));
	}
#endif

	/* Connect */

	result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));

	if(result == -1) {
		if(errno == EINPROGRESS) {
			c->status.connecting = true;
			return;
		}

		closesocket(c->socket);

		ifdebug(CONNECTIONS) logger(LOG_ERR, _("%s: %s"), c->hostname, strerror(errno));

		goto begin;
	}

	logger(LOG_DEBUG, _("finishing connection"));
	finish_connecting(c);

	return;
}

void setup_outgoing_connection(outgoing_t *outgoing)
{
	connection_t *c;
	node_t *n;

	cp();

	n = lookup_node(outgoing->name);

	if(n)
		if(n->connection) {
			ifdebug(CONNECTIONS) logger(LOG_INFO, _("Already connected to %s"), outgoing->name);

			n->connection->outgoing = outgoing;
			return;
		}

	c = new_connection();
	c->name = xstrdup(outgoing->name);

	init_configuration(&c->config_tree);
	read_connection_config(c);

	outgoing->cfg = lookup_config(c->config_tree, "Address");

	if(!outgoing->cfg) {
		logger(LOG_ERR, _("No address specified for %s"), c->name);
		free_connection(c);
		free(outgoing->name);
		free(outgoing);
		return;
	}

	c->outgoing = outgoing;
	c->last_ping_time = now;

	connection_add(c);

	do_outgoing_connection(c);
}

/*
  accept a new tcp connect and create a
  new connection
*/
bool handle_new_meta_connection(int sock)
{
	connection_t *c;
	sockaddr_t sa;
	int fd, len = sizeof(sa);
	int result;

	cp();

	fd = accept(sock, &sa.sa, &len);

	if(fd < 0) {
		logger(LOG_ERR, _("Accepting a new connection failed: %s"),
			   strerror(errno));
		return false;
	}

#ifdef O_NONBLOCK
	{
		int flags = fcntl(fd, F_GETFL);

		if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(fd);
			logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl",
				   strerror(errno));
			return -1;
		}
	}
#endif

	sockaddrunmap(&sa);

	c = new_connection();

	c->address = sa;
	c->hostname = sockaddr2hostname(&sa);
	c->socket = fd;
	c->last_ping_time = now;

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, _("Connection from %s"), c->hostname);

	connection_add(c);

	c->allow_request = ID;
	gnutls_init(&c->session, GNUTLS_CLIENT);
	gnutls_set_default_priority(c->session);
	gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, myself->connection->credentials);
	gnutls_certificate_server_set_request(c->session, GNUTLS_CERT_REQUEST);
//	gnutls_certificate_client_set_select_function(c->session, certselfunc);
//	gnutls_certificate_server_set_select_function(c->session, scertselfunc);
	gnutls_transport_set_ptr(c->session, c->socket);
	gnutls_handshake(c->session);

	return true;
}

void try_outgoing_connections(void)
{
	static config_t *cfg = NULL;
	char *name;
	outgoing_t *outgoing;

	cp();

	for(cfg = lookup_config(config_tree, "ConnectTo"); cfg;
		cfg = lookup_config_next(config_tree, cfg)) {
		get_config_string(cfg, &name);

		if(!check_id(name)) {
			logger(LOG_ERR,
				   _("Invalid name for outgoing connection in %s line %d"),
				   cfg->file, cfg->line);
			free(name);
			continue;
		}

		outgoing = xmalloc_and_zero(sizeof(*outgoing));
		outgoing->name = name;
		setup_outgoing_connection(outgoing);
	}
}
