/*
    net_setup.c -- Setup.
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

    $Id: net_setup.c,v 1.1.2.50 2003/12/20 21:25:17 guus Exp $
*/

#include "system.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h>

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "device.h"
#include "event.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "route.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

char *myport;

#if 0
bool read_rsa_public_key(connection_t *c)
{
	FILE *fp;
	char *fname;
	char *key;

	cp();

	if(!c->rsa_key) {
		c->rsa_key = RSA_new();
//		RSA_blinding_on(c->rsa_key, NULL);
	}

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &key)) {
		BN_hex2bn(&c->rsa_key->n, key);
		BN_hex2bn(&c->rsa_key->e, "FFFF");
		free(key);
		return true;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &fname)) {
		fp = fopen(fname, "r");

		if(!fp) {
			logger(LOG_ERR, _("Error reading RSA public key file `%s': %s"),
				   fname, strerror(errno));
			free(fname);
			return false;
		}

		free(fname);
		c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);

		if(c->rsa_key)
			return true;		/* Woohoo. */

		/* If it fails, try PEM_read_RSA_PUBKEY. */
		fp = fopen(fname, "r");

		if(!fp) {
			logger(LOG_ERR, _("Error reading RSA public key file `%s': %s"),
				   fname, strerror(errno));
			free(fname);
			return false;
		}

		free(fname);
		c->rsa_key = PEM_read_RSA_PUBKEY(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);

		if(c->rsa_key) {
//				RSA_blinding_on(c->rsa_key, NULL);
			return true;
		}

		logger(LOG_ERR, _("Reading RSA public key file `%s' failed: %s"),
			   fname, strerror(errno));
		return false;
	}

	/* Else, check if a harnessed public key is in the config file */

	asprintf(&fname, "%s/hosts/%s", confbase, c->name);
	fp = fopen(fname, "r");

	if(fp) {
		c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);
	}

	free(fname);

	if(c->rsa_key)
		return true;

	/* Try again with PEM_read_RSA_PUBKEY. */

	asprintf(&fname, "%s/hosts/%s", confbase, c->name);
	fp = fopen(fname, "r");

	if(fp) {
		c->rsa_key = PEM_read_RSA_PUBKEY(fp, &c->rsa_key, NULL, NULL);
//		RSA_blinding_on(c->rsa_key, NULL);
		fclose(fp);
	}

	free(fname);

	if(c->rsa_key)
		return true;

	logger(LOG_ERR, _("No public key for %s specified!"), c->name);

	return false;
}
#endif

bool setup_credentials(void)
{
	char *trust = NULL, *crl = NULL;
	char *key = NULL, *cert = NULL;
	int result;

	cp();

	gnutls_certificate_allocate_credentials(&myself->connection->credentials);

	if(get_config_string(lookup_config(config_tree, "TrustFile"), &trust)) {
		result = gnutls_certificate_set_x509_trust_file(myself->connection->credentials, trust, GNUTLS_X509_FMT_PEM);
		if(result < 0) {
			logger(LOG_ERR, _("Error reading trust file '%s': %s"), trust, gnutls_strerror(result));
			free(trust);
			return false;
		}
		free(trust);
	}

	if(get_config_string(lookup_config(config_tree, "CRLFile"), &crl)) {
		result = gnutls_certificate_set_x509_crl_file(myself->connection->credentials, crl, GNUTLS_X509_FMT_PEM);
		if(result) {
			logger(LOG_ERR, _("Error reading CRL file '%s': %s"), crl, gnutls_strerror(result));
			free(crl);
			return false;
		}
		free(crl);
	}

	if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &key))
		asprintf(&key, "%s/rsa_key.priv", confbase);

	if(!get_config_string(lookup_config(config_tree, "CertificateFile"), &cert))
		asprintf(&cert, "%s/hosts/%s", confbase, myself->name);

	
	gnutls_certificate_set_x509_trust_file(myself->connection->credentials, cert, GNUTLS_X509_FMT_PEM);
	logger(LOG_DEBUG, _("JOEHOE"));
	gnutls_certificate_set_verify_flags(myself->connection->credentials, GNUTLS_VERIFY_DISABLE_CA_SIGN);
	
	result = gnutls_certificate_set_x509_key_file(myself->connection->credentials, cert, key, GNUTLS_X509_FMT_PEM);

	if(result) {
		logger(LOG_ERR, _("Error reading credentials from %s and %s: %s"), cert, key, gnutls_strerror(result));
		free(key);
		free(cert);
		return false;
	}

	free(key);
	free(cert);
	
	return true;
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
bool setup_myself(void)
{
	config_t *cfg;
	subnet_t *subnet;
	char *name, *hostname, *mode, *afname, *cipher, *digest;
	char *address = NULL;
	char *envp[5];
	struct addrinfo *ai, *aip, hint = {0};
	bool choice;
	int i, err, result;

	cp();

	myself = new_node();
	myself->connection = new_connection();
	init_configuration(&myself->connection->config_tree);

	asprintf(&myself->hostname, _("MYSELF"));
	asprintf(&myself->connection->hostname, _("MYSELF"));

	myself->connection->options = 0;
	myself->connection->protocol_version = PROT_CURRENT;

	if(!get_config_string(lookup_config(config_tree, "Name"), &name)) {	/* Not acceptable */
		logger(LOG_ERR, _("Name for tinc daemon required!"));
		return false;
	}

	if(!check_id(name)) {
		logger(LOG_ERR, _("Invalid name for myself!"));
		free(name);
		return false;
	}

	myself->name = name;
	myself->connection->name = xstrdup(name);

	if(!setup_credentials())
		return false;

	if(!read_connection_config(myself->connection)) {
		logger(LOG_ERR, _("Cannot open host configuration file for myself!"));
		return false;
	}

	if(!get_config_string (lookup_config(myself->connection->config_tree, "Port"), &myport))
		asprintf(&myport, "655");

	/* Read in all the subnets specified in the host configuration file */

	cfg = lookup_config(myself->connection->config_tree, "Subnet");

	while(cfg) {
		if(!get_config_subnet(cfg, &subnet))
			return false;

		subnet_add(myself, subnet);

		cfg = lookup_config_next(myself->connection->config_tree, cfg);
	}

	/* Check some options */

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(get_config_bool(lookup_config(myself->connection->config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(myself->connection->config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(get_config_bool(lookup_config(myself->connection->config_tree, "PMTUDiscovery"), &choice) && choice)
		myself->options |= OPTION_PMTU_DISCOVERY;

	if(myself->options & OPTION_TCPONLY)
		myself->options |= OPTION_INDIRECT;

	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);

	if(get_config_string(lookup_config(config_tree, "Mode"), &mode)) {
		if(!strcasecmp(mode, "router"))
			routing_mode = RMODE_ROUTER;
		else if(!strcasecmp(mode, "switch"))
			routing_mode = RMODE_SWITCH;
		else if(!strcasecmp(mode, "hub"))
			routing_mode = RMODE_HUB;
		else {
			logger(LOG_ERR, _("Invalid routing mode!"));
			return false;
		}
		free(mode);
	} else
		routing_mode = RMODE_ROUTER;

	get_config_bool(lookup_config(config_tree, "PriorityInheritance"), &priorityinheritance);

#if !defined(SOL_IP) || !defined(IP_TOS)
	if(priorityinheritance)
		logger(LOG_WARNING, _("PriorityInheritance not supported on this platform"));
#endif

	if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire))
		macexpire = 600;

	if(get_config_int(lookup_config(config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(LOG_ERR, _("Bogus maximum timeout!"));
			return false;
		}
	} else
		maxtimeout = 900;

	if(get_config_string(lookup_config(config_tree, "AddressFamily"), &afname)) {
		if(!strcasecmp(afname, "IPv4"))
			addressfamily = AF_INET;
		else if(!strcasecmp(afname, "IPv6"))
			addressfamily = AF_INET6;
		else if(!strcasecmp(afname, "any"))
			addressfamily = AF_UNSPEC;
		else {
			logger(LOG_ERR, _("Invalid address family!"));
			return false;
		}
		free(afname);
	}

	get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);

	/* Generate packet encryption key */

	if(get_config_string (lookup_config(myself->connection->config_tree, "Cipher"), &cipher)) {
		if(!strcasecmp(cipher, "none")) {
			myself->cipher = GCRY_CIPHER_NONE;
		} else {
			myself->cipher = gcry_cipher_map_name(cipher);

			if(!myself->cipher) {
				logger(LOG_ERR, _("Unrecognized cipher type!"));
				return false;
			}
		}
	} else
		myself->cipher = GCRY_CIPHER_AES;

	if(myself->cipher) {
		result = gcry_cipher_open(&myself->cipher_ctx, myself->cipher, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);

		if(result) {
			logger(LOG_ERR, _("Error during initialisation of cipher for %s (%s): %s"),
					myself->name, myself->hostname, gcry_strerror(result));
			return false;
		}

	}

	if(myself->cipher) {
		myself->cipherkeylen = gcry_cipher_get_algo_keylen(myself->cipher);
		myself->cipherblklen = gcry_cipher_get_algo_blklen(myself->cipher);
	} else {
		myself->cipherkeylen = 1;
	}

	logger(LOG_DEBUG, _("Key %s len %d"), gcry_cipher_algo_name(myself->cipher), myself->cipherkeylen);
	myself->cipherkey = xmalloc(myself->cipherkeylen);
	gcry_randomize(myself->cipherkey, myself->cipherkeylen, GCRY_STRONG_RANDOM);
	if(myself->cipher)
		gcry_cipher_setkey(myself->cipher_ctx, myself->cipherkey, myself->cipherkeylen);

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
		keylifetime = 3600;

	keyexpires = now + keylifetime;
	
	/* Check if we want to use message authentication codes... */

	if(get_config_string (lookup_config(myself->connection->config_tree, "Digest"), &digest)) {
		if(!strcasecmp(digest, "none")) {
			myself->digest = GCRY_MD_NONE;
		} else {
			myself->digest = gcry_md_map_name(digest);

			if(!myself->digest) {
				logger(LOG_ERR, _("Unrecognized digest type!"));
				return false;
			}
		}
	} else
		myself->digest = GCRY_MD_SHA1;


	if(myself->digest) {
		result = gcry_md_open(&myself->digest_ctx, myself->digest, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);

		if(result) {
			logger(LOG_ERR, _("Error during initialisation of digest for %s (%s): %s"),
					myself->name, myself->hostname, gcry_strerror(result));
			return false;
		}

	}

	if(myself->digest) {
		myself->digestlen = gcry_md_get_algo_dlen(myself->digest);
	} else {
		myself->digestlen = 1;
	}

	myself->digestkey = xmalloc(myself->digestlen);
	gcry_randomize(myself->digestkey, myself->digestlen, GCRY_STRONG_RANDOM);
	if(myself->digest)
		gcry_md_setkey(myself->digest_ctx, myself->digestkey, myself->digestlen);

	if(get_config_int(lookup_config(myself->connection->config_tree, "MACLength"), &myself->maclength)) {
		if(myself->digest) {
			if(myself->maclength > myself->digestlen) {
				logger(LOG_ERR, _("MAC length exceeds size of digest!"));
				return false;
			} else if(myself->maclength < 0) {
				logger(LOG_ERR, _("Bogus MAC length!"));
				return false;
			}
		}
	} else
		myself->maclength = 4;

	/* Compression */

	if(get_config_int(lookup_config(myself->connection->config_tree, "Compression"),
		&myself->compression)) {
		if(myself->compression < 0 || myself->compression > 11) {
			logger(LOG_ERR, _("Bogus compression level!"));
			return false;
		}
	} else
		myself->compression = 0;

	/* Done */

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.active = true;
	myself->status.reachable = true;
	node_add(myself);

	graph();

	/* Open device */

	if(!setup_device())
		return false;

	/* Run tinc-up script to further initialize the tap interface */
	asprintf(&envp[0], "NETNAME=%s", netname ? : "");
	asprintf(&envp[1], "DEVICE=%s", device ? : "");
	asprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	asprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	execute_script("tinc-up", envp);

	for(i = 0; i < 5; i++)
		free(envp[i]);

	/* Open sockets */

	get_config_string(lookup_config(config_tree, "BindToAddress"), &address);

	hint.ai_family = addressfamily;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = AI_PASSIVE;

	err = getaddrinfo(address, myport, &hint, &ai);

	if(err || !ai) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "getaddrinfo",
			   gai_strerror(err));
		return false;
	}

	listen_sockets = 0;

	for(aip = ai; aip; aip = aip->ai_next) {
		listen_socket[listen_sockets].tcp =
			setup_listen_socket((sockaddr_t *) aip->ai_addr);

		if(listen_socket[listen_sockets].tcp < 0)
			continue;

		listen_socket[listen_sockets].udp =
			setup_vpn_in_socket((sockaddr_t *) aip->ai_addr);

		if(listen_socket[listen_sockets].udp < 0)
			continue;

		ifdebug(CONNECTIONS) {
			hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
			logger(LOG_NOTICE, _("Listening on %s"), hostname);
			free(hostname);
		}

		listen_socket[listen_sockets].sa.sa = *aip->ai_addr;
		listen_sockets++;
	}

	freeaddrinfo(ai);

	if(listen_sockets)
		logger(LOG_NOTICE, _("Ready"));
	else {
		logger(LOG_ERR, _("Unable to create any listening socket!"));
		return false;
	}

	return true;
}

/*
  setup all initial network connections
*/
bool setup_network_connections(void)
{
	cp();

	now = time(NULL);

	init_connections();
	init_subnets();
	init_nodes();
	init_edges();
	init_events();
	init_requests();

	if(get_config_int(lookup_config(config_tree, "PingTimeout"), &pingtimeout)) {
		if(pingtimeout < 1) {
			pingtimeout = 86400;
		}
	} else
		pingtimeout = 60;

	if(!setup_myself())
		return false;

	try_outgoing_connections();

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(void)
{
	avl_node_t *node, *next;
	connection_t *c;
	char *envp[5];
	int i;

	cp();

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;

		if(c->outgoing)
			free(c->outgoing->name), free(c->outgoing), c->outgoing = NULL;
		terminate_connection(c, false);
	}

	if(myself && myself->connection)
		terminate_connection(myself->connection, false);

	for(i = 0; i < listen_sockets; i++) {
		close(listen_socket[i].tcp);
		close(listen_socket[i].udp);
	}

	exit_requests();
	exit_events();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();

	asprintf(&envp[0], "NETNAME=%s", netname ? : "");
	asprintf(&envp[1], "DEVICE=%s", device ? : "");
	asprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	asprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	execute_script("tinc-down", envp);

	for(i = 0; i < 4; i++)
		free(envp[i]);

	close_device();

	return;
}
