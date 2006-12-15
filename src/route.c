/*
    route.c -- routing
    Copyright (C) 2000-2004 Ivo Timmermans <ivo@tinc-vpn.org>,
                  2000-2004 Guus Sliepen <guus@tinc-vpn.org>

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

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif
#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#include "logger/logger.h"
#include "rt/rt.h"
#include "rt/subnet.h"
#include "support/avl.h"
#include "support/ethernet.h"
#include "support/ipv4.h"
#include "support/ipv6.h"

static mac_t mymac = {{0xFE, 0xFD, 0, 0, 0, 0}};

/* Sizes of various headers */

static const size_t ether_size = sizeof(struct ether_header);
static const size_t arp_size = sizeof(struct ether_arp);
static const size_t ip_size = sizeof(struct ip);
static const size_t icmp_size = sizeof(struct icmp) - sizeof(struct ip);
static const size_t ip6_size = sizeof(struct ip6_hdr);
static const size_t icmp6_size = sizeof(struct icmp6_hdr);
static const size_t ns_size = sizeof(struct nd_neighbor_solicit);
static const size_t opt_size = sizeof(struct nd_opt_hdr);

static struct timeval expires(int seconds) {
	struct timeval tv;

	gettimeofday(&tv, NULL);
	tv.tv_sec += seconds;

	return tv;
}

/* RFC 1071 */

static __inline__ uint16_t inet_checksum(const void *data, int len, uint16_t prevsum) {
	const uint16_t *p = data;
	uint32_t checksum = prevsum ^ 0xFFFF;

	while(len >= 2) {
		checksum += *p++;
		len -= 2;
	}
	
	if(len)
		checksum += *(uint8_t *)p;

	while(checksum >> 16)
		checksum = (checksum & 0xFFFF) + (checksum >> 16);

	return ~checksum;
}

static __inline__ bool ratelimit(int frequency) {
	static time_t lasttime = 0;
	static int count = 0;
	time_t now = time(NULL);
	
	if(lasttime == now) {
		if(++count > frequency)
			return true;
	} else {
		lasttime = now;
		count = 0;
	}

	return false;
}

static __inline__ bool checklength(node_t *source, int len, int minlen) {
	if(len < minlen) {
		logger(LOG_WARNING, _("Got too short packet from %s"), source->name);
		return false;
	} else
		return true;
}
	
static __inline__ void learn_mac(mac_t *address) {
	subnet_t *subnet;
	avl_node_t *node;

	subnet = subnet_get_mac(address);

	/* If we don't know this MAC address yet, store it */

	if(!subnet) {
		logger(LOG_INFO, _("Learned new MAC address %hx:%hx:%hx:%hx:%hx:%hx"),
				   address->x[0], address->x[1], address->x[2], address->x[3],
				   address->x[4], address->x[5]);

		subnet = subnet_new();
		subnet->type = SUBNET_TYPE_MAC;
		subnet->expires = expires(rt_macexpire);
		subnet->net.mac.address = *address;
		subnet->owner = myself;
		subnet_add(subnet);

		/* And tell all other tinc daemons it's our MAC */

#if 0
		for(node = connection_tree->head; node; node = node->next) {
			c = node->data;
			if(c->status.active)
				send_add_subnet(c, subnet);
		}
#endif
	}

	if(timerisset(&subnet->expires))
		subnet->expires = expires(rt_macexpire);
}

void age_subnets(void) {
	subnet_t *s;

#if 0
	for(node = myself->subnet_tree->head; node; node = next) {
		next = node->next;
		s = node->data;
		if(s->expires && s->expires < now) {
			{
				char netstr[MAXNETSTR];
				if(net2str(netstr, sizeof netstr, s))
					logger(LOG_INFO, _("Subnet %s expired"), netstr);
			}

			for(node2 = connection_tree->head; node2; node2 = node2->next) {
				c = node2->data;
				if(c->status.active)
					send_del_subnet(c, s);
			}

			subnet_del(myself, s);
		}
	}
#endif
}

static void send_packet(node_t *dest, const uint8_t *packet, int len) {
	if(dest == myself) {
		rt_vnd->send(rt_vnd, packet, len);
	} else if (dest->tnl) {
		dest->tnl->send_packet(dest->tnl, packet, len);
	} else {
		logger(LOG_ERR, _("No tunnel for packet destination %s!"), dest->name);
	}
}

static void broadcast_packet(node_t *source, const uint8_t *packet, int len) {
	tnl_t *tnl;
	edge_t *edge;

	if(source != myself)
		send_packet(myself, packet, len);
	
	avl_foreach(rt_tnls, tnl, {
		edge = tnl->data;
		if(edge && edge->status.mst && edge->to != source)
			send_packet(edge->to, packet, len);
	});
}

static __inline__ void route_mac(node_t *source, const uint8_t *packet, int len) {
	subnet_t *subnet;

	/* Learn source address */

	if(source == myself)
		learn_mac((mac_t *)(packet + 6));

	/* Lookup destination address */

	subnet = subnet_get_mac((mac_t *)(packet));

	if(!subnet) {
		broadcast_packet(source, packet, len);
		return;
	}

	if(subnet->owner == source) {
		logger(LOG_WARNING, _("Packet looping back to %s!"), source->name);
		return;
	}

	send_packet(subnet->owner, packet, len);
}

/* RFC 792 */

static void route_ipv4_unreachable(node_t *source, const uint8_t *packet, int len, uint8_t type, uint8_t code) {
	uint8_t reply[ether_size + IP_MSS];

	struct ip ip = {0};
	struct icmp icmp = {0};
	
	struct in_addr ip_src;
	struct in_addr ip_dst;
	uint32_t oldlen;

	if(ratelimit(3))
		return;
	
	/* Copy headers from packet into properly aligned structs on the stack */

	memcpy(&ip, packet + ether_size, ip_size);

	/* Remember original source and destination */
	
	ip_src = ip.ip_src;
	ip_dst = ip.ip_dst;

	oldlen = len - ether_size;

	if(type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED)
		icmp.icmp_nextmtu = htons(len - ether_size);

	if(oldlen >= IP_MSS - ip_size - icmp_size)
		oldlen = IP_MSS - ip_size - icmp_size;
	
	/* Copy first part of original contents to ICMP message */
	
	memmove(reply + ether_size + ip_size + icmp_size, packet + ether_size, oldlen);

	/* Fill in IPv4 header */
	
	ip.ip_v = 4;
	ip.ip_hl = ip_size / 4;
	ip.ip_tos = 0;
	ip.ip_len = htons(ip_size + icmp_size + oldlen);
	ip.ip_id = 0;
	ip.ip_off = 0;
	ip.ip_ttl = 255;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0;
	ip.ip_src = ip_dst;
	ip.ip_dst = ip_src;

	ip.ip_sum = inet_checksum(&ip, ip_size, ~0);
	
	/* Fill in ICMP header */
	
	icmp.icmp_type = type;
	icmp.icmp_code = code;
	icmp.icmp_cksum = 0;
	
	icmp.icmp_cksum = inet_checksum(&icmp, icmp_size, ~0);
	icmp.icmp_cksum = inet_checksum(packet + ether_size + ip_size + icmp_size, oldlen, icmp.icmp_cksum);

	/* Copy structs on stack back to packet */

	memcpy(reply + ether_size, &ip, ip_size);
	memcpy(reply + ether_size + ip_size, &icmp, icmp_size);
	
	send_packet(source, reply, ether_size + ip_size + icmp_size + oldlen);
}

/* RFC 791 */

static __inline__ void fragment_ipv4_packet(node_t *dest, const uint8_t *packet, int len) {
	struct ip ip;
	char fragment[dest->tnl->mtu];
	int fraglen, maxlen, todo;
	const uint8_t *offset;
	uint16_t ip_off, origf;
	
	memcpy(&ip, packet + ether_size, ip_size);

	if(ip.ip_hl != ip_size / 4)
		return;
	
	todo = ntohs(ip.ip_len) - ip_size;

	if(ether_size + ip_size + todo != len) {
		logger(LOG_WARNING, _("Length of packet (%d) doesn't match length in IPv4 header (%d)"), len, ether_size + ip_size + todo);
		return;
	}

	logger(LOG_INFO, _("Fragmenting packet of %d bytes to %s"), len, dest->name);

	offset = packet + ether_size + ip_size;
	maxlen = (dest->tnl->mtu - ether_size - ip_size) & ~0x7;
	ip_off = ntohs(ip.ip_off);
	origf = ip_off & ~IP_OFFMASK;
	ip_off &= IP_OFFMASK;
	
	while(todo) {
		fraglen = todo > maxlen ? maxlen : todo;
		memcpy(fragment + ether_size + ip_size, offset, fraglen);
		todo -= fraglen;
		offset += fraglen;

		ip.ip_len = htons(ip_size + fraglen);
		ip.ip_off = htons(ip_off | origf | (todo ? IP_MF : 0));
		ip.ip_sum = 0;
		ip.ip_sum = inet_checksum(&ip, ip_size, ~0);
		memcpy(fragment, packet, ether_size);
		memcpy(fragment + ether_size, &ip, ip_size);

		send_packet(dest, fragment, ether_size + ip_size + fraglen);

		ip_off += fraglen / 8;
	}	
}

static __inline__ void route_ipv4_unicast(node_t *source, const uint8_t *packet, int len) {
	subnet_t *subnet;
	node_t *via;

	subnet = subnet_get_ipv4((ipv4_t *)(packet + 30));

	if(!subnet) {
		logger(LOG_WARNING, _("Cannot route packet from %s: unknown IPv4 destination address %d.%d.%d.%d"),
				source->name,
				packet[30],
				packet[31],
				packet[32],
				packet[33]);

		route_ipv4_unreachable(source, packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN);
		return;
	}
	
	if(subnet->owner == source) {
		logger(LOG_WARNING, _("Packet looping back to %s!"), source->name);
		return;
	}

	if(!subnet->owner->status.reachable)
		route_ipv4_unreachable(source, packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);

	via = (subnet->owner->via == myself) ? subnet->owner->nexthop : subnet->owner->via;
	
	if(len > via->tnl->mtu && via != myself) {
		logger(LOG_INFO, _("Packet for %s length %d larger than MTU %d"), subnet->owner->name, len, via->tnl->mtu);
		if(packet[20] & 0x40) {
			len = via->tnl->mtu;
			route_ipv4_unreachable(source, packet, len, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
		} else {
			fragment_ipv4_packet(via, packet, len);
		}

		return;
	}

	send_packet(subnet->owner, packet, len);
}

static __inline__ void route_ipv4(node_t *source, const uint8_t *packet, int len) {
	if(!checklength(source, len, ether_size + ip_size))
		return;

	route_ipv4_unicast(source, packet, len);
}

/* RFC 2463 */

static void route_ipv6_unreachable(node_t *source, const uint8_t *packet, int len, uint8_t type, uint8_t code) {
	uint8_t reply[ether_size + IP_MSS];
	struct ip6_hdr ip6;
	struct icmp6_hdr icmp6 = {0};
	uint16_t checksum;	

	struct {
		struct in6_addr ip6_src;	/* source address */
		struct in6_addr ip6_dst;	/* destination address */
		uint32_t length;
		uint32_t next;
	} pseudo;

	if(ratelimit(3))
		return;
	
	/* Copy headers from packet to structs on the stack */

	memcpy(&ip6, packet + ether_size, ip6_size);

	/* Remember original source and destination */
	
	pseudo.ip6_src = ip6.ip6_dst;
	pseudo.ip6_dst = ip6.ip6_src;

	pseudo.length = len - ether_size;

	if(type == ICMP6_PACKET_TOO_BIG)
		icmp6.icmp6_mtu = htonl(pseudo.length);
	
	if(pseudo.length >= IP_MSS - ip6_size - icmp6_size)
		pseudo.length = IP_MSS - ip6_size - icmp6_size;
	
	/* Copy first part of original contents to ICMP message */
	
	memcpy(reply + ether_size + ip6_size + icmp6_size, packet + ether_size, pseudo.length);

	/* Fill in IPv6 header */
	
	ip6.ip6_flow = htonl(0x60000000UL);
	ip6.ip6_plen = htons(icmp6_size + pseudo.length);
	ip6.ip6_nxt = IPPROTO_ICMPV6;
	ip6.ip6_hlim = 255;
	ip6.ip6_src = pseudo.ip6_src;
	ip6.ip6_dst = pseudo.ip6_dst;

	/* Fill in ICMP header */
	
	icmp6.icmp6_type = type;
	icmp6.icmp6_code = code;
	icmp6.icmp6_cksum = 0;

	/* Create pseudo header */
		
	pseudo.length = htonl(icmp6_size + pseudo.length);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */
	
	checksum = inet_checksum(&pseudo, sizeof(pseudo), ~0);
	checksum = inet_checksum(&icmp6, icmp6_size, checksum);
	checksum = inet_checksum(reply + ether_size + ip6_size + icmp6_size, ntohl(pseudo.length) - icmp6_size, checksum);

	icmp6.icmp6_cksum = checksum;

	/* Copy structs on stack back to packet */

	memcpy(reply + ether_size, &ip6, ip6_size);
	memcpy(reply + ether_size + ip6_size, &icmp6, icmp6_size);
	
	send_packet(source, reply, ether_size + ip6_size + ntohl(pseudo.length));
}

static __inline__ void route_ipv6_unicast(node_t *source, const uint8_t *packet, int len) {
	subnet_t *subnet;
	node_t *via;

	subnet = subnet_get_ipv6((ipv6_t *)(packet + 38));

	if(!subnet) {
		logger(LOG_WARNING, _("Cannot route packet from %s: unknown IPv6 destination address %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"),
				source->name,
				ntohs(*(uint16_t *)(packet + 38)),
				ntohs(*(uint16_t *)(packet + 40)),
				ntohs(*(uint16_t *)(packet + 42)),
				ntohs(*(uint16_t *)(packet + 44)),
				ntohs(*(uint16_t *)(packet + 46)),
				ntohs(*(uint16_t *)(packet + 48)),
				ntohs(*(uint16_t *)(packet + 50)),
				ntohs(*(uint16_t *)(packet + 52)));

		route_ipv6_unreachable(source, packet, len, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR);
		return;
	}

	if(subnet->owner == source) {
		logger(LOG_WARNING, _("Packet looping back to %s!"), source->name);
		return;
	}

	if(!subnet->owner->status.reachable)
		route_ipv6_unreachable(source, packet, len, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);

	via = (subnet->owner->via == myself) ? subnet->owner->nexthop : subnet->owner->via;
	
	if(len > via->tnl->mtu && via != myself) {
		logger(LOG_INFO, _("Packet for %s length %d larger than MTU %d"), subnet->owner->name, len, via->tnl->mtu);
		len = via->tnl->mtu;
		route_ipv6_unreachable(source, packet, len, ICMP6_PACKET_TOO_BIG, 0);
		return;
	}

	send_packet(subnet->owner, packet, len);
}

/* RFC 2461 */

static void route_neighborsol(node_t *source, const uint8_t *packet, int len) {
	uint8_t reply[len];
	struct ip6_hdr ip6;
	struct nd_neighbor_solicit ns;
	struct nd_opt_hdr opt;
	subnet_t *subnet;
	uint16_t checksum;

	struct {
		struct in6_addr ip6_src;	/* source address */
		struct in6_addr ip6_dst;	/* destination address */
		uint32_t length;
		uint32_t next;
	} pseudo;

	if(!checklength(source, len, ether_size + ip6_size + ns_size + opt_size + ETH_ALEN))
		return;
	
	if(source != myself) {
		logger(LOG_WARNING, _("Got neighbor solicitation request from %s while in router mode!"), source->name);
		return;
	}

	/* Copy headers from packet to structs on the stack */

	memcpy(&ip6, packet + ether_size, ip6_size);
	memcpy(&ns, packet + ether_size + ip6_size, ns_size);
	memcpy(&opt, packet + ether_size + ip6_size + ns_size, opt_size);

	/* First, snatch the source address from the neighbor solicitation packet */

	if(rt_overwrite_mac)
		memcpy(mymac.x, packet + ETH_ALEN, ETH_ALEN);

	/* Check if this is a valid neighbor solicitation request */

	if(ns.nd_ns_hdr.icmp6_type != ND_NEIGHBOR_SOLICIT ||
	   opt.nd_opt_type != ND_OPT_SOURCE_LINKADDR) {
		logger(LOG_WARNING, _("Cannot route packet: received unknown type neighbor solicitation request"));
		return;
	}

	/* Create pseudo header */

	pseudo.ip6_src = ip6.ip6_src;
	pseudo.ip6_dst = ip6.ip6_dst;
	pseudo.length = htonl(ns_size + opt_size + ETH_ALEN);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */

	checksum = inet_checksum(&pseudo, sizeof(pseudo), ~0);
	checksum = inet_checksum(&ns, ns_size, checksum);
	checksum = inet_checksum(&opt, opt_size, checksum);
	checksum = inet_checksum(packet + ether_size + ip6_size + ns_size + opt_size, ETH_ALEN, checksum);

	if(checksum) {
		logger(LOG_WARNING, _("Cannot route packet: checksum error for neighbor solicitation request"));
		return;
	}

	/* Check if the IPv6 address exists on the VPN */

	subnet = subnet_get_ipv6((ipv6_t *) &ns.nd_ns_target);

	if(!subnet) {
		logger(LOG_WARNING, _("Cannot route packet: neighbor solicitation request for unknown address %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[0]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[1]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[2]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[3]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[4]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[5]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[6]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[7]));

		return;
	}

	/* Check if it is for our own subnet */

	if(subnet->owner == myself)
		return;					/* silently ignore */

	/* Create neighbor advertation reply */

	memcpy(reply, packet + ETH_ALEN, ETH_ALEN);	/* copy destination address */
	memcpy(reply + ETH_ALEN, packet + ETH_ALEN, ETH_ALEN);	/* copy destination address */
	reply[ETH_ALEN * 2 - 1] ^= 0xFF;	/* mangle source address so it looks like it's not from us */

	ip6.ip6_dst = ip6.ip6_src;			/* swap destination and source protocoll address */
	ip6.ip6_src = ns.nd_ns_target;

	memcpy(reply + ether_size + ip6_size + ns_size + opt_size, reply + ETH_ALEN, ETH_ALEN);	/* add fake source hard addr */

	ns.nd_ns_cksum = 0;
	ns.nd_ns_type = ND_NEIGHBOR_ADVERT;
	ns.nd_ns_reserved = htonl(0x40000000UL);	/* Set solicited flag */
	opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;

	/* Create pseudo header */

	pseudo.ip6_src = ip6.ip6_src;
	pseudo.ip6_dst = ip6.ip6_dst;
	pseudo.length = htonl(ns_size + opt_size + ETH_ALEN);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */

	checksum = inet_checksum(&pseudo, sizeof(pseudo), ~0);
	checksum = inet_checksum(&ns, ns_size, checksum);
	checksum = inet_checksum(&opt, opt_size, checksum);
	checksum = inet_checksum(packet + ether_size + ip6_size + ns_size + opt_size, ETH_ALEN, checksum);

	ns.nd_ns_hdr.icmp6_cksum = checksum;

	/* Copy structs on stack back to packet */

	memcpy(reply + ether_size, &ip6, ip6_size);
	memcpy(reply + ether_size + ip6_size, &ns, ns_size);
	memcpy(reply + ether_size + ip6_size + ns_size, &opt, opt_size);

	send_packet(source, reply, len);
}

static __inline__ void route_ipv6(node_t *source, const uint8_t *packet, int len) {
	if(!checklength(source, len, ether_size + ip6_size))
		return;

	if(packet[20] == IPPROTO_ICMPV6 && checklength(source, len, ether_size + ip6_size + icmp6_size) && packet[54] == ND_NEIGHBOR_SOLICIT) {
		route_neighborsol(source, packet, len);
		return;
	}

	route_ipv6_unicast(source, packet, len);
}

/* RFC 826 */

static void route_arp(node_t *source, const uint8_t *packet, int len) {
	uint8_t reply[len];
	struct ether_arp arp;
	subnet_t *subnet;
	struct in_addr addr;

	if(!checklength(source, len, ether_size + arp_size))
		return;

	if(source != myself) {
		logger(LOG_WARNING, _("Got ARP request from %s while in router mode!"), source->name);
		return;
	}

	/* First, snatch the source address from the ARP packet */

	if(rt_overwrite_mac)
		memcpy(mymac.x, packet + ETH_ALEN, ETH_ALEN);

	/* Copy headers from packet to structs on the stack */

	memcpy(&arp, packet + ether_size, arp_size);

	/* Check if this is a valid ARP request */

	if(ntohs(arp.arp_hrd) != ARPHRD_ETHER || ntohs(arp.arp_pro) != ETH_P_IP ||
	   arp.arp_hln != ETH_ALEN || arp.arp_pln != sizeof(addr) || ntohs(arp.arp_op) != ARPOP_REQUEST) {
		logger(LOG_WARNING, _("Cannot route packet: received unknown type ARP request"));
		return;
	}

	/* Check if the IPv4 address exists on the VPN */

	subnet = subnet_get_ipv4((ipv4_t *) &arp.arp_tpa);

	if(!subnet) {
		logger(LOG_WARNING, _("Cannot route packet: ARP request for unknown address %d.%d.%d.%d"),
				   arp.arp_tpa[0], arp.arp_tpa[1], arp.arp_tpa[2],
				   arp.arp_tpa[3]);
		return;
	}

	/* Check if it is for our own subnet */

	if(subnet->owner == myself)
		return;					/* silently ignore */

	memcpy(reply, packet + ETH_ALEN, ETH_ALEN);	/* copy destination address */
	memcpy(reply + ETH_ALEN, packet + ETH_ALEN, ETH_ALEN);	/* copy destination address */
	reply[ETH_ALEN * 2 - 1] ^= 0xFF;	/* mangle source address so it looks like it's not from us */

	memcpy(&addr, arp.arp_tpa, sizeof(addr));	/* save protocol addr */
	memcpy(arp.arp_tpa, arp.arp_spa, sizeof(addr));	/* swap destination and source protocol address */
	memcpy(arp.arp_spa, &addr, sizeof(addr));	/* ... */

	memcpy(arp.arp_tha, arp.arp_sha, ETH_ALEN);	/* set target hard/proto addr */
	memcpy(arp.arp_sha, reply + ETH_ALEN, ETH_ALEN);	/* add fake source hard addr */
	arp.arp_op = htons(ARPOP_REPLY);

	/* Copy structs on stack back to packet */

	memcpy(reply + ether_size, &arp, arp_size);

	send_packet(source, reply, len);
}

void route(node_t *source, const uint8_t *packet, int len) {
	if(!checklength(source, len, ether_size))
		return;

	switch (rt_mode) {
		case RT_MODE_ROUTER:
			{
				uint16_t type;

				type = ntohs(*((uint16_t *)(packet + 12)));
				switch (type) {
					case ETH_P_ARP:
						route_arp(source, packet, len);
						break;

					case ETH_P_IP:
						route_ipv4(source, packet, len);
						break;

					case ETH_P_IPV6:
						route_ipv6(source, packet, len);
						break;

					default:
						logger(LOG_WARNING, _("Cannot route packet from %s: unknown type %hx"), source->name, type);
						break;
				}
			}
			break;

		case RT_MODE_SWITCH:
			route_mac(source, packet, len);
			break;

		case RT_MODE_HUB:
			broadcast_packet(source, packet, len);
			break;
	}
}
