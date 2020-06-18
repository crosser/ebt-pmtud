/*
 *  ebt_pmtud
 *
 *	Author:
 *	Eugene Crosser <crosser@average.org>
 *	copied after ARP/ARPREPLY modules written by:
 *	Bart De Schuymer <bdschuym@pandora.be>
 *	Tim Gardner <timg@tpi.com>
 *	Grzegorz Borowiak <grzes@gnu.univ.gda.pl>
 *	Bart De Schuymer <bdschuym@pandora.be>
 *
 *  June, 2020
 *
 */
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <net/ip.h>
#include "ebt_pmtud.h"

#if 1
# define DPRINT(...) printk(__VA_ARGS__)
#else
# define DPRINT(...) /* */
#endif

/*** ICMP Sender ***/

/*
 *  Created on: May 27, 2019
 *      Author: Mikhail Sennikovsky
 */

/**
 * Helper for send_icmp6_packet_too_big().
 *
 *   Fill ICMPv6 header with data.
 */
static inline void frag_needed_fill_icmp6_header(struct icmp6hdr *icmp6_hdr,
	u32 mtu_max)
{
	memset(icmp6_hdr, 0, sizeof(struct icmp6hdr));
	icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
	icmp6_hdr->icmp6_code = 0;
	icmp6_hdr->icmp6_cksum = 0;
	icmp6_hdr->icmp6_mtu = htonl(mtu_max);
}

/**
 * Helper for send_icmp4_frag_needed().
 *
 *    Fill ICMP header with data.
 */
static inline void frag_needed_fill_icmp4_header(struct icmphdr *icmp_hdr,
	int mtu_max)
{
	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->type = ICMP_DEST_UNREACH;
	icmp_hdr->code = ICMP_FRAG_NEEDED;
	icmp_hdr->un.frag.mtu = htons(mtu_max);
	icmp_hdr->checksum = 0;
}

/**
 * Helper for send_icmp4_frag_needed().
 *
 *    Fill IP header with data.
 */
static inline void frag_needed_fill_ip4_header(struct iphdr *hdr,
	struct sk_buff *orig_skb, int tot_len)
{
	static u16 icmp_ident = 0;
	struct iphdr *orig_ip_hdr = ip_hdr(orig_skb);

	memset(hdr, 0, sizeof(struct iphdr));
	hdr->version = 4;
	hdr->ihl = 5;
	hdr->tos = 0xc0;
	hdr->tot_len = htons(tot_len);
	hdr->id = htons(icmp_ident++);
	hdr->frag_off = 0;
	hdr->ttl = 255;
	hdr->protocol = IPPROTO_ICMP;

	memcpy(&hdr->saddr, &orig_ip_hdr->daddr, 4);
	memcpy(&hdr->daddr, &orig_ip_hdr->saddr, 4);
	hdr->check = 0;
}

/**
 * Helper for send_icmp6_packet_too_big().
 *
 *   Fill IPv6 header with data.
 */
static inline void frag_needed_fill_ip6_header(struct ipv6hdr *hdr,
	struct sk_buff *orig_skb, u16 payload_len)
{
	struct ipv6hdr *orig_ip6_hdr = ipv6_hdr(orig_skb);

	memset(hdr, 0, sizeof(struct ipv6hdr));
	hdr->version = 6;
	hdr->priority = 0;
	/* Keep ip6_hdr->flow_lbl as zero. */
	hdr->payload_len = htons(payload_len);
	hdr->nexthdr = IPPROTO_ICMPV6;
	hdr->hop_limit = 255;

	memcpy(&hdr->saddr, &orig_ip6_hdr->daddr, sizeof(struct in6_addr));
	memcpy(&hdr->daddr, &orig_ip6_hdr->saddr, sizeof(struct in6_addr));
}

/**
 * Helper for send_icmp4_frag_needed().
 *
 *    Fill ethernet header with data.
 */
static inline void frag_needed_fill_eth_header(struct ethhdr *hdr,
	struct sk_buff *orig_skb, __be16 proto)
{
	struct ethhdr *orig_eth_hdr = eth_hdr(orig_skb);

	memset(hdr, 0, sizeof(struct ethhdr));
	ether_addr_copy(hdr->h_dest, orig_eth_hdr->h_source);
	ether_addr_copy(hdr->h_source, orig_eth_hdr->h_dest);
	hdr->h_proto = proto;
}

/**
 * This routine constructs and sends ICMP Destination
 * Unreachable Message with "fragmentation needed" operation code.
 *
 * This is a helper function for _mangle_ethoip6_packet().
 *
 * @param cfg		EthoIP6 internal data.
 * @param skb		Incomming packet socket buffer.
 * @param mtu		MTU to be sent back with ICMP message.
 *
 * @return 0 if ICMP packet was successully transmitted back to guest or
 *		negative error code otherwise.
 */
static int send_icmp4_frag_needed(struct net_device *dev,
	struct sk_buff *orig_skb, int mtu_max)
{
	u8 *pkt;
	int pkt_len;
	int icmp_payload_len;
	int iphdr_len;

	struct ethhdr *eth_hdr;
	struct iphdr *ip_hdr;
	struct icmphdr *icmp_hdr;
	struct sk_buff *skb;

	int err = 0;

	iphdr_len = ip_hdrlen(orig_skb);
	icmp_payload_len = iphdr_len + 8;
	pkt_len =
		sizeof(struct ethhdr) +
		sizeof(struct iphdr) +
		sizeof(struct icmphdr) +
		icmp_payload_len;

	skb = alloc_skb(pkt_len, GFP_KERNEL);
	if (!skb) {
		pr_warn_ratelimited("could not send ICMPv4 "
			"fragmentation needed: no skb available\n");
		return -ENOMEM;
	}

	pkt = (u8 *)skb_put(skb, pkt_len);
	skb->pkt_type = PACKET_HOST;
	skb->dev = dev;

	/* Assign headers to proper offsets. */
	eth_hdr = (struct ethhdr *)pkt;
	ip_hdr = (struct iphdr *)(pkt + sizeof(*eth_hdr));
	icmp_hdr = (struct icmphdr *)(pkt + sizeof(*eth_hdr) +
		sizeof(*ip_hdr));

	frag_needed_fill_eth_header(eth_hdr, orig_skb, cpu_to_be16(ETH_P_IP));

	frag_needed_fill_ip4_header(
		ip_hdr,
		orig_skb,
		pkt_len - sizeof(struct ethhdr));

	frag_needed_fill_icmp4_header(icmp_hdr, mtu_max);

	/* Copy "Internet Header + 64 bits of Original Data Datagram". */
	err = skb_copy_bits(orig_skb,
		skb_network_header(orig_skb) - orig_skb->data,
		(u8 *)icmp_hdr + sizeof(struct icmphdr),
		icmp_payload_len);
	if (unlikely(err)) {
		pr_warn_ratelimited("cannot copy ICMP payload\n");
		goto free_skb;
	}

	/* Update checksums. */
	icmp_hdr->checksum =
		ip_compute_csum(icmp_hdr,
			sizeof(struct icmphdr) + icmp_payload_len);
	ip_hdr->check = ip_fast_csum(ip_hdr, ip_hdr->ihl);

	err = dev_queue_xmit(skb);
	if (unlikely(err < 0)) {
		pr_warn_ratelimited("could not xmit ICMPv4 "
			"fragmentation needed\n");
	}

exit:
	return err;
free_skb:
	kfree_skb(skb);
	goto exit;
}

/**
 * This routine composes and sends ICMPv6 Packet Too Big message to
 * the host discovered as a sender in given @skb.
 */
static int send_icmp6_packet_too_big(struct net_device *dev,
	struct sk_buff *orig_skb, int mtu_max)
{
	u8 *pkt;
	int pkt_len;
	struct sk_buff *skb;
	int err;

	struct ethhdr *eth_hdr;
	struct ipv6hdr *ipv6_hdr;
	struct icmp6hdr *icmp6_hdr;

	int icmpv6_partial_csum;
	int icmpv6_payload_len =
		min_t(int, IPV6_MIN_MTU,
			orig_skb->len - sizeof(struct ethhdr));

	if (unlikely(icmpv6_payload_len < 0)) {
		pr_warn_ratelimited("corrupted skb detected\n");
		return -EINVAL;
	}

	pkt_len =
		sizeof(struct ethhdr) +
		sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr) +
		icmpv6_payload_len;

	skb = alloc_skb(pkt_len, GFP_KERNEL);
	if (unlikely(!skb)) {
		pr_warn_ratelimited("could not allocate skb in order "
			"to send ICMPv6 packet too big message\n");
		return -ENOMEM;
	}

	pkt = (u8 *)skb_put(skb, pkt_len);
	skb->pkt_type = PACKET_HOST;
	skb->dev = dev;

	eth_hdr = (struct ethhdr *)pkt;
	ipv6_hdr = (struct ipv6hdr *)(pkt + sizeof(*eth_hdr));
	icmp6_hdr = (struct icmp6hdr *)(pkt + sizeof(*eth_hdr) +
		sizeof(*ipv6_hdr));

	frag_needed_fill_eth_header(eth_hdr, orig_skb,
		cpu_to_be16(ETH_P_IPV6));

	frag_needed_fill_ip6_header(ipv6_hdr, orig_skb,
		pkt_len - sizeof(struct ethhdr) - sizeof(struct ipv6hdr));

	frag_needed_fill_icmp6_header(icmp6_hdr, mtu_max);

	/* Copy ICMP payload. */
	err = skb_copy_bits(orig_skb,
		sizeof(struct ethhdr),
		(u8 *)icmp6_hdr + sizeof(struct icmp6hdr),
		icmpv6_payload_len);
	if (unlikely(err)) {
		pr_warn_ratelimited("cannot copy data into ICMPv6 "
			"packet too big response\n");
		goto free_skb;
	}

	/* Update ICMPv6 checksum. */
	icmpv6_partial_csum =
		csum_partial(icmp6_hdr,
			sizeof(struct icmp6hdr) + icmpv6_payload_len, 0);
	icmp6_hdr->icmp6_cksum =
		csum_ipv6_magic(&ipv6_hdr->saddr, &ipv6_hdr->daddr,
			sizeof(struct icmp6hdr) + icmpv6_payload_len,
			IPPROTO_ICMPV6, icmpv6_partial_csum);

	err = dev_queue_xmit(skb);
	if (unlikely(err))
		pr_warn_ratelimited("could not xmit "
			"ICMPv6 packet too big message\n");

exit:
	return err;
free_skb:
	kfree_skb(skb);
	goto exit;
}

/*** Match ***/

static bool
skb_validate_network_len(const struct sk_buff *skb, unsigned int mtu)
{
	/* Before relying on skb, check if required pointers were set. */
	/*
	if (unlikely(!skb_mac_header_was_set(skb) ||
	    !skb_transport_header_was_set(skb))) {
		pr_warn_ratelimited("skb_unfragmentable_size: skb not ready");
		return true;
	}
	*/
	if (!skb_is_gso(skb))
		return skb->len -
			(skb_network_header(skb) - skb_mac_header(skb))
				<= mtu;

	return skb_gso_validate_network_len(skb, mtu);
}

static bool
ebt_pmtud_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct ebt_pmtud_info *info = par->matchinfo;
	const struct iphdr *ih;
	struct iphdr _iph;
	bool result;

	ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (ih == NULL)
		return false;
	if (ih->protocol != IPPROTO_TCP)
		return false;
	DPRINT("pmtud: tcp frame size %d, gso=%s, frag_off=0x%04x\n",
		skb->len, skb_is_gso(skb)?"yes":"no", ntohs(ih->frag_off));
	if (!(ih->frag_off & htons(IP_DF)) || skb->ignore_df)
		return false;
	result = skb_validate_network_len(skb, info->size);
	DPRINT("pmtud: skb_validate_network_len(...,%d) returned %d\n",
		info->size, result);
	return !result;
}

static int
ebt_pmtud_mt_check(const struct xt_mtchk_param *par)
{
	const struct ebt_pmtud_info *info = par->matchinfo;
	const struct ebt_entry *e = par->entryinfo;

	if (e->ethproto != htons(ETH_P_IP) &&
	    e->ethproto != htons(ETH_P_IPV6))
		return -EINVAL;
	if (info->size < 576)
		return -EINVAL;
	return 0;
}

static struct xt_match ebt_pmtud_mt_reg __read_mostly = {
	.name		= "pmtud",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.match		= ebt_pmtud_mt,
	.checkentry	= ebt_pmtud_mt_check,
	.matchsize	= sizeof(struct ebt_pmtud_info),
	.me		= THIS_MODULE,
};

/*** Target ***/

static unsigned int
ebt_pmtud_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ebt_pmtud_tg_info *info = par->targinfo;
	const struct iphdr *ih;
	struct iphdr _iph;

	ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (ih == NULL)
		return EBT_DROP;
	if (skb->protocol == htons(ETH_P_IP)) {
		DPRINT("PMTUD: send_icmp4_frag_needed() over %s", xt_inname(par));
		send_icmp4_frag_needed(xt_in(par), skb, 576 /*info->maxmtu*/);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		DPRINT("PMTUD: send_icmp6_packet_too_big(skb) over %s", xt_inname(par));
		send_icmp6_packet_too_big(xt_in(par), skb, 576 /*info->maxmtu*/);
	} else
		pr_warn_ratelimited("pmtud: unsupprted protocol 0x%04x",
				    ntohs(skb->protocol));
	return EBT_DROP;

}

static int
ebt_pmtud_tg_check(const struct xt_tgchk_param *par)
{
	const struct ebt_pmtud_tg_info *info = par->targinfo;
	const struct ebt_entry *e = par->entryinfo;

	DPRINT("PMTUD: target check, ethproto=0x%04x\n", ntohs(e->ethproto));
	if (e->ethproto != htons(ETH_P_IP) &&
	    e->ethproto != htons(ETH_P_IPV6))
		return -EINVAL;
	/* if (info->maxmtu < 576)
		return -EINVAL; */
	return 0;
}

static struct xt_target ebt_pmtud_tg_reg __read_mostly = {
	.name		= "PMTUD",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "filter",
	.hooks		= (1 << NF_BR_PRE_ROUTING)
			| (1 << NF_BR_LOCAL_IN)
			| (1 << NF_BR_FORWARD)
			| (1 << NF_BR_LOCAL_OUT)
			| (1 << NF_BR_POST_ROUTING),
	.target		= ebt_pmtud_tg,
	.checkentry	= ebt_pmtud_tg_check,
	.targetsize	= sizeof(struct ebt_pmtud_tg_info),
	.me		= THIS_MODULE,
};

static int __init ebt_pmtud_init(void)
{
	int rc;

	rc = xt_register_match(&ebt_pmtud_mt_reg);
	if (rc)
		return rc;
	return xt_register_target(&ebt_pmtud_tg_reg);
}

static void __exit ebt_pmtud_fini(void)
{
	xt_unregister_target(&ebt_pmtud_tg_reg);
	xt_unregister_match(&ebt_pmtud_mt_reg);
}

module_init(ebt_pmtud_init);
module_exit(ebt_pmtud_fini);
MODULE_DESCRIPTION("Ebtables: PMTUD packet match and target");
MODULE_LICENSE("GPL");
