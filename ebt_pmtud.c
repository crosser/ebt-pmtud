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
	if (skb->protocol == htons(ETH_P_IP))
		DPRINT("PMTUD: send_icmp4_frag_needed(skb)");
	else if (skb->protocol == htons(ETH_P_IPV6))
		DPRINT("PMTUD: send_icmp6_packet_too_big(skb)");
	else
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
MODULE_DESCRIPTION("Ebtables: PMTUD packet match");
MODULE_LICENSE("GPL");
