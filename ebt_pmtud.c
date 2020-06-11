/*
 *  ebt_pmtud
 *
 *	Author:
 *	Eugene Crosser <crosser@average.org>
 *	copied after PMTUD module written by:
 *	Bart De Schuymer <bdschuym@pandora.be>
 *	Tim Gardner <timg@tpi.com>
 *
 *  June, 2020
 *
 */
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include "ebt_pmtud.h"

static bool
ebt_pmtud_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct ebt_pmtud_info *info = par->matchinfo;
	const struct iphdr *ih;
	struct iphdr _iph;

	ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (ih == NULL)
		return false;

	return true;
}

static int ebt_pmtud_mt_check(const struct xt_mtchk_param *par)
{
	const struct ebt_pmtud_info *info = par->matchinfo;
	const struct ebt_entry *e = par->entryinfo;

	if (e->ethproto != htons(ETH_P_IP) ||
	    !(e->invflags & EBT_IPROTO))
		return -EINVAL;
	if (info->size < 20)		/* TODO: make real check */
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

static int __init ebt_pmtud_init(void)
{
	return xt_register_match(&ebt_pmtud_mt_reg);
}

static void __exit ebt_pmtud_fini(void)
{
	xt_unregister_match(&ebt_pmtud_mt_reg);
}

module_init(ebt_pmtud_init);
module_exit(ebt_pmtud_fini);
MODULE_DESCRIPTION("Ebtables: PMTUD packet match");
MODULE_LICENSE("GPL");
