/*
 *  ebt_pmtud
 *
 *      Author:
 *      Eugene Crosser <crosser@average.org>
 *      copied after PMTUD module written by:
 *      Bart De Schuymer <bdschuym@pandora.be>
 *      Tim Gardner <timg@tpi.com>
 *
 *  June, 2020
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <netinet/ether.h>

#include "ebt_pmtud.h"

#define PMTUD_SIZE   '1'

static const struct option opts[] = {
	{ "pmtud-size"    , required_argument, 0, PMTUD_SIZE },
	XT_GETOPT_TABLEEND,
};

static void help(void)
{
	printf(
"pmtud options:\n"
"--pmtud-size  [!] size        : MTU size to trigger ICMP response\n"
);
}

#define OPT_SIZE 1

static int
parse(int c, char **argv, int invert, unsigned int *flags,
	    const void *entry, struct xt_entry_match **match)
{
	struct ebt_pmtud_info *pmtudinfo =
		(struct ebt_pmtud_info *)(*match)->data;
	char *end;
	uint32_t *size;

	switch (c) {
	case PMTUD_SIZE:
		pmtudinfo->size = strtol(optarg, &end, 10);
		break;
	default:
		return 0;
	}
	return 1;
}

static void print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct ebt_pmtud_info *pmtudinfo = (struct ebt_pmtud_info *)match->data;

	printf("--pmtud-size %d ", pmtudinfo->size);
}

static struct xtables_match brpmtud_match = {
	.name		= "pmtud",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_BRIDGE,
	.size		= XT_ALIGN(sizeof(struct ebt_pmtud_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ebt_pmtud_info)),
	.help		= help,
	.parse		= parse,
	.print		= print,
	.extra_opts	= opts,
};

void _init(void)
{
	xtables_register_match(&brpmtud_match);
}
