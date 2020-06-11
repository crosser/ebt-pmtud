/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_BRIDGE_EBT_PMTUD_H
#define __LINUX_BRIDGE_EBT_PMTUD_H

#include <linux/types.h>
#include <linux/if_ether.h>

#define EBT_PMTUD_MATCH "pmtud"

struct ebt_pmtud_info
{
	__be32 size;
};

#endif
