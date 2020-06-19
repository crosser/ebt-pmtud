# EBTABLES target to send forged ICMP "frag needed" / "too big" packets

The purpose of this piece of software is to force TCP PMTU discovery
on connections that run over Layer 2 without a router. This is necessary
when virtual machines that are connected over (virtualized) Layer 2
network have SDN technology under them replaced with one that uses smaller
MTU. Guest OS cannot be forced to dynamically adjst MTU, but we can hope
to save TCP connections (including those that are already running) by
sending ICMP packets that trigger PMTU discovery and will make guest's
TCP stack shink MSS.

Filter for `--protocol IPv4` or `--protocol IPv6`
Filter for `ip` by `--ip-protocol TCP` or `ip6` by `--ip6-protocol TCP`
Enable `pmtud` extention with `-m` flag.
Specify MTU threshold size with `--pmtud-size NNNN`. Match target will
trigger on Ethernet frames that would not fit in that MTU. So most likely
specify `-j DROP` to drop them, but any other target is possible. Send of
ICMP responses can be suppressed with `--pmtud-suppress-icmp`.

Example match (for individual interface to keep counter separate):

sudo ebtables-nft -A FORWARD -m pmtud -i n02aabbccddee \
	-p IPv4 --ip-protocol TCP --pmtud-size 576 -j DROP

To see the counters:

sudo ebtables-nft -L --Lc

