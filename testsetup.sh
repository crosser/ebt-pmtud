#!/usr/bin/sudo sh

SBIN=/usr/local/sbin

brctl addbr pmtubr
for leg in 1 2; do
	ip netns add pmtuns$leg
	ip link add ve${leg}e type veth peer ve${leg}i
	ip link set ve${leg}i netns pmtuns$leg
	brctl addif pmtubr ve${leg}e
	ip netns exec pmtuns$leg ip addr add 192.168.168.19$leg/24 dev ve${leg}i
	ip netns exec pmtuns$leg ip link set ve${leg}i up
	ip link set ve${leg}e up
done
ip link set pmtubr up

${SBIN}/ebtables-nft -N divert
${SBIN}/ebtables-nft -A divert --log -j ACCEPT
${SBIN}/ebtables-nft -A FORWARD -p IPv4 --ip-protocol TCP -j divert

#  sudo ip netns exec pmtuns2 nc -l -p 9999
#  sudo ip netns exec pmtuns1 nc 192.168.168.192 9999
