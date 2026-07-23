#!/usr/bin/env bash
# Idempotent host-side outbound networking for Cloud Hypervisor Guests.
# cats-noded creates one /30 tap per Cat inside this private /16; this script
# enables forwarding and NAT without exposing any Guest ports on the host.
set -euo pipefail

CIDR=${CATS_GUEST_NETWORK_CIDR:-10.240.0.0/16}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $CIDR =~ ^([0-9]{1,3}\.){2}0\.0/16$ ]] || {
  echo "CATS_GUEST_NETWORK_CIDR must be an aligned IPv4 /16" >&2
  exit 1
}

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=1
sysctl -q -w net.ipv4.conf.default.rp_filter=1

iptables -t nat -C POSTROUTING -s "$CIDR" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$CIDR" -j MASQUERADE

# Guests get Internet egress, not access to the worker, VPC/control network or
# cloud instance metadata. vsock remains the only Host/Guest control channel.
iptables -C INPUT -i 'cat+' -j DROP 2>/dev/null || \
  iptables -I INPUT 1 -i 'cat+' -j DROP
iptables -C FORWARD -i 'cat+' '!' -s "$CIDR" -j DROP 2>/dev/null || \
  iptables -I FORWARD 1 -i 'cat+' '!' -s "$CIDR" -j DROP
for blocked in 169.254.169.254/32 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  iptables -C FORWARD -i 'cat+' -d "$blocked" -j DROP 2>/dev/null || \
    iptables -I FORWARD 1 -i 'cat+' -d "$blocked" -j DROP
done
iptables -C FORWARD -i 'cat+' -s "$CIDR" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i 'cat+' -s "$CIDR" -j ACCEPT
iptables -C FORWARD -o 'cat+' -d "$CIDR" -m conntrack --ctstate RELATED,ESTABLISHED \
  -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -o 'cat+' -d "$CIDR" -m conntrack --ctstate RELATED,ESTABLISHED \
    -j ACCEPT
