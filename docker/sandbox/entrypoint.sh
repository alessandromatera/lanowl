#!/bin/bash
# Runs as root, once per start: the firewall first, then down to uid 10001 for good.
# `set -e`: a rule that fails stops the container — no firewall, no shell. lanowl's
# canary would find no socket and keep the tool off.
set -euo pipefail

# lanowl's host: unreachable from here (its dashboard, its sshd). No default — a sandbox that
# does not know what to wall off does not start, and the shell stays off.
HOST_IP="${LANOWL_HOST_IP:?set LANOWL_HOST_IP to the address of lanowl's host}"
# SANDBOX_OFFLINE=1: the audit's sandbox (lanowl-sandbox-offline). The same walls towards the
# LAN, and on top: no internet
# at all, and no DNS — Docker's resolver and the LAN's forward a question to the internet, and
# a question can carry anything out.
OFFLINE="${SANDBOX_OFFLINE:-0}"
# Everything that is not the internet: the LAN and the VPN sites (10/8), every Docker network
# (172.16/12 — dropped whole, see below), the home LANs (192.168/16), the overlays and the
# ISP's CGNAT (100.64/10), link-local and multicast.
LOCAL_NETS="10.0.0.0/8 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 224.0.0.0/4"

iptables -F OUTPUT
iptables -P OUTPUT DROP
[ "$OFFLINE" = 1 ] && iptables -A OUTPUT -d 127.0.0.11 -j DROP   # Docker's DNS: not offline
iptables -A OUTPUT -o lo -j ACCEPT                    # Docker's DNS lives at 127.0.0.11
UDP_PORTS="53,33434:33534"                            # DNS, traceroute
[ "$OFFLINE" = 1 ] && UDP_PORTS="33434:33534"
# lanowl's host itself — the dashboard, sshd — and any other container: nothing at all.
iptables -A OUTPUT -d "$HOST_IP" -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
for net in $LOCAL_NETS; do
    # A TCP connection may shake hands (SYN, then ACK: a port reads open or closed) and
    # nothing more. The third packet — the request — is dropped. connbytes turns on the
    # namespace's conntrack accounting by itself.
    iptables -A OUTPUT -d "$net" -p tcp -m connbytes --connbytes 3: \
             --connbytes-dir original --connbytes-mode packets -j DROP
    iptables -A OUTPUT -d "$net" -p tcp -j ACCEPT
    iptables -A OUTPUT -d "$net" -p icmp -j ACCEPT
    iptables -A OUTPUT -d "$net" -p udp -m multiport --dports "$UDP_PORTS" -j ACCEPT
    iptables -A OUTPUT -d "$net" -j DROP
done
# The internet: open, but new connections are rate-limited — a tricked model must not be
# able to flood someone from the house's address. Offline: closed (the policy is DROP).
if [ "$OFFLINE" != 1 ]; then
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate NEW -m limit --limit 20/second --limit-burst 60 -j ACCEPT
fi
ip6tables -F OUTPUT
ip6tables -P OUTPUT DROP
ip6tables -A OUTPUT -o lo -j ACCEPT
echo "sandbox: firewall set ($(iptables -S OUTPUT | wc -l) rules), host $HOST_IP unreachable$([ "$OFFLINE" = 1 ] && echo ', OFFLINE: no internet, no DNS')"

# The socket's volume, handed to uid 10001 (CHOWN is enough for any owner; the server then
# makes it 700 itself, as its owner, and removes a stale socket).
chown 10001:10001 /run/sandbox

# For good: uid 10001, and NET_RAW is the only capability left in every set — the bounding set
# included, so nothing started from here can get NET_ADMIN back (and no-new-privileges, set in
# compose, stops setuid binaries). `iptables -F` from a command reads "Permission denied".
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
     --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw --bounding-set=-all,+net_raw \
     /usr/bin/python3 /opt/sandbox/server.py
