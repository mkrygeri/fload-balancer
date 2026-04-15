#!/bin/sh
set -e

# Add the VIP as a secondary address so senders can route to it
ip addr add 10.100.0.200/32 dev eth0 2>/dev/null || true

# Pre-populate ARP for all backends so bpf_fib_lookup can resolve MACs.
# Without this, XDP forwarding silently drops packets.
for ip in 10.100.0.51 10.100.0.52 10.100.0.53 10.100.0.54; do
    ping -c 1 -W 1 "$ip" >/dev/null 2>&1 &
done
wait

# Keep ARP entries alive in the background
(while true; do
    for ip in 10.100.0.51 10.100.0.52 10.100.0.53 10.100.0.54; do
        ping -c 1 -W 1 "$ip" >/dev/null 2>&1 &
    done
    wait
    sleep 30
done) &

exec lbserver -config /etc/fload-balancer/config.yaml
