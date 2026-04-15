# Containerlab Test Environment

Spins up a self-contained test lab with 12 fake flow senders, 4 collectors,
and the fload-balancer in between – all on a single Docker bridge network.

## Network Layout

```
                          VIP 10.100.0.200
 sender01  10.100.0.11 ─┐       │
 sender02  10.100.0.12 ─┤       ▼
 sender03  10.100.0.13 ─┤  ┌─────────┐    collector01  10.100.0.51
 sender04  10.100.0.14 ─┤  │   lb    │──► collector02  10.100.0.52
 sender05  10.100.0.15 ─┤  │  .100   │──► collector03  10.100.0.53
 sender06  10.100.0.16 ─┤  └─────────┘──► collector04  10.100.0.54
 sender07  10.100.0.17 ─┤
 sender08  10.100.0.18 ─┤   Management network
 sender09  10.100.0.19 ─┤   10.100.0.0/24
 sender10  10.100.0.20 ─┤
 sender11  10.100.0.21 ─┤
 sender12  10.100.0.22 ─┘
```

## Quick Start

```bash
cd clab/

# 1. Build all images (LB, sender, collector)
make images

# 2. Deploy the lab
make deploy

# 3. Open the web UI
make ui
#   → http://localhost:8080
```

## Sender Mix

| Senders     | Flow Type      | Port | Rate (pps) |
|-------------|----------------|------|------------|
| 01,02,09,10 | NetFlow v5     | 2055 | 50-75      |
| 03,04,12    | NetFlow v9     | 2055 | 35-60      |
| 05,06       | sFlow          | 6343 | 30-45      |
| 07,08,11    | Mixed          | 2055 | 50-80      |

Total aggregate: ~655 pps across 12 senders.

## Monitoring

```bash
# Backend health and stats
make backends
make stats
make flow-stats
make seq-stats

# Active sessions
make sessions

# Collector reception logs
make logs-collectors

# All container logs (snapshot)
make logs

# Follow LB logs live
make logs-lb
```

## Accessing the UI and API

| Service | Address                   |
|---------|---------------------------|
| Web UI  | http://localhost:18080     |
| gRPC    | localhost:50051            |
| lbctl   | `docker exec clab-fload-lab-lb lbctl -addr localhost:50051 <cmd>` |

## Teardown

```bash
make destroy
```

## Notes

- The LB runs in **privileged** mode with `XDP_MODE=skb` (generic/SKB XDP)
  on the container's veth. Native XDP_TX on veth drops packets because the
  peer lacks an XDP program, so generic mode is used for the test lab.
- The startup script adds the VIP address and keeps ARP entries warm for
  `bpf_fib_lookup` (XDP doesn't trigger ARP resolution).
- Adjust sender `RATE` environment variables in `fload-lab.clab.yml` to
  increase/decrease load. Set above `threshold_pps` (5000) in
  `lb-config.yaml` to trigger rebalancing.
