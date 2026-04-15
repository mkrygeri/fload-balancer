//go:build ignore

/*
 * XDP Load Balancer for NetFlow/IPFIX/sFlow
 *
 * Performs UDP load balancing with session persistence,
 * flow type identification, and sequence number tracking.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BACKENDS    64
#define MAX_SESSIONS    65536
#define MAX_VIP_PORTS   64
#define MAX_SEQ_ENTRIES 65536
#define MAX_FLOWSETS    16  /* max flowsets/sets to scan for templates */

/* Flow type identifiers */
#define FLOW_TYPE_UNKNOWN 0
#define FLOW_TYPE_NFV5    1
#define FLOW_TYPE_NFV9    2
#define FLOW_TYPE_IPFIX   3
#define FLOW_TYPE_SFLOW   4
#define FLOW_TYPE_MAX     5

#ifndef AF_INET
#define AF_INET 2
#endif

/* ---------- Shared structures (must match Go) ---------- */

struct lb_config {
    __be32 vip_ip;
    __u32  num_backends;
    __u32  seq_tracking;     /* 0=disabled, 1=enabled */
    __u32  seq_window_size;  /* reorder window for seq tracking */
};

struct backend {
    __be32 ip;
    __be16 port;       /* network byte order; 0 = keep original dest port */
    __u8   active;
    __u8   weight;
};

struct five_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   pad[3];
};

struct session {
    __u32 backend_idx;
    __u32 flow_type;
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

struct be_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 rx_flows;
};

struct ft_stats {
    __u64 packets;
    __u64 bytes;
};

struct seq_state {
    __u32 expected_next;
    __u32 last_seq;
    __u64 total_received;
    __u64 gaps;
    __u64 duplicates;
    __u64 out_of_order;
};

/* Template event metadata sent to userspace via perf buffer.
 * The raw packet (eth+ip+udp+payload) is appended by bpf_perf_event_output. */
struct template_event {
    __u32 src_ip;       /* network byte order */
    __u32 flow_type;    /* FLOW_TYPE_NFV9 or FLOW_TYPE_IPFIX */
    __u16 src_port;     /* network byte order */
    __u16 pad;
    __u32 backend_idx;
};

/* ---------- BPF Maps ---------- */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIP_PORTS);
    __type(key, __be16);     /* port in network byte order */
    __type(value, __u8);
} vip_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, struct five_tuple);
    __type(value, struct session);
} sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct be_stats);
} backend_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, FLOW_TYPE_MAX);
    __type(key, __u32);
    __type(value, struct ft_stats);
} flow_type_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SEQ_ENTRIES);
    __type(key, struct five_tuple);
    __type(value, struct seq_state);
} seq_track SEC(".maps");

/* Per-backend sampling rate: 0 or 1 = forward all, N>1 = forward 1-in-N */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u32);
} sampling_rate SEC(".maps");

/* Perf event array for sending template-bearing packets to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} template_events SEC(".maps");

/* ---------- Helpers ---------- */

static __always_inline __u32 fnv1a_hash(__u32 a, __u32 b, __u32 c)
{
    __u32 h = 2166136261u;
    h ^= (a      ) & 0xff; h *= 16777619u;
    h ^= (a >>  8) & 0xff; h *= 16777619u;
    h ^= (a >> 16) & 0xff; h *= 16777619u;
    h ^= (a >> 24) & 0xff; h *= 16777619u;
    h ^= (b      ) & 0xff; h *= 16777619u;
    h ^= (b >>  8) & 0xff; h *= 16777619u;
    h ^= (b >> 16) & 0xff; h *= 16777619u;
    h ^= (b >> 24) & 0xff; h *= 16777619u;
    h ^= (c      ) & 0xff; h *= 16777619u;
    h ^= (c >>  8) & 0xff; h *= 16777619u;
    h ^= (c >> 16) & 0xff; h *= 16777619u;
    h ^= (c >> 24) & 0xff; h *= 16777619u;
    return h;
}

/* Recompute IPv4 header checksum (assumes ihl==5, 20 bytes) */
static __always_inline __u16 compute_ip_csum(struct iphdr *iph, void *data_end)
{
    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return 0;

    __u16 *buf = (__u16 *)iph;
    __u32 csum = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += buf[i];

    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

/* Identify flow type from the first bytes of UDP payload */
static __always_inline __u32 identify_flow(void *payload, void *data_end)
{
    /* Need at least 4 bytes */
    if (payload + 4 > data_end)
        return FLOW_TYPE_UNKNOWN;

    __u16 ver16 = bpf_ntohs(*(__u16 *)payload);
    __u32 ver32 = bpf_ntohl(*(__u32 *)payload);

    /*
     * NetFlow v5: first 2 bytes = 5
     * NetFlow v9: first 2 bytes = 9
     * IPFIX:      first 2 bytes = 10
     * sFlow v5:   first 4 bytes = 5  (first 2 bytes = 0)
     */
    switch (ver16) {
    case 5:  return FLOW_TYPE_NFV5;
    case 9:  return FLOW_TYPE_NFV9;
    case 10: return FLOW_TYPE_IPFIX;
    case 0:
        if (ver32 == 5)
            return FLOW_TYPE_SFLOW;
        break;
    }

    return FLOW_TYPE_UNKNOWN;
}

/*
 * Extract the number of flow records from a packet.
 * Returns 1 as fallback for unknown types or when count can't be determined
 * (i.e. falls back to PPS-equivalent counting).
 */
static __always_inline __u32 extract_flow_count(void *payload, void *data_end,
                                                 __u32 flow_type)
{
    switch (flow_type) {
    case FLOW_TYPE_NFV5: {
        /* v5 header: ver(2)+count(2) - count is number of flow records (1-30) */
        if (payload + 4 > data_end) return 1;
        __u16 cnt = bpf_ntohs(*(__u16 *)(payload + 2));
        if (cnt == 0 || cnt > 30) return 1;
        return cnt;
    }
    case FLOW_TYPE_NFV9: {
        /* v9 header: ver(2)+count(2) - count of records in FlowSets */
        if (payload + 4 > data_end) return 1;
        __u16 cnt = bpf_ntohs(*(__u16 *)(payload + 2));
        return cnt > 0 ? cnt : 1;
    }
    case FLOW_TYPE_IPFIX:
        /* IPFIX has no count field in header - fall back to 1 (PPS) */
        return 1;

    case FLOW_TYPE_SFLOW: {
        /* sFlow v5: ver(4)+addr_type(4)+addr(4|16)+sub_agent(4)+seq(4)+uptime(4)+num_samples(4) */
        if (payload + 8 > data_end) return 1;
        __u32 addr_type = bpf_ntohl(*(__u32 *)(payload + 4));
        if (addr_type == 1) { /* IPv4 agent */
            if (payload + 28 > data_end) return 1;
            __u32 n = bpf_ntohl(*(__u32 *)(payload + 24));
            return n > 0 ? n : 1;
        } else if (addr_type == 2) { /* IPv6 agent */
            if (payload + 40 > data_end) return 1;
            __u32 n = bpf_ntohl(*(__u32 *)(payload + 36));
            return n > 0 ? n : 1;
        }
        return 1;
    }
    default:
        return 1;
    }
}

struct seq_info {
    __u32 seq;
    __u32 increment;
};

/* Extract sequence number and expected increment for known flow types */
static __always_inline int extract_seq(void *payload, void *data_end,
                                       __u32 flow_type, struct seq_info *out)
{
    switch (flow_type) {
    case FLOW_TYPE_NFV5:
        /* v5 header: ver(2)+count(2)+uptime(4)+secs(4)+nsecs(4)+flow_seq(4) */
        if (payload + 20 > data_end) return -1;
        out->seq = bpf_ntohl(*(__u32 *)(payload + 16));
        out->increment = bpf_ntohs(*(__u16 *)(payload + 2)); /* count */
        if (out->increment == 0)
            out->increment = 1;
        return 0;

    case FLOW_TYPE_NFV9:
        /* v9 header: ver(2)+count(2)+uptime(4)+secs(4)+seq(4)+src_id(4) */
        if (payload + 16 > data_end) return -1;
        out->seq = bpf_ntohl(*(__u32 *)(payload + 12));
        out->increment = 1;
        return 0;

    case FLOW_TYPE_IPFIX:
        /* IPFIX header: ver(2)+len(2)+time(4)+seq(4)+domain(4) */
        if (payload + 12 > data_end) return -1;
        out->seq = bpf_ntohl(*(__u32 *)(payload + 8));
        out->increment = 1;
        return 0;

    case FLOW_TYPE_SFLOW: {
        /* sFlow v5: ver(4)+addr_type(4)+addr(4|16)+sub_agent(4)+seq(4) */
        if (payload + 8 > data_end) return -1;
        __u32 addr_type = bpf_ntohl(*(__u32 *)(payload + 4));
        if (addr_type == 1) { /* IPv4 agent */
            if (payload + 20 > data_end) return -1;
            out->seq = bpf_ntohl(*(__u32 *)(payload + 16));
        } else if (addr_type == 2) { /* IPv6 agent */
            if (payload + 32 > data_end) return -1;
            out->seq = bpf_ntohl(*(__u32 *)(payload + 28));
        } else {
            return -1;
        }
        out->increment = 1;
        return 0;
    }
    default:
        return -1;
    }
}

/* Update sequence tracking state */
static __always_inline void update_seq_tracking(struct seq_state *st,
                                                 struct seq_info *si,
                                                 __u32 window_size)
{
    __u32 seq = si->seq;

    if (st->total_received == 0) {
        /* First packet for this source */
        st->expected_next = seq + si->increment;
        st->last_seq = seq;
        st->total_received = 1;
        return;
    }

    __sync_fetch_and_add(&st->total_received, 1);

    if (seq == st->expected_next) {
        /* In order */
        st->expected_next = seq + si->increment;
    } else if (seq > st->expected_next) {
        /* Gap detected: missed packets */
        __sync_fetch_and_add(&st->gaps, 1);
        st->expected_next = seq + si->increment;
    } else if (seq >= st->expected_next - window_size) {
        /* Late packet within acceptable window */
        __sync_fetch_and_add(&st->out_of_order, 1);
    } else {
        /* Duplicate or wrapped */
        __sync_fetch_and_add(&st->duplicates, 1);
    }

    st->last_seq = seq;
}

/*
 * Check if a NetFlow v9 packet contains template flowsets.
 * v9 header: ver(2)+count(2)+uptime(4)+secs(4)+seq(4)+src_id(4) = 20 bytes
 * Template flowset: id=0, Options template flowset: id=1
 */
static __always_inline int v9_has_templates(void *payload, void *data_end)
{
    if (payload + 24 > data_end)
        return 0;

    __u16 fs_id  = bpf_ntohs(*(__u16 *)(payload + 20));
    if (fs_id == 0 || fs_id == 1)
        return 1;

    __u16 fs_len = bpf_ntohs(*(__u16 *)(payload + 22));
    if (fs_len < 4 || fs_len > 1480)
        return 0;
    if (payload + 20 + fs_len + 4 > data_end)
        return 0;
    fs_id = bpf_ntohs(*(__u16 *)(payload + 20 + fs_len));
    if (fs_id == 0 || fs_id == 1)
        return 1;

    __u16 fs_len2 = bpf_ntohs(*(__u16 *)(payload + 20 + fs_len + 2));
    if (fs_len2 < 4 || fs_len2 > 1480)
        return 0;
    __u32 off3 = 20 + (__u32)fs_len + (__u32)fs_len2;
    if (off3 > 1480 || payload + off3 + 4 > data_end)
        return 0;
    fs_id = bpf_ntohs(*(__u16 *)(payload + off3));
    if (fs_id == 0 || fs_id == 1)
        return 1;

    return 0;
}

/*
 * Check if an IPFIX packet contains template sets.
 * IPFIX header: ver(2)+length(2)+time(4)+seq(4)+obs_domain(4) = 16 bytes
 * Template set: id=2, Options template set: id=3
 */
static __always_inline int ipfix_has_templates(void *payload, void *data_end)
{
    if (payload + 20 > data_end)
        return 0;

    __u16 set_id  = bpf_ntohs(*(__u16 *)(payload + 16));
    if (set_id == 2 || set_id == 3)
        return 1;

    __u16 set_len = bpf_ntohs(*(__u16 *)(payload + 18));
    if (set_len < 4 || set_len > 1480)
        return 0;
    if (payload + 16 + set_len + 4 > data_end)
        return 0;
    set_id = bpf_ntohs(*(__u16 *)(payload + 16 + set_len));
    if (set_id == 2 || set_id == 3)
        return 1;

    __u16 set_len2 = bpf_ntohs(*(__u16 *)(payload + 16 + set_len + 2));
    if (set_len2 < 4 || set_len2 > 1480)
        return 0;
    __u32 off3 = 16 + (__u32)set_len + (__u32)set_len2;
    if (off3 > 1480 || payload + off3 + 4 > data_end)
        return 0;
    set_id = bpf_ntohs(*(__u16 *)(payload + off3));
    if (set_id == 2 || set_id == 3)
        return 1;

    return 0;
}

/* ---------- XDP Main ---------- */

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Parse Ethernet --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* --- Parse IPv4 --- */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->ihl != 5)
        return XDP_PASS;   /* skip IP options */
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* --- Parse UDP --- */
    struct udphdr *udp = (void *)(iph + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* --- Check VIP IP --- */
    __u32 cfg_key = 0;
    struct lb_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg)
        return XDP_PASS;
    if (iph->daddr != cfg->vip_ip)
        return XDP_PASS;

    /* --- Check VIP port --- */
    __be16 dport = udp->dest;
    __u8 *port_ok = bpf_map_lookup_elem(&vip_ports, &dport);
    if (!port_ok)
        return XDP_PASS;

    /* --- Build 5-tuple --- */
    struct five_tuple key = {};
    key.src_ip   = iph->saddr;
    key.dst_ip   = iph->daddr;
    key.src_port = udp->source;
    key.dst_port = udp->dest;
    key.protocol = IPPROTO_UDP;

    __u64 pkt_len = data_end - data;

    /* --- Session lookup --- */
    struct session *sess = bpf_map_lookup_elem(&sessions, &key);
    __u32 backend_idx;
    __u32 flow_type = FLOW_TYPE_UNKNOWN;

    if (sess) {
        backend_idx = sess->backend_idx;
        flow_type = sess->flow_type;
        __sync_fetch_and_add(&sess->packets, 1);
        __sync_fetch_and_add(&sess->bytes, pkt_len);
        sess->last_seen_ns = bpf_ktime_get_ns();
    } else {
        /* New session: hash-select backend */
        __u32 num = cfg->num_backends;
        if (num == 0 || num > MAX_BACKENDS)
            return XDP_PASS;

        __u32 hash = fnv1a_hash(iph->saddr,
                                (__u32)udp->source << 16 | (__u32)udp->dest,
                                iph->protocol);
        backend_idx = hash % num;

        /* Identify flow type from first packet */
        void *payload = (void *)(udp + 1);
        flow_type = identify_flow(payload, data_end);

        struct session new_sess = {};
        new_sess.backend_idx  = backend_idx;
        new_sess.flow_type    = flow_type;
        new_sess.packets      = 1;
        new_sess.bytes        = pkt_len;
        new_sess.last_seen_ns = bpf_ktime_get_ns();

        bpf_map_update_elem(&sessions, &key, &new_sess, BPF_NOEXIST);
        sess = bpf_map_lookup_elem(&sessions, &key);
    }

    /* --- Find an active backend (probe up to MAX_BACKENDS) --- */
    __u32 num_be = cfg->num_backends;
    if (num_be == 0 || num_be > MAX_BACKENDS)
        return XDP_PASS;

    struct backend *be = NULL;
    __u32 chosen_idx = backend_idx;

    /* Check if the assigned backend is alive first (fast path) */
    struct backend *assigned = bpf_map_lookup_elem(&backends, &backend_idx);
    if (assigned && assigned->active) {
        be = assigned;
        chosen_idx = backend_idx;
    } else {
        /*
         * Backend is down — redistribute using the flow's 5-tuple hash
         * to spread failed-over sessions across all remaining healthy
         * backends, avoiding thundering-herd on a single successor.
         */
        __u32 failover_hash = fnv1a_hash(key.src_ip,
                                          (__u32)key.src_port << 16 | (__u32)key.dst_port,
                                          key.protocol ^ 0x9e3779b9);
        for (int i = 0; i < MAX_BACKENDS; i++) {
            if ((__u32)i >= num_be)
                break;
            __u32 idx = (failover_hash + (__u32)i) % num_be;
            if (idx == backend_idx)
                continue; /* skip the dead one */
            struct backend *candidate = bpf_map_lookup_elem(&backends, &idx);
            if (candidate && candidate->active) {
                be = candidate;
                chosen_idx = idx;
                break;
            }
        }
    }
    if (!be)
        return XDP_PASS;

    /* Update backend index in session if we failovered */
    if (sess && chosen_idx != backend_idx)
        sess->backend_idx = chosen_idx;

    /* --- Sequence tracking (optional) --- */
    if (cfg->seq_tracking && flow_type != FLOW_TYPE_UNKNOWN) {
        void *payload = (void *)(udp + 1);
        struct seq_info si = {};
        if (extract_seq(payload, data_end, flow_type, &si) == 0) {
            struct seq_state *st = bpf_map_lookup_elem(&seq_track, &key);
            if (st) {
                __u32 win = cfg->seq_window_size;
                if (win == 0) win = 16;
                update_seq_tracking(st, &si, win);
            } else {
                struct seq_state new_st = {};
                new_st.expected_next = si.seq + si.increment;
                new_st.last_seq = si.seq;
                new_st.total_received = 1;
                bpf_map_update_elem(&seq_track, &key, &new_st, BPF_NOEXIST);
            }
        }
    }

    /* --- Update per-backend stats --- */
    struct be_stats *bst = bpf_map_lookup_elem(&backend_stats, &chosen_idx);
    if (bst) {
        bst->rx_packets += 1;
        bst->rx_bytes += pkt_len;
        void *fc_payload = (void *)(udp + 1);
        bst->rx_flows += extract_flow_count(fc_payload, data_end, flow_type);
    }

    /* --- Template detection & perf output (for v9/IPFIX only) --- */
    int is_template = 0;
    if (flow_type == FLOW_TYPE_NFV9 || flow_type == FLOW_TYPE_IPFIX) {
        void *payload = (void *)(udp + 1);
        if (flow_type == FLOW_TYPE_NFV9)
            is_template = v9_has_templates(payload, data_end);
        else
            is_template = ipfix_has_templates(payload, data_end);

        if (is_template) {
            struct template_event evt = {};
            evt.src_ip      = iph->saddr;
            evt.flow_type   = flow_type;
            evt.src_port    = udp->source;
            evt.backend_idx = chosen_idx;

            /* Send metadata + full raw packet to userspace */
            __u64 flags = BPF_F_CURRENT_CPU | (pkt_len << 32);
            bpf_perf_event_output(ctx, &template_events, flags,
                                  &evt, sizeof(evt));
        }
    }

    /* --- Packet sampling (optional, per-backend) --- */
    /* Template packets always bypass sampling to preserve collector state */
    if (!is_template) {
        __u32 *srate = bpf_map_lookup_elem(&sampling_rate, &chosen_idx);
        if (srate && *srate > 1) {
            if (bpf_get_prandom_u32() % *srate != 0)
                return XDP_DROP;
        }
    }

    /* --- Update per-flow-type stats --- */
    __u32 ft_key = flow_type;
    struct ft_stats *fst = bpf_map_lookup_elem(&flow_type_stats, &ft_key);
    if (fst) {
        fst->packets += 1;
        fst->bytes += pkt_len;
    }

    /* --- Rewrite destination --- */
    iph->daddr = be->ip;
    if (be->port != 0)
        udp->dest = be->port;

    /* Recompute IP checksum */
    iph->check = 0;
    iph->check = compute_ip_csum(iph, data_end);

    /* Zero UDP checksum (optional in IPv4) */
    udp->check = 0;

    /* --- FIB lookup for L2 forwarding --- */
    struct bpf_fib_lookup fib = {};
    fib.family    = AF_INET;
    fib.l4_protocol = IPPROTO_UDP;
    fib.sport     = udp->source;
    fib.dport     = udp->dest;
    fib.tot_len   = bpf_ntohs(iph->tot_len);
    fib.ifindex   = ctx->ingress_ifindex;
    fib.ipv4_src  = iph->saddr;
    fib.ipv4_dst  = iph->daddr;

    int fib_rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (fib_rc == BPF_FIB_LKUP_RET_SUCCESS) {
        /* Update MACs from FIB result */
        __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);

        /* Redirect to correct interface (or TX if same) */
        if (fib.ifindex != ctx->ingress_ifindex)
            return bpf_redirect(fib.ifindex, 0);
        return XDP_TX;
    }

    /* FIB lookup failed - drop (backend unreachable) */
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
