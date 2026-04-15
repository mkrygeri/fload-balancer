#!/usr/bin/env python3
"""Fake flow sender – generates NetFlow v5/v9 and sFlow packets."""

import os
import random
import socket
import struct
import time

TARGET_IP = os.environ.get("TARGET_IP", "10.100.0.200")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "2055"))
RATE = int(os.environ.get("RATE", "50"))  # packets per second
FLOW_TYPE = os.environ.get("FLOW_TYPE", "mixed")  # netflow5, netflow9, sflow, mixed
SENDER_ID = int(os.environ.get("SENDER_ID", "1"))

# Seed RNG per sender so each generates different traffic
random.seed(SENDER_ID * 31337)


def _rand_ip():
    return struct.pack("!I", random.randint(0x0A000001, 0xC0A8FFFE))


def build_netflow5(seq):
    """Build a NetFlow v5 packet with 1-10 flow records."""
    count = random.randint(1, 10)
    now = int(time.time())
    uptime = int((time.monotonic() * 1000)) & 0xFFFFFFFF

    # 24-byte header
    hdr = struct.pack(
        "!HHIIIIBBh",
        5,               # version
        count,           # count
        uptime,          # sysUptime (ms)
        now,             # unix_secs
        0,               # unix_nsecs
        seq,             # flow_sequence
        0,               # engine_type
        SENDER_ID & 0xFF,  # engine_id
        0,               # sampling_interval
    )

    records = b""
    for _ in range(count):
        rec = struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            _rand_ip(),          # srcaddr
            _rand_ip(),          # dstaddr
            b"\x00\x00\x00\x00",  # nexthop
            random.randint(1, 48),  # input ifIndex
            random.randint(1, 48),  # output ifIndex
            random.randint(1, 10000),  # dPkts
            random.randint(64, 1500) * random.randint(1, 10000),  # dOctets
            uptime - random.randint(0, 30000),  # first
            uptime,              # last
            random.randint(1024, 65535),  # srcport
            random.choice([80, 443, 53, 8080, 22]),  # dstport
            0,                   # pad1
            0x02,                # tcp_flags (SYN)
            6,                   # protocol (TCP)
            0,                   # tos
            random.randint(1, 65000),  # src_as
            random.randint(1, 65000),  # dst_as
            24,                  # src_mask
            24,                  # dst_mask
            0,                   # pad2
        )
        records += rec

    return hdr + records


def build_netflow9(seq):
    """Build a NetFlow v9 packet with a template flowset every 10th packet."""
    now = int(time.time())
    uptime = int((time.monotonic() * 1000)) & 0xFFFFFFFF
    source_id = SENDER_ID

    # 20-byte v9 header
    hdr = struct.pack(
        "!HHIII",
        9,          # version
        1,          # count (one flowset)
        uptime,     # sysUptime
        now,        # unix_secs
        seq,        # sequence_number
    )
    hdr += struct.pack("!I", source_id)

    # Every 10th packet, send a template flowset (id=0)
    if seq % 10 == 0:
        # Template flowset: id=0, template_id=256, field_count=4
        # Fields: IN_BYTES(1)/4, IN_PKTS(2)/4, IPV4_SRC_ADDR(8)/4, IPV4_DST_ADDR(12)/4
        tmpl_data = struct.pack(
            "!HH HH HHHH HHHH",
            0,    # flowset_id = 0 (template)
            28,   # flowset length (4 hdr + 4 tmpl hdr + 4*4 field defs = 28)
            256,  # template_id
            4,    # field_count
            1, 4,   # IN_BYTES, length 4
            2, 4,   # IN_PKTS, length 4
            8, 4,   # IPV4_SRC_ADDR, length 4
            12, 4,  # IPV4_DST_ADDR, length 4
        )
        return hdr + tmpl_data
    else:
        # Data flowset (id=256)
        count = random.randint(1, 5)
        record_len = 16  # 4 fields * 4 bytes each
        flowset_len = 4 + record_len * count  # 4-byte header + records
        fs = struct.pack("!HH", 256, flowset_len)
        for _ in range(count):
            fs += struct.pack("!II", random.randint(64, 150000), random.randint(1, 10000))
            fs += _rand_ip() + _rand_ip()
        return hdr + fs


def build_sflow(seq):
    """Build a minimal sFlow v5 datagram (header, enough for identification)."""
    agent_ip = struct.unpack("!I", socket.inet_aton(f"10.{SENDER_ID}.0.1"))[0]
    num_samples = random.randint(1, 3)

    # sFlow v5 header: version(4) + addr_type(4) + agent(4) + sub_agent(4)
    #                 + seq(4) + uptime(4) + num_samples(4) = 28 bytes
    hdr = struct.pack(
        "!IIIIIII",
        5,                # sflow version
        1,                # address type (IPv4)
        agent_ip,         # agent address
        SENDER_ID,        # sub-agent id
        seq,              # sequence number
        int(time.monotonic() * 1000) & 0xFFFFFFFF,  # uptime
        num_samples,      # number of samples
    )

    # Add minimal flow samples (enterprise=0, format=1 = flow_sample)
    samples = b""
    for _ in range(num_samples):
        # sample header: enterprise_format(4) + length(4)
        sample_data = _rand_ip() * 4  # 16 bytes of random data
        sample_hdr = struct.pack("!II", 1, len(sample_data))
        samples += sample_hdr + sample_data

    return hdr + samples


BUILDERS = {
    "netflow5": build_netflow5,
    "netflow9": build_netflow9,
    "sflow": build_sflow,
}


def main():
    print(
        f"sender {SENDER_ID}: target={TARGET_IP}:{TARGET_PORT} "
        f"rate={RATE}pps type={FLOW_TYPE}",
        flush=True,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    interval = 1.0 / RATE if RATE > 0 else 1.0

    types = list(BUILDERS.keys()) if FLOW_TYPE == "mixed" else [FLOW_TYPE]

    while True:
        ft = random.choice(types)
        pkt = BUILDERS[ft](seq)
        try:
            sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
        except OSError as e:
            print(f"sender {SENDER_ID}: send error: {e}", flush=True)
            time.sleep(1)
            continue

        seq += 1
        time.sleep(interval)


if __name__ == "__main__":
    main()
