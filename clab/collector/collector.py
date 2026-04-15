#!/usr/bin/env python3
"""Fake flow collector – receives UDP flows and exposes a TCP health-check port."""

import os
import socket
import struct
import threading
import time

UDP_PORT = int(os.environ.get("UDP_PORT", "2055"))
HEALTH_PORT = int(os.environ.get("HEALTH_PORT", "8080"))
STATS_INTERVAL = int(os.environ.get("STATS_INTERVAL", "10"))
COLLECTOR_ID = os.environ.get("COLLECTOR_ID", "1")

FLOW_NAMES = {5: "NFv5", 9: "NFv9", 10: "IPFIX"}

# Counters
lock = threading.Lock()
stats = {"packets": 0, "bytes": 0, "nfv5": 0, "nfv9": 0, "ipfix": 0, "sflow": 0, "unknown": 0}


def identify_flow(data):
    if len(data) < 4:
        return "unknown"
    ver16 = struct.unpack("!H", data[:2])[0]
    if ver16 == 5:
        return "nfv5"
    if ver16 == 9:
        return "nfv9"
    if ver16 == 10:
        return "ipfix"
    ver32 = struct.unpack("!I", data[:4])[0]
    if ver32 == 5:
        return "sflow"
    return "unknown"


def udp_listener():
    """Receive UDP flow packets and count them."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    print(f"collector {COLLECTOR_ID}: listening UDP :{UDP_PORT}", flush=True)

    while True:
        data, addr = sock.recvfrom(65535)
        ft = identify_flow(data)
        with lock:
            stats["packets"] += 1
            stats["bytes"] += len(data)
            stats[ft] += 1


def health_check_server():
    """Simple TCP server for health checks – accepts and closes connections."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", HEALTH_PORT))
    srv.listen(8)
    print(f"collector {COLLECTOR_ID}: health-check TCP :{HEALTH_PORT}", flush=True)

    while True:
        conn, _ = srv.accept()
        conn.close()


def stats_printer():
    """Periodically print reception stats."""
    while True:
        time.sleep(STATS_INTERVAL)
        with lock:
            s = dict(stats)
        pps = s["packets"] / STATS_INTERVAL
        print(
            f"collector {COLLECTOR_ID}: "
            f"pkts={s['packets']} bytes={s['bytes']} "
            f"nfv5={s['nfv5']} nfv9={s['nfv9']} ipfix={s['ipfix']} "
            f"sflow={s['sflow']} unknown={s['unknown']} "
            f"(~{pps:.0f} pps avg)",
            flush=True,
        )
        # Reset counters each interval for rate display
        with lock:
            for k in stats:
                stats[k] = 0


def main():
    print(f"collector {COLLECTOR_ID}: starting", flush=True)

    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=health_check_server, daemon=True).start()

    stats_printer()


if __name__ == "__main__":
    main()
