# Benchmark & Test Results

**System:** 12th Gen Intel Core i7-12700K (20 threads) · Linux · Go 1.23.0 · amd64

## Test Summary

| Package | Tests | Status |
|---------|------:|--------|
| `internal/config` | 12 | ✅ All pass |
| `internal/ebpf` | 6 | ✅ All pass |
| `internal/health` | 5 | ✅ All pass |
| `internal/templatecache` | 29 | ✅ All pass |
| `internal/webui` | 5 | ✅ All pass |
| **Total** | **57** | **✅ All pass** |

Coverage areas:
- **Config**: YAML loading, defaults, validation (missing fields, empty backends, bad YAML)
- **eBPF helpers**: IP↔uint32 conversion, port byte-order swap, flow type names, round-trips
- **Health checker**: TCP probe success/failure, retries, target management
- **Template cache**: NFv9/IPFIX parsing (single, multi, options templates), multi-source/domain, updates, concurrent access, packet building, round-trip (parse → cache → rebuild → re-parse)
- **Template sender**: byte-order helpers, sender creation, no-op replay with empty cache
- **Web UI**: template-stats endpoint (nil cache, populated cache), backend list management, static file serving, byte-order helpers

---

## Benchmark Results

All benchmarks run with `-benchmem -count=3`. Values below are the median of 3 runs.

### Config

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Defaults | 5.70 | 0 | 0 |
| Validate | 1.68 | 0 | 0 |

Config validation is essentially free — a single field-presence check with no allocations.

### eBPF Helpers

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| IPToUint32 | 2.94 | 0 | 0 |
| Uint32ToIP | 0.13 | 0 | 0 |
| FlowTypeName | 0.61 | 0 | 0 |

All IP/port conversion functions complete in under 3 ns with zero allocations, ensuring negligible overhead in the hot packet-processing path.

### Health Checker

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ProbeSuccess (TCP) | 53,286 | 1,657 | 31 |

A successful TCP health probe completes in ~53 µs. This is dominated by kernel TCP handshake latency — the Go code overhead is minimal.

### Template Cache (Core)

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ProcessNFv9Template | 261 | 144 | 5 |
| ProcessIPFIXTemplate | 300 | 149 | 6 |
| ProcessNFv9MultiTemplate (5 templates) | 1,007 | 536 | 20 |
| BuildNFv9Packet | 585 | 408 | 9 |
| BuildIPFIXPacket | 590 | 372 | 9 |
| GetTemplatesForDomain | 148 | 56 | 3 |
| GetStats | 10.6 | 0 | 0 |
| ConcurrentReadWrite | 739 | 128 | 6 |

**Key takeaways:**
- **Template ingestion** (ProcessPacket) runs at ~260–300 ns per template (~3.3–3.8M templates/sec). This is fast enough for any real-world exporter — even aggressive template refresh at thousands per second adds negligible overhead.
- **Packet building** (BuildTemplatePacket) completes in ~585 ns, well under the ~53 µs TCP probe cost, so template replay during failover is effectively instant.
- **Concurrent read/write** under contention averages ~740 ns — the RWMutex strategy provides good read parallelism with minimal write contention.
- **GetStats** is a lock-free-equivalent read at ~10 ns.

### Template Cache (Byte-order helpers)

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| htons | 0.15 | 0 | 0 |
| ntohs | 0.15 | 0 | 0 |

Sub-nanosecond, zero-allocation byte swaps.

---

## Throughput Estimates

Based on the benchmarks above, estimated sustainable throughput on this CPU:

| Operation | Throughput |
|-----------|-----------|
| NFv9 template parse | ~3.8M ops/sec |
| IPFIX template parse | ~3.3M ops/sec |
| Template packet build | ~1.7M ops/sec |
| Template lookup | ~6.7M ops/sec |
| IP conversion (uint32↔IP) | ~340M ops/sec |
| Config validate | ~594M ops/sec |

These numbers confirm the Go userspace components add negligible overhead relative to the XDP/eBPF data plane, which processes packets at line rate in kernel space.

---

## How to Reproduce

```bash
# Run all tests
go test ./internal/... -v -count=1

# Run benchmarks
go test ./internal/... -bench=. -benchmem -count=3 -run=^$
```
