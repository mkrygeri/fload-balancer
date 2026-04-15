package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// FlowType constants matching BPF definitions.
const (
	FlowTypeUnknown = 0
	FlowTypeNFv5    = 1
	FlowTypeNFv9    = 2
	FlowTypeIPFIX   = 3
	FlowTypeSFlow   = 4
	FlowTypeMax     = 5
)

// FlowTypeName returns a human-readable name for a flow type.
func FlowTypeName(ft uint32) string {
	switch ft {
	case FlowTypeNFv5:
		return "NetFlow v5"
	case FlowTypeNFv9:
		return "NetFlow v9"
	case FlowTypeIPFIX:
		return "IPFIX"
	case FlowTypeSFlow:
		return "sFlow"
	default:
		return "Unknown"
	}
}

// Manager manages the loaded BPF program and its maps.
type Manager struct {
	mu      sync.RWMutex
	objs    XdpLbObjects
	xdpLink link.Link
	iface   string
	logger  *slog.Logger
}

// LBConfig mirrors the BPF struct lb_config.
type LBConfig struct {
	VIPIP         uint32
	NumBackends   uint32
	SeqTracking   uint32
	SeqWindowSize uint32
}

// Backend mirrors the BPF struct backend.
type Backend struct {
	IP     uint32
	Port   uint16
	Active uint8
	Weight uint8
}

// FiveTuple mirrors the BPF struct five_tuple.
type FiveTuple struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]uint8
}

// Session mirrors the BPF struct session.
type Session struct {
	BackendIdx uint32
	FlowType   uint32
	Packets    uint64
	Bytes      uint64
	LastSeenNs uint64
}

// BeStats mirrors the BPF struct be_stats.
type BeStats struct {
	RxPackets uint64
	RxBytes   uint64
	RxFlows   uint64
}

// FtStats mirrors the BPF struct ft_stats.
type FtStats struct {
	Packets uint64
	Bytes   uint64
}

// SeqState mirrors the BPF struct seq_state.
type SeqState struct {
	ExpectedNext  uint32
	LastSeq       uint32
	TotalReceived uint64
	Gaps          uint64
	Duplicates    uint64
	OutOfOrder    uint64
}

// IPToUint32 converts a net.IP to uint32 in network byte order.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP converts a uint32 in network byte order to net.IP.
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// PortToNetwork converts a host uint16 port to network byte order.
func PortToNetwork(port uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	return binary.LittleEndian.Uint16(b)
}

// Load loads the compiled BPF objects and attaches to the given interface.
func Load(iface string, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var objs XdpLbObjects
	if err := LoadXdpLbObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	ifObj, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: ifObj.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching XDP to %s: %w", iface, err)
	}

	logger.Info("XDP program attached", "interface", iface, "ifindex", ifObj.Index)

	return &Manager{
		objs:    objs,
		xdpLink: xdpLink,
		iface:   iface,
		logger:  logger,
	}, nil
}

// Close detaches XDP and releases resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.xdpLink != nil {
		m.xdpLink.Close()
	}
	return m.objs.Close()
}

// UpdateConfig writes the LB configuration to the BPF config map.
func (m *Manager) UpdateConfig(cfg LBConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := uint32(0)
	return m.objs.ConfigMap.Update(key, cfg, ebpf.UpdateAny)
}

// SetVIPPorts sets the ports that the load balancer will intercept.
func (m *Manager) SetVIPPorts(ports []uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing entries by iterating and deleting
	var portKey uint16
	iter := m.objs.VipPorts.Iterate()
	var keysToDelete []uint16
	var dummy uint8
	for iter.Next(&portKey, &dummy) {
		keysToDelete = append(keysToDelete, portKey)
	}
	for _, k := range keysToDelete {
		nk := PortToNetwork(k)
		// Try both forms since the key might be stored either way
		m.objs.VipPorts.Delete(k)
		m.objs.VipPorts.Delete(nk)
	}

	// Add new ports
	val := uint8(1)
	for _, p := range ports {
		nbo := PortToNetwork(p)
		if err := m.objs.VipPorts.Update(nbo, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("adding VIP port %d: %w", p, err)
		}
	}
	return nil
}

// UpdateBackend writes a single backend entry.
func (m *Manager) UpdateBackend(idx uint32, be Backend) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.objs.Backends.Update(idx, be, ebpf.UpdateAny)
}

// SetBackendActive sets the active status of a backend.
func (m *Manager) SetBackendActive(idx uint32, active bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var be Backend
	if err := m.objs.Backends.Lookup(idx, &be); err != nil {
		return err
	}
	if active {
		be.Active = 1
	} else {
		be.Active = 0
	}
	return m.objs.Backends.Update(idx, be, ebpf.UpdateAny)
}

// GetSessions returns all current sessions.
func (m *Manager) GetSessions() (map[FiveTuple]Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[FiveTuple]Session)
	var key FiveTuple
	var val Session
	iter := m.objs.Sessions.Iterate()
	for iter.Next(&key, &val) {
		result[key] = val
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// FlushSessions removes all session entries.
func (m *Manager) FlushSessions() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var key FiveTuple
	var val Session
	iter := m.objs.Sessions.Iterate()
	var keys []FiveTuple
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		m.objs.Sessions.Delete(k)
	}
	return nil
}

// FlushExpiredSessions removes sessions older than maxAgeNs.
func (m *Manager) FlushExpiredSessions(maxAgeNs uint64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var key FiveTuple
	var val Session
	iter := m.objs.Sessions.Iterate()
	var expired []FiveTuple
	for iter.Next(&key, &val) {
		if val.LastSeenNs < maxAgeNs {
			expired = append(expired, key)
		}
	}
	for _, k := range expired {
		m.objs.Sessions.Delete(k)
		m.objs.SeqTrack.Delete(k)
	}
	return len(expired), nil
}

// GetBackendStats returns per-backend statistics (summed across CPUs).
func (m *Manager) GetBackendStats(numBackends int) ([]BeStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]BeStats, numBackends)
	for i := 0; i < numBackends; i++ {
		key := uint32(i)
		var perCPU []BeStats
		if err := m.objs.BackendStats.Lookup(key, &perCPU); err != nil {
			continue
		}
		var total BeStats
		for _, cpu := range perCPU {
			total.RxPackets += cpu.RxPackets
			total.RxBytes += cpu.RxBytes
		}
		result[i] = total
	}
	return result, nil
}

// GetFlowTypeStats returns per-flow-type statistics (summed across CPUs).
func (m *Manager) GetFlowTypeStats() ([FlowTypeMax]FtStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result [FlowTypeMax]FtStats
	for i := 0; i < FlowTypeMax; i++ {
		key := uint32(i)
		var perCPU []FtStats
		if err := m.objs.FlowTypeStats.Lookup(key, &perCPU); err != nil {
			continue
		}
		for _, cpu := range perCPU {
			result[i].Packets += cpu.Packets
			result[i].Bytes += cpu.Bytes
		}
	}
	return result, nil
}

// GetSequenceStats returns all sequence tracking entries.
func (m *Manager) GetSequenceStats() (map[FiveTuple]SeqState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[FiveTuple]SeqState)
	var key FiveTuple
	var val SeqState
	iter := m.objs.SeqTrack.Iterate()
	for iter.Next(&key, &val) {
		result[key] = val
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// SetSamplingRate sets the sampling rate for a backend.
// rate=0 or 1 means forward all; rate=N>1 means forward 1-in-N.
func (m *Manager) SetSamplingRate(idx uint32, rate uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objs.SamplingRate.Update(idx, rate, ebpf.UpdateAny)
}

// GetSamplingRate returns the sampling rate for a backend.
func (m *Manager) GetSamplingRate(idx uint32) (uint32, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var rate uint32
	if err := m.objs.SamplingRate.Lookup(idx, &rate); err != nil {
		return 0, err
	}
	return rate, nil
}

// ReassignSession moves a session to a different backend.
func (m *Manager) ReassignSession(key FiveTuple, newBackendIdx uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var sess Session
	if err := m.objs.Sessions.Lookup(key, &sess); err != nil {
		return err
	}
	sess.BackendIdx = newBackendIdx
	return m.objs.Sessions.Update(key, sess, ebpf.UpdateExist)
}

// TemplateEvent represents a template-bearing packet detected by XDP.
// The struct layout must match the C struct template_event.
type TemplateEvent struct {
	SrcIP      uint32 // network byte order
	FlowType   uint32
	SrcPort    uint16 // network byte order
	Pad        uint16
	BackendIdx uint32
}

// TemplateEventCallback is called for each template event with the event
// metadata and the raw packet bytes (ethernet+ip+udp+payload).
type TemplateEventCallback func(evt TemplateEvent, rawPacket []byte)

// StartTemplateReader opens a perf reader on the template_events map and
// calls cb for each event. It blocks until ctx is done or an error occurs.
// Call this in a goroutine.
func (m *Manager) StartTemplateReader(bufSize int, cb TemplateEventCallback) (*perf.Reader, error) {
	m.mu.RLock()
	perfMap := m.objs.TemplateEvents
	m.mu.RUnlock()

	if perfMap == nil {
		return nil, fmt.Errorf("template_events map not loaded")
	}

	rd, err := perf.NewReader(perfMap, bufSize)
	if err != nil {
		return nil, fmt.Errorf("opening perf reader: %w", err)
	}

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				m.logger.Error("perf read error", "err", err)
				continue
			}

			if record.LostSamples > 0 {
				m.logger.Warn("perf lost samples", "count", record.LostSamples)
				continue
			}

			raw := record.RawSample
			if len(raw) < 16 { // sizeof(template_event) = 16 bytes
				continue
			}

			var evt TemplateEvent
			evt.SrcIP = binary.LittleEndian.Uint32(raw[0:4])
			evt.FlowType = binary.LittleEndian.Uint32(raw[4:8])
			evt.SrcPort = binary.LittleEndian.Uint16(raw[8:10])
			evt.BackendIdx = binary.LittleEndian.Uint32(raw[12:16])

			// The packet data follows the metadata
			pktData := raw[16:]
			cb(evt, pktData)
		}
	}()

	return rd, nil
}
