package templatecache

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	FlowTypeNFv9  = 2
	FlowTypeIPFIX = 3

	// Header sizes
	nfv9HeaderLen  = 20
	ipfixHeaderLen = 16

	// NetFlow v9 flowset IDs
	nfv9TemplateFlowsetID = 0
	nfv9OptionsFlowsetID  = 1

	// IPFIX set IDs
	ipfixTemplateSetID        = 2
	ipfixOptionsTemplateSetID = 3
)

// ObsDomainKey uniquely identifies an observation domain from a specific source.
type ObsDomainKey struct {
	SrcIP             uint32 // network byte order
	ObservationDomain uint32
}

// TemplateKey uniquely identifies a single template.
type TemplateKey struct {
	SrcIP             uint32
	ObservationDomain uint32
	TemplateID        uint16
}

// TemplateRecord stores a single cached template's raw bytes.
type TemplateRecord struct {
	TemplateID uint16
	FlowType   uint32
	// Raw bytes of the template record (template_id + field_count + fields).
	RawRecord []byte
	// Whether this is an options template.
	IsOptions bool
	// Last time this template was seen.
	LastSeen time.Time
}

// Stats exposes template cache statistics.
type Stats struct {
	TotalTemplates     int
	ObservationDomains int
	EventsReceived     uint64
}

// Cache stores and retrieves NetFlow v9 / IPFIX templates keyed by
// (source_ip, observation_domain_id, template_id).
type Cache struct {
	mu     sync.RWMutex
	logger *slog.Logger

	// templates stores individual template records.
	// TemplateKey → *TemplateRecord
	templates map[TemplateKey]*TemplateRecord

	// domainTemplates tracks which template IDs exist per observation domain.
	// ObsDomainKey → set of TemplateIDs
	domainTemplates map[ObsDomainKey]map[uint16]struct{}

	// domainFlowType tracks the flow type per observation domain.
	domainFlowType map[ObsDomainKey]uint32

	// domainSrcPort tracks the source UDP port per observation domain.
	domainSrcPort map[ObsDomainKey]uint16

	eventsReceived uint64
}

// New creates a new template cache.
func New(logger *slog.Logger) *Cache {
	if logger == nil {
		logger = slog.Default()
	}
	return &Cache{
		logger:          logger,
		templates:       make(map[TemplateKey]*TemplateRecord),
		domainTemplates: make(map[ObsDomainKey]map[uint16]struct{}),
		domainFlowType:  make(map[ObsDomainKey]uint32),
		domainSrcPort:   make(map[ObsDomainKey]uint16),
	}
}

// ProcessPacket parses a raw UDP payload for v9/IPFIX templates and caches them.
// srcIP is in network byte order, srcPort is in network byte order.
func (c *Cache) ProcessPacket(srcIP uint32, srcPort uint16, flowType uint32, payload []byte) error {
	switch flowType {
	case FlowTypeNFv9:
		return c.processNFv9(srcIP, srcPort, payload)
	case FlowTypeIPFIX:
		return c.processIPFIX(srcIP, srcPort, payload)
	default:
		return nil
	}
}

func (c *Cache) processNFv9(srcIP uint32, srcPort uint16, payload []byte) error {
	if len(payload) < nfv9HeaderLen {
		return fmt.Errorf("v9 payload too short: %d", len(payload))
	}

	// v9 header: ver(2)+count(2)+uptime(4)+unix_secs(4)+seq(4)+source_id(4)
	sourceID := binary.BigEndian.Uint32(payload[16:20])

	dk := ObsDomainKey{SrcIP: srcIP, ObservationDomain: sourceID}

	offset := nfv9HeaderLen
	for offset+4 <= len(payload) {
		fsID := binary.BigEndian.Uint16(payload[offset : offset+2])
		fsLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		if fsLen < 4 || offset+fsLen > len(payload) {
			break
		}

		if fsID == nfv9TemplateFlowsetID {
			c.parseNFv9Templates(srcIP, dk, srcPort, payload[offset+4:offset+fsLen], false)
		} else if fsID == nfv9OptionsFlowsetID {
			c.parseNFv9OptionsTemplate(srcIP, dk, srcPort, payload[offset+4:offset+fsLen])
		}

		offset += fsLen
	}

	return nil
}

func (c *Cache) parseNFv9Templates(srcIP uint32, dk ObsDomainKey, srcPort uint16, data []byte, isOptions bool) {
	off := 0
	for off+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[off : off+2])
		fieldCount := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		recordLen := 4 + fieldCount*4 // template_id(2) + field_count(2) + fields(4 each)
		if off+recordLen > len(data) {
			break
		}

		raw := make([]byte, recordLen)
		copy(raw, data[off:off+recordLen])

		c.storeTemplate(srcIP, dk, srcPort, templateID, FlowTypeNFv9, isOptions, raw)
		off += recordLen
	}
}

func (c *Cache) parseNFv9OptionsTemplate(srcIP uint32, dk ObsDomainKey, srcPort uint16, data []byte) {
	// Options template flowset: template_id(2)+option_scope_length(2)+option_length(2)+fields...
	if len(data) < 6 {
		return
	}
	templateID := binary.BigEndian.Uint16(data[0:2])
	scopeLen := int(binary.BigEndian.Uint16(data[2:4]))
	optionLen := int(binary.BigEndian.Uint16(data[4:6]))
	recordLen := 6 + scopeLen + optionLen
	if recordLen > len(data) {
		recordLen = len(data)
	}

	raw := make([]byte, recordLen)
	copy(raw, data[:recordLen])

	c.storeTemplate(srcIP, dk, srcPort, templateID, FlowTypeNFv9, true, raw)
}

func (c *Cache) processIPFIX(srcIP uint32, srcPort uint16, payload []byte) error {
	if len(payload) < ipfixHeaderLen {
		return fmt.Errorf("IPFIX payload too short: %d", len(payload))
	}

	// IPFIX header: ver(2)+length(2)+export_time(4)+seq(4)+obs_domain(4)
	obsDomain := binary.BigEndian.Uint32(payload[12:16])

	dk := ObsDomainKey{SrcIP: srcIP, ObservationDomain: obsDomain}

	offset := ipfixHeaderLen
	msgLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if msgLen > len(payload) {
		msgLen = len(payload)
	}

	for offset+4 <= msgLen {
		setID := binary.BigEndian.Uint16(payload[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		if setLen < 4 || offset+setLen > msgLen {
			break
		}

		if setID == ipfixTemplateSetID {
			c.parseIPFIXTemplates(srcIP, dk, srcPort, payload[offset+4:offset+setLen], false)
		} else if setID == ipfixOptionsTemplateSetID {
			c.parseIPFIXOptionsTemplates(srcIP, dk, srcPort, payload[offset+4:offset+setLen])
		}

		offset += setLen
	}

	return nil
}

func (c *Cache) parseIPFIXTemplates(srcIP uint32, dk ObsDomainKey, srcPort uint16, data []byte, isOptions bool) {
	off := 0
	for off+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[off : off+2])
		fieldCount := int(binary.BigEndian.Uint16(data[off+2 : off+4]))

		// Calculate record length: template_id(2)+field_count(2) + fields
		// Each field: element_id(2)+field_length(2) [+enterprise_number(4) if bit 15 set]
		recordStart := off
		off += 4
		for f := 0; f < fieldCount && off+4 <= len(data); f++ {
			elemID := binary.BigEndian.Uint16(data[off : off+2])
			off += 4
			if elemID&0x8000 != 0 { // enterprise bit set
				if off+4 > len(data) {
					return
				}
				off += 4
			}
		}

		raw := make([]byte, off-recordStart)
		copy(raw, data[recordStart:off])

		c.storeTemplate(srcIP, dk, srcPort, templateID, FlowTypeIPFIX, isOptions, raw)
	}
}

func (c *Cache) parseIPFIXOptionsTemplates(srcIP uint32, dk ObsDomainKey, srcPort uint16, data []byte) {
	off := 0
	for off+6 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[off : off+2])
		fieldCount := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		scopeFieldCount := int(binary.BigEndian.Uint16(data[off+4 : off+6]))
		_ = scopeFieldCount

		recordStart := off
		off += 6
		for f := 0; f < fieldCount && off+4 <= len(data); f++ {
			elemID := binary.BigEndian.Uint16(data[off : off+2])
			off += 4
			if elemID&0x8000 != 0 {
				if off+4 > len(data) {
					return
				}
				off += 4
			}
		}

		raw := make([]byte, off-recordStart)
		copy(raw, data[recordStart:off])

		c.storeTemplate(srcIP, dk, srcPort, templateID, FlowTypeIPFIX, true, raw)
	}
}

func (c *Cache) storeTemplate(srcIP uint32, dk ObsDomainKey, srcPort uint16, templateID uint16, flowType uint32, isOptions bool, raw []byte) {
	tk := TemplateKey{
		SrcIP:             srcIP,
		ObservationDomain: dk.ObservationDomain,
		TemplateID:        templateID,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.eventsReceived++

	c.templates[tk] = &TemplateRecord{
		TemplateID: templateID,
		FlowType:   flowType,
		RawRecord:  raw,
		IsOptions:  isOptions,
		LastSeen:   time.Now(),
	}

	if c.domainTemplates[dk] == nil {
		c.domainTemplates[dk] = make(map[uint16]struct{})
	}
	c.domainTemplates[dk][templateID] = struct{}{}
	c.domainFlowType[dk] = flowType
	c.domainSrcPort[dk] = srcPort

	c.logger.Debug("template cached",
		"src_ip", Uint32ToIP(srcIP).String(),
		"obs_domain", dk.ObservationDomain,
		"template_id", templateID,
		"flow_type", flowType,
		"options", isOptions,
		"size", len(raw),
	)
}

// GetTemplatesForDomain returns all cached templates for a given (src_ip, observation_domain).
func (c *Cache) GetTemplatesForDomain(srcIP uint32, obsDomain uint32) []*TemplateRecord {
	dk := ObsDomainKey{SrcIP: srcIP, ObservationDomain: obsDomain}

	c.mu.RLock()
	defer c.mu.RUnlock()

	tids, ok := c.domainTemplates[dk]
	if !ok {
		return nil
	}

	var records []*TemplateRecord
	for tid := range tids {
		tk := TemplateKey{SrcIP: srcIP, ObservationDomain: obsDomain, TemplateID: tid}
		if rec, ok := c.templates[tk]; ok {
			records = append(records, rec)
		}
	}
	return records
}

// GetAllDomainsForSource returns all observation domain IDs known for a source IP.
func (c *Cache) GetAllDomainsForSource(srcIP uint32) []uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	seen := make(map[uint32]struct{})
	for dk := range c.domainTemplates {
		if dk.SrcIP == srcIP {
			seen[dk.ObservationDomain] = struct{}{}
		}
	}

	domains := make([]uint32, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	return domains
}

// GetDomainSrcPort returns the source UDP port last seen for a domain.
func (c *Cache) GetDomainSrcPort(srcIP uint32, obsDomain uint32) uint16 {
	dk := ObsDomainKey{SrcIP: srcIP, ObservationDomain: obsDomain}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.domainSrcPort[dk]
}

// GetDomainFlowType returns the flow type for a domain.
func (c *Cache) GetDomainFlowType(srcIP uint32, obsDomain uint32) uint32 {
	dk := ObsDomainKey{SrcIP: srcIP, ObservationDomain: obsDomain}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.domainFlowType[dk]
}

// BuildTemplatePacket constructs a raw v9/IPFIX UDP payload containing all
// cached templates for a given (source_ip, observation_domain).
// This is used to "replay" templates to a new collector after failover.
func (c *Cache) BuildTemplatePacket(srcIP uint32, obsDomain uint32) ([]byte, uint32, error) {
	records := c.GetTemplatesForDomain(srcIP, obsDomain)
	if len(records) == 0 {
		return nil, 0, fmt.Errorf("no templates cached for domain")
	}

	flowType := c.GetDomainFlowType(srcIP, obsDomain)

	switch flowType {
	case FlowTypeNFv9:
		return c.buildNFv9Packet(obsDomain, records), flowType, nil
	case FlowTypeIPFIX:
		return c.buildIPFIXPacket(obsDomain, records), flowType, nil
	default:
		return nil, 0, fmt.Errorf("unknown flow type %d for domain", flowType)
	}
}

func (c *Cache) buildNFv9Packet(sourceID uint32, records []*TemplateRecord) []byte {
	// Separate regular and options templates
	var regular, options []*TemplateRecord
	for _, r := range records {
		if r.IsOptions {
			options = append(options, r)
		} else {
			regular = append(regular, r)
		}
	}

	// Build template flowsets
	var flowsets []byte

	if len(regular) > 0 {
		var fsData []byte
		for _, r := range regular {
			fsData = append(fsData, r.RawRecord...)
		}
		// Flowset header: id(2) + length(2)
		fsLen := 4 + len(fsData)
		// Pad to 4-byte boundary
		if pad := fsLen % 4; pad != 0 {
			fsData = append(fsData, make([]byte, 4-pad)...)
			fsLen += 4 - pad
		}
		fs := make([]byte, 4)
		binary.BigEndian.PutUint16(fs[0:2], nfv9TemplateFlowsetID)
		binary.BigEndian.PutUint16(fs[2:4], uint16(fsLen))
		flowsets = append(flowsets, fs...)
		flowsets = append(flowsets, fsData...)
	}

	if len(options) > 0 {
		var fsData []byte
		for _, r := range options {
			fsData = append(fsData, r.RawRecord...)
		}
		fsLen := 4 + len(fsData)
		if pad := fsLen % 4; pad != 0 {
			fsData = append(fsData, make([]byte, 4-pad)...)
			fsLen += 4 - pad
		}
		fs := make([]byte, 4)
		binary.BigEndian.PutUint16(fs[0:2], nfv9OptionsFlowsetID)
		binary.BigEndian.PutUint16(fs[2:4], uint16(fsLen))
		flowsets = append(flowsets, fs...)
		flowsets = append(flowsets, fsData...)
	}

	// v9 header: ver(2)+count(2)+uptime(4)+unix_secs(4)+seq(4)+source_id(4)
	hdr := make([]byte, nfv9HeaderLen)
	binary.BigEndian.PutUint16(hdr[0:2], 9)             // version
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(records))) // count (template records)
	now := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(hdr[4:8], 0)             // sys_uptime (not critical for templates)
	binary.BigEndian.PutUint32(hdr[8:12], now)           // unix_secs
	binary.BigEndian.PutUint32(hdr[12:16], 0)            // sequence (0 for synthetic)
	binary.BigEndian.PutUint32(hdr[16:20], sourceID)     // source_id

	pkt := make([]byte, 0, nfv9HeaderLen+len(flowsets))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, flowsets...)
	return pkt
}

func (c *Cache) buildIPFIXPacket(obsDomain uint32, records []*TemplateRecord) []byte {
	var regular, options []*TemplateRecord
	for _, r := range records {
		if r.IsOptions {
			options = append(options, r)
		} else {
			regular = append(regular, r)
		}
	}

	var sets []byte

	if len(regular) > 0 {
		var setData []byte
		for _, r := range regular {
			setData = append(setData, r.RawRecord...)
		}
		setLen := 4 + len(setData)
		if pad := setLen % 4; pad != 0 {
			setData = append(setData, make([]byte, 4-pad)...)
			setLen += 4 - pad
		}
		sh := make([]byte, 4)
		binary.BigEndian.PutUint16(sh[0:2], ipfixTemplateSetID)
		binary.BigEndian.PutUint16(sh[2:4], uint16(setLen))
		sets = append(sets, sh...)
		sets = append(sets, setData...)
	}

	if len(options) > 0 {
		var setData []byte
		for _, r := range options {
			setData = append(setData, r.RawRecord...)
		}
		setLen := 4 + len(setData)
		if pad := setLen % 4; pad != 0 {
			setData = append(setData, make([]byte, 4-pad)...)
			setLen += 4 - pad
		}
		sh := make([]byte, 4)
		binary.BigEndian.PutUint16(sh[0:2], ipfixOptionsTemplateSetID)
		binary.BigEndian.PutUint16(sh[2:4], uint16(setLen))
		sets = append(sets, sh...)
		sets = append(sets, setData...)
	}

	// IPFIX header: ver(2)+length(2)+export_time(4)+seq(4)+obs_domain(4)
	totalLen := ipfixHeaderLen + len(sets)
	hdr := make([]byte, ipfixHeaderLen)
	binary.BigEndian.PutUint16(hdr[0:2], 10)                   // version
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))      // message length
	binary.BigEndian.PutUint32(hdr[4:8], uint32(time.Now().Unix())) // export_time
	binary.BigEndian.PutUint32(hdr[8:12], 0)                    // sequence (0 for synthetic)
	binary.BigEndian.PutUint32(hdr[12:16], obsDomain)            // observation_domain_id

	pkt := make([]byte, 0, totalLen)
	pkt = append(pkt, hdr...)
	pkt = append(pkt, sets...)
	return pkt
}

// GetStats returns cache statistics.
func (c *Cache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Stats{
		TotalTemplates:     len(c.templates),
		ObservationDomains: len(c.domainTemplates),
		EventsReceived:     c.eventsReceived,
	}
}

// Uint32ToIP converts a BPF map uint32 back to net.IP.
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, n)
	return ip
}
