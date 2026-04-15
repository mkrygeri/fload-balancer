package templatecache

import (
	"encoding/binary"
	"sync"
	"testing"
)

// --- helpers to build synthetic flow packets ---

func buildNFv9TemplatePacket(sourceID uint32, templates []nfv9TemplateDef) []byte {
	// Build template flowset body
	var fsBody []byte
	for _, t := range templates {
		rec := make([]byte, 4+t.fieldCount*4)
		binary.BigEndian.PutUint16(rec[0:2], t.templateID)
		binary.BigEndian.PutUint16(rec[2:4], uint16(t.fieldCount))
		for i := 0; i < t.fieldCount; i++ {
			binary.BigEndian.PutUint16(rec[4+i*4:6+i*4], uint16(i+1)) // type
			binary.BigEndian.PutUint16(rec[6+i*4:8+i*4], 4)           // length
		}
		fsBody = append(fsBody, rec...)
	}
	// Flowset: id=0 (template), length
	fsLen := 4 + len(fsBody)
	if pad := fsLen % 4; pad != 0 {
		fsBody = append(fsBody, make([]byte, 4-pad)...)
		fsLen += 4 - pad
	}
	fs := make([]byte, 4)
	binary.BigEndian.PutUint16(fs[0:2], 0)
	binary.BigEndian.PutUint16(fs[2:4], uint16(fsLen))

	// v9 header
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 9)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(templates)))
	binary.BigEndian.PutUint32(hdr[16:20], sourceID)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, fs...)
	pkt = append(pkt, fsBody...)
	return pkt
}

type nfv9TemplateDef struct {
	templateID uint16
	fieldCount int
}

func buildNFv9OptionsTemplatePacket(sourceID uint32, templateID uint16, scopeLen, optionLen int) []byte {
	// Options template flowset body: templateID(2)+scopeLen(2)+optionLen(2)+data
	body := make([]byte, 6+scopeLen+optionLen)
	binary.BigEndian.PutUint16(body[0:2], templateID)
	binary.BigEndian.PutUint16(body[2:4], uint16(scopeLen))
	binary.BigEndian.PutUint16(body[4:6], uint16(optionLen))

	fsLen := 4 + len(body)
	if pad := fsLen % 4; pad != 0 {
		body = append(body, make([]byte, 4-pad)...)
		fsLen += 4 - pad
	}
	fs := make([]byte, 4)
	binary.BigEndian.PutUint16(fs[0:2], 1) // options template flowset
	binary.BigEndian.PutUint16(fs[2:4], uint16(fsLen))

	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 9)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[16:20], sourceID)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, fs...)
	pkt = append(pkt, body...)
	return pkt
}

func buildIPFIXTemplatePacket(obsDomain uint32, templates []ipfixTemplateDef) []byte {
	// Build template set body
	var setBody []byte
	for _, t := range templates {
		rec := make([]byte, 4+t.fieldCount*4)
		binary.BigEndian.PutUint16(rec[0:2], t.templateID)
		binary.BigEndian.PutUint16(rec[2:4], uint16(t.fieldCount))
		for i := 0; i < t.fieldCount; i++ {
			binary.BigEndian.PutUint16(rec[4+i*4:6+i*4], uint16(i+1)) // element ID (no enterprise bit)
			binary.BigEndian.PutUint16(rec[6+i*4:8+i*4], 4)           // field length
		}
		setBody = append(setBody, rec...)
	}

	setLen := 4 + len(setBody)
	if pad := setLen % 4; pad != 0 {
		setBody = append(setBody, make([]byte, 4-pad)...)
		setLen += 4 - pad
	}
	sh := make([]byte, 4)
	binary.BigEndian.PutUint16(sh[0:2], 2) // template set
	binary.BigEndian.PutUint16(sh[2:4], uint16(setLen))

	totalLen := 16 + 4 + len(setBody)
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint16(hdr[0:2], 10)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(hdr[4:8], 1000) // export time
	binary.BigEndian.PutUint32(hdr[8:12], 1)   // seq
	binary.BigEndian.PutUint32(hdr[12:16], obsDomain)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, sh...)
	pkt = append(pkt, setBody...)
	return pkt
}

type ipfixTemplateDef struct {
	templateID uint16
	fieldCount int
}

func buildIPFIXOptionsTemplatePacket(obsDomain uint32, templateID uint16, fieldCount, scopeCount int) []byte {
	rec := make([]byte, 6+fieldCount*4)
	binary.BigEndian.PutUint16(rec[0:2], templateID)
	binary.BigEndian.PutUint16(rec[2:4], uint16(fieldCount))
	binary.BigEndian.PutUint16(rec[4:6], uint16(scopeCount))
	for i := 0; i < fieldCount; i++ {
		binary.BigEndian.PutUint16(rec[6+i*4:8+i*4], uint16(i+1))
		binary.BigEndian.PutUint16(rec[8+i*4:10+i*4], 4)
	}

	setLen := 4 + len(rec)
	if pad := setLen % 4; pad != 0 {
		rec = append(rec, make([]byte, 4-pad)...)
		setLen += 4 - pad
	}
	sh := make([]byte, 4)
	binary.BigEndian.PutUint16(sh[0:2], 3) // options template set
	binary.BigEndian.PutUint16(sh[2:4], uint16(setLen))

	totalLen := 16 + 4 + len(rec)
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint16(hdr[0:2], 10)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(hdr[12:16], obsDomain)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, sh...)
	pkt = append(pkt, rec...)
	return pkt
}

func ipFromBytes(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

// --- Tests ---

func TestNewCache(t *testing.T) {
	c := New(nil)
	if c == nil {
		t.Fatal("New returned nil")
	}
	stats := c.GetStats()
	if stats.TotalTemplates != 0 || stats.ObservationDomains != 0 || stats.EventsReceived != 0 {
		t.Fatalf("new cache should be empty, got %+v", stats)
	}
}

func TestProcessNFv9SingleTemplate(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	srcPort := uint16(12345)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 5}})

	if err := c.ProcessPacket(srcIP, srcPort, FlowTypeNFv9, pkt); err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	stats := c.GetStats()
	if stats.TotalTemplates != 1 {
		t.Errorf("expected 1 template, got %d", stats.TotalTemplates)
	}
	if stats.ObservationDomains != 1 {
		t.Errorf("expected 1 obs domain, got %d", stats.ObservationDomains)
	}
	if stats.EventsReceived != 1 {
		t.Errorf("expected 1 event, got %d", stats.EventsReceived)
	}

	records := c.GetTemplatesForDomain(srcIP, 100)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TemplateID != 256 {
		t.Errorf("expected template ID 256, got %d", records[0].TemplateID)
	}
	if records[0].FlowType != FlowTypeNFv9 {
		t.Errorf("expected flow type NFv9, got %d", records[0].FlowType)
	}
	if records[0].IsOptions {
		t.Error("expected non-options template")
	}
	// 4 bytes header + 5 fields × 4 bytes = 24 bytes
	if len(records[0].RawRecord) != 24 {
		t.Errorf("expected 24 raw bytes, got %d", len(records[0].RawRecord))
	}
}

func TestProcessNFv9MultipleTemplates(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(200, []nfv9TemplateDef{
		{templateID: 256, fieldCount: 3},
		{templateID: 257, fieldCount: 7},
	})

	if err := c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt); err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	stats := c.GetStats()
	if stats.TotalTemplates != 2 {
		t.Errorf("expected 2 templates, got %d", stats.TotalTemplates)
	}

	records := c.GetTemplatesForDomain(srcIP, 200)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestProcessNFv9OptionsTemplate(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9OptionsTemplatePacket(300, 260, 4, 8)

	if err := c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt); err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	records := c.GetTemplatesForDomain(srcIP, 300)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if !records[0].IsOptions {
		t.Error("expected options template")
	}
	if records[0].TemplateID != 260 {
		t.Errorf("expected template ID 260, got %d", records[0].TemplateID)
	}
}

func TestProcessIPFIXSingleTemplate(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)
	pkt := buildIPFIXTemplatePacket(500, []ipfixTemplateDef{{templateID: 300, fieldCount: 4}})

	if err := c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, pkt); err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	stats := c.GetStats()
	if stats.TotalTemplates != 1 {
		t.Errorf("expected 1 template, got %d", stats.TotalTemplates)
	}

	records := c.GetTemplatesForDomain(srcIP, 500)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TemplateID != 300 {
		t.Errorf("expected template ID 300, got %d", records[0].TemplateID)
	}
	if records[0].FlowType != FlowTypeIPFIX {
		t.Errorf("expected IPFIX flow type, got %d", records[0].FlowType)
	}
}

func TestProcessIPFIXMultipleTemplates(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)
	pkt := buildIPFIXTemplatePacket(600, []ipfixTemplateDef{
		{templateID: 310, fieldCount: 2},
		{templateID: 311, fieldCount: 6},
		{templateID: 312, fieldCount: 3},
	})

	if err := c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, pkt); err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	stats := c.GetStats()
	if stats.TotalTemplates != 3 {
		t.Errorf("expected 3 templates, got %d", stats.TotalTemplates)
	}
}

func TestProcessIPFIXOptionsTemplate(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)
	pkt := buildIPFIXOptionsTemplatePacket(700, 350, 5, 2)

	if err := c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, pkt); err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	records := c.GetTemplatesForDomain(srcIP, 700)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if !records[0].IsOptions {
		t.Error("expected options template")
	}
}

func TestMultipleSourcesAndDomains(t *testing.T) {
	c := New(nil)
	src1 := ipFromBytes(10, 0, 0, 1)
	src2 := ipFromBytes(10, 0, 0, 2)

	// src1, domain 100
	pkt1 := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 3}})
	c.ProcessPacket(src1, 0, FlowTypeNFv9, pkt1)

	// src1, domain 200
	pkt2 := buildNFv9TemplatePacket(200, []nfv9TemplateDef{{templateID: 257, fieldCount: 4}})
	c.ProcessPacket(src1, 0, FlowTypeNFv9, pkt2)

	// src2, domain 100
	pkt3 := buildIPFIXTemplatePacket(100, []ipfixTemplateDef{{templateID: 300, fieldCount: 2}})
	c.ProcessPacket(src2, 0, FlowTypeIPFIX, pkt3)

	// Verify isolation
	domains1 := c.GetAllDomainsForSource(src1)
	if len(domains1) != 2 {
		t.Errorf("src1 should have 2 domains, got %d", len(domains1))
	}

	domains2 := c.GetAllDomainsForSource(src2)
	if len(domains2) != 1 {
		t.Errorf("src2 should have 1 domain, got %d", len(domains2))
	}

	if c.GetDomainFlowType(src1, 100) != FlowTypeNFv9 {
		t.Error("src1 domain 100 should be NFv9")
	}
	if c.GetDomainFlowType(src2, 100) != FlowTypeIPFIX {
		t.Error("src2 domain 100 should be IPFIX")
	}

	stats := c.GetStats()
	if stats.TotalTemplates != 3 {
		t.Errorf("expected 3 total templates, got %d", stats.TotalTemplates)
	}
	if stats.ObservationDomains != 3 {
		t.Errorf("expected 3 obs domains, got %d", stats.ObservationDomains)
	}
}

func TestTemplateUpdate(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)

	// First version: 3 fields
	pkt1 := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 3}})
	c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt1)

	recs := c.GetTemplatesForDomain(srcIP, 100)
	if len(recs[0].RawRecord) != 4+3*4 {
		t.Errorf("expected 16 bytes initially, got %d", len(recs[0].RawRecord))
	}

	// Update: 7 fields (same template ID)
	pkt2 := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 7}})
	c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt2)

	recs = c.GetTemplatesForDomain(srcIP, 100)
	if len(recs) != 1 {
		t.Fatalf("should still be 1 template, got %d", len(recs))
	}
	if len(recs[0].RawRecord) != 4+7*4 {
		t.Errorf("expected 32 bytes after update, got %d", len(recs[0].RawRecord))
	}

	stats := c.GetStats()
	if stats.TotalTemplates != 1 {
		t.Errorf("should still be 1 unique template, got %d", stats.TotalTemplates)
	}
	if stats.EventsReceived != 2 {
		t.Errorf("events should be 2, got %d", stats.EventsReceived)
	}
}

func TestDomainSrcPort(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	srcPort := uint16(54321)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 2}})

	c.ProcessPacket(srcIP, srcPort, FlowTypeNFv9, pkt)
	got := c.GetDomainSrcPort(srcIP, 100)
	if got != srcPort {
		t.Errorf("expected src port %d, got %d", srcPort, got)
	}
}

func TestBuildNFv9TemplatePacket(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)

	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{
		{templateID: 256, fieldCount: 3},
		{templateID: 257, fieldCount: 5},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)

	built, flowType, err := c.BuildTemplatePacket(srcIP, 100)
	if err != nil {
		t.Fatalf("BuildTemplatePacket: %v", err)
	}
	if flowType != FlowTypeNFv9 {
		t.Errorf("expected NFv9, got %d", flowType)
	}
	if len(built) < 20 {
		t.Fatalf("built packet too short: %d", len(built))
	}

	// Verify header
	ver := binary.BigEndian.Uint16(built[0:2])
	if ver != 9 {
		t.Errorf("expected version 9, got %d", ver)
	}
	srcID := binary.BigEndian.Uint32(built[16:20])
	if srcID != 100 {
		t.Errorf("expected source ID 100, got %d", srcID)
	}
}

func TestBuildIPFIXTemplatePacket(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)

	pkt := buildIPFIXTemplatePacket(500, []ipfixTemplateDef{
		{templateID: 300, fieldCount: 4},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, pkt)

	built, flowType, err := c.BuildTemplatePacket(srcIP, 500)
	if err != nil {
		t.Fatalf("BuildTemplatePacket: %v", err)
	}
	if flowType != FlowTypeIPFIX {
		t.Errorf("expected IPFIX, got %d", flowType)
	}

	ver := binary.BigEndian.Uint16(built[0:2])
	if ver != 10 {
		t.Errorf("expected version 10, got %d", ver)
	}
	obsDom := binary.BigEndian.Uint32(built[12:16])
	if obsDom != 500 {
		t.Errorf("expected obs domain 500, got %d", obsDom)
	}
	msgLen := binary.BigEndian.Uint16(built[2:4])
	if int(msgLen) != len(built) {
		t.Errorf("IPFIX msg length %d != actual %d", msgLen, len(built))
	}
}

func TestBuildTemplatePacketEmpty(t *testing.T) {
	c := New(nil)
	_, _, err := c.BuildTemplatePacket(ipFromBytes(1, 2, 3, 4), 999)
	if err == nil {
		t.Error("expected error for empty domain")
	}
}

func TestProcessPacketUnknownType(t *testing.T) {
	c := New(nil)
	err := c.ProcessPacket(0, 0, 99, []byte{1, 2, 3, 4})
	if err != nil {
		t.Errorf("unknown flow type should return nil, got %v", err)
	}
}

func TestProcessNFv9TooShort(t *testing.T) {
	c := New(nil)
	err := c.ProcessPacket(0, 0, FlowTypeNFv9, []byte{0, 9, 0, 1})
	if err == nil {
		t.Error("expected error for short payload")
	}
}

func TestProcessIPFIXTooShort(t *testing.T) {
	c := New(nil)
	err := c.ProcessPacket(0, 0, FlowTypeIPFIX, []byte{0, 10, 0, 1})
	if err == nil {
		t.Error("expected error for short payload")
	}
}

func TestGetAllDomainsEmpty(t *testing.T) {
	c := New(nil)
	domains := c.GetAllDomainsForSource(ipFromBytes(1, 2, 3, 4))
	if len(domains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(domains))
	}
}

func TestGetTemplatesForDomainEmpty(t *testing.T) {
	c := New(nil)
	recs := c.GetTemplatesForDomain(ipFromBytes(1, 2, 3, 4), 999)
	if recs != nil {
		t.Errorf("expected nil, got %v", recs)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 3}})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)
		}()
	}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.GetStats()
			c.GetTemplatesForDomain(srcIP, 100)
			c.GetAllDomainsForSource(srcIP)
		}()
	}
	wg.Wait()

	stats := c.GetStats()
	if stats.EventsReceived != 100 {
		t.Errorf("expected 100 events, got %d", stats.EventsReceived)
	}
}

func TestUint32ToIP(t *testing.T) {
	ip := Uint32ToIP(ipFromBytes(10, 0, 0, 1))
	if ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip.String())
	}
}

// --- Round-trip test: parse → cache → rebuild → re-parse ---

func TestNFv9RoundTrip(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)

	original := buildNFv9TemplatePacket(100, []nfv9TemplateDef{
		{templateID: 256, fieldCount: 3},
		{templateID: 257, fieldCount: 5},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeNFv9, original)

	built, _, err := c.BuildTemplatePacket(srcIP, 100)
	if err != nil {
		t.Fatalf("BuildTemplatePacket: %v", err)
	}

	// Re-parse the built packet into a fresh cache
	c2 := New(nil)
	if err := c2.ProcessPacket(srcIP, 0, FlowTypeNFv9, built); err != nil {
		t.Fatalf("re-parsing built packet: %v", err)
	}

	recs := c2.GetTemplatesForDomain(srcIP, 100)
	if len(recs) != 2 {
		t.Fatalf("round-trip: expected 2 templates, got %d", len(recs))
	}
}

func TestIPFIXRoundTrip(t *testing.T) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)

	original := buildIPFIXTemplatePacket(500, []ipfixTemplateDef{
		{templateID: 300, fieldCount: 4},
		{templateID: 301, fieldCount: 2},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, original)

	built, _, err := c.BuildTemplatePacket(srcIP, 500)
	if err != nil {
		t.Fatalf("BuildTemplatePacket: %v", err)
	}

	c2 := New(nil)
	if err := c2.ProcessPacket(srcIP, 0, FlowTypeIPFIX, built); err != nil {
		t.Fatalf("re-parsing built packet: %v", err)
	}

	recs := c2.GetTemplatesForDomain(srcIP, 500)
	if len(recs) != 2 {
		t.Fatalf("round-trip: expected 2 templates, got %d", len(recs))
	}
}

// --- Benchmarks ---

func BenchmarkProcessNFv9Template(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 10}})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)
	}
}

func BenchmarkProcessIPFIXTemplate(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)
	pkt := buildIPFIXTemplatePacket(500, []ipfixTemplateDef{{templateID: 300, fieldCount: 10}})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, pkt)
	}
}

func BenchmarkProcessNFv9MultiTemplate(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{
		{templateID: 256, fieldCount: 5},
		{templateID: 257, fieldCount: 8},
		{templateID: 258, fieldCount: 12},
		{templateID: 259, fieldCount: 3},
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)
	}
}

func BenchmarkBuildNFv9Packet(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{
		{templateID: 256, fieldCount: 10},
		{templateID: 257, fieldCount: 8},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.BuildTemplatePacket(srcIP, 100)
	}
}

func BenchmarkBuildIPFIXPacket(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(192, 168, 1, 1)
	pkt := buildIPFIXTemplatePacket(500, []ipfixTemplateDef{
		{templateID: 300, fieldCount: 10},
		{templateID: 301, fieldCount: 6},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeIPFIX, pkt)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.BuildTemplatePacket(srcIP, 500)
	}
}

func BenchmarkGetTemplatesForDomain(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{
		{templateID: 256, fieldCount: 5},
		{templateID: 257, fieldCount: 8},
		{templateID: 258, fieldCount: 3},
	})
	c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.GetTemplatesForDomain(srcIP, 100)
	}
}

func BenchmarkGetStats(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	for d := uint32(0); d < 50; d++ {
		pkt := buildNFv9TemplatePacket(d, []nfv9TemplateDef{{templateID: 256, fieldCount: 5}})
		c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.GetStats()
	}
}

func BenchmarkConcurrentReadWrite(b *testing.B) {
	c := New(nil)
	srcIP := ipFromBytes(10, 0, 0, 1)
	pkt := buildNFv9TemplatePacket(100, []nfv9TemplateDef{{templateID: 256, fieldCount: 5}})

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.ProcessPacket(srcIP, 0, FlowTypeNFv9, pkt)
			c.GetTemplatesForDomain(srcIP, 100)
		}
	})
}
