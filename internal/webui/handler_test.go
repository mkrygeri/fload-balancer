package webui

import (
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"fload-balancer/internal/config"
	"fload-balancer/internal/templatecache"
)

// TestHandleTemplateStatsNilCache verifies the template-stats endpoint when
// no cache is configured returns valid JSON with zeros.
func TestHandleTemplateStatsNilCache(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		VIPIP:     "10.0.0.1",
		VIPPorts:  []uint16{2055},
		Backends:  []config.BackendConfig{{IP: "10.0.1.1"}},
	}
	h := &Handler{
		cfg:       cfg,
		tmplCache: nil,
		backends:  cfg.Backends,
		mux:       http.NewServeMux(),
	}
	h.mux.HandleFunc("/api/template-stats", h.handleTemplateStats)

	req := httptest.NewRequest("GET", "/api/template-stats", nil)
	rr := httptest.NewRecorder()
	h.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type=%s", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["total_templates"] != float64(0) {
		t.Errorf("total_templates=%v", resp["total_templates"])
	}
}

// TestHandleTemplateStatsWithCache verifies stats are returned from a real cache.
func TestHandleTemplateStatsWithCache(t *testing.T) {
	cache := templatecache.New(nil)
	cfg := &config.Config{
		Interface: "lo",
		VIPIP:     "10.0.0.1",
		VIPPorts:  []uint16{2055},
		Backends:  []config.BackendConfig{{IP: "10.0.1.1"}},
	}
	h := &Handler{
		cfg:       cfg,
		tmplCache: cache,
		backends:  cfg.Backends,
		mux:       http.NewServeMux(),
	}
	h.mux.HandleFunc("/api/template-stats", h.handleTemplateStats)

	// Feed a v9 template into the cache
	pkt := buildNFv9TestPacket(100, 256, 5)
	cache.ProcessPacket(0x0a000001, 0x1234, templatecache.FlowTypeNFv9, pkt)

	req := httptest.NewRequest("GET", "/api/template-stats", nil)
	rr := httptest.NewRecorder()
	h.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}

	var resp templatecache.Stats
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalTemplates != 1 {
		t.Errorf("TotalTemplates=%d, want 1", resp.TotalTemplates)
	}
	if resp.ObservationDomains != 1 {
		t.Errorf("ObservationDomains=%d, want 1", resp.ObservationDomains)
	}
}

// TestSetBackends verifies the SetBackends helper.
func TestSetBackends(t *testing.T) {
	h := &Handler{
		backends: []config.BackendConfig{{IP: "10.0.0.1"}},
	}
	newBE := []config.BackendConfig{{IP: "10.0.0.2"}, {IP: "10.0.0.3"}}
	h.SetBackends(newBE)

	if len(h.backends) != 2 {
		t.Fatalf("len=%d, want 2", len(h.backends))
	}
	// Verify it's a copy (mutating original doesn't affect handler)
	newBE[0].IP = "changed"
	if h.backends[0].IP == "changed" {
		t.Error("SetBackends did not copy the slice")
	}
}

// TestStaticFileServing verifies the embedded static files are served.
func TestStaticFileServing(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		VIPIP:     "10.0.0.1",
		VIPPorts:  []uint16{2055},
		Backends:  []config.BackendConfig{{IP: "10.0.1.1"}},
	}
	h := &Handler{
		cfg:      cfg,
		backends: cfg.Backends,
		mux:      http.NewServeMux(),
	}
	// Register routes manually to serve static content
	staticFS, _ := fs.Sub(staticFiles, "static")
	h.mux.Handle("/", http.FileServer(http.FS(staticFS)))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if len(body) == 0 {
		t.Error("empty body for /")
	}
}

func TestNtohs(t *testing.T) {
	cases := []uint16{0, 80, 2055, 4739, 65535}
	for _, port := range cases {
		// ntohs should be its own inverse (swap bytes twice = identity)
		n := ntohs(port)
		back := ntohs(n)
		if back != port {
			t.Errorf("ntohs(ntohs(%d)) = %d", port, back)
		}
	}
}

// buildNFv9TestPacket builds a minimal NFv9 template packet for testing.
func buildNFv9TestPacket(sourceID uint32, templateID uint16, fieldCount int) []byte {
	// Template record
	rec := make([]byte, 4+fieldCount*4)
	binary.BigEndian.PutUint16(rec[0:2], templateID)
	binary.BigEndian.PutUint16(rec[2:4], uint16(fieldCount))
	for i := 0; i < fieldCount; i++ {
		binary.BigEndian.PutUint16(rec[4+i*4:6+i*4], uint16(i+1))
		binary.BigEndian.PutUint16(rec[6+i*4:8+i*4], 4)
	}

	// Flowset: id=0 (template), length
	fsLen := 4 + len(rec)
	fs := make([]byte, 4)
	binary.BigEndian.PutUint16(fs[0:2], 0)
	binary.BigEndian.PutUint16(fs[2:4], uint16(fsLen))

	// v9 header
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 9)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[16:20], sourceID)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, fs...)
	pkt = append(pkt, rec...)
	return pkt
}
