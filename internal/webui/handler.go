package webui

import (
	"context"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"fload-balancer/internal/config"
	bpf "fload-balancer/internal/ebpf"
	"fload-balancer/internal/metrics"
	"fload-balancer/internal/templatecache"
)

//go:embed static/*
var staticFiles embed.FS

type backendJSON struct {
	Index        int     `json:"index"`
	IP           string  `json:"ip"`
	Port         int     `json:"port"`
	Weight       int     `json:"weight"`
	Active       bool    `json:"active"`
	RxPackets    uint64  `json:"rx_packets"`
	RxBytes      uint64  `json:"rx_bytes"`
	RxFlows      uint64  `json:"rx_flows"`
	PPS          float64 `json:"pps"`
	BPS          float64 `json:"bps"`
	FPS          float64 `json:"fps"`
	SamplingRate uint32  `json:"sampling_rate"`
}

type flowTypeJSON struct {
	FlowType string `json:"flow_type"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

type sessionJSON struct {
	SrcIP      string `json:"src_ip"`
	SrcPort    uint32 `json:"src_port"`
	DstIP      string `json:"dst_ip"`
	DstPort    uint32 `json:"dst_port"`
	BackendIdx uint32 `json:"backend_idx"`
	FlowType   string `json:"flow_type"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
}

type seqJSON struct {
	SrcIP         string `json:"src_ip"`
	SrcPort       uint32 `json:"src_port"`
	FlowType      string `json:"flow_type"`
	ExpectedNext  uint32 `json:"expected_next"`
	LastSeq       uint32 `json:"last_seq"`
	TotalReceived uint64 `json:"total_received"`
	Gaps          uint64 `json:"gaps"`
	Duplicates    uint64 `json:"duplicates"`
	OutOfOrder    uint64 `json:"out_of_order"`
}

type configJSON struct {
	Interface     string   `json:"interface"`
	VIPIP         string   `json:"vip_ip"`
	VIPPorts      []uint16 `json:"vip_ports"`
	SeqTracking   bool     `json:"seq_tracking"`
	SeqWindowSize int      `json:"seq_window_size"`
	SessionTimeout int     `json:"session_timeout_sec"`
	NumBackends   int      `json:"num_backends"`
	NumSessions   int      `json:"num_sessions"`
}

type overviewJSON struct {
	Timestamp      string         `json:"timestamp"`
	Config         configJSON     `json:"config"`
	Backends       []backendJSON  `json:"backends"`
	FlowTypes      []flowTypeJSON `json:"flow_types"`
	TotalPackets   uint64         `json:"total_packets"`
	TotalBytes     uint64         `json:"total_bytes"`
	TotalFlows     uint64         `json:"total_flows"`
	TotalPPS       float64        `json:"total_pps"`
	TotalBPS       float64        `json:"total_bps"`
	TotalFPS       float64        `json:"total_fps"`
	SessionCount   int            `json:"session_count"`
}

// Handler serves the web UI and JSON API.
type Handler struct {
	mu         sync.RWMutex
	cfg        *config.Config
	mgr        *bpf.Manager
	collector  *metrics.Collector
	tmplCache  *templatecache.Cache
	backends   []config.BackendConfig
	logger     *slog.Logger
	mux        *http.ServeMux
}

// New creates a new web UI handler.
func New(cfg *config.Config, mgr *bpf.Manager, collector *metrics.Collector, tmplCache *templatecache.Cache, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:       cfg,
		mgr:       mgr,
		collector: collector,
		tmplCache: tmplCache,
		backends:  append([]config.BackendConfig{}, cfg.Backends...),
		logger:    logger,
		mux:       http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

// SetBackends updates the cached backend list.
func (h *Handler) SetBackends(backends []config.BackendConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.backends = append([]config.BackendConfig{}, backends...)
}

func (h *Handler) registerRoutes() {
	// API endpoints
	h.mux.HandleFunc("/api/overview", h.handleOverview)
	h.mux.HandleFunc("/api/backends", h.handleBackends)
	h.mux.HandleFunc("/api/sessions", h.handleSessions)
	h.mux.HandleFunc("/api/flow-stats", h.handleFlowStats)
	h.mux.HandleFunc("/api/seq-stats", h.handleSeqStats)
	h.mux.HandleFunc("/api/template-stats", h.handleTemplateStats)

	// Serve embedded static files
	staticFS, _ := fs.Sub(staticFiles, "static")
	h.mux.Handle("/", http.FileServer(http.FS(staticFS)))
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// ListenAndServe starts the HTTP server. Blocks until ctx is cancelled.
func (h *Handler) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	h.logger.Info("web UI listening", "addr", addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (h *Handler) writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("encoding JSON response", "err", err)
	}
}

func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request) {
	snap := h.collector.Collect()

	h.mu.RLock()
	backends := make([]config.BackendConfig, len(h.backends))
	copy(backends, h.backends)
	h.mu.RUnlock()

	var totalPkts, totalBytes, totalFlows uint64
	var beList []backendJSON
	for i, b := range backends {
		bj := backendJSON{
			Index:  i,
			IP:     b.IP,
			Port:   int(b.Port),
			Weight: int(b.Weight),
			Active: true,
		}
		if i < len(snap.BackendStats) {
			bj.RxPackets = snap.BackendStats[i].RxPackets
			bj.RxBytes = snap.BackendStats[i].RxBytes
			bj.RxFlows = snap.BackendStats[i].RxFlows
			totalPkts += bj.RxPackets
			totalBytes += bj.RxBytes
			totalFlows += bj.RxFlows
		}
		if i < len(snap.BackendPPS) {
			bj.PPS = snap.BackendPPS[i]
			bj.BPS = snap.BackendBPS[i]
		}
		if i < len(snap.BackendFPS) {
			bj.FPS = snap.BackendFPS[i]
		}
		if sr, err := h.mgr.GetSamplingRate(uint32(i)); err == nil {
			bj.SamplingRate = sr
		}
		beList = append(beList, bj)
	}

	var ftList []flowTypeJSON
	for i := uint32(0); i < bpf.FlowTypeMax; i++ {
		if snap.FlowTypeStats[i].Packets == 0 {
			continue
		}
		ftList = append(ftList, flowTypeJSON{
			FlowType: bpf.FlowTypeName(i),
			Packets:  snap.FlowTypeStats[i].Packets,
			Bytes:    snap.FlowTypeStats[i].Bytes,
		})
	}

	resp := overviewJSON{
		Timestamp: snap.Timestamp.Format(time.RFC3339),
		Config: configJSON{
			Interface:      h.cfg.Interface,
			VIPIP:          h.cfg.VIPIP,
			VIPPorts:       h.cfg.VIPPorts,
			SeqTracking:    h.cfg.SeqTracking,
			SeqWindowSize:  h.cfg.SeqWindowSize,
			SessionTimeout: h.cfg.SessionTimeoutSec,
			NumBackends:    len(backends),
			NumSessions:    snap.SessionCount,
		},
		Backends:     beList,
		FlowTypes:    ftList,
		TotalPackets: totalPkts,
		TotalBytes:   totalBytes,
		TotalFlows:   totalFlows,
		TotalPPS:     snap.TotalPPS,
		TotalBPS:     snap.TotalBPS,
		TotalFPS:     snap.TotalFPS,
		SessionCount: snap.SessionCount,
	}
	h.writeJSON(w, resp)
}

func (h *Handler) handleBackends(w http.ResponseWriter, r *http.Request) {
	snap := h.collector.Latest()

	h.mu.RLock()
	backends := make([]config.BackendConfig, len(h.backends))
	copy(backends, h.backends)
	h.mu.RUnlock()

	var list []backendJSON
	for i, b := range backends {
		bj := backendJSON{
			Index:  i,
			IP:     b.IP,
			Port:   int(b.Port),
			Weight: int(b.Weight),
			Active: true,
		}
		if i < len(snap.BackendStats) {
			bj.RxPackets = snap.BackendStats[i].RxPackets
			bj.RxBytes = snap.BackendStats[i].RxBytes
			bj.RxFlows = snap.BackendStats[i].RxFlows
		}
		if i < len(snap.BackendPPS) {
			bj.PPS = snap.BackendPPS[i]
			bj.BPS = snap.BackendBPS[i]
		}
		if i < len(snap.BackendFPS) {
			bj.FPS = snap.BackendFPS[i]
		}
		if sr, err := h.mgr.GetSamplingRate(uint32(i)); err == nil {
			bj.SamplingRate = sr
		}
		list = append(list, bj)
	}
	h.writeJSON(w, list)
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.mgr.GetSessions()
	if err != nil {
		http.Error(w, fmt.Sprintf("reading sessions: %v", err), http.StatusInternalServerError)
		return
	}

	var list []sessionJSON
	for key, val := range sessions {
		list = append(list, sessionJSON{
			SrcIP:      bpf.Uint32ToIP(key.SrcIP).String(),
			SrcPort:    uint32(ntohs(key.SrcPort)),
			DstIP:      bpf.Uint32ToIP(key.DstIP).String(),
			DstPort:    uint32(ntohs(key.DstPort)),
			BackendIdx: val.BackendIdx,
			FlowType:   bpf.FlowTypeName(val.FlowType),
			Packets:    val.Packets,
			Bytes:      val.Bytes,
		})
	}
	h.writeJSON(w, list)
}

func (h *Handler) handleFlowStats(w http.ResponseWriter, r *http.Request) {
	snap := h.collector.Latest()
	var list []flowTypeJSON
	for i := uint32(0); i < bpf.FlowTypeMax; i++ {
		if snap.FlowTypeStats[i].Packets == 0 {
			continue
		}
		list = append(list, flowTypeJSON{
			FlowType: bpf.FlowTypeName(i),
			Packets:  snap.FlowTypeStats[i].Packets,
			Bytes:    snap.FlowTypeStats[i].Bytes,
		})
	}
	h.writeJSON(w, list)
}

func (h *Handler) handleSeqStats(w http.ResponseWriter, r *http.Request) {
	seqStats, err := h.mgr.GetSequenceStats()
	if err != nil {
		http.Error(w, fmt.Sprintf("reading seq stats: %v", err), http.StatusInternalServerError)
		return
	}

	sessions, _ := h.mgr.GetSessions()

	var list []seqJSON
	for key, st := range seqStats {
		flowType := "Unknown"
		if sess, ok := sessions[key]; ok {
			flowType = bpf.FlowTypeName(sess.FlowType)
		}
		list = append(list, seqJSON{
			SrcIP:         bpf.Uint32ToIP(key.SrcIP).String(),
			SrcPort:       uint32(ntohs(key.SrcPort)),
			FlowType:      flowType,
			ExpectedNext:  st.ExpectedNext,
			LastSeq:       st.LastSeq,
			TotalReceived: st.TotalReceived,
			Gaps:          st.Gaps,
			Duplicates:    st.Duplicates,
			OutOfOrder:    st.OutOfOrder,
		})
	}
	h.writeJSON(w, list)
}

func ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return binary.LittleEndian.Uint16(b)
}

func (h *Handler) handleTemplateStats(w http.ResponseWriter, r *http.Request) {
	if h.tmplCache == nil {
		h.writeJSON(w, map[string]interface{}{
			"total_templates":     0,
			"observation_domains": 0,
			"events_received":     0,
		})
		return
	}
	stats := h.tmplCache.GetStats()
	h.writeJSON(w, stats)
}
