package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"

	pb "fload-balancer/api/v1"
	"fload-balancer/internal/config"
	bpf "fload-balancer/internal/ebpf"
	"fload-balancer/internal/health"
	"fload-balancer/internal/metrics"

	"google.golang.org/grpc"
)

// Server implements the gRPC LoadBalancerService.
type Server struct {
	pb.UnimplementedLoadBalancerServiceServer

	mu        sync.RWMutex
	cfg       *config.Config
	mgr       *bpf.Manager
	collector *metrics.Collector
	hc        *health.Checker
	logger    *slog.Logger

	// Live backend tracking
	backends []config.BackendConfig
}

// New creates a new gRPC server.
func New(cfg *config.Config, mgr *bpf.Manager, collector *metrics.Collector, hc *health.Checker, logger *slog.Logger) *Server {
	return &Server{
		cfg:       cfg,
		mgr:       mgr,
		collector: collector,
		hc:        hc,
		logger:    logger,
		backends:  append([]config.BackendConfig{}, cfg.Backends...),
	}
}

// Register adds the service to a gRPC server.
func (s *Server) Register(gs *grpc.Server) {
	pb.RegisterLoadBalancerServiceServer(gs, s)
}

// --- Backend management ---

func (s *Server) AddBackend(_ context.Context, req *pb.AddBackendRequest) (*pb.AddBackendResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := uint32(len(s.backends))
	ip := net.ParseIP(req.Ip).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", req.Ip)
	}

	weight := uint8(req.Weight)
	if weight == 0 {
		weight = 1
	}

	be := bpf.Backend{
		IP:     binary.BigEndian.Uint32(ip),
		Port:   bpf.PortToNetwork(uint16(req.Port)),
		Active: 1,
		Weight: weight,
	}
	if err := s.mgr.UpdateBackend(idx, be); err != nil {
		return nil, fmt.Errorf("updating BPF backend: %w", err)
	}

	s.backends = append(s.backends, config.BackendConfig{
		IP:     req.Ip,
		Port:   uint16(req.Port),
		Weight: weight,
	})

	// Update config map with new backend count
	s.syncConfigMap()

	s.logger.Info("backend added", "index", idx, "ip", req.Ip, "port", req.Port)
	return &pb.AddBackendResponse{Index: idx}, nil
}

func (s *Server) RemoveBackend(_ context.Context, req *pb.RemoveBackendRequest) (*pb.RemoveBackendResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := req.Index
	if int(idx) >= len(s.backends) {
		return nil, fmt.Errorf("backend index %d out of range", idx)
	}

	// Mark inactive in BPF
	if err := s.mgr.SetBackendActive(idx, false); err != nil {
		return nil, fmt.Errorf("deactivating backend: %w", err)
	}

	s.logger.Info("backend removed", "index", idx)
	return &pb.RemoveBackendResponse{}, nil
}

func (s *Server) ListBackends(_ context.Context, _ *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entries []*pb.BackendEntry
	for i, b := range s.backends {
		entries = append(entries, &pb.BackendEntry{
			Index:  uint32(i),
			Ip:     b.IP,
			Port:   uint32(b.Port),
			Active: true,
			Weight: uint32(b.Weight),
		})
	}
	return &pb.ListBackendsResponse{Backends: entries}, nil
}

// --- Sessions ---

func (s *Server) GetSessions(_ context.Context, _ *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	sessions, err := s.mgr.GetSessions()
	if err != nil {
		return nil, err
	}

	var entries []*pb.SessionEntry
	for key, val := range sessions {
		entries = append(entries, &pb.SessionEntry{
			SrcIp:      bpf.Uint32ToIP(key.SrcIP).String(),
			DstIp:      bpf.Uint32ToIP(key.DstIP).String(),
			SrcPort:    uint32(ntohs(key.SrcPort)),
			DstPort:    uint32(ntohs(key.DstPort)),
			BackendIdx: val.BackendIdx,
			FlowType:   bpf.FlowTypeName(val.FlowType),
			Packets:    val.Packets,
			Bytes:      val.Bytes,
			LastSeenNs: val.LastSeenNs,
		})
	}
	return &pb.GetSessionsResponse{Sessions: entries}, nil
}

func (s *Server) FlushSessions(_ context.Context, _ *pb.FlushSessionsRequest) (*pb.FlushSessionsResponse, error) {
	sessions, err := s.mgr.GetSessions()
	if err != nil {
		return nil, err
	}
	count := len(sessions)
	if err := s.mgr.FlushSessions(); err != nil {
		return nil, err
	}
	s.logger.Info("sessions flushed", "count", count)
	return &pb.FlushSessionsResponse{Flushed: uint32(count)}, nil
}

// --- Metrics ---

func (s *Server) GetBackendStats(_ context.Context, _ *pb.GetBackendStatsRequest) (*pb.GetBackendStatsResponse, error) {
	s.mu.RLock()
	numBE := len(s.backends)
	backends := make([]config.BackendConfig, numBE)
	copy(backends, s.backends)
	s.mu.RUnlock()

	stats, err := s.mgr.GetBackendStats(numBE)
	if err != nil {
		return nil, err
	}

	var entries []*pb.BackendStatsEntry
	for i, st := range stats {
		ip := ""
		if i < len(backends) {
			ip = backends[i].IP
		}
		entries = append(entries, &pb.BackendStatsEntry{
			Index:     uint32(i),
			Ip:        ip,
			RxPackets: st.RxPackets,
			RxBytes:   st.RxBytes,
		})
	}
	return &pb.GetBackendStatsResponse{Stats: entries}, nil
}

func (s *Server) GetFlowTypeStats(_ context.Context, _ *pb.GetFlowTypeStatsRequest) (*pb.GetFlowTypeStatsResponse, error) {
	ftStats, err := s.mgr.GetFlowTypeStats()
	if err != nil {
		return nil, err
	}

	var entries []*pb.FlowTypeStatsEntry
	for i := uint32(0); i < bpf.FlowTypeMax; i++ {
		if ftStats[i].Packets == 0 && ftStats[i].Bytes == 0 {
			continue
		}
		entries = append(entries, &pb.FlowTypeStatsEntry{
			FlowType: bpf.FlowTypeName(i),
			Packets:  ftStats[i].Packets,
			Bytes:    ftStats[i].Bytes,
		})
	}
	return &pb.GetFlowTypeStatsResponse{Stats: entries}, nil
}

func (s *Server) GetSequenceStats(_ context.Context, _ *pb.GetSequenceStatsRequest) (*pb.GetSequenceStatsResponse, error) {
	seqStats, err := s.mgr.GetSequenceStats()
	if err != nil {
		return nil, err
	}

	// Also get sessions to know flow types
	sessions, _ := s.mgr.GetSessions()

	var entries []*pb.SequenceStatsEntry
	for key, st := range seqStats {
		flowType := "Unknown"
		if sess, ok := sessions[key]; ok {
			flowType = bpf.FlowTypeName(sess.FlowType)
		}

		entries = append(entries, &pb.SequenceStatsEntry{
			SrcIp:         bpf.Uint32ToIP(key.SrcIP).String(),
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
	return &pb.GetSequenceStatsResponse{Stats: entries}, nil
}

// --- Configuration ---

func (s *Server) GetConfig(_ context.Context, _ *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ports := make([]uint32, len(s.cfg.VIPPorts))
	for i, p := range s.cfg.VIPPorts {
		ports[i] = uint32(p)
	}

	return &pb.GetConfigResponse{
		Config: &pb.LBConfigMsg{
			VipIp:           s.cfg.VIPIP,
			VipPorts:        ports,
			SeqTracking:     s.cfg.SeqTracking,
			SeqWindowSize:   uint32(s.cfg.SeqWindowSize),
			SessionTimeoutS: uint32(s.cfg.SessionTimeoutSec),
			HealthIntervalS: uint32(s.cfg.HealthCheck.IntervalS),
			HealthTimeoutS:  uint32(s.cfg.HealthCheck.TimeoutS),
		},
	}, nil
}

func (s *Server) UpdateConfig(_ context.Context, req *pb.UpdateConfigRequest) (*pb.UpdateConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := req.Config
	if c == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Update live config
	if c.VipIp != "" {
		s.cfg.VIPIP = c.VipIp
	}
	if len(c.VipPorts) > 0 {
		ports := make([]uint16, len(c.VipPorts))
		for i, p := range c.VipPorts {
			ports[i] = uint16(p)
		}
		s.cfg.VIPPorts = ports
		if err := s.mgr.SetVIPPorts(ports); err != nil {
			return nil, fmt.Errorf("updating VIP ports: %w", err)
		}
	}

	s.cfg.SeqTracking = c.SeqTracking
	if c.SeqWindowSize > 0 {
		s.cfg.SeqWindowSize = int(c.SeqWindowSize)
	}
	if c.SessionTimeoutS > 0 {
		s.cfg.SessionTimeoutSec = int(c.SessionTimeoutS)
	}

	// Push to BPF
	s.syncConfigMap()

	s.logger.Info("config updated")
	return &pb.UpdateConfigResponse{}, nil
}

func (s *Server) syncConfigMap() {
	seqTrack := uint32(0)
	if s.cfg.SeqTracking {
		seqTrack = 1
	}
	bpfCfg := bpf.LBConfig{
		VIPIP:         bpf.IPToUint32(net.ParseIP(s.cfg.VIPIP)),
		NumBackends:   uint32(len(s.backends)),
		SeqTracking:   seqTrack,
		SeqWindowSize: uint32(s.cfg.SeqWindowSize),
	}
	if err := s.mgr.UpdateConfig(bpfCfg); err != nil {
		s.logger.Error("syncing config to BPF", "err", err)
	}
	if s.collector != nil {
		s.collector.SetNumBackends(len(s.backends))
	}
}

// ntohs converts a network byte order uint16 to host byte order.
func ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return binary.LittleEndian.Uint16(b)
}
