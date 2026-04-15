package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fload-balancer/internal/config"
	bpf "fload-balancer/internal/ebpf"
	"fload-balancer/internal/health"
	"fload-balancer/internal/metrics"
	"fload-balancer/internal/rebalancer"
	"fload-balancer/internal/server"
	"fload-balancer/internal/templatecache"
	"fload-balancer/internal/webui"

	"google.golang.org/grpc"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		logger.Error("loading config", "err", err)
		os.Exit(1)
	}
	logger.Info("config loaded",
		"interface", cfg.Interface,
		"vip", cfg.VIPIP,
		"ports", cfg.VIPPorts,
		"backends", len(cfg.Backends),
	)

	// Load and attach XDP program
	mgr, err := bpf.Load(cfg.Interface, logger)
	if err != nil {
		logger.Error("loading BPF", "err", err)
		os.Exit(1)
	}
	defer mgr.Close()

	// Configure VIP IP and backends
	if err := applyConfig(mgr, cfg); err != nil {
		logger.Error("applying config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start health checker
	var hc *health.Checker
	if cfg.HealthCheck.Enabled {
		hc = health.New(
			mgr,
			time.Duration(cfg.HealthCheck.IntervalS)*time.Second,
			time.Duration(cfg.HealthCheck.TimeoutS)*time.Second,
			cfg.HealthCheck.Retries,
			logger,
		)
		var targets []health.BackendTarget
		for i, b := range cfg.Backends {
			targets = append(targets, health.BackendTarget{
				Index:      uint32(i),
				IP:         b.IP,
				HealthPort: b.HealthPort,
			})
		}
		hc.SetTargets(targets)
		hc.Start(ctx)
		logger.Info("health checker started",
			"interval", cfg.HealthCheck.IntervalS,
			"timeout", cfg.HealthCheck.TimeoutS,
		)
	}

	// Start metrics collector
	collector := metrics.NewCollector(mgr, len(cfg.Backends), 5*time.Second, logger)
	collector.Start(ctx)

	// Start template cache and perf reader
	tmplCache := templatecache.New(logger)
	tmplSender := templatecache.NewSender(tmplCache, logger)

	// The perf reader intercepts template-bearing v9/IPFIX packets from XDP
	// and feeds them into the template cache. The raw packet includes
	// ethernet(14)+IP(20)+UDP(8) headers before the flow payload.
	const ethIPUDPLen = 42
	perfRd, err := mgr.StartTemplateReader(4096*256, func(evt bpf.TemplateEvent, rawPkt []byte) {
		if len(rawPkt) <= ethIPUDPLen {
			return
		}
		udpPayload := rawPkt[ethIPUDPLen:]
		if err := tmplCache.ProcessPacket(evt.SrcIP, evt.SrcPort, evt.FlowType, udpPayload); err != nil {
			logger.Debug("template parse error", "err", err)
		}
	})
	if err != nil {
		logger.Warn("template perf reader not started (non-fatal)", "err", err)
	} else {
		logger.Info("template cache started")
	}

	// Start session cleanup goroutine
	go sessionCleanup(ctx, mgr, cfg, logger)

	// Start rebalancer
	var rb *rebalancer.Rebalancer
	if cfg.Rebalance.Enabled {
		rbCfg := rebalancer.Config{
			Enabled:               true,
			AssessmentIntervalSec: cfg.Rebalance.AssessmentIntervalSec,
			AssessmentCount:       cfg.Rebalance.AssessmentCount,
			ThresholdPPS:          cfg.Rebalance.ThresholdPPS,
			ThresholdFPS:          cfg.Rebalance.ThresholdFPS,
			SamplingThresholdPPS:  cfg.Rebalance.SamplingThresholdPPS,
			SamplingThresholdFPS:  cfg.Rebalance.SamplingThresholdFPS,
			SamplingRate:          uint32(cfg.Rebalance.SamplingRate),
			MaxSessionsToMove:    cfg.Rebalance.MaxSessionsToMove,
		}
		var backendAddrs []rebalancer.BackendAddr
		for _, b := range cfg.Backends {
			backendAddrs = append(backendAddrs, rebalancer.BackendAddr{
				IP:   b.IP,
				Port: b.Port,
			})
		}
		rb = rebalancer.New(rbCfg, mgr, collector, len(cfg.Backends), logger, tmplSender, backendAddrs)
		rb.Start(ctx)
		logger.Info("rebalancer started",
			"interval", cfg.Rebalance.AssessmentIntervalSec,
			"assessments", cfg.Rebalance.AssessmentCount,
			"threshold_pps", cfg.Rebalance.ThresholdPPS,
		)
	}

	// Start gRPC server
	grpcSrv := grpc.NewServer()
	svc := server.New(cfg, mgr, collector, hc, logger)
	svc.Register(grpcSrv)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("gRPC listen", "addr", cfg.GRPCAddr, "err", err)
		os.Exit(1)
	}
	logger.Info("gRPC server listening", "addr", cfg.GRPCAddr)

	go func() {
		if err := grpcSrv.Serve(lis); err != nil {
			logger.Error("gRPC serve", "err", err)
		}
	}()

	// Start optional web UI
	if cfg.WebUI.Enabled {
		wui := webui.New(cfg, mgr, collector, tmplCache, logger)
		go func() {
			if err := wui.ListenAndServe(ctx, cfg.WebUI.Addr); err != nil {
				logger.Error("web UI", "err", err)
			}
		}()
	}

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down", "signal", sig)

	cancel()
	grpcSrv.GracefulStop()
	if hc != nil {
		hc.Stop()
	}
	if rb != nil {
		rb.Stop()
	}
	if perfRd != nil {
		perfRd.Close()
	}
	collector.Stop()
}

func applyConfig(mgr *bpf.Manager, cfg *config.Config) error {
	// Set VIP IP + global config
	seqTrack := uint32(0)
	if cfg.SeqTracking {
		seqTrack = 1
	}
	bpfCfg := bpf.LBConfig{
		VIPIP:         bpf.IPToUint32(net.ParseIP(cfg.VIPIP)),
		NumBackends:   uint32(len(cfg.Backends)),
		SeqTracking:   seqTrack,
		SeqWindowSize: uint32(cfg.SeqWindowSize),
	}
	if err := mgr.UpdateConfig(bpfCfg); err != nil {
		return fmt.Errorf("setting config: %w", err)
	}

	// Set VIP ports
	if err := mgr.SetVIPPorts(cfg.VIPPorts); err != nil {
		return fmt.Errorf("setting VIP ports: %w", err)
	}

	// Add backends
	for i, b := range cfg.Backends {
		ip := net.ParseIP(b.IP).To4()
		if ip == nil {
			return fmt.Errorf("backend[%d]: invalid IP %q", i, b.IP)
		}
		be := bpf.Backend{
			IP:     binary.BigEndian.Uint32(ip),
			Port:   bpf.PortToNetwork(b.Port),
			Active: 1,
			Weight: b.Weight,
		}
		if err := mgr.UpdateBackend(uint32(i), be); err != nil {
			return fmt.Errorf("adding backend[%d]: %w", i, err)
		}
	}

	return nil
}

func sessionCleanup(ctx context.Context, mgr *bpf.Manager, cfg *config.Config, logger *slog.Logger) {
	interval := time.Duration(cfg.SessionTimeoutSec) * time.Second / 2
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// bpf_ktime_get_ns is nanoseconds since boot
			// We don't have direct access to boot time, so we use a relative cutoff
			// by reading current ktime from a session and computing delta.
			// For simplicity, we call FlushExpiredSessions which compares LastSeenNs.
			// The caller needs to provide the cutoff in ktime ns.
			// As a reasonable approach, we read current time via a helper.
			cutoff := uint64(time.Duration(cfg.SessionTimeoutSec) * time.Second)
			// We need ktime_get_ns equivalent. Since we can't call it from userspace directly,
			// we use /proc/uptime to estimate boot-relative time.
			uptime, err := getUptimeNs()
			if err != nil {
				logger.Error("getting uptime", "err", err)
				continue
			}
			maxAge := uptime - cutoff
			flushed, err := mgr.FlushExpiredSessions(maxAge)
			if err != nil {
				logger.Error("session cleanup", "err", err)
				continue
			}
			if flushed > 0 {
				logger.Info("expired sessions cleaned", "count", flushed)
			}
		}
	}
}

func getUptimeNs() (uint64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	var secs, frac float64
	if _, err := fmt.Sscanf(string(data), "%f %f", &secs, &frac); err != nil {
		return 0, err
	}
	return uint64(secs * 1e9), nil
}
