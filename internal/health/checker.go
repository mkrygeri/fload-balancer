package health

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	bpf "fload-balancer/internal/ebpf"
)

// BackendTarget describes a backend to health-check.
type BackendTarget struct {
	Index      uint32
	IP         string
	HealthPort uint16
}

// Checker performs periodic TCP health checks on backends
// and updates their active status in the BPF map.
type Checker struct {
	mu       sync.Mutex
	mgr      *bpf.Manager
	targets  []BackendTarget
	interval time.Duration
	timeout  time.Duration
	retries  int
	logger   *slog.Logger
	cancel   context.CancelFunc
}

// New creates a new health checker.
func New(mgr *bpf.Manager, interval, timeout time.Duration, retries int, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Checker{
		mgr:      mgr,
		interval: interval,
		timeout:  timeout,
		retries:  retries,
		logger:   logger,
	}
}

// SetTargets updates the list of backends to check.
func (c *Checker) SetTargets(targets []BackendTarget) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targets = make([]BackendTarget, len(targets))
	copy(c.targets, targets)
}

// Start begins periodic health checking.
func (c *Checker) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.loop(ctx)
}

// Stop stops the health checker.
func (c *Checker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Checker) loop(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Run immediately on start
	c.checkAll()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkAll()
		}
	}
}

func (c *Checker) checkAll() {
	c.mu.Lock()
	targets := make([]BackendTarget, len(c.targets))
	copy(targets, c.targets)
	c.mu.Unlock()

	for _, t := range targets {
		if t.HealthPort == 0 {
			// No health port configured; always active
			continue
		}
		healthy := c.probe(t)
		if err := c.mgr.SetBackendActive(t.Index, healthy); err != nil {
			c.logger.Error("failed to update backend status",
				"index", t.Index, "ip", t.IP, "err", err)
		}
		if !healthy {
			c.logger.Warn("backend unhealthy",
				"index", t.Index, "ip", t.IP, "health_port", t.HealthPort)
		}
	}
}

func (c *Checker) probe(t BackendTarget) bool {
	addr := fmt.Sprintf("%s:%d", t.IP, t.HealthPort)
	for attempt := 0; attempt < c.retries; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, c.timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}
