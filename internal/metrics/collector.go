package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	bpf "fload-balancer/internal/ebpf"
)

// Snapshot holds a point-in-time copy of all metrics from BPF maps.
type Snapshot struct {
	Timestamp     time.Time
	BackendStats  []bpf.BeStats
	FlowTypeStats [bpf.FlowTypeMax]bpf.FtStats
	SeqStats      map[bpf.FiveTuple]bpf.SeqState
	SessionCount  int

	// Computed rates (per second) based on delta from previous snapshot.
	BackendPPS []float64 // packets per second per backend
	BackendBPS []float64 // bytes per second per backend
	BackendFPS []float64 // flows per second per backend
	TotalPPS   float64
	TotalBPS   float64
	TotalFPS   float64
}

// Collector periodically reads BPF maps and caches the latest metrics.
type Collector struct {
	mu          sync.RWMutex
	mgr         *bpf.Manager
	numBackends int
	interval    time.Duration
	logger      *slog.Logger
	latest      Snapshot
	prev        Snapshot // previous snapshot for rate computation
	cancel      context.CancelFunc
}

// NewCollector creates a metrics collector.
func NewCollector(mgr *bpf.Manager, numBackends int, interval time.Duration, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		mgr:         mgr,
		numBackends: numBackends,
		interval:    interval,
		logger:      logger,
	}
}

// SetNumBackends updates the number of backends to query.
func (c *Collector) SetNumBackends(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.numBackends = n
}

// Latest returns the most recent metrics snapshot.
func (c *Collector) Latest() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

// Start begins periodic metric collection.
func (c *Collector) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.loop(ctx)
}

// Stop stops the collector.
func (c *Collector) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Collect performs a single metric snapshot.
func (c *Collector) Collect() Snapshot {
	c.mu.RLock()
	numBE := c.numBackends
	prev := c.prev
	c.mu.RUnlock()

	snap := Snapshot{Timestamp: time.Now()}

	if bstats, err := c.mgr.GetBackendStats(numBE); err == nil {
		snap.BackendStats = bstats
	} else {
		c.logger.Error("collecting backend stats", "err", err)
	}

	if ftstats, err := c.mgr.GetFlowTypeStats(); err == nil {
		snap.FlowTypeStats = ftstats
	} else {
		c.logger.Error("collecting flow type stats", "err", err)
	}

	if seqstats, err := c.mgr.GetSequenceStats(); err == nil {
		snap.SeqStats = seqstats
	} else {
		c.logger.Error("collecting sequence stats", "err", err)
	}

	if sessions, err := c.mgr.GetSessions(); err == nil {
		snap.SessionCount = len(sessions)
	}

	// Compute rates from previous snapshot
	dt := snap.Timestamp.Sub(prev.Timestamp).Seconds()
	if dt > 0 && len(prev.BackendStats) > 0 {
		snap.BackendPPS = make([]float64, len(snap.BackendStats))
		snap.BackendBPS = make([]float64, len(snap.BackendStats))
		snap.BackendFPS = make([]float64, len(snap.BackendStats))
		for i := range snap.BackendStats {
			if i < len(prev.BackendStats) {
				dpkt := snap.BackendStats[i].RxPackets - prev.BackendStats[i].RxPackets
				dbyt := snap.BackendStats[i].RxBytes - prev.BackendStats[i].RxBytes
				dflw := snap.BackendStats[i].RxFlows - prev.BackendStats[i].RxFlows
				snap.BackendPPS[i] = float64(dpkt) / dt
				snap.BackendBPS[i] = float64(dbyt) / dt
				snap.BackendFPS[i] = float64(dflw) / dt
				snap.TotalPPS += snap.BackendPPS[i]
				snap.TotalBPS += snap.BackendBPS[i]
				snap.TotalFPS += snap.BackendFPS[i]
			}
		}
	} else {
		snap.BackendPPS = make([]float64, len(snap.BackendStats))
		snap.BackendBPS = make([]float64, len(snap.BackendStats))
		snap.BackendFPS = make([]float64, len(snap.BackendStats))
	}

	// Store latest
	c.mu.Lock()
	c.prev = c.latest
	c.latest = snap
	c.mu.Unlock()

	return snap
}

func (c *Collector) loop(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.Collect()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Collect()
		}
	}
}
