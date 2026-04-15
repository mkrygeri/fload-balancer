package rebalancer

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	bpf "fload-balancer/internal/ebpf"
	"fload-balancer/internal/metrics"
	"fload-balancer/internal/templatecache"
)

// Config holds rebalancer settings.
type Config struct {
	// Enabled turns the rebalancer on/off.
	Enabled bool

	// AssessmentIntervalSec is the polling interval for each rate assessment.
	AssessmentIntervalSec int

	// AssessmentCount is the number of consecutive assessments that must
	// exceed the threshold before action is taken (prevents reacting to spikes).
	AssessmentCount int

	// ThresholdPPS: if a backend exceeds this packets-per-second, consider rebalancing.
	ThresholdPPS float64

	// ThresholdFPS: if a backend exceeds this flows-per-second, consider rebalancing.
	// When set (> 0), FPS is preferred over PPS. Falls back to PPS if FPS is unavailable.
	ThresholdFPS float64

	// SamplingThresholdPPS: if a backend exceeds this PPS even after rebalancing,
	// enable packet sampling on that backend.
	SamplingThresholdPPS float64

	// SamplingThresholdFPS: if a backend exceeds this FPS even after rebalancing,
	// enable packet sampling. When set (> 0), FPS is preferred over PPS.
	SamplingThresholdFPS float64

	// SamplingRate: the 1-in-N sampling rate to apply when threshold is exceeded.
	// e.g. 2 = forward every other packet, 4 = forward 1 in 4.
	SamplingRate uint32

	// MaxSessionsToMove limits how many sessions are moved per rebalance action.
	MaxSessionsToMove int
}

// Rebalancer monitors per-backend PPS and takes corrective action.
type Rebalancer struct {
	mu          sync.Mutex
	cfg         Config
	mgr         *bpf.Manager
	collector   *metrics.Collector
	logger      *slog.Logger
	numBackends int
	cancel      context.CancelFunc

	// Template sender for replaying templates on failover.
	tmplSender *templatecache.Sender
	// Backend addresses for template replay.
	backendAddrs []BackendAddr

	// Per-backend breach counters: how many consecutive assessments exceeded threshold.
	breachCounts []int
	// Per-backend sampling breach counters.
	samplingBreachCounts []int
}

// BackendAddr holds backend connection info for template replay.
type BackendAddr struct {
	IP   string
	Port uint16
}

// New creates a new Rebalancer.
func New(cfg Config, mgr *bpf.Manager, collector *metrics.Collector, numBackends int, logger *slog.Logger, tmplSender *templatecache.Sender, addrs []BackendAddr) *Rebalancer {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.AssessmentCount < 1 {
		cfg.AssessmentCount = 3
	}
	if cfg.MaxSessionsToMove < 1 {
		cfg.MaxSessionsToMove = 10
	}
	if cfg.SamplingRate < 2 {
		cfg.SamplingRate = 2
	}
	return &Rebalancer{
		cfg:                  cfg,
		mgr:                  mgr,
		collector:            collector,
		numBackends:          numBackends,
		logger:               logger,
		tmplSender:           tmplSender,
		backendAddrs:         addrs,
		breachCounts:         make([]int, numBackends),
		samplingBreachCounts: make([]int, numBackends),
	}
}

// SetNumBackends updates the backend count (call when backends change).
func (r *Rebalancer) SetNumBackends(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.numBackends = n
	// Resize counters
	if len(r.breachCounts) < n {
		r.breachCounts = append(r.breachCounts, make([]int, n-len(r.breachCounts))...)
		r.samplingBreachCounts = append(r.samplingBreachCounts, make([]int, n-len(r.samplingBreachCounts))...)
	}
}

// Start begins periodic assessment.
func (r *Rebalancer) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	go r.loop(ctx)
}

// Stop stops the rebalancer.
func (r *Rebalancer) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *Rebalancer) loop(ctx context.Context) {
	interval := time.Duration(r.cfg.AssessmentIntervalSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.assess()
		}
	}
}

func (r *Rebalancer) assess() {
	snap := r.collector.Latest()

	r.mu.Lock()
	defer r.mu.Unlock()

	numBE := r.numBackends
	if numBE < 2 {
		return // nothing to rebalance with < 2 backends
	}

	// Ensure PPS data is available
	if len(snap.BackendPPS) < numBE {
		return
	}

	// Determine whether to use FPS or PPS for rebalancing thresholds.
	// FPS is preferred when ThresholdFPS > 0 and FPS data is available.
	useFPSRebalance := r.cfg.ThresholdFPS > 0 && len(snap.BackendFPS) >= numBE
	useFPSSampling := r.cfg.SamplingThresholdFPS > 0 && len(snap.BackendFPS) >= numBE

	// Phase 1: Track sustained threshold breaches for rebalancing
	for i := 0; i < numBE; i++ {
		breached := false
		if useFPSRebalance {
			breached = snap.BackendFPS[i] > r.cfg.ThresholdFPS
		} else {
			breached = snap.BackendPPS[i] > r.cfg.ThresholdPPS
		}
		if breached {
			r.breachCounts[i]++
		} else {
			r.breachCounts[i] = 0
		}
	}

	// Check if any backend has sustained breach requiring rebalance
	for i := 0; i < numBE; i++ {
		if r.breachCounts[i] >= r.cfg.AssessmentCount {
			r.rebalanceFrom(i, numBE, snap)
			r.breachCounts[i] = 0
		}
	}

	// Phase 2: Track sustained breach for sampling (higher threshold)
	samplingThresholdActive := r.cfg.SamplingThresholdPPS > 0 || r.cfg.SamplingThresholdFPS > 0
	if samplingThresholdActive {
		for i := 0; i < numBE; i++ {
			breached := false
			if useFPSSampling {
				breached = snap.BackendFPS[i] > r.cfg.SamplingThresholdFPS
			} else if r.cfg.SamplingThresholdPPS > 0 {
				breached = snap.BackendPPS[i] > r.cfg.SamplingThresholdPPS
			}

			if breached {
				r.samplingBreachCounts[i]++
			} else {
				r.samplingBreachCounts[i] = 0
				// Remove sampling if rate dropped below threshold
				r.disableSampling(uint32(i))
			}

			if r.samplingBreachCounts[i] >= r.cfg.AssessmentCount {
				r.enableSampling(uint32(i))
				r.samplingBreachCounts[i] = 0
			}
		}
	}
}

// rebalanceFrom moves sessions away from an overloaded backend, distributing
// them across all available backends sorted by load (least-loaded first) to
// avoid thundering-herd on a single target.
func (r *Rebalancer) rebalanceFrom(overloaded int, numBE int, snap metrics.Snapshot) {
	// Find healthy backends sorted by load (least-loaded first)
	useFPS := r.cfg.ThresholdFPS > 0 && len(snap.BackendFPS) >= numBE

	type beLoad struct {
		idx  int
		rate float64
	}
	loads := make([]beLoad, 0, numBE)
	for i := 0; i < numBE; i++ {
		if i == overloaded {
			continue
		}
		rate := float64(0)
		if useFPS && i < len(snap.BackendFPS) {
			rate = snap.BackendFPS[i]
		} else if i < len(snap.BackendPPS) {
			rate = snap.BackendPPS[i]
		}
		loads = append(loads, beLoad{idx: i, rate: rate})
	}
	sort.Slice(loads, func(a, b int) bool {
		return loads[a].rate < loads[b].rate
	})

	if len(loads) == 0 {
		return
	}

	logArgs := []any{
		"from_backend", overloaded,
		"targets", len(loads),
	}
	if useFPS {
		logArgs = append(logArgs, "fps", snap.BackendFPS[overloaded], "threshold_fps", r.cfg.ThresholdFPS)
	} else {
		logArgs = append(logArgs, "pps", snap.BackendPPS[overloaded], "threshold_pps", r.cfg.ThresholdPPS)
	}
	r.logger.Warn("rebalancing: backend overloaded", logArgs...)

	// Get all sessions assigned to the overloaded backend
	sessions, err := r.mgr.GetSessions()
	if err != nil {
		r.logger.Error("rebalancer: getting sessions", "err", err)
		return
	}

	// Distribute sessions round-robin across targets sorted by load.
	// This spreads the load evenly rather than dumping everything on one backend.
	moved := 0
	targetIdx := 0
	movedPerTarget := make(map[int]map[uint32]struct{}) // target -> set of source IPs
	for key, sess := range sessions {
		if moved >= r.cfg.MaxSessionsToMove {
			break
		}
		if sess.BackendIdx == uint32(overloaded) {
			target := loads[targetIdx%len(loads)].idx
			if err := r.mgr.ReassignSession(key, uint32(target)); err != nil {
				r.logger.Error("rebalancer: reassigning session", "err", err)
				continue
			}
			if movedPerTarget[target] == nil {
				movedPerTarget[target] = make(map[uint32]struct{})
			}
			movedPerTarget[target][key.SrcIP] = struct{}{}
			moved++
			targetIdx++
		}
	}

	if moved > 0 {
		r.logger.Info("rebalancer: sessions redistributed",
			"count", moved,
			"from", overloaded,
			"across_backends", len(movedPerTarget),
		)

		// Replay templates for moved source IPs to their new backends
		if r.tmplSender != nil {
			for target, srcIPs := range movedPerTarget {
				if target < len(r.backendAddrs) {
					dst := r.backendAddrs[target]
					for srcIP := range srcIPs {
						if err := r.tmplSender.ReplayTemplates(srcIP, dst.IP, dst.Port); err != nil {
							r.logger.Error("rebalancer: template replay failed",
								"src_ip", bpf.Uint32ToIP(srcIP).String(),
								"dst", dst.IP,
								"err", err,
							)
						}
					}
				}
			}
		}
	}
}

func (r *Rebalancer) enableSampling(idx uint32) {
	current, _ := r.mgr.GetSamplingRate(idx)
	if current >= r.cfg.SamplingRate {
		return // already sampling at same or higher rate
	}
	if err := r.mgr.SetSamplingRate(idx, r.cfg.SamplingRate); err != nil {
		r.logger.Error("rebalancer: setting sampling rate", "err", err, "backend", idx)
		return
	}
	r.logger.Warn("rebalancer: sampling enabled",
		"backend", idx,
		"rate", r.cfg.SamplingRate,
	)
}

func (r *Rebalancer) disableSampling(idx uint32) {
	current, _ := r.mgr.GetSamplingRate(idx)
	if current <= 1 {
		return // not sampling
	}
	if err := r.mgr.SetSamplingRate(idx, 0); err != nil {
		r.logger.Error("rebalancer: clearing sampling rate", "err", err, "backend", idx)
		return
	}
	r.logger.Info("rebalancer: sampling disabled", "backend", idx)
}
