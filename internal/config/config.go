package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the load balancer.
type Config struct {
	// Interface to attach XDP program to.
	Interface string `yaml:"interface"`

	// Virtual IP that receives flow traffic.
	VIPIP string `yaml:"vip_ip"`

	// Ports to load-balance (e.g. 2055, 4739, 6343, 9995).
	VIPPorts []uint16 `yaml:"vip_ports"`

	// Backend collectors.
	Backends []BackendConfig `yaml:"backends"`

	// gRPC listen address.
	GRPCAddr string `yaml:"grpc_addr"`

	// Session timeout in seconds. Expired sessions are cleaned up.
	SessionTimeoutSec int `yaml:"session_timeout_sec"`

	// Sequence tracking.
	SeqTracking   bool `yaml:"seq_tracking"`
	SeqWindowSize int  `yaml:"seq_window_size"`

	// Health check settings.
	HealthCheck HealthCheckConfig `yaml:"health_check"`

	// Optional web UI.
	WebUI WebUIConfig `yaml:"web_ui"`

	// Rebalancer settings.
	Rebalance RebalanceConfig `yaml:"rebalance"`
}

// WebUIConfig configures the optional web dashboard.
type WebUIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

// RebalanceConfig configures automatic rebalancing and sampling.
type RebalanceConfig struct {
	Enabled bool `yaml:"enabled"`

	// AssessmentIntervalSec is how often (seconds) to check backend rates.
	AssessmentIntervalSec int `yaml:"assessment_interval_sec"`

	// AssessmentCount is how many consecutive assessments must exceed the
	// threshold before action is taken (avoids reacting to transient spikes).
	AssessmentCount int `yaml:"assessment_count"`

	// ThresholdPPS: rebalance sessions away from a backend exceeding this PPS.
	ThresholdPPS float64 `yaml:"threshold_pps"`

	// ThresholdFPS: rebalance sessions away from a backend exceeding this FPS
	// (flows per second). When set, FPS is preferred over PPS for rebalancing
	// decisions. Falls back to PPS when flow count cannot be determined.
	ThresholdFPS float64 `yaml:"threshold_fps"`

	// SamplingThresholdPPS: enable packet sampling if PPS still exceeds this
	// after rebalancing. Set 0 to disable sampling.
	SamplingThresholdPPS float64 `yaml:"sampling_threshold_pps"`

	// SamplingThresholdFPS: enable packet sampling if FPS still exceeds this
	// after rebalancing. When set, FPS is preferred over PPS. Set 0 to disable.
	SamplingThresholdFPS float64 `yaml:"sampling_threshold_fps"`

	// SamplingRate: 1-in-N sampling rate (e.g. 2 = 50%, 4 = 25%).
	SamplingRate int `yaml:"sampling_rate"`

	// MaxSessionsToMove: max sessions moved per rebalance action.
	MaxSessionsToMove int `yaml:"max_sessions_to_move"`
}

// BackendConfig describes a downstream collector.
type BackendConfig struct {
	IP   string `yaml:"ip"`
	Port uint16 `yaml:"port"`

	// Weight for future weighted load balancing (default 1).
	Weight uint8 `yaml:"weight"`

	// TCP port for health checking. 0 = disabled.
	HealthPort uint16 `yaml:"health_port"`
}

// HealthCheckConfig configures the TCP health checker.
type HealthCheckConfig struct {
	Enabled    bool `yaml:"enabled"`
	IntervalS  int  `yaml:"interval_sec"`
	TimeoutS   int  `yaml:"timeout_sec"`
	Retries    int  `yaml:"retries"`
}

// Defaults fills in zero values with sensible defaults.
func (c *Config) Defaults() {
	if c.GRPCAddr == "" {
		c.GRPCAddr = ":50051"
	}
	if c.SessionTimeoutSec == 0 {
		c.SessionTimeoutSec = 300
	}
	if c.SeqWindowSize == 0 {
		c.SeqWindowSize = 16
	}
	if c.HealthCheck.IntervalS == 0 {
		c.HealthCheck.IntervalS = 10
	}
	if c.HealthCheck.TimeoutS == 0 {
		c.HealthCheck.TimeoutS = 3
	}
	if c.HealthCheck.Retries == 0 {
		c.HealthCheck.Retries = 3
	}
	for i := range c.Backends {
		if c.Backends[i].Weight == 0 {
			c.Backends[i].Weight = 1
		}
	}
	if c.WebUI.Addr == "" {
		c.WebUI.Addr = ":8080"
	}
	if c.Rebalance.AssessmentIntervalSec == 0 {
		c.Rebalance.AssessmentIntervalSec = 10
	}
	if c.Rebalance.AssessmentCount == 0 {
		c.Rebalance.AssessmentCount = 3
	}
	if c.Rebalance.SamplingRate == 0 {
		c.Rebalance.SamplingRate = 2
	}
	if c.Rebalance.MaxSessionsToMove == 0 {
		c.Rebalance.MaxSessionsToMove = 10
	}
}

// Validate checks the configuration for obvious errors.
func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface is required")
	}
	if c.VIPIP == "" {
		return fmt.Errorf("vip_ip is required")
	}
	if len(c.VIPPorts) == 0 {
		return fmt.Errorf("at least one vip_port is required")
	}
	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend is required")
	}
	for i, b := range c.Backends {
		if b.IP == "" {
			return fmt.Errorf("backend[%d]: ip is required", i)
		}
	}
	return nil
}

// LoadFile reads and parses a YAML config file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return &cfg, nil
}
