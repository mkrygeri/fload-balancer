package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	c := &Config{}
	c.Defaults()

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"GRPCAddr", c.GRPCAddr, ":50051"},
		{"SessionTimeoutSec", c.SessionTimeoutSec, 300},
		{"SeqWindowSize", c.SeqWindowSize, 16},
		{"HealthCheck.IntervalS", c.HealthCheck.IntervalS, 10},
		{"HealthCheck.TimeoutS", c.HealthCheck.TimeoutS, 3},
		{"HealthCheck.Retries", c.HealthCheck.Retries, 3},
		{"WebUI.Addr", c.WebUI.Addr, ":8080"},
		{"Rebalance.AssessmentIntervalSec", c.Rebalance.AssessmentIntervalSec, 10},
		{"Rebalance.AssessmentCount", c.Rebalance.AssessmentCount, 3},
		{"Rebalance.SamplingRate", c.Rebalance.SamplingRate, 2},
		{"Rebalance.MaxSessionsToMove", c.Rebalance.MaxSessionsToMove, 10},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("Defaults() %s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestDefaultsNoOverwrite(t *testing.T) {
	c := &Config{
		GRPCAddr:          ":9999",
		SessionTimeoutSec: 60,
		SeqWindowSize:     32,
	}
	c.Defaults()

	if c.GRPCAddr != ":9999" {
		t.Errorf("Defaults overwrote GRPCAddr")
	}
	if c.SessionTimeoutSec != 60 {
		t.Errorf("Defaults overwrote SessionTimeoutSec")
	}
	if c.SeqWindowSize != 32 {
		t.Errorf("Defaults overwrote SeqWindowSize")
	}
}

func TestDefaultsBackendWeight(t *testing.T) {
	c := &Config{
		Backends: []BackendConfig{
			{IP: "10.0.0.1", Weight: 0},
			{IP: "10.0.0.2", Weight: 5},
		},
	}
	c.Defaults()

	if c.Backends[0].Weight != 1 {
		t.Errorf("expected weight 1, got %d", c.Backends[0].Weight)
	}
	if c.Backends[1].Weight != 5 {
		t.Errorf("expected weight 5, got %d", c.Backends[1].Weight)
	}
}

func TestValidateMinimal(t *testing.T) {
	c := &Config{
		Interface: "eth0",
		VIPIP:     "10.0.0.100",
		VIPPorts:  []uint16{2055},
		Backends:  []BackendConfig{{IP: "10.0.1.1"}},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

func TestValidateMissingInterface(t *testing.T) {
	c := &Config{VIPIP: "10.0.0.100", VIPPorts: []uint16{2055}, Backends: []BackendConfig{{IP: "10.0.1.1"}}}
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing interface")
	}
}

func TestValidateMissingVIPIP(t *testing.T) {
	c := &Config{Interface: "eth0", VIPPorts: []uint16{2055}, Backends: []BackendConfig{{IP: "10.0.1.1"}}}
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing vip_ip")
	}
}

func TestValidateNoPorts(t *testing.T) {
	c := &Config{Interface: "eth0", VIPIP: "10.0.0.100", Backends: []BackendConfig{{IP: "10.0.1.1"}}}
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing ports")
	}
}

func TestValidateNoBackends(t *testing.T) {
	c := &Config{Interface: "eth0", VIPIP: "10.0.0.100", VIPPorts: []uint16{2055}}
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing backends")
	}
}

func TestValidateBackendMissingIP(t *testing.T) {
	c := &Config{Interface: "eth0", VIPIP: "10.0.0.100", VIPPorts: []uint16{2055}, Backends: []BackendConfig{{IP: ""}}}
	if err := c.Validate(); err == nil {
		t.Error("expected error for backend with empty IP")
	}
}

func TestLoadFile(t *testing.T) {
	yaml := `
interface: eth0
vip_ip: "10.0.0.100"
vip_ports: [2055, 4739]
backends:
  - ip: "10.0.1.10"
    port: 2055
    weight: 2
    health_port: 8080
  - ip: "10.0.1.11"
    port: 2055
grpc_addr: ":9999"
session_timeout_sec: 120
seq_tracking: true
seq_window_size: 32
health_check:
  enabled: true
  interval_sec: 5
  timeout_sec: 2
  retries: 2
web_ui:
  enabled: true
  addr: ":8888"
rebalance:
  enabled: true
  assessment_interval_sec: 5
  assessment_count: 4
  threshold_pps: 10000
  sampling_threshold_pps: 50000
  sampling_rate: 4
  max_sessions_to_move: 20
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.Interface != "eth0" {
		t.Errorf("Interface=%s, want eth0", cfg.Interface)
	}
	if cfg.VIPIP != "10.0.0.100" {
		t.Errorf("VIPIP=%s", cfg.VIPIP)
	}
	if len(cfg.VIPPorts) != 2 {
		t.Errorf("VIPPorts=%v", cfg.VIPPorts)
	}
	if len(cfg.Backends) != 2 {
		t.Errorf("Backends count=%d", len(cfg.Backends))
	}
	if cfg.Backends[0].Weight != 2 {
		t.Errorf("Backend[0].Weight=%d", cfg.Backends[0].Weight)
	}
	if cfg.Backends[1].Weight != 1 { // defaulted
		t.Errorf("Backend[1].Weight=%d, expected default 1", cfg.Backends[1].Weight)
	}
	if cfg.GRPCAddr != ":9999" {
		t.Errorf("GRPCAddr=%s", cfg.GRPCAddr)
	}
	if cfg.SessionTimeoutSec != 120 {
		t.Errorf("SessionTimeoutSec=%d", cfg.SessionTimeoutSec)
	}
	if !cfg.SeqTracking {
		t.Error("SeqTracking should be true")
	}
	if cfg.SeqWindowSize != 32 {
		t.Errorf("SeqWindowSize=%d", cfg.SeqWindowSize)
	}
	if !cfg.Rebalance.Enabled {
		t.Error("Rebalance.Enabled should be true")
	}
	if cfg.Rebalance.ThresholdPPS != 10000 {
		t.Errorf("ThresholdPPS=%f", cfg.Rebalance.ThresholdPPS)
	}
	if cfg.Rebalance.SamplingRate != 4 {
		t.Errorf("SamplingRate=%d", cfg.Rebalance.SamplingRate)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := LoadFile("/tmp/nonexistent_config_xyz.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{{bad yaml"), 0644)

	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func BenchmarkDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := &Config{
			Backends: []BackendConfig{{IP: "10.0.0.1"}, {IP: "10.0.0.2"}},
		}
		c.Defaults()
	}
}

func BenchmarkValidate(b *testing.B) {
	c := &Config{
		Interface: "eth0",
		VIPIP:     "10.0.0.100",
		VIPPorts:  []uint16{2055, 4739, 6343},
		Backends: []BackendConfig{
			{IP: "10.0.1.1"}, {IP: "10.0.1.2"}, {IP: "10.0.1.3"},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Validate()
	}
}
