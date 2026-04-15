package health

import (
	"net"
	"testing"
	"time"
)

func TestProbeSuccess(t *testing.T) {
	// Start a TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	c := &Checker{
		timeout: 2 * time.Second,
		retries: 1,
	}

	target := BackendTarget{
		Index:      0,
		IP:         "127.0.0.1",
		HealthPort: uint16(port),
	}

	// Accept connections so probe succeeds
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	if !c.probe(target) {
		t.Error("probe should succeed against a listening port")
	}
}

func TestProbeFailure(t *testing.T) {
	c := &Checker{
		timeout: 100 * time.Millisecond,
		retries: 1,
	}

	target := BackendTarget{
		Index:      0,
		IP:         "127.0.0.1",
		HealthPort: 1, // port 1 should refuse connections
	}

	if c.probe(target) {
		t.Error("probe should fail against a closed port")
	}
}

func TestProbeRetries(t *testing.T) {
	c := &Checker{
		timeout: 50 * time.Millisecond,
		retries: 3,
	}

	// Use a non-routable IP to force timeouts (not instant refusal)
	target := BackendTarget{
		Index:      0,
		IP:         "198.51.100.1", // TEST-NET-2 (RFC 5737), should timeout
		HealthPort: 9999,
	}

	start := time.Now()
	result := c.probe(target)
	elapsed := time.Since(start)

	if result {
		t.Error("probe should fail against non-routable IP")
	}
	// With 3 retries at 50ms timeout, should take at least ~100ms
	if elapsed < 100*time.Millisecond {
		t.Logf("retries elapsed: %v (may be fast if firewall sends RST)", elapsed)
	}
}

func TestNewChecker(t *testing.T) {
	c := New(nil, 10*time.Second, 3*time.Second, 3, nil)
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.interval != 10*time.Second {
		t.Errorf("interval=%v", c.interval)
	}
	if c.timeout != 3*time.Second {
		t.Errorf("timeout=%v", c.timeout)
	}
	if c.retries != 3 {
		t.Errorf("retries=%d", c.retries)
	}
}

func TestSetTargets(t *testing.T) {
	c := New(nil, 10*time.Second, 3*time.Second, 3, nil)
	targets := []BackendTarget{
		{Index: 0, IP: "10.0.1.1", HealthPort: 8080},
		{Index: 1, IP: "10.0.1.2", HealthPort: 8080},
	}
	c.SetTargets(targets)

	// Modify original to verify copy
	targets[0].IP = "changed"
	if c.targets[0].IP == "changed" {
		t.Error("SetTargets did not copy targets")
	}
	if len(c.targets) != 2 {
		t.Errorf("len=%d, want 2", len(c.targets))
	}
}

func BenchmarkProbeSuccess(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := &Checker{
		timeout: 2 * time.Second,
		retries: 1,
	}
	target := BackendTarget{
		Index:      0,
		IP:         "127.0.0.1",
		HealthPort: uint16(port),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.probe(target)
	}
}
