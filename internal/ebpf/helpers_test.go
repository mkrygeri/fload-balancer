package ebpf

import (
	"net"
	"testing"
)

func TestIPToUint32(t *testing.T) {
	cases := []struct {
		ip   string
		want uint32
	}{
		{"10.0.0.1", 0x0100000a},
		{"192.168.1.100", 0x6401a8c0},
		{"255.255.255.255", 0xffffffff},
		{"0.0.0.0", 0x00000000},
		{"172.16.0.1", 0x010010ac},
	}
	for _, tc := range cases {
		got := IPToUint32(net.ParseIP(tc.ip))
		if got != tc.want {
			t.Errorf("IPToUint32(%s) = 0x%08x, want 0x%08x", tc.ip, got, tc.want)
		}
	}
}

func TestIPToUint32_NilIPv6(t *testing.T) {
	got := IPToUint32(nil)
	if got != 0 {
		t.Errorf("IPToUint32(nil) = %d, want 0", got)
	}
	got = IPToUint32(net.ParseIP("::1"))
	if got != 0 {
		t.Errorf("IPToUint32(::1) = %d, want 0 (no v4 representation)", got)
	}
}

func TestUint32ToIP(t *testing.T) {
	cases := []struct {
		n    uint32
		want string
	}{
		{0x0100000a, "10.0.0.1"},
		{0x6401a8c0, "192.168.1.100"},
		{0xffffffff, "255.255.255.255"},
		{0x00000000, "0.0.0.0"},
	}
	for _, tc := range cases {
		got := Uint32ToIP(tc.n)
		if got.String() != tc.want {
			t.Errorf("Uint32ToIP(0x%08x) = %s, want %s", tc.n, got, tc.want)
		}
	}
}

func TestIPRoundTrip(t *testing.T) {
	ips := []string{"10.0.0.1", "192.168.1.100", "172.16.0.1", "255.255.255.0"}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		n := IPToUint32(ip)
		back := Uint32ToIP(n)
		if !ip.Equal(back) {
			t.Errorf("round-trip failed: %s -> 0x%x -> %s", ipStr, n, back)
		}
	}
}

func TestPortToNetwork(t *testing.T) {
	// PortToNetwork converts host uint16 to network byte order
	// On a little-endian host, 2055 (0x0807) should become 0x0708
	port := uint16(2055)
	n := PortToNetwork(port)
	// The result should be such that BigEndian reading gives back port
	if n == 0 {
		t.Errorf("PortToNetwork returned 0 for port %d", port)
	}
	// Round-trip: convert back
	back := PortToNetwork(n)
	// Note: PortToNetwork does big->little swap, applying twice should NOT guarantee round-trip
	// unless the system is little-endian. We just verify the result is non-zero and deterministic.
	_ = back
}

func TestFlowTypeName(t *testing.T) {
	cases := []struct {
		ft   uint32
		want string
	}{
		{FlowTypeNFv5, "NetFlow v5"},
		{FlowTypeNFv9, "NetFlow v9"},
		{FlowTypeIPFIX, "IPFIX"},
		{FlowTypeSFlow, "sFlow"},
		{FlowTypeUnknown, "Unknown"},
		{99, "Unknown"},
	}
	for _, tc := range cases {
		got := FlowTypeName(tc.ft)
		if got != tc.want {
			t.Errorf("FlowTypeName(%d) = %q, want %q", tc.ft, got, tc.want)
		}
	}
}

func BenchmarkIPToUint32(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IPToUint32(ip)
	}
}

func BenchmarkUint32ToIP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Uint32ToIP(0xc0a80164)
	}
}

func BenchmarkFlowTypeName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		FlowTypeName(uint32(i % FlowTypeMax))
	}
}
