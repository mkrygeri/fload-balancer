package templatecache

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"syscall"
)

// Sender constructs and sends spoofed template packets via raw socket.
type Sender struct {
	logger *slog.Logger
	cache  *Cache
}

// NewSender creates a template sender.
func NewSender(cache *Cache, logger *slog.Logger) *Sender {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sender{cache: cache, logger: logger}
}

// ReplayTemplates sends all cached templates for a source IP to a new backend.
// srcIP is the device IP (network byte order) whose templates we replay.
// dstIP and dstPort are the new backend's address.
func (s *Sender) ReplayTemplates(srcIP uint32, dstIP string, dstPort uint16) error {
	domains := s.cache.GetAllDomainsForSource(srcIP)
	if len(domains) == 0 {
		return nil // no templates to replay
	}

	srcIPNet := Uint32ToIP(srcIP)
	sent := 0

	for _, obsDomain := range domains {
		payload, _, err := s.cache.BuildTemplatePacket(srcIP, obsDomain)
		if err != nil {
			s.logger.Debug("skipping domain for template replay",
				"obs_domain", obsDomain,
				"err", err,
			)
			continue
		}

		srcPort := s.cache.GetDomainSrcPort(srcIP, obsDomain)
		if srcPort == 0 {
			srcPort = htons(49152) // fallback
		}

		if err := sendSpoofedUDP(srcIPNet, ntohs(srcPort), dstIP, dstPort, payload); err != nil {
			s.logger.Error("template replay: send failed",
				"src_ip", srcIPNet.String(),
				"dst", fmt.Sprintf("%s:%d", dstIP, dstPort),
				"obs_domain", obsDomain,
				"err", err,
			)
			continue
		}
		sent++
	}

	if sent > 0 {
		s.logger.Info("template replay completed",
			"src_device", srcIPNet.String(),
			"dst", fmt.Sprintf("%s:%d", dstIP, dstPort),
			"domains_sent", sent,
		)
	}
	return nil
}

// sendSpoofedUDP sends a UDP datagram with a spoofed source IP via raw socket.
func sendSpoofedUDP(srcIP net.IP, srcPort uint16, dstIPStr string, dstPort uint16, payload []byte) error {
	dstIP := net.ParseIP(dstIPStr).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid destination IP: %s", dstIPStr)
	}
	srcIP = srcIP.To4()
	if srcIP == nil {
		return fmt.Errorf("invalid source IP")
	}

	// Build UDP header
	udpLen := 8 + len(payload)
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpHdr[6:8], 0) // checksum (optional for IPv4 UDP)

	// Build IP header (20 bytes, no options)
	totalLen := 20 + udpLen
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version=4, ihl=5
	ipHdr[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHdr[4:6], 0) // identification
	ipHdr[6] = 0x40                            // flags: DF
	ipHdr[7] = 0
	ipHdr[8] = 64               // TTL
	ipHdr[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(ipHdr[10:12], 0) // checksum (kernel calculates with IP_HDRINCL)
	copy(ipHdr[12:16], srcIP)
	copy(ipHdr[16:20], dstIP)

	// Assemble full packet
	pkt := make([]byte, 0, totalLen)
	pkt = append(pkt, ipHdr...)
	pkt = append(pkt, udpHdr...)
	pkt = append(pkt, payload...)

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	// IP_HDRINCL tells the kernel we provide the full IP header
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("IP_HDRINCL: %w", err)
	}

	// Send
	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dstIP)
	if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

func ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return binary.LittleEndian.Uint16(b)
}

func htons(h uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, h)
	return binary.BigEndian.Uint16(b)
}
