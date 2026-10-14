package layers

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/gopcap/gopcap/pkg/capture"
)

func buildTestVLANIPv4TCP() []byte {
	// Ethernet (14) + 802.1Q VLAN (4) + IPv4 (20) + TCP (20) + Payload (5)
	pkt := make([]byte, 14+4+20+20+5)
	// DstMAC & SrcMAC
	copy(pkt[0:6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(pkt[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint16(pkt[12:14], uint16(EtherTypeVLAN))
	binary.BigEndian.PutUint16(pkt[14:16], 100) // VLAN ID 100
	binary.BigEndian.PutUint16(pkt[16:18], uint16(EtherTypeIPv4))

	ip := pkt[18:38]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 45)
	ip[8] = 64
	ip[9] = uint8(IPProtocolTCP)
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})

	tcp := pkt[38:58]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	binary.BigEndian.PutUint32(tcp[4:8], 1001)
	binary.BigEndian.PutUint32(tcp[8:12], 2002)
	tcp[12] = 5 << 4
	tcp[13] = TCPFlagSYN | TCPFlagACK
	binary.BigEndian.PutUint16(tcp[14:16], 4096)

	copy(pkt[58:], []byte("hello"))
	return pkt
}

func TestDecodeVLANIPv4TCP(t *testing.T) {
	raw := capture.RawPacket{
		LinkType: capture.LinkTypeEthernet,
		Data:     buildTestVLANIPv4TCP(),
	}

	var decoded DecodedPacket
	if err := DecodePacket(raw, &decoded); err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}

	if !decoded.HasEthernet || !decoded.Ethernet.HasVLAN || decoded.Ethernet.VLANID != 100 {
		t.Errorf("expected VLAN 100, got HasVLAN=%v VLANID=%d", decoded.Ethernet.HasVLAN, decoded.Ethernet.VLANID)
	}
	if !decoded.HasIPv4 {
		t.Fatalf("expected HasIPv4=true")
	}
	if decoded.SrcIP() != netip.MustParseAddr("10.0.0.1") || decoded.DstIP() != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("unexpected IPs: %s -> %s", decoded.SrcIP(), decoded.DstIP())
	}
	if !decoded.HasTCP || decoded.TCP.SrcPort != 12345 || decoded.TCP.DstPort != 80 {
		t.Errorf("unexpected TCP ports: %d -> %d", decoded.TCP.SrcPort, decoded.TCP.DstPort)
	}
	if decoded.TCP.FlagsString() != "SYN,ACK" {
		t.Errorf("unexpected flags: %s", decoded.TCP.FlagsString())
	}
	if string(decoded.Payload) != "hello" {
		t.Errorf("unexpected payload: %q", string(decoded.Payload))
	}
}

func TestDecodeLoopbackIPv6UDP(t *testing.T) {
	// 4-byte BSD loopback (AF_INET6 = 30 on Darwin) + 40-byte IPv6 + 8-byte UDP + 4-byte payload
	pkt := make([]byte, 4+40+8+4)
	binary.LittleEndian.PutUint32(pkt[0:4], 30)

	ip6 := pkt[4:44]
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], 12) // UDP(8) + payload(4)
	ip6[6] = uint8(IPProtocolUDP)
	ip6[7] = 64
	ip6[23] = 1 // ::1
	ip6[39] = 1 // ::1

	udp := pkt[44:52]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 5353)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(pkt[52:], []byte("ping"))

	var decoded DecodedPacket
	err := DecodePacket(capture.RawPacket{
		LinkType: capture.LinkTypeNull,
		Data:     pkt,
	}, &decoded)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}
	if !decoded.HasLoopback || !decoded.HasIPv6 || !decoded.HasUDP {
		t.Fatalf("expected Loopback + IPv6 + UDP, got %+v", decoded)
	}
	if decoded.SrcIP() != netip.MustParseAddr("::1") {
		t.Errorf("expected ::1, got %v", decoded.SrcIP())
	}
	if string(decoded.Payload) != "ping" {
		t.Errorf("expected payload 'ping', got %q", string(decoded.Payload))
	}
}

func BenchmarkZeroCopyDecode(b *testing.B) {
	raw := capture.RawPacket{
		LinkType: capture.LinkTypeEthernet,
		Data:     buildTestVLANIPv4TCP(),
	}
	var decoded DecodedPacket
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := DecodePacket(raw, &decoded); err != nil {
			b.Fatal(err)
		}
	}
}
