package stream

import (
	"net/netip"
	"testing"

	"github.com/gopcap/gopcap/pkg/layers"
)

func TestTCPOutOfOrderAndOverlapReassembly(t *testing.T) {
	var latestStream string
	assembler := NewTCPAssembler(func(ev StreamEvent) {
		if ev.Direction == DirClientToServer {
			latestStream = string(ev.StreamBuffer)
		}
	})

	clientIP := netip.MustParseAddr("10.0.0.1")
	serverIP := netip.MustParseAddr("10.0.0.2")

	sendSeg := func(seq uint32, flags uint8, payload string) {
		pkt := &layers.DecodedPacket{
			HasIPv4: true,
			IPv4: layers.IPv4Header{
				SrcIP:    clientIP,
				DstIP:    serverIP,
				Protocol: layers.IPProtocolTCP,
			},
			HasTCP: true,
			TCP: layers.TCPHeader{
				SrcPort: 50000,
				DstPort: 80,
				Seq:     seq,
				Flags:   flags,
				Payload: []byte(payload),
			},
			Payload: []byte(payload),
		}
		assembler.ProcessPacket(pkt)
	}

	// 1. SYN at ISN=100 (consumes 1 sequence number -> NextSeq = 101)
	sendSeg(100, layers.TCPFlagSYN, "")

	// 2. Out-of-order segment arrives first: seq=107 ("WORLD", after 6-byte "HELLO ")
	sendSeg(107, layers.TCPFlagACK, "WORLD")
	if latestStream != "" {
		t.Fatalf("expected empty stream while gap exists, got %q", latestStream)
	}

	// 3. Missing segment arrives: seq=101 ("HELLO ", 6 bytes: 101..106)
	sendSeg(101, layers.TCPFlagACK, "HELLO ")
	if latestStream != "HELLO WORLD" {
		t.Fatalf("expected 'HELLO WORLD', got %q", latestStream)
	}

	// 4. Overlapping retransmission: seq=109 ("RLD!!!") where "RLD" (109..111) overlaps and "!!!" is new
	sendSeg(109, layers.TCPFlagACK|layers.TCPFlagPSH, "RLD!!!")
	if latestStream != "HELLO WORLD!!!" {
		t.Fatalf("expected 'HELLO WORLD!!!', got %q", latestStream)
	}
}
