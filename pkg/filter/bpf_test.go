package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/gopcap/gopcap/pkg/layers"
)

func TestBPFVM(t *testing.T) {
	// Classic BPF program matching Ethernet IPv4 (EtherType == 0x0800) and TCP (IP proto == 6)
	prog := []BPFInstruction{
		{Code: BpfLd | BpfH | BpfAbs, K: 12},                     // ldh [12]
		{Code: BpfJmp | BpfJeq | BpfK, Jt: 0, Jf: 3, K: 0x0800}, // jeq #0x0800, +0, +3
		{Code: BpfLd | BpfB | BpfAbs, K: 23},                     // ldb [23] (IPv4 protocol)
		{Code: BpfJmp | BpfJeq | BpfK, Jt: 0, Jf: 1, K: 6},      // jeq #6, +0, +1
		{Code: BpfRet | BpfK, K: 65535},                          // ret #65535
		{Code: BpfRet | BpfK, K: 0},                              // ret #0
	}
	vm := NewBPFVM(prog)

	pkt := make([]byte, 34)
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	pkt[23] = 6 // TCP
	if !vm.Match(pkt) {
		t.Errorf("expected BPFVM to match IPv4 TCP packet")
	}

	pkt[23] = 17 // UDP
	if vm.Match(pkt) {
		t.Errorf("expected BPFVM NOT to match IPv4 UDP packet")
	}
}

func TestCompileAndMatch(t *testing.T) {
	pkt := &layers.DecodedPacket{
		HasIPv4: true,
		IPv4: layers.IPv4Header{
			SrcIP:    netip.MustParseAddr("192.168.1.10"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			Protocol: layers.IPProtocolTCP,
		},
		HasTCP: true,
		TCP: layers.TCPHeader{
			SrcPort: 51234,
			DstPort: 443,
		},
	}

	f1, err := Compile("tcp and dst port 443 and src host 192.168.1.10")
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if !f1.Match(pkt) {
		t.Errorf("expected filter f1 to match packet")
	}

	f2, err := Compile("tcp && port 80")
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if f2.Match(pkt) {
		t.Errorf("expected filter f2 not to match port 443 packet")
	}

	httpPkt := &layers.DecodedPacket{
		HasIPv4: true,
		HasTCP:  true,
		TCP:     layers.TCPHeader{SrcPort: 50000, DstPort: 8080},
		Payload: []byte("POST /api/v1/items HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n"),
	}
	fHttp, err := Compile("http")
	if err != nil {
		t.Fatalf("Compile('http') failed: %v", err)
	}
	if !fHttp.Match(httpPkt) {
		t.Errorf("expected filter 'http' to match HTTP POST packet on non-standard port 8080")
	}

	fContains, err := Compile(`tcp contains "POST /api/v1" and http contains "api.example.com"`)
	if err != nil {
		t.Fatalf("Compile('tcp contains ...') failed: %v", err)
	}
	if !fContains.Match(httpPkt) {
		t.Errorf("expected filter 'tcp contains' to match httpPkt")
	}

	fContainsMiss, err := Compile(`tcp contains "not-present-keyword"`)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if fContainsMiss.Match(httpPkt) {
		t.Errorf("expected filter 'tcp contains' not to match missing keyword")
	}
}
