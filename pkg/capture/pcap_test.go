package capture

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func TestPcapReadWriteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	pw, err := NewPcapWriter(&buf, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("NewPcapWriter failed: %v", err)
	}

	ts1 := time.Unix(1700000000, 123456000)
	ts2 := time.Unix(1700000001, 654321000)

	inputs := []RawPacket{
		{
			Info:     CaptureInfo{Timestamp: ts1, CaptureLength: 4, Length: 4},
			LinkType: LinkTypeEthernet,
			Data:     []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			Info:     CaptureInfo{Timestamp: ts2, CaptureLength: 6, Length: 60},
			LinkType: LinkTypeEthernet,
			Data:     []byte{1, 2, 3, 4, 5, 6},
		},
	}

	for _, pkt := range inputs {
		if err := pw.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket failed: %v", err)
		}
	}

	pr, err := NewPcapReader(&buf)
	if err != nil {
		t.Fatalf("NewPcapReader failed: %v", err)
	}
	if pr.LinkType() != LinkTypeEthernet {
		t.Fatalf("expected LinkTypeEthernet, got %v", pr.LinkType())
	}

	for i, want := range inputs {
		got, err := pr.NextPacket()
		if err != nil {
			t.Fatalf("NextPacket[%d] failed: %v", i, err)
		}
		if !got.Info.Timestamp.Equal(want.Info.Timestamp) {
			t.Errorf("packet[%d] timestamp = %v, want %v", i, got.Info.Timestamp, want.Info.Timestamp)
		}
		if !bytes.Equal(got.Data, want.Data) {
			t.Errorf("packet[%d] data = %x, want %x", i, got.Data, want.Data)
		}
		if got.Info.Length != want.Info.Length {
			t.Errorf("packet[%d] orig length = %d, want %d", i, got.Info.Length, want.Info.Length)
		}
	}

	if _, err := pr.NextPacket(); err != io.EOF {
		t.Errorf("expected io.EOF after reading all packets, got %v", err)
	}
}

func TestPcapBigEndianNanoReader(t *testing.T) {
	var buf bytes.Buffer
	var hdr [24]byte
	// In a Big-Endian PCAP file, magic 0xa1b23c4d is written in Big-Endian byte order.
	binary.BigEndian.PutUint32(hdr[0:4], pcapMagicNanosecLE)
	binary.BigEndian.PutUint16(hdr[4:6], 2)
	binary.BigEndian.PutUint16(hdr[6:8], 4)
	binary.BigEndian.PutUint32(hdr[16:20], 65535)
	binary.BigEndian.PutUint32(hdr[20:24], uint32(LinkTypeNull))
	buf.Write(hdr[:])

	var rec [16]byte
	binary.BigEndian.PutUint32(rec[0:4], 100)
	binary.BigEndian.PutUint32(rec[4:8], 999999999) // 999,999,999 ns
	binary.BigEndian.PutUint32(rec[8:12], 4)
	binary.BigEndian.PutUint32(rec[12:16], 4)
	buf.Write(rec[:])
	buf.Write([]byte{2, 0, 0, 0})

	pr, err := NewPcapReader(&buf)
	if err != nil {
		t.Fatalf("NewPcapReader failed: %v", err)
	}
	pkt, err := pr.NextPacket()
	if err != nil {
		t.Fatalf("NextPacket failed: %v", err)
	}
	if pkt.Info.Timestamp.Nanosecond() != 999999999 {
		t.Errorf("expected 999999999 ns, got %d", pkt.Info.Timestamp.Nanosecond())
	}
}
