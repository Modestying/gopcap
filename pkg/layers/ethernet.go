package layers

import (
	"encoding/binary"
	"fmt"
)

// MACAddr represents a 6-byte IEEE 802 MAC address as a value type (allocation-free).
type MACAddr [6]byte

func (m MACAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// EthernetHeader represents an Ethernet II frame header (with optional 802.1Q VLAN tag).
type EthernetHeader struct {
	DstMAC    MACAddr
	SrcMAC    MACAddr
	VLANID    uint16
	HasVLAN   bool
	EtherType EtherType
	Payload   []byte
}

// DecodeEthernet parses an Ethernet II frame and optional 802.1Q VLAN tags in zero-copy mode.
func DecodeEthernet(data []byte, out *EthernetHeader) error {
	if len(data) < 14 {
		return ErrPacketTooShort
	}

	copy(out.DstMAC[:], data[0:6])
	copy(out.SrcMAC[:], data[6:12])
	etherType := EtherType(binary.BigEndian.Uint16(data[12:14]))
	offset := 14

	// Handle 802.1Q VLAN tag (and QinQ double tagging)
	for etherType == EtherTypeVLAN {
		if len(data) < offset+4 {
			return ErrPacketTooShort
		}
		tci := binary.BigEndian.Uint16(data[offset : offset+2])
		out.VLANID = tci & 0x0FFF
		out.HasVLAN = true
		etherType = EtherType(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
	}

	out.EtherType = etherType
	out.Payload = data[offset:]
	return nil
}

// LoopbackHeader represents a BSD/macOS DLT_NULL 4-byte loopback header.
type LoopbackHeader struct {
	Family    uint32
	EtherType EtherType
	Payload   []byte
}

// DecodeLoopback parses a 4-byte BSD loopback header (used on macOS lo0).
func DecodeLoopback(data []byte, out *LoopbackHeader) error {
	if len(data) < 4 {
		return ErrPacketTooShort
	}

	// BSD loopback family can be in host byte order (LittleEndian on x86/arm64) or BigEndian (OpenBSD DLT_LOOP)
	fam := binary.LittleEndian.Uint32(data[0:4])
	if fam > 0xFFFF {
		fam = binary.BigEndian.Uint32(data[0:4])
	}
	out.Family = fam

	switch fam {
	case 2: // AF_INET
		out.EtherType = EtherTypeIPv4
	case 24, 28, 30: // AF_INET6 across BSDs / macOS (30 on Darwin)
		out.EtherType = EtherTypeIPv6
	default:
		out.EtherType = EtherType(fam)
	}

	out.Payload = data[4:]
	return nil
}
