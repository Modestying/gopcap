package layers

import (
	"encoding/binary"
	"strings"
)

// TCP flag bitmasks.
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
	TCPFlagECE uint8 = 0x40
	TCPFlagCWR uint8 = 0x80
)

// TCPHeader represents a TCP segment header (RFC 9293).
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
	Payload    []byte
}

// HasFlag checks whether the given TCP flag bit(s) are set.
func (t *TCPHeader) HasFlag(flag uint8) bool {
	return (t.Flags & flag) != 0
}

// FlagsString returns a human-readable representation of set TCP flags (e.g. "SYN,ACK").
func (t *TCPHeader) FlagsString() string {
	var parts []string
	if t.HasFlag(TCPFlagSYN) {
		parts = append(parts, "SYN")
	}
	if t.HasFlag(TCPFlagACK) {
		parts = append(parts, "ACK")
	}
	if t.HasFlag(TCPFlagPSH) {
		parts = append(parts, "PSH")
	}
	if t.HasFlag(TCPFlagFIN) {
		parts = append(parts, "FIN")
	}
	if t.HasFlag(TCPFlagRST) {
		parts = append(parts, "RST")
	}
	if t.HasFlag(TCPFlagURG) {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return "NONE"
	}
	return strings.Join(parts, ",")
}

// DecodeTCP decodes a TCP segment header in zero-copy mode.
func DecodeTCP(data []byte, out *TCPHeader) error {
	if len(data) < 20 {
		return ErrPacketTooShort
	}

	dataOffset := (data[12] >> 4) * 4
	if dataOffset < 20 || len(data) < int(dataOffset) {
		return ErrInvalidHeaderLen
	}

	out.SrcPort = binary.BigEndian.Uint16(data[0:2])
	out.DstPort = binary.BigEndian.Uint16(data[2:4])
	out.Seq = binary.BigEndian.Uint32(data[4:8])
	out.Ack = binary.BigEndian.Uint32(data[8:12])
	out.DataOffset = dataOffset
	out.Flags = data[13]
	out.Window = binary.BigEndian.Uint16(data[14:16])
	out.Checksum = binary.BigEndian.Uint16(data[16:18])
	out.Urgent = binary.BigEndian.Uint16(data[18:20])

	if dataOffset > 20 {
		out.Options = data[20:dataOffset]
	} else {
		out.Options = nil
	}

	out.Payload = data[dataOffset:]
	return nil
}
