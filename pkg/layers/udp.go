package layers

import "encoding/binary"

// UDPHeader represents a UDP datagram header (RFC 768).
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

// DecodeUDP decodes a UDP datagram header in zero-copy mode.
func DecodeUDP(data []byte, out *UDPHeader) error {
	if len(data) < 8 {
		return ErrPacketTooShort
	}

	out.SrcPort = binary.BigEndian.Uint16(data[0:2])
	out.DstPort = binary.BigEndian.Uint16(data[2:4])
	out.Length = binary.BigEndian.Uint16(data[4:6])
	out.Checksum = binary.BigEndian.Uint16(data[6:8])

	end := len(data)
	if int(out.Length) >= 8 && int(out.Length) < end {
		end = int(out.Length)
	}
	out.Payload = data[8:end]
	return nil
}
