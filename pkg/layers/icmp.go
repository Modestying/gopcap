package layers

import "encoding/binary"

// ICMPHeader represents an ICMPv4 or ICMPv6 header.
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Payload  []byte
}

// DecodeICMP decodes an ICMPv4 or ICMPv6 header in zero-copy mode.
func DecodeICMP(data []byte, out *ICMPHeader) error {
	if len(data) < 8 {
		return ErrPacketTooShort
	}
	out.Type = data[0]
	out.Code = data[1]
	out.Checksum = binary.BigEndian.Uint16(data[2:4])
	out.ID = binary.BigEndian.Uint16(data[4:6])
	out.Seq = binary.BigEndian.Uint16(data[6:8])
	out.Payload = data[8:]
	return nil
}
