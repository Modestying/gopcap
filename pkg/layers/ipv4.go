package layers

import (
	"encoding/binary"
	"net/netip"
)

// IPv4Header represents an IPv4 packet header (RFC 791).
type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	Flags          uint8
	FragOffset     uint16
	TTL            uint8
	Protocol       IPProtocol
	Checksum       uint16
	SrcIP          netip.Addr
	DstIP          netip.Addr
	Options        []byte
	Payload        []byte
}

// DecodeIPv4 decodes an IPv4 packet header in zero-copy mode.
func DecodeIPv4(data []byte, out *IPv4Header) error {
	if len(data) < 20 {
		return ErrPacketTooShort
	}

	vihl := data[0]
	version := vihl >> 4
	if version != 4 {
		return ErrInvalidIPVersion
	}

	ihl := (vihl & 0x0F) * 4
	if ihl < 20 || len(data) < int(ihl) {
		return ErrInvalidHeaderLen
	}

	totalLen := binary.BigEndian.Uint16(data[2:4])
	flagsAndFrag := binary.BigEndian.Uint16(data[6:8])

	out.Version = version
	out.IHL = ihl
	out.TOS = data[1]
	out.TotalLength = totalLen
	out.ID = binary.BigEndian.Uint16(data[4:6])
	out.Flags = uint8(flagsAndFrag >> 13)
	out.FragOffset = flagsAndFrag & 0x1FFF
	out.TTL = data[8]
	out.Protocol = IPProtocol(data[9])
	out.Checksum = binary.BigEndian.Uint16(data[10:12])
	out.SrcIP = netip.AddrFrom4([4]byte{data[12], data[13], data[14], data[15]})
	out.DstIP = netip.AddrFrom4([4]byte{data[16], data[17], data[18], data[19]})

	if ihl > 20 {
		out.Options = data[20:ihl]
	} else {
		out.Options = nil
	}

	end := len(data)
	if int(totalLen) >= int(ihl) && int(totalLen) < end {
		end = int(totalLen)
	}
	out.Payload = data[ihl:end]
	return nil
}
