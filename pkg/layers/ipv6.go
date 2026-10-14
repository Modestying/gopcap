package layers

import (
	"encoding/binary"
	"net/netip"
)

// IPv6Header represents an IPv6 packet header (RFC 8200).
type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   IPProtocol
	HopLimit     uint8
	SrcIP        netip.Addr
	DstIP        netip.Addr
	Payload      []byte
}

// DecodeIPv6 decodes an IPv6 header and skips standard IPv6 extension headers in zero-copy mode.
func DecodeIPv6(data []byte, out *IPv6Header) error {
	if len(data) < 40 {
		return ErrPacketTooShort
	}

	vtcfl := binary.BigEndian.Uint32(data[0:4])
	version := uint8(vtcfl >> 28)
	if version != 6 {
		return ErrInvalidIPVersion
	}

	out.Version = version
	out.TrafficClass = uint8((vtcfl >> 20) & 0xFF)
	out.FlowLabel = vtcfl & 0xFFFFF
	out.PayloadLen = binary.BigEndian.Uint16(data[4:6])
	nextHdr := IPProtocol(data[6])
	out.HopLimit = data[7]

	var src, dst [16]byte
	copy(src[:], data[8:24])
	copy(dst[:], data[24:40])
	out.SrcIP = netip.AddrFrom16(src)
	out.DstIP = netip.AddrFrom16(dst)

	end := len(data)
	if int(40+out.PayloadLen) < end {
		end = int(40 + out.PayloadLen)
	}
	payload := data[40:end]

	// Skip common IPv6 extension headers (Hop-by-Hop=0, Routing=43, Fragment=44, DestOptions=60)
	for {
		switch nextHdr {
		case 0, 43, 60:
			if len(payload) < 2 {
				return ErrPacketTooShort
			}
			extLen := int(payload[1]+1) * 8
			if len(payload) < extLen {
				return ErrPacketTooShort
			}
			nextHdr = IPProtocol(payload[0])
			payload = payload[extLen:]
		case 44: // Fragment header is fixed 8 bytes
			if len(payload) < 8 {
				return ErrPacketTooShort
			}
			nextHdr = IPProtocol(payload[0])
			payload = payload[8:]
		default:
			out.NextHeader = nextHdr
			out.Payload = payload
			return nil
		}
	}
}
