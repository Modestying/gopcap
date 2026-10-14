package layers

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gopcap/gopcap/pkg/capture"
)

// EtherType represents L2 payload protocol identifiers.
type EtherType uint16

const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeVLAN EtherType = 0x8100
	EtherTypeIPv6 EtherType = 0x86DD
)

func (et EtherType) String() string {
	switch et {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeVLAN:
		return "802.1Q-VLAN"
	case EtherTypeIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("0x%04x", uint16(et))
	}
}

// IPProtocol represents L3 next-header / protocol numbers (IANA).
type IPProtocol uint8

const (
	IPProtocolICMP   IPProtocol = 1
	IPProtocolTCP    IPProtocol = 6
	IPProtocolUDP    IPProtocol = 17
	IPProtocolIPv6   IPProtocol = 41
	IPProtocolICMPv6 IPProtocol = 58
)

func (p IPProtocol) String() string {
	switch p {
	case IPProtocolICMP:
		return "ICMP"
	case IPProtocolTCP:
		return "TCP"
	case IPProtocolUDP:
		return "UDP"
	case IPProtocolICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto(%d)", uint8(p))
	}
}

var (
	ErrPacketTooShort     = errors.New("layers: packet too short for header")
	ErrUnsupportedLink    = errors.New("layers: unsupported link type")
	ErrInvalidHeaderLen   = errors.New("layers: invalid header length")
	ErrInvalidIPVersion   = errors.New("layers: invalid IP version")
)

// DecodedPacket is a reusable, zero-copy decoded representation of a network packet across L2-L4.
// It uses value fields and netip.Addr (which is allocation-free) to eliminate heap allocations during decoding.
type DecodedPacket struct {
	Timestamp time.Time
	LinkType  capture.LinkType

	HasEthernet bool
	Ethernet    EthernetHeader

	HasLoopback bool
	Loopback    LoopbackHeader

	HasIPv4 bool
	IPv4    IPv4Header

	HasIPv6 bool
	IPv6    IPv6Header

	HasTCP bool
	TCP    TCPHeader

	HasUDP bool
	UDP    UDPHeader

	HasICMP bool
	ICMP    ICMPHeader

	// Application/Transport payload slice pointing directly into the raw packet buffer (zero-copy).
	Payload []byte
}

// Reset clears all decoded state so DecodedPacket can be reused across packets without allocation.
func (p *DecodedPacket) Reset() {
	*p = DecodedPacket{}
}

// SrcIP returns the source IP address (IPv4 or IPv6), or an invalid netip.Addr if no network layer exists.
func (p *DecodedPacket) SrcIP() netip.Addr {
	if p.HasIPv4 {
		return p.IPv4.SrcIP
	}
	if p.HasIPv6 {
		return p.IPv6.SrcIP
	}
	return netip.Addr{}
}

// DstIP returns the destination IP address (IPv4 or IPv6), or an invalid netip.Addr if no network layer exists.
func (p *DecodedPacket) DstIP() netip.Addr {
	if p.HasIPv4 {
		return p.IPv4.DstIP
	}
	if p.HasIPv6 {
		return p.IPv6.DstIP
	}
	return netip.Addr{}
}

// SrcPort returns the L4 source port (TCP or UDP), or 0 if not applicable.
func (p *DecodedPacket) SrcPort() uint16 {
	if p.HasTCP {
		return p.TCP.SrcPort
	}
	if p.HasUDP {
		return p.UDP.SrcPort
	}
	return 0
}

// DstPort returns the L4 destination port (TCP or UDP), or 0 if not applicable.
func (p *DecodedPacket) DstPort() uint16 {
	if p.HasTCP {
		return p.TCP.DstPort
	}
	if p.HasUDP {
		return p.UDP.DstPort
	}
	return 0
}

// TransportProtocol returns the L4 protocol identifier.
func (p *DecodedPacket) TransportProtocol() IPProtocol {
	if p.HasIPv4 {
		return p.IPv4.Protocol
	}
	if p.HasIPv6 {
		return p.IPv6.NextHeader
	}
	return 0
}

// DecodePacket decodes a capture.RawPacket into out (zero-copy).
func DecodePacket(raw capture.RawPacket, out *DecodedPacket) error {
	out.Reset()
	out.Timestamp = raw.Info.Timestamp
	out.LinkType = raw.LinkType

	var (
		etherType EtherType
		l3Data    []byte
		err       error
	)

	switch raw.LinkType {
	case capture.LinkTypeEthernet:
		err = DecodeEthernet(raw.Data, &out.Ethernet)
		if err != nil {
			return err
		}
		out.HasEthernet = true
		etherType = out.Ethernet.EtherType
		l3Data = out.Ethernet.Payload

	case capture.LinkTypeNull, capture.LinkTypeLoop:
		err = DecodeLoopback(raw.Data, &out.Loopback)
		if err != nil {
			return err
		}
		out.HasLoopback = true
		etherType = out.Loopback.EtherType
		l3Data = out.Loopback.Payload

	case capture.LinkTypeRaw:
		if len(raw.Data) < 1 {
			return ErrPacketTooShort
		}
		version := raw.Data[0] >> 4
		if version == 4 {
			etherType = EtherTypeIPv4
		} else if version == 6 {
			etherType = EtherTypeIPv6
		} else {
			return ErrInvalidIPVersion
		}
		l3Data = raw.Data

	default:
		return ErrUnsupportedLink
	}

	var (
		nextProto IPProtocol
		l4Data    []byte
	)

	switch etherType {
	case EtherTypeIPv4:
		if err := DecodeIPv4(l3Data, &out.IPv4); err != nil {
			return err
		}
		out.HasIPv4 = true
		nextProto = out.IPv4.Protocol
		l4Data = out.IPv4.Payload

	case EtherTypeIPv6:
		if err := DecodeIPv6(l3Data, &out.IPv6); err != nil {
			return err
		}
		out.HasIPv6 = true
		nextProto = out.IPv6.NextHeader
		l4Data = out.IPv6.Payload

	default:
		out.Payload = l3Data
		return nil
	}

	switch nextProto {
	case IPProtocolTCP:
		if err := DecodeTCP(l4Data, &out.TCP); err != nil {
			return err
		}
		out.HasTCP = true
		out.Payload = out.TCP.Payload

	case IPProtocolUDP:
		if err := DecodeUDP(l4Data, &out.UDP); err != nil {
			return err
		}
		out.HasUDP = true
		out.Payload = out.UDP.Payload

	case IPProtocolICMP, IPProtocolICMPv6:
		if err := DecodeICMP(l4Data, &out.ICMP); err != nil {
			return err
		}
		out.HasICMP = true
		out.Payload = out.ICMP.Payload

	default:
		out.Payload = l4Data
	}

	return nil
}
