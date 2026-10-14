package capture

import (
	"errors"
	"net"
	"time"
)

// LinkType defines the data link layer type (matching libpcap DLT_* / LINKTYPE_* values).
type LinkType uint32

const (
	LinkTypeNull       LinkType = 0   // BSD loopback encapsulation (macOS lo0)
	LinkTypeEthernet   LinkType = 1   // IEEE 802.3 Ethernet
	LinkTypeRaw        LinkType = 101 // Raw IP (IPv4 or IPv6)
	LinkTypeLoop       LinkType = 108 // OpenBSD loopback
	LinkTypeLinuxSLL   LinkType = 113 // Linux cooked capture
)

func (lt LinkType) String() string {
	switch lt {
	case LinkTypeNull:
		return "BSD_LOOPBACK"
	case LinkTypeEthernet:
		return "ETHERNET"
	case LinkTypeRaw:
		return "RAW_IP"
	case LinkTypeLoop:
		return "OPENBSD_LOOP"
	case LinkTypeLinuxSLL:
		return "LINUX_SLL"
	default:
		return "UNKNOWN"
	}
}

// CaptureInfo holds metadata about a captured packet.
type CaptureInfo struct {
	Timestamp     time.Time
	CaptureLength int
	Length        int
	InterfaceName string
}

// RawPacket represents a raw packet captured from an interface or PCAP file.
type RawPacket struct {
	Info     CaptureInfo
	LinkType LinkType
	Data     []byte
}

// PacketSource is a unified interface for reading raw packets from either
// a live network interface or an offline PCAP file.
type PacketSource interface {
	// NextPacket reads the next available packet. Returns io.EOF when complete.
	NextPacket() (RawPacket, error)
	// LinkType returns the underlying data link type.
	LinkType() LinkType
	// Close releases underlying file descriptors or handles.
	Close() error
}

// LiveConfig configures live network interface capture.
type LiveConfig struct {
	Device      string        // Interface name, e.g., "en0", "eth0", "lo0"
	SnapLen     int           // Maximum bytes to capture per packet (default 65535)
	Promiscuous bool          // Put interface into promiscuous mode
	Timeout     time.Duration // Read buffer timeout
}

// InterfaceInfo describes a network interface available for packet capture.
type InterfaceInfo struct {
	Name         string
	Index        int
	MTU          int
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	Addrs        []net.Addr
}

// ListInterfaces returns all network interfaces on the host using pure Go.
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]InterfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		result = append(result, InterfaceInfo{
			Name:         iface.Name,
			Index:        iface.Index,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr,
			Flags:        iface.Flags,
			Addrs:        addrs,
		})
	}
	return result, nil
}

var (
	ErrInvalidPcapMagic  = errors.New("capture: invalid pcap magic number")
	ErrTruncatedPacket   = errors.New("capture: truncated packet record")
	ErrNoBPFDevice       = errors.New("capture: no available /dev/bpf* device (check permissions or sudo)")
	ErrUnsupportedOS     = errors.New("capture: live capture not supported on this OS")
	ErrCaptureClosed     = errors.New("capture: packet source is closed")
)
