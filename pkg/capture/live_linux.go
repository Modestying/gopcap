//go:build linux

package capture

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	solPacket            = 263
	packetAddMembership  = 1
	packetMrPromisc      = 1
	ethPAll              = 0x0003
)

type packetMreq struct {
	Ifindex int32
	Type    uint16
	Alen    uint16
	Address [8]byte
}

// linuxLiveCapture implements PacketSource on Linux using AF_PACKET raw sockets in pure Go (zero CGO).
type linuxLiveCapture struct {
	fd       int
	iface    string
	snapLen  int
	linkType LinkType
	buf      []byte
	closed   bool
	mu       sync.Mutex
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// OpenLive opens a live packet capture on Linux using AF_PACKET, SOCK_RAW.
func OpenLive(cfg LiveConfig) (PacketSource, error) {
	if cfg.Device == "" {
		cfg.Device = "eth0"
	}
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 65535
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}

	iface, err := net.InterfaceByName(cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("capture: interface %s not found: %w", cfg.Device, err)
	}

	proto := int(htons(ethPAll))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("capture: failed to open AF_PACKET socket (check CAP_NET_RAW or sudo): %w", err)
	}

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("capture: failed to bind interface %s: %w", cfg.Device, err)
	}

	if cfg.Promiscuous {
		mreq := packetMreq{
			Ifindex: int32(iface.Index),
			Type:    packetMrPromisc,
		}
		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			uintptr(solPacket),
			uintptr(packetAddMembership),
			uintptr(unsafe.Pointer(&mreq)),
			unsafe.Sizeof(mreq),
			0,
		)
		_ = errno
	}

	tv := syscall.NsecToTimeval(cfg.Timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	return &linuxLiveCapture{
		fd:       fd,
		iface:    cfg.Device,
		snapLen:  cfg.SnapLen,
		linkType: LinkTypeEthernet,
		buf:      make([]byte, cfg.SnapLen),
	}, nil
}

func (c *linuxLiveCapture) LinkType() LinkType {
	return c.linkType
}

func (c *linuxLiveCapture) NextPacket() (RawPacket, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return RawPacket{}, ErrCaptureClosed
		}
		fd := c.fd
		buf := c.buf
		c.mu.Unlock()

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return RawPacket{}, err
		}
		if n <= 0 {
			continue
		}

		capLen := n
		if capLen > c.snapLen {
			capLen = c.snapLen
		}
		pktBytes := make([]byte, capLen)
		copy(pktBytes, buf[:capLen])

		return RawPacket{
			Info: CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: capLen,
				Length:        n,
				InterfaceName: c.iface,
			},
			LinkType: c.linkType,
			Data:     pktBytes,
		}, nil
	}
}

func (c *linuxLiveCapture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return syscall.Close(c.fd)
}
