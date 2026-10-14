//go:build darwin

package capture

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// bpfLiveCapture implements PacketSource on macOS using /dev/bpf* devices in pure Go (zero CGO).
type bpfLiveCapture struct {
	fd       int
	iface    string
	linkType LinkType
	buf      []byte
	offset   int
	nbytes   int
	closed   bool
	mu       sync.Mutex
}

// OpenLive opens a live packet capture on macOS using Berkeley Packet Filter (/dev/bpf*).
func OpenLive(cfg LiveConfig) (PacketSource, error) {
	if cfg.Device == "" {
		cfg.Device = "en0"
	}
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 65535
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}

	fd := -1
	var openErr error
	for i := 0; i < 256; i++ {
		devPath := fmt.Sprintf("/dev/bpf%d", i)
		fd, openErr = syscall.Open(devPath, syscall.O_RDONLY, 0)
		if openErr == nil {
			break
		}
		if openErr == syscall.EBUSY {
			continue
		}
		if openErr == syscall.ENOENT {
			break
		}
	}
	if fd < 0 {
		if openErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoBPFDevice, openErr)
		}
		return nil, ErrNoBPFDevice
	}

	// Set requested buffer length before binding interface
	bufLen := cfg.SnapLen
	if bufLen < 32768 {
		bufLen = 32768
	}
	_, _ = syscall.SetBpfBuflen(fd, bufLen)

	// Bind BPF device to target network interface (BIOCSETIF)
	if err := syscall.SetBpfInterface(fd, cfg.Device); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("capture: failed to bind %s to BPF: %w", cfg.Device, err)
	}

	// Enable immediate mode so read returns as soon as packets arrive (BIOCIMMEDIATE)
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("capture: failed to set BIOCIMMEDIATE: %w", err)
	}

	// Query actual buffer length allocated by kernel (BIOCGBLEN)
	actualBufLen, err := syscall.BpfBuflen(fd)
	if err != nil || actualBufLen <= 0 {
		actualBufLen = bufLen
	}

	// Set read timeout (BIOCSRTIMEOUT)
	tv := syscall.NsecToTimeval(cfg.Timeout.Nanoseconds())
	_ = syscall.SetBpfTimeout(fd, &tv)

	// Enable promiscuous mode if requested (BIOCPROMISC)
	if cfg.Promiscuous {
		_ = syscall.SetBpfPromisc(fd, 1)
	}

	// Query data link type (BIOCGDLT)
	dlt, err := syscall.BpfDatalink(fd)
	linkType := LinkTypeEthernet
	if err == nil {
		linkType = LinkType(dlt)
	}

	return &bpfLiveCapture{
		fd:       fd,
		iface:    cfg.Device,
		linkType: linkType,
		buf:      make([]byte, actualBufLen),
	}, nil
}

func bpfWordAlign(x int) int {
	const align = syscall.SizeofBpfHdr
	// On macOS 64-bit, BPF_WORDALIGN rounds up to 4-byte boundary (sizeof(int32))
	_ = align
	return (x + 3) &^ 3
}

func (c *bpfLiveCapture) LinkType() LinkType {
	return c.linkType
}

func (c *bpfLiveCapture) NextPacket() (RawPacket, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return RawPacket{}, ErrCaptureClosed
		}

		// If current buffer still has unread BPF records, parse the next one
		if c.offset < c.nbytes {
			remaining := c.buf[c.offset:c.nbytes]
			if len(remaining) >= int(unsafe.Sizeof(syscall.BpfHdr{})) {
				hdr := (*syscall.BpfHdr)(unsafe.Pointer(&remaining[0]))
				hdrLen := int(hdr.Hdrlen)
				capLen := int(hdr.Caplen)
				dataLen := int(hdr.Datalen)

				if hdrLen > 0 && hdrLen+capLen <= len(remaining) {
					pktBytes := make([]byte, capLen)
					copy(pktBytes, remaining[hdrLen:hdrLen+capLen])

					ts := time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000)
					c.offset += bpfWordAlign(hdrLen + capLen)
					c.mu.Unlock()

					return RawPacket{
						Info: CaptureInfo{
							Timestamp:     ts,
							CaptureLength: capLen,
							Length:        dataLen,
							InterfaceName: c.iface,
						},
						LinkType: c.linkType,
						Data:     pktBytes,
					}, nil
				}
			}
			// Buffer exhausted or misaligned tail
			c.offset = 0
			c.nbytes = 0
		}

		fd := c.fd
		buf := c.buf
		c.mu.Unlock()

		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return RawPacket{}, err
		}
		if n == 0 {
			// Read timeout expired with no packets; retry loop
			continue
		}

		c.mu.Lock()
		c.offset = 0
		c.nbytes = n
		c.mu.Unlock()
	}
}

func (c *bpfLiveCapture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return syscall.Close(c.fd)
}

// Keep binary import used for endian helper consistency across platforms.
var _ = binary.LittleEndian
