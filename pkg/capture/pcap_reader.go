package capture

import (
	"encoding/binary"
	"io"
	"os"
	"time"
)

const (
	pcapMagicMicrosecLE = 0xa1b2c3d4
	pcapMagicMicrosecBE = 0xd4c3b2a1
	pcapMagicNanosecLE  = 0xa1b23c4d
	pcapMagicNanosecBE  = 0x4d3cb2a1

	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16
)

// PcapFileHeader represents the 24-byte global header of a standard .pcap file.
type PcapFileHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	LinkType     LinkType
}

// PcapReader reads packets from a standard .pcap file or stream in pure Go.
type PcapReader struct {
	r          io.Reader
	closer     io.Closer
	byteOrder  binary.ByteOrder
	nanoSecond bool
	header     PcapFileHeader
	recBuf     [pcapRecordHeaderLen]byte
}

// OpenPcapFile opens a .pcap file from disk for reading.
func OpenPcapFile(path string) (*PcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pr, err := NewPcapReader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	pr.closer = f
	return pr, nil
}

// NewPcapReader creates a PcapReader from any io.Reader.
func NewPcapReader(r io.Reader) (*PcapReader, error) {
	var rawHdr [pcapGlobalHeaderLen]byte
	if _, err := io.ReadFull(r, rawHdr[:]); err != nil {
		return nil, err
	}

	magicLE := binary.LittleEndian.Uint32(rawHdr[0:4])
	pr := &PcapReader{r: r}

	switch magicLE {
	case pcapMagicMicrosecLE:
		pr.byteOrder = binary.LittleEndian
		pr.nanoSecond = false
	case pcapMagicNanosecLE:
		pr.byteOrder = binary.LittleEndian
		pr.nanoSecond = true
	case pcapMagicMicrosecBE:
		pr.byteOrder = binary.BigEndian
		pr.nanoSecond = false
	case pcapMagicNanosecBE:
		pr.byteOrder = binary.BigEndian
		pr.nanoSecond = true
	default:
		return nil, ErrInvalidPcapMagic
	}

	bo := pr.byteOrder
	pr.header = PcapFileHeader{
		MagicNumber:  bo.Uint32(rawHdr[0:4]),
		VersionMajor: bo.Uint16(rawHdr[4:6]),
		VersionMinor: bo.Uint16(rawHdr[6:8]),
		ThisZone:     int32(bo.Uint32(rawHdr[8:12])),
		SigFigs:      bo.Uint32(rawHdr[12:16]),
		SnapLen:      bo.Uint32(rawHdr[16:20]),
		LinkType:     LinkType(bo.Uint32(rawHdr[20:24])),
	}

	return pr, nil
}

// Header returns the parsed PCAP file header.
func (pr *PcapReader) Header() PcapFileHeader {
	return pr.header
}

// LinkType returns the LinkType of the PCAP stream.
func (pr *PcapReader) LinkType() LinkType {
	return pr.header.LinkType
}

// NextPacket reads the next packet record from the PCAP stream.
func (pr *PcapReader) NextPacket() (RawPacket, error) {
	if _, err := io.ReadFull(pr.r, pr.recBuf[:]); err != nil {
		return RawPacket{}, err
	}

	bo := pr.byteOrder
	tsSec := bo.Uint32(pr.recBuf[0:4])
	tsSubSec := bo.Uint32(pr.recBuf[4:8])
	capLen := bo.Uint32(pr.recBuf[8:12])
	origLen := bo.Uint32(pr.recBuf[12:16])

	// Guard against corrupted huge capLen
	maxAllowed := pr.header.SnapLen
	if maxAllowed < 262144 {
		maxAllowed = 262144
	}
	if capLen > maxAllowed {
		return RawPacket{}, ErrTruncatedPacket
	}

	data := make([]byte, capLen)
	if _, err := io.ReadFull(pr.r, data); err != nil {
		if err == io.EOF {
			return RawPacket{}, ErrTruncatedPacket
		}
		return RawPacket{}, err
	}

	var nsec int64
	if pr.nanoSecond {
		nsec = int64(tsSubSec)
	} else {
		nsec = int64(tsSubSec) * 1000
	}

	return RawPacket{
		Info: CaptureInfo{
			Timestamp:     time.Unix(int64(tsSec), nsec),
			CaptureLength: int(capLen),
			Length:        int(origLen),
		},
		LinkType: pr.header.LinkType,
		Data:     data,
	}, nil
}

// Close closes the underlying file if opened via OpenPcapFile.
func (pr *PcapReader) Close() error {
	if pr.closer != nil {
		return pr.closer.Close()
	}
	return nil
}
