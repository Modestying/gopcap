package capture

import (
	"encoding/binary"
	"io"
	"os"
)

// PcapWriter writes captured packets in standard .pcap format (microsecond resolution, Little-Endian).
type PcapWriter struct {
	w        io.Writer
	closer   io.Closer
	snapLen  uint32
	linkType LinkType
	recBuf   [pcapRecordHeaderLen]byte
}

// CreatePcapFile creates a new .pcap file on disk and writes the global header.
func CreatePcapFile(path string, linkType LinkType, snapLen uint32) (*PcapWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	pw, err := NewPcapWriter(f, linkType, snapLen)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	pw.closer = f
	return pw, nil
}

// NewPcapWriter initializes a PcapWriter on w and immediately writes the 24-byte PCAP global header.
func NewPcapWriter(w io.Writer, linkType LinkType, snapLen uint32) (*PcapWriter, error) {
	if snapLen == 0 {
		snapLen = 65535
	}
	var hdr [pcapGlobalHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagicMicrosecLE)
	binary.LittleEndian.PutUint16(hdr[4:6], 2) // Major version 2
	binary.LittleEndian.PutUint16(hdr[6:8], 4) // Minor version 4
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))

	if _, err := w.Write(hdr[:]); err != nil {
		return nil, err
	}

	return &PcapWriter{
		w:        w,
		snapLen:  snapLen,
		linkType: linkType,
	}, nil
}

// WritePacket writes a single RawPacket into the PCAP stream.
func (pw *PcapWriter) WritePacket(pkt RawPacket) error {
	ts := pkt.Info.Timestamp
	var sec, usec uint32
	if !ts.IsZero() {
		sec = uint32(ts.Unix())
		usec = uint32(ts.Nanosecond() / 1000)
	}

	capLen := uint32(len(pkt.Data))
	origLen := uint32(pkt.Info.Length)
	if origLen < capLen {
		origLen = capLen
	}

	binary.LittleEndian.PutUint32(pw.recBuf[0:4], sec)
	binary.LittleEndian.PutUint32(pw.recBuf[4:8], usec)
	binary.LittleEndian.PutUint32(pw.recBuf[8:12], capLen)
	binary.LittleEndian.PutUint32(pw.recBuf[12:16], origLen)

	if _, err := pw.w.Write(pw.recBuf[:]); err != nil {
		return err
	}
	_, err := pw.w.Write(pkt.Data)
	return err
}

// Close closes the underlying file if created via CreatePcapFile.
func (pw *PcapWriter) Close() error {
	if pw.closer != nil {
		return pw.closer.Close()
	}
	return nil
}
