package l7

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	tlsRecordTypeHandshake = 22
	tlsHandshakeClientHello = 1
	tlsHandshakeServerHello = 2

	tlsExtServerName = 0x0000
	tlsExtALPN       = 0x0010
)

// TLSClientHello holds metadata extracted from a TLS ClientHello handshake record.
type TLSClientHello struct {
	RecordVersion    uint16
	HandshakeVersion uint16
	ServerName       string // SNI (Server Name Indication)
	ALPNProtocols    []string
	CipherSuites     []uint16
}

var (
	ErrNotTLSClientHello = errors.New("l7/tls: not a TLS ClientHello record")
	ErrTLSTruncated      = errors.New("l7/tls: truncated TLS ClientHello record")
)

// VersionString formats a TLS version uint16 (e.g. 0x0303 -> "TLS 1.2").
func TLSVersionString(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// Summary returns a single-line human-readable summary of the TLS ClientHello.
func (ch *TLSClientHello) Summary() string {
	sni := ch.ServerName
	if sni == "" {
		sni = "<none>"
	}
	alpn := "-"
	if len(ch.ALPNProtocols) > 0 {
		alpn = strings.Join(ch.ALPNProtocols, ",")
	}
	return fmt.Sprintf("TLS ClientHello ver=%s SNI=%s ALPN=%s ciphers=%d",
		TLSVersionString(ch.HandshakeVersion), sni, alpn, len(ch.CipherSuites))
}

// ParseTLSClientHello parses a TLS Record containing a ClientHello handshake message
// and extracts SNI (Server Name Indication), ALPN, and CipherSuites.
func ParseTLSClientHello(data []byte) (*TLSClientHello, error) {
	// TLS Record header is 5 bytes: ContentType(1), Version(2), Length(2)
	if len(data) < 9 {
		return nil, ErrNotTLSClientHello
	}
	if data[0] != tlsRecordTypeHandshake {
		return nil, ErrNotTLSClientHello
	}

	recVer := binary.BigEndian.Uint16(data[1:3])
	if recVer < 0x0300 || recVer > 0x0304 {
		return nil, ErrNotTLSClientHello
	}

	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	hs := data[5:]
	if len(hs) > recLen {
		hs = hs[:recLen]
	}

	// Handshake header: HandshakeType(1), Length(3 bytes)
	if len(hs) < 4 || hs[0] != tlsHandshakeClientHello {
		return nil, ErrNotTLSClientHello
	}
	hsLen := (int(hs[1]) << 16) | (int(hs[2]) << 8) | int(hs[3])
	body := hs[4:]
	if len(body) < hsLen {
		return nil, ErrTLSTruncated
	}
	body = body[:hsLen]

	// ClientVersion(2) + Random(32) = 34 bytes
	if len(body) < 35 {
		return nil, ErrTLSTruncated
	}
	hsVer := binary.BigEndian.Uint16(body[0:2])
	offset := 34

	// SessionID
	sessIDLen := int(body[offset])
	offset++
	if offset+sessIDLen+2 > len(body) {
		return nil, ErrTLSTruncated
	}
	offset += sessIDLen

	// CipherSuites
	csLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if csLen%2 != 0 || offset+csLen+1 > len(body) {
		return nil, ErrTLSTruncated
	}
	ciphers := make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(body[offset+i:offset+i+2]))
	}
	offset += csLen

	// CompressionMethods
	compLen := int(body[offset])
	offset++
	if offset+compLen > len(body) {
		return nil, ErrTLSTruncated
	}
	offset += compLen

	ch := &TLSClientHello{
		RecordVersion:    recVer,
		HandshakeVersion: hsVer,
		CipherSuites:     ciphers,
	}

	// Optional Extensions
	if offset+2 > len(body) {
		return ch, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extTotalLen > len(body) {
		extTotalLen = len(body) - offset
	}
	extEnd := offset + extTotalLen

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extEnd {
			break
		}
		extData := body[offset : offset+extLen]
		offset += extLen

		switch extType {
		case tlsExtServerName:
			if sni := parseSNIExtension(extData); sni != "" {
				ch.ServerName = sni
			}
		case tlsExtALPN:
			ch.ALPNProtocols = parseALPNExtension(extData)
		}
	}

	return ch, nil
}

func parseSNIExtension(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	off := 2
	if off+listLen > len(ext) {
		return ""
	}
	end := off + listLen
	for off+3 <= end {
		nameType := ext[off]
		nameLen := int(binary.BigEndian.Uint16(ext[off+1 : off+3]))
		off += 3
		if off+nameLen > end {
			break
		}
		if nameType == 0 { // host_name
			return string(ext[off : off+nameLen])
		}
		off += nameLen
	}
	return ""
}

func parseALPNExtension(ext []byte) []string {
	if len(ext) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	off := 2
	if off+listLen > len(ext) {
		return nil
	}
	end := off + listLen
	var protos []string
	for off < end {
		pLen := int(ext[off])
		off++
		if pLen == 0 || off+pLen > end {
			break
		}
		protos = append(protos, string(ext[off:off+pLen]))
		off += pLen
	}
	return protos
}
