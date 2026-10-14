package l7

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Common DNS record types (RFC 1035 / RFC 3596).
type DNSType uint16

const (
	DNSTypeA     DNSType = 1
	DNSTypeNS    DNSType = 2
	DNSTypeCNAME DNSType = 5
	DNSTypeSOA   DNSType = 6
	DNSTypePTR   DNSType = 12
	DNSTypeMX    DNSType = 15
	DNSTypeTXT   DNSType = 16
	DNSTypeAAAA  DNSType = 28
	DNSTypeSRV   DNSType = 33
	DNSTypeHTTPS DNSType = 65
)

func (t DNSType) String() string {
	switch t {
	case DNSTypeA:
		return "A"
	case DNSTypeNS:
		return "NS"
	case DNSTypeCNAME:
		return "CNAME"
	case DNSTypeSOA:
		return "SOA"
	case DNSTypePTR:
		return "PTR"
	case DNSTypeMX:
		return "MX"
	case DNSTypeTXT:
		return "TXT"
	case DNSTypeAAAA:
		return "AAAA"
	case DNSTypeSRV:
		return "SRV"
	case DNSTypeHTTPS:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE(%d)", uint16(t))
	}
}

// DNSQuestion represents a query entry in a DNS message.
type DNSQuestion struct {
	Name  string
	Type  DNSType
	Class uint16
}

// DNSResourceRecord represents an answer, authority, or additional record in a DNS message.
type DNSResourceRecord struct {
	Name  string
	Type  DNSType
	Class uint16
	TTL   uint32
	Value string
}

// DNSMessage represents a parsed DNS query or response (RFC 1035).
type DNSMessage struct {
	ID         uint16
	IsResponse bool
	Opcode     uint8
	RCode      uint8
	Questions  []DNSQuestion
	Answers    []DNSResourceRecord
}

var (
	ErrDNSTooShort   = errors.New("l7/dns: message too short")
	ErrDNSBadName    = errors.New("l7/dns: malformed or looping domain name")
	ErrDNSTruncated  = errors.New("l7/dns: truncated resource record")
)

// Summary returns a concise one-line description of the DNS message.
func (m *DNSMessage) Summary() string {
	if !m.IsResponse {
		if len(m.Questions) > 0 {
			q := m.Questions[0]
			return fmt.Sprintf("DNS Query id=0x%04x %s %s", m.ID, q.Type, q.Name)
		}
		return fmt.Sprintf("DNS Query id=0x%04x", m.ID)
	}
	var ans []string
	for _, a := range m.Answers {
		ans = append(ans, fmt.Sprintf("%s=%s", a.Type, a.Value))
	}
	qName := ""
	if len(m.Questions) > 0 {
		qName = m.Questions[0].Name
	}
	return fmt.Sprintf("DNS Response id=0x%04x rcode=%d %s [%s]", m.ID, m.RCode, qName, strings.Join(ans, ", "))
}

// ParseDNS parses a DNS payload (typically UDP port 53 or mDNS port 5353).
func ParseDNS(data []byte) (*DNSMessage, error) {
	if len(data) < 12 {
		return nil, ErrDNSTooShort
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))

	msg := &DNSMessage{
		ID:         binary.BigEndian.Uint16(data[0:2]),
		IsResponse: (flags & 0x8000) != 0,
		Opcode:     uint8((flags >> 11) & 0x0F),
		RCode:      uint8(flags & 0x000F),
	}

	offset := 12
	for i := 0; i < qdCount && i < 64; i++ {
		name, nextOff, err := decodeDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		if nextOff+4 > len(data) {
			return nil, ErrDNSTruncated
		}
		qType := DNSType(binary.BigEndian.Uint16(data[nextOff : nextOff+2]))
		qClass := binary.BigEndian.Uint16(data[nextOff+2 : nextOff+4])
		msg.Questions = append(msg.Questions, DNSQuestion{
			Name:  name,
			Type:  qType,
			Class: qClass,
		})
		offset = nextOff + 4
	}

	for i := 0; i < anCount && i < 64; i++ {
		if offset >= len(data) {
			break
		}
		name, nextOff, err := decodeDNSName(data, offset)
		if err != nil {
			return msg, nil // Return partial if answers are truncated
		}
		if nextOff+10 > len(data) {
			return msg, nil
		}
		rType := DNSType(binary.BigEndian.Uint16(data[nextOff : nextOff+2]))
		rClass := binary.BigEndian.Uint16(data[nextOff+2 : nextOff+4])
		ttl := binary.BigEndian.Uint32(data[nextOff+4 : nextOff+8])
		rdLen := int(binary.BigEndian.Uint16(data[nextOff+8 : nextOff+10]))
		rdataStart := nextOff + 10
		if rdataStart+rdLen > len(data) {
			return msg, nil
		}

		rdata := data[rdataStart : rdataStart+rdLen]
		val := formatDNSRData(data, rdataStart, rType, rdata)

		msg.Answers = append(msg.Answers, DNSResourceRecord{
			Name:  name,
			Type:  rType,
			Class: rClass,
			TTL:   ttl,
			Value: val,
		})
		offset = rdataStart + rdLen
	}

	return msg, nil
}

func formatDNSRData(msg []byte, rdataOffset int, rType DNSType, rdata []byte) string {
	switch rType {
	case DNSTypeA:
		if len(rdata) == 4 {
			return netip.AddrFrom4([4]byte{rdata[0], rdata[1], rdata[2], rdata[3]}).String()
		}
	case DNSTypeAAAA:
		if len(rdata) == 16 {
			var b16 [16]byte
			copy(b16[:], rdata)
			return netip.AddrFrom16(b16).String()
		}
	case DNSTypeCNAME, DNSTypeNS, DNSTypePTR:
		if name, _, err := decodeDNSName(msg, rdataOffset); err == nil {
			return name
		}
	case DNSTypeMX:
		if len(rdata) >= 3 {
			if name, _, err := decodeDNSName(msg, rdataOffset+2); err == nil {
				return name
			}
		}
	case DNSTypeTXT:
		if len(rdata) > 0 {
			txtLen := int(rdata[0])
			if 1+txtLen <= len(rdata) {
				return string(rdata[1 : 1+txtLen])
			}
		}
	}
	return fmt.Sprintf("<%d bytes>", len(rdata))
}

// decodeDNSName decompresses an RFC 1035 domain name with pointer loop protection.
func decodeDNSName(msg []byte, startOffset int) (string, int, error) {
	if startOffset >= len(msg) {
		return "", 0, ErrDNSTruncated
	}

	var labels []string
	curr := startOffset
	nextOffset := -1
	jumps := 0

	for {
		if curr >= len(msg) {
			return "", 0, ErrDNSBadName
		}
		length := int(msg[curr])
		if length == 0 {
			if nextOffset == -1 {
				nextOffset = curr + 1
			}
			break
		}

		// Check for RFC 1035 compression pointer (top 2 bits == 11)
		if (length & 0xC0) == 0xC0 {
			if curr+1 >= len(msg) {
				return "", 0, ErrDNSBadName
			}
			if nextOffset == -1 {
				nextOffset = curr + 2
			}
			ptr := ((length & 0x3F) << 8) | int(msg[curr+1])
			if ptr >= len(msg) {
				return "", 0, ErrDNSBadName
			}
			curr = ptr
			jumps++
			if jumps > 32 {
				return "", 0, ErrDNSBadName
			}
			continue
		}

		if (length & 0xC0) != 0 {
			return "", 0, ErrDNSBadName
		}

		curr++
		if curr+length > len(msg) {
			return "", 0, ErrDNSBadName
		}
		labels = append(labels, string(msg[curr:curr+length]))
		curr += length
	}

	if len(labels) == 0 {
		return ".", nextOffset, nil
	}
	return strings.Join(labels, "."), nextOffset, nil
}
