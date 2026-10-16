package filter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gopcap/gopcap/pkg/l7"
	"github.com/gopcap/gopcap/pkg/layers"
)

// Classic BPF instruction classes and opcodes (RFC / BSD bpf.h).
const (
	BpfLd   uint16 = 0x00
	BpfLdx  uint16 = 0x01
	BpfSt   uint16 = 0x02
	BpfStx  uint16 = 0x03
	BpfAlu  uint16 = 0x04
	BpfJmp  uint16 = 0x05
	BpfRet  uint16 = 0x06
	BpfMisc uint16 = 0x07

	// Load sizes & modes
	BpfW   uint16 = 0x00 // 32-bit word
	BpfH   uint16 = 0x08 // 16-bit half-word
	BpfB   uint16 = 0x10 // 8-bit byte
	BpfImm uint16 = 0x00
	BpfAbs uint16 = 0x20
	BpfInd uint16 = 0x40
	BpfMem uint16 = 0x60
	BpfLen uint16 = 0x80
	BpfMsh uint16 = 0xa0

	// Jump conditions
	BpfJa   uint16 = 0x00
	BpfJeq  uint16 = 0x10
	BpfJgt  uint16 = 0x20
	BpfJge  uint16 = 0x30
	BpfJset uint16 = 0x40

	// Source operand
	BpfK uint16 = 0x00
	BpfX uint16 = 0x08
	BpfA uint16 = 0x10

	// ALU operations
	BpfAdd uint16 = 0x00
	BpfSub uint16 = 0x10
	BpfMul uint16 = 0x20
	BpfDiv uint16 = 0x30
	BpfOr  uint16 = 0x40
	BpfAnd uint16 = 0x50
	BpfLsh uint16 = 0x60
	BpfRsh uint16 = 0x70
)

// BPFInstruction represents a single classic BPF instruction (sock_filter / bpf_insn).
type BPFInstruction struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// BPFVM executes classic BPF bytecode programs in pure Go against raw packet bytes.
type BPFVM struct {
	Program []BPFInstruction
}

// NewBPFVM creates a pure-Go BPF virtual machine for the given instruction list.
func NewBPFVM(prog []BPFInstruction) *BPFVM {
	return &BPFVM{Program: prog}
}

// Match executes the BPF program on raw packet bytes. Returns true if the return value > 0.
func (vm *BPFVM) Match(pkt []byte) bool {
	if len(vm.Program) == 0 {
		return true
	}

	var a, x uint32
	var scratch [16]uint32

	for pc := 0; pc < len(vm.Program); pc++ {
		ins := vm.Program[pc]
		switch ins.Code {
		case BpfLd | BpfW | BpfAbs:
			off := int(ins.K)
			if off < 0 || off+4 > len(pkt) {
				return false
			}
			a = binary.BigEndian.Uint32(pkt[off : off+4])

		case BpfLd | BpfH | BpfAbs:
			off := int(ins.K)
			if off < 0 || off+2 > len(pkt) {
				return false
			}
			a = uint32(binary.BigEndian.Uint16(pkt[off : off+2]))

		case BpfLd | BpfB | BpfAbs:
			off := int(ins.K)
			if off < 0 || off+1 > len(pkt) {
				return false
			}
			a = uint32(pkt[off])

		case BpfLd | BpfW | BpfInd:
			off := int(x + ins.K)
			if off < 0 || off+4 > len(pkt) {
				return false
			}
			a = binary.BigEndian.Uint32(pkt[off : off+4])

		case BpfLd | BpfH | BpfInd:
			off := int(x + ins.K)
			if off < 0 || off+2 > len(pkt) {
				return false
			}
			a = uint32(binary.BigEndian.Uint16(pkt[off : off+2]))

		case BpfLd | BpfB | BpfInd:
			off := int(x + ins.K)
			if off < 0 || off+1 > len(pkt) {
				return false
			}
			a = uint32(pkt[off])

		case BpfLd | BpfW | BpfLen:
			a = uint32(len(pkt))

		case BpfLd | BpfImm:
			a = ins.K

		case BpfLdx | BpfImm:
			x = ins.K

		case BpfLdx | BpfB | BpfMsh:
			off := int(ins.K)
			if off < 0 || off+1 > len(pkt) {
				return false
			}
			x = uint32(pkt[off]&0x0F) * 4

		case BpfLd | BpfMem:
			if ins.K < 16 {
				a = scratch[ins.K]
			}

		case BpfLdx | BpfMem:
			if ins.K < 16 {
				x = scratch[ins.K]
			}

		case BpfSt:
			if ins.K < 16 {
				scratch[ins.K] = a
			}

		case BpfStx:
			if ins.K < 16 {
				scratch[ins.K] = x
			}

		case BpfJmp | BpfJa:
			pc += int(ins.K)

		case BpfJmp | BpfJeq | BpfK:
			if a == ins.K {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}

		case BpfJmp | BpfJgt | BpfK:
			if a > ins.K {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}

		case BpfJmp | BpfJge | BpfK:
			if a >= ins.K {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}

		case BpfJmp | BpfJset | BpfK:
			if (a & ins.K) != 0 {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}

		case BpfAlu | BpfAdd | BpfK:
			a += ins.K
		case BpfAlu | BpfSub | BpfK:
			a -= ins.K
		case BpfAlu | BpfAnd | BpfK:
			a &= ins.K
		case BpfAlu | BpfOr | BpfK:
			a |= ins.K
		case BpfAlu | BpfLsh | BpfK:
			a <<= ins.K
		case BpfAlu | BpfRsh | BpfK:
			a >>= ins.K

		case BpfRet | BpfK:
			return ins.K > 0
		case BpfRet | BpfA:
			return a > 0
		}
	}
	return false
}

// PacketFilter evaluates decoded packets against a compiled tcpdump-like filter expression.
type PacketFilter struct {
	expr       string
	predicates []func(*layers.DecodedPacket) bool
}

// Compile parses a human-readable filter expression (similar to tcpdump syntax)
// into a fast predicate chain over layers.DecodedPacket.
//
// Supported primitives (combinable with "and" / "&&"):
//   - L2/L3/L4 Protocol: "tcp", "udp", "icmp", "icmp6", "ip", "ip6", "arp"
//   - L7 Protocol:       "http", "tls", "https", "ssl", "dns"
//   - Payload Contains:  "tcp contains \"keyword\"", "udp contains \"keyword\"", "http contains \"keyword\"", "contains \"keyword\""
//   - Host/IP:           "host 1.2.3.4", "src host 10.0.0.1", "dst host 10.0.0.2"
//   - Port:              "port 80", "src port 443", "dst port 53"
func Compile(expr string) (*PacketFilter, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return &PacketFilter{expr: ""}, nil
	}

	tokens, err := tokenizeExpr(trimmed)
	if err != nil {
		return nil, err
	}
	clauses := splitTokenClauses(tokens)
	preds := make([]func(*layers.DecodedPacket) bool, 0, len(clauses))

	for _, clause := range clauses {
		pred, err := parseClause(clause)
		if err != nil {
			return nil, err
		}
		preds = append(preds, pred)
	}

	return &PacketFilter{
		expr:       trimmed,
		predicates: preds,
	}, nil
}

// tokenizeExpr splits a filter expression into tokens while preserving quoted strings
// (e.g., `tcp contains "GET /index"` -> ["tcp", "contains", "GET /index"]).
func tokenizeExpr(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	var quote byte

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
				continue
			}
			if ch == quote {
				tokens = append(tokens, cur.String())
				cur.Reset()
				quote = 0
				continue
			}
			cur.WriteByte(ch)
			continue
		}

		if ch == '"' || ch == '\'' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			quote = ch
			continue
		}

		if ch == '&' && i+1 < len(s) && s[i+1] == '&' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			tokens = append(tokens, "and")
			i++
			continue
		}

		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}

		cur.WriteByte(ch)
	}

	if quote != 0 {
		return nil, fmt.Errorf("filter: unterminated quoted string in %q", s)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}

func splitTokenClauses(tokens []string) [][]string {
	var clauses [][]string
	var cur []string
	for _, tok := range tokens {
		if strings.EqualFold(tok, "and") {
			if len(cur) > 0 {
				clauses = append(clauses, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, tok)
	}
	if len(cur) > 0 {
		clauses = append(clauses, cur)
	}
	return clauses
}

func parseClause(tokens []string) (func(*layers.DecodedPacket) bool, error) {
	if len(tokens) == 0 {
		return func(*layers.DecodedPacket) bool { return true }, nil
	}

	first := strings.ToLower(tokens[0])
	switch len(tokens) {
	case 1:
		switch first {
		case "tcp":
			return func(p *layers.DecodedPacket) bool { return p.HasTCP }, nil
		case "udp":
			return func(p *layers.DecodedPacket) bool { return p.HasUDP }, nil
		case "icmp":
			return func(p *layers.DecodedPacket) bool { return p.HasICMP && p.HasIPv4 }, nil
		case "icmp6", "icmpv6":
			return func(p *layers.DecodedPacket) bool { return p.HasICMP && p.HasIPv6 }, nil
		case "ip", "ipv4":
			return func(p *layers.DecodedPacket) bool { return p.HasIPv4 }, nil
		case "ip6", "ipv6":
			return func(p *layers.DecodedPacket) bool { return p.HasIPv6 }, nil
		case "arp":
			return func(p *layers.DecodedPacket) bool {
				return p.HasEthernet && p.Ethernet.EtherType == layers.EtherTypeARP
			}, nil
		case "http":
			return func(p *layers.DecodedPacket) bool {
				return p.HasTCP && l7.IsLikelyHTTP(p.Payload)
			}, nil
		case "tls", "ssl", "https":
			return func(p *layers.DecodedPacket) bool {
				if !p.HasTCP || len(p.Payload) < 5 {
					return false
				}
				_, err := l7.ParseTLSClientHello(p.Payload)
				return err == nil
			}, nil
		case "dns":
			return func(p *layers.DecodedPacket) bool {
				if !p.HasUDP && !p.HasTCP {
					return false
				}
				if p.SrcPort() != 53 && p.DstPort() != 53 && p.SrcPort() != 5353 && p.DstPort() != 5353 {
					return false
				}
				_, err := l7.ParseDNS(p.Payload)
				return err == nil
			}, nil
		default:
			return nil, fmt.Errorf("filter: unknown protocol primitive %q", tokens[0])
		}

	case 2:
		switch first {
		case "host":
			addr, err := netip.ParseAddr(tokens[1])
			if err != nil {
				return nil, fmt.Errorf("filter: invalid IP address %q: %w", tokens[1], err)
			}
			return func(p *layers.DecodedPacket) bool {
				return p.SrcIP() == addr || p.DstIP() == addr
			}, nil

		case "port":
			port, err := parsePort(tokens[1])
			if err != nil {
				return nil, err
			}
			return func(p *layers.DecodedPacket) bool {
				return p.SrcPort() == port || p.DstPort() == port
			}, nil

		case "src":
			addr, err := netip.ParseAddr(tokens[1])
			if err != nil {
				return nil, fmt.Errorf("filter: invalid src IP %q: %w", tokens[1], err)
			}
			return func(p *layers.DecodedPacket) bool {
				return p.SrcIP() == addr
			}, nil

		case "dst":
			addr, err := netip.ParseAddr(tokens[1])
			if err != nil {
				return nil, fmt.Errorf("filter: invalid dst IP %q: %w", tokens[1], err)
			}
			return func(p *layers.DecodedPacket) bool {
				return p.DstIP() == addr
			}, nil

		case "contains":
			needle := []byte(tokens[1])
			return func(p *layers.DecodedPacket) bool {
				return len(p.Payload) > 0 && bytes.Contains(p.Payload, needle)
			}, nil
		}

	case 3:
		dir := first
		kind := strings.ToLower(tokens[1])
		val := tokens[2]

		if kind == "contains" {
			needle := []byte(val)
			switch dir {
			case "tcp":
				return func(p *layers.DecodedPacket) bool {
					return p.HasTCP && bytes.Contains(p.Payload, needle)
				}, nil
			case "udp":
				return func(p *layers.DecodedPacket) bool {
					return p.HasUDP && bytes.Contains(p.Payload, needle)
				}, nil
			case "http":
				return func(p *layers.DecodedPacket) bool {
					return p.HasTCP && l7.IsLikelyHTTP(p.Payload) && bytes.Contains(p.Payload, needle)
				}, nil
			case "icmp":
				return func(p *layers.DecodedPacket) bool {
					return p.HasICMP && bytes.Contains(p.Payload, needle)
				}, nil
			default:
				return nil, fmt.Errorf("filter: unsupported protocol %q for contains", tokens[0])
			}
		}

		if (dir == "src" || dir == "dst") && kind == "host" {
			addr, err := netip.ParseAddr(val)
			if err != nil {
				return nil, fmt.Errorf("filter: invalid IP address %q: %w", val, err)
			}
			if dir == "src" {
				return func(p *layers.DecodedPacket) bool { return p.SrcIP() == addr }, nil
			}
			return func(p *layers.DecodedPacket) bool { return p.DstIP() == addr }, nil
		}

		if (dir == "src" || dir == "dst") && kind == "port" {
			port, err := parsePort(val)
			if err != nil {
				return nil, err
			}
			if dir == "src" {
				return func(p *layers.DecodedPacket) bool { return p.SrcPort() == port }, nil
			}
			return func(p *layers.DecodedPacket) bool { return p.DstPort() == port }, nil
		}
	}

	return nil, fmt.Errorf("filter: unsupported expression clause %q", strings.Join(tokens, " "))
}

func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("filter: invalid port number %q", s)
	}
	return uint16(v), nil
}

// Match returns true if the decoded packet satisfies all predicates in the filter.
func (f *PacketFilter) Match(p *layers.DecodedPacket) bool {
	if f == nil || len(f.predicates) == 0 {
		return true
	}
	for _, pred := range f.predicates {
		if !pred(p) {
			return false
		}
	}
	return true
}
