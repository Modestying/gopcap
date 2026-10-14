package stream

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/gopcap/gopcap/pkg/layers"
)

// Direction indicates the direction of traffic within a bidirectional TCP connection.
type Direction uint8

const (
	DirClientToServer Direction = iota
	DirServerToClient
)

func (d Direction) String() string {
	if d == DirClientToServer {
		return "C->S"
	}
	return "S->C"
}

// Endpoint represents a single (IP, Port) pair.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

func (e Endpoint) String() string {
	if e.IP.Is6() {
		return fmt.Sprintf("[%s]:%d", e.IP.String(), e.Port)
	}
	return fmt.Sprintf("%s:%d", e.IP.String(), e.Port)
}

// FlowKey uniquely identifies a bidirectional TCP connection in canonical order.
type FlowKey struct {
	Low  Endpoint
	High Endpoint
}

// MakeFlowKey constructs a canonical bidirectional FlowKey and reports whether src is Low.
func MakeFlowKey(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) (FlowKey, bool) {
	a := Endpoint{IP: srcIP, Port: srcPort}
	b := Endpoint{IP: dstIP, Port: dstPort}

	cmp := a.IP.Compare(b.IP)
	if cmp < 0 || (cmp == 0 && a.Port <= b.Port) {
		return FlowKey{Low: a, High: b}, true
	}
	return FlowKey{Low: b, High: a}, false
}

// TCPState represents the connection state of a tracked TCP session.
type TCPState uint8

const (
	StateNew TCPState = iota
	StateSynSent
	StateEstablished
	StateClosing
	StateClosed
)

type tcpSegment struct {
	seq  uint32
	data []byte
}

// HalfStream tracks sequence numbers and out-of-order segments for one direction of a TCP flow.
type HalfStream struct {
	Initialized bool
	NextSeq     uint32
	pending     []tcpSegment
	assembled   []byte
}

// StreamEvent is emitted whenever contiguous TCP payload bytes are reassembled.
type StreamEvent struct {
	Key       FlowKey
	Client    Endpoint
	Server    Endpoint
	Direction Direction
	Timestamp time.Time
	// NewBytes contains the newly reassembled contiguous chunk.
	NewBytes []byte
	// StreamBuffer contains the accumulated contiguous bytes in this direction so far.
	StreamBuffer []byte
}

// StreamCallback is invoked when new contiguous TCP bytes become available on a flow.
type StreamCallback func(event StreamEvent)

// TCPConnection represents a tracked bidirectional TCP session.
type TCPConnection struct {
	Key        FlowKey
	Client     Endpoint
	Server     Endpoint
	State      TCPState
	ClientHalf HalfStream
	ServerHalf HalfStream
	LastSeen   time.Time
}

// TCPAssembler reassembles bidirectional TCP streams from decoded packets, handling
// out-of-order delivery, retransmissions, and overlapping segments.
type TCPAssembler struct {
	conns          map[FlowKey]*TCPConnection
	maxPendingSegs int
	maxStreamBytes int
	onData         StreamCallback
}

// NewTCPAssembler creates a TCP stream reassembly engine.
func NewTCPAssembler(onData StreamCallback) *TCPAssembler {
	return &TCPAssembler{
		conns:          make(map[FlowKey]*TCPConnection),
		maxPendingSegs: 64,
		maxStreamBytes: 256 * 1024, // 256 KB per half-stream cap
		onData:         onData,
	}
}

// ProcessPacket feeds a decoded TCP packet into the reassembly state machine.
func (a *TCPAssembler) ProcessPacket(pkt *layers.DecodedPacket) {
	if !pkt.HasTCP {
		return
	}
	srcIP := pkt.SrcIP()
	dstIP := pkt.DstIP()
	if !srcIP.IsValid() || !dstIP.IsValid() {
		return
	}

	tcp := &pkt.TCP
	key, _ := MakeFlowKey(srcIP, dstIP, tcp.SrcPort, tcp.DstPort)

	conn, exists := a.conns[key]
	if !exists {
		client := Endpoint{IP: srcIP, Port: tcp.SrcPort}
		server := Endpoint{IP: dstIP, Port: tcp.DstPort}
		// If first seen packet is SYN+ACK or from a well-known server port (<1024) toward ephemeral port,
		// infer client vs server accurately.
		if tcp.HasFlag(layers.TCPFlagSYN) && tcp.HasFlag(layers.TCPFlagACK) {
			client, server = server, client
		} else if !tcp.HasFlag(layers.TCPFlagSYN) && tcp.SrcPort < 1024 && tcp.DstPort >= 1024 {
			client, server = server, client
		}
		conn = &TCPConnection{
			Key:      key,
			Client:   client,
			Server:   server,
			State:    StateNew,
			LastSeen: pkt.Timestamp,
		}
		a.conns[key] = conn
	}
	conn.LastSeen = pkt.Timestamp

	var (
		dir  Direction
		half *HalfStream
	)
	if srcIP == conn.Client.IP && tcp.SrcPort == conn.Client.Port {
		dir = DirClientToServer
		half = &conn.ClientHalf
	} else {
		dir = DirServerToClient
		half = &conn.ServerHalf
	}

	if tcp.HasFlag(layers.TCPFlagRST) {
		conn.State = StateClosed
		return
	}

	seq := tcp.Seq
	if tcp.HasFlag(layers.TCPFlagSYN) {
		if conn.State == StateNew {
			conn.State = StateSynSent
		} else {
			conn.State = StateEstablished
		}
		half.Initialized = true
		half.NextSeq = seq + 1
		seq++ // Payload (if any on SYN) starts at seq+1
	} else if !half.Initialized {
		// Mid-stream pickup
		half.Initialized = true
		half.NextSeq = seq
		conn.State = StateEstablished
	}

	payload := tcp.Payload
	if len(payload) > 0 {
		newContiguous := a.insertSegment(half, seq, payload)
		if len(newContiguous) > 0 && a.onData != nil {
			a.onData(StreamEvent{
				Key:          conn.Key,
				Client:       conn.Client,
				Server:       conn.Server,
				Direction:    dir,
				Timestamp:    pkt.Timestamp,
				NewBytes:     newContiguous,
				StreamBuffer: half.assembled,
			})
		}
	}

	if tcp.HasFlag(layers.TCPFlagFIN) {
		conn.State = StateClosing
		if seqDiff(seq+uint32(len(payload)), half.NextSeq) == 0 {
			half.NextSeq++
		}
	}
}

// seqDiff computes signed 32-bit sequence number difference (a - b) handling wrap-around (RFC 1982).
func seqDiff(a, b uint32) int32 {
	return int32(a - b)
}

func (a *TCPAssembler) insertSegment(half *HalfStream, seq uint32, data []byte) []byte {
	// Trim any prefix that has already been acknowledged/assembled (retransmission or partial overlap)
	diff := seqDiff(seq, half.NextSeq)
	if diff < 0 {
		overlap := int(-diff)
		if overlap >= len(data) {
			return nil // Full retransmission
		}
		data = data[overlap:]
		seq = half.NextSeq
		diff = 0
	}

	// Fast path: in-order segment
	if diff == 0 {
		var newlyAdded []byte
		newlyAdded = append(newlyAdded, data...)
		half.NextSeq += uint32(len(data))

		// Drain any queued out-of-order segments that are now contiguous
		for len(half.pending) > 0 {
			first := half.pending[0]
			d := seqDiff(first.seq, half.NextSeq)
			if d > 0 {
				break // Gap still exists
			}
			half.pending = half.pending[1:]
			if d < 0 {
				trim := int(-d)
				if trim >= len(first.data) {
					continue
				}
				first.data = first.data[trim:]
			}
			newlyAdded = append(newlyAdded, first.data...)
			half.NextSeq += uint32(len(first.data))
		}

		if len(half.assembled)+len(newlyAdded) <= a.maxStreamBytes {
			half.assembled = append(half.assembled, newlyAdded...)
		}
		return newlyAdded
	}

	// Out-of-order segment: buffer copy up to maxPendingSegs
	if len(half.pending) >= a.maxPendingSegs {
		return nil
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	half.pending = append(half.pending, tcpSegment{seq: seq, data: copied})
	sort.Slice(half.pending, func(i, j int) bool {
		return seqDiff(half.pending[i].seq, half.pending[j].seq) < 0
	})
	return nil
}

// ActiveConnections returns the number of currently tracked TCP connections.
func (a *TCPAssembler) ActiveConnections() int {
	return len(a.conns)
}

// FlushOlderThan removes connections that have been idle longer than maxIdle.
func (a *TCPAssembler) FlushOlderThan(now time.Time, maxIdle time.Duration) int {
	removed := 0
	for k, conn := range a.conns {
		if now.Sub(conn.LastSeen) > maxIdle {
			delete(a.conns, k)
			removed++
		}
	}
	return removed
}
