package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gopcap/gopcap/pkg/capture"
	"github.com/gopcap/gopcap/pkg/filter"
	"github.com/gopcap/gopcap/pkg/l7"
	"github.com/gopcap/gopcap/pkg/layers"
	"github.com/gopcap/gopcap/pkg/stream"
)

func main() {
	var (
		listIfaces = flag.Bool("list", false, "List all available network interfaces")
		ifaceName  = flag.String("i", "en0", "Network interface for live capture (e.g. en0, lo0, eth0)")
		readFile   = flag.String("r", "", "Read packets from an offline .pcap file instead of live capture")
		writeFile  = flag.String("w", "", "Write captured/matched packets to a .pcap file")
		genDemo    = flag.String("gen-demo", "", "Generate a sample multi-protocol .pcap file (DNS, HTTP, TLS, ICMP) and exit")
		filterExpr = flag.String("f", "", "Packet filter expression (e.g. 'tcp and port 443', 'udp and port 53')")
		maxCount   = flag.Int("c", 0, "Stop after capturing N matching packets (0 = unlimited)")
		snapLen    = flag.Int("s", 65535, "SnapLen (maximum bytes per packet)")
		promisc    = flag.Bool("promisc", false, "Enable promiscuous mode on live interface")
		noColor    = flag.Bool("no-color", false, "Disable colored terminal output")
	)
	flag.Parse()

	if *noColor || os.Getenv("NO_COLOR") != "" {
		colorEnabled = false
	}

	if *listIfaces {
		printInterfaces()
		return
	}

	if *genDemo != "" {
		if err := generateDemoPcap(*genDemo); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating demo pcap: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated demo PCAP file at %s\n", *genDemo)
		return
	}

	pktFilter, err := filter.Compile(*filterExpr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid filter expression %q: %v\n", *filterExpr, err)
		os.Exit(1)
	}

	var src capture.PacketSource
	if *readFile != "" {
		src, err = capture.OpenPcapFile(*readFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open PCAP file %q: %v\n", *readFile, err)
			os.Exit(1)
		}
		fmt.Printf("Reading from PCAP file %s (LinkType: %s)\n", *readFile, src.LinkType())
	} else {
		src, err = capture.OpenLive(capture.LiveConfig{
			Device:      *ifaceName,
			SnapLen:     *snapLen,
			Promiscuous: *promisc,
			Timeout:     100 * time.Millisecond,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start live capture on %s: %v\n", *ifaceName, err)
			os.Exit(1)
		}
		fmt.Printf("Listening on interface %s (LinkType: %s, pure Go / CGO_ENABLED=0)...\n", *ifaceName, src.LinkType())
	}
	defer src.Close()

	var writer *capture.PcapWriter
	if *writeFile != "" {
		writer, err = capture.CreatePcapFile(*writeFile, src.LinkType(), uint32(*snapLen))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output PCAP %q: %v\n", *writeFile, err)
			os.Exit(1)
		}
		defer writer.Close()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nInterrupted, closing packet source...\n")
		_ = src.Close()
	}()

	assembler := stream.NewTCPAssembler(func(ev stream.StreamEvent) {
		if ch, err := l7.ParseTLSClientHello(ev.StreamBuffer); err == nil {
			fmt.Printf("    %s %s %s\n",
				colorize(badgeTLS, " L7 TLS "),
				colorize(ansiDim, fmt.Sprintf("[%s %s->%s]", ev.Direction, ev.Client, ev.Server)),
				colorize(ansiBrightMagenta, ch.Summary()))
			return
		}
		if httpMsg, err := l7.ParseHTTP(ev.StreamBuffer); err == nil {
			fmt.Printf("    %s %s %s\n",
				colorize(badgeHTTP, " L7 HTTP "),
				colorize(ansiDim, fmt.Sprintf("[%s %s->%s]", ev.Direction, ev.Client, ev.Server)),
				colorize(ansiBrightGreen, httpMsg.Summary()))
			if len(httpMsg.Body) > 0 {
				fmt.Printf("    %s %s\n",
					colorize(ansiYellow, fmt.Sprintf("[HTTP Body (%d bytes)]", len(httpMsg.Body))),
					colorize(ansiCyan, httpMsg.BodyString()))
			}
		}
	})

	var decoded layers.DecodedPacket
	matched := 0

	for {
		raw, err := src.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, capture.ErrCaptureClosed) || errors.Is(err, syscall.EBADF) {
				break
			}
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
			break
		}

		if err := layers.DecodePacket(raw, &decoded); err != nil {
			continue
		}

		if !pktFilter.Match(&decoded) {
			continue
		}

		matched++
		if writer != nil {
			_ = writer.WritePacket(raw)
		}

		printPacketSummary(matched, &decoded)

		if decoded.HasTCP {
			assembler.ProcessPacket(&decoded)
		} else if decoded.HasUDP && (decoded.UDP.SrcPort == 53 || decoded.UDP.DstPort == 53 || decoded.UDP.SrcPort == 5353 || decoded.UDP.DstPort == 5353) {
			if dnsMsg, err := l7.ParseDNS(decoded.Payload); err == nil {
				fmt.Printf("    %s %s\n",
					colorize(badgeDNS, " L7 DNS "),
					colorize(ansiBrightCyan, dnsMsg.Summary()))
			}
		}

		if *maxCount > 0 && matched >= *maxCount {
			break
		}
	}

	fmt.Printf("Done. Total matched packets: %d (Active TCP flows tracked: %d)\n",
		matched, assembler.ActiveConnections())
}

func printInterfaces() {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list interfaces: %v\n", err)
		os.Exit(1)
	}
	for _, iface := range ifaces {
		var addrs []string
		for _, a := range iface.Addrs {
			addrs = append(addrs, a.String())
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			mac = "-"
		}
		fmt.Printf("%-10s idx=%-2d mtu=%-5d mac=%-17s addrs=[%s]\n",
			iface.Name, iface.Index, iface.MTU, mac, strings.Join(addrs, ", "))
	}
}

// ANSI color codes inspired by Wireshark protocol coloring rules.
const (
	ansiReset         = "\033[0m"
	ansiDim           = "\033[2m"
	ansiBold          = "\033[1m"
	ansiRed           = "\033[91m"
	ansiGreen         = "\033[32m"
	ansiBrightGreen   = "\033[92m"
	ansiYellow        = "\033[93m"
	ansiBlue          = "\033[94m"
	ansiMagenta       = "\033[35m"
	ansiBrightMagenta = "\033[95m"
	ansiCyan          = "\033[36m"
	ansiBrightCyan    = "\033[96m"
	ansiGray          = "\033[90m"

	// Protocol badges (background + foreground)
	badgeTCP  = "\033[1;44;97m"  // Blue bg, white text
	badgeRST  = "\033[1;41;97m"  // Red bg, white text (TCP RST)
	badgeSYN  = "\033[1;42;30m"  // Green bg, black text (TCP SYN/Handshake)
	badgeHTTP = "\033[1;42;30m"  // Green bg, black text (HTTP)
	badgeTLS  = "\033[1;45;97m"  // Magenta bg, white text (TLS/HTTPS)
	badgeUDP  = "\033[1;46;30m"  // Cyan bg, black text (UDP)
	badgeDNS  = "\033[1;106;30m" // Bright Cyan bg, black text (DNS)
	badgeICMP = "\033[1;43;30m"  // Yellow bg, black text (ICMP)
	badgeARP  = "\033[1;100;97m" // Dark gray bg, white text (ARP/L2)
)

var colorEnabled = true

func colorize(color, text string) string {
	if !colorEnabled || color == "" {
		return text
	}
	return color + text + ansiReset
}

func printPacketSummary(idx int, p *layers.DecodedPacket) {
	ts := colorize(ansiDim, p.Timestamp.Format("15:04:05.000000"))
	num := colorize(ansiGray, fmt.Sprintf("#%-4d", idx))

	switch {
	case p.HasTCP:
		badge := badgeTCP
		lineColor := ansiBlue
		protoLabel := " TCP  "

		switch {
		case p.TCP.HasFlag(layers.TCPFlagRST):
			badge = badgeRST
			lineColor = ansiRed
		case l7.IsLikelyHTTP(p.Payload):
			badge = badgeHTTP
			lineColor = ansiBrightGreen
			protoLabel = " HTTP "
		case len(p.Payload) >= 5 && p.Payload[0] == 22:
			if _, err := l7.ParseTLSClientHello(p.Payload); err == nil {
				badge = badgeTLS
				lineColor = ansiBrightMagenta
				protoLabel = " TLS  "
			}
		case p.TCP.HasFlag(layers.TCPFlagSYN):
			badge = badgeSYN
			lineColor = ansiYellow
		case p.TCP.HasFlag(layers.TCPFlagFIN):
			lineColor = ansiYellow
		}

		flow := fmt.Sprintf("%s:%d -> %s:%d", p.SrcIP(), p.TCP.SrcPort, p.DstIP(), p.TCP.DstPort)
		flags := fmt.Sprintf("[%s]", p.TCP.FlagsString())
		meta := fmt.Sprintf("seq=%d ack=%d len=%d", p.TCP.Seq, p.TCP.Ack, len(p.Payload))

		fmt.Printf("%s %s %s %s %s %s\n",
			num,
			ts,
			colorize(badge, protoLabel),
			colorize(lineColor+ansiBold, flow),
			colorize(lineColor, flags),
			colorize(ansiDim, meta),
		)

	case p.HasUDP:
		badge := badgeUDP
		lineColor := ansiBrightCyan
		protoLabel := " UDP  "
		if p.UDP.SrcPort == 53 || p.UDP.DstPort == 53 || p.UDP.SrcPort == 5353 || p.UDP.DstPort == 5353 {
			badge = badgeDNS
			protoLabel = " DNS  "
		}
		flow := fmt.Sprintf("%s:%d -> %s:%d", p.SrcIP(), p.UDP.SrcPort, p.DstIP(), p.UDP.DstPort)
		meta := fmt.Sprintf("len=%d", len(p.Payload))

		fmt.Printf("%s %s %s %s %s\n",
			num,
			ts,
			colorize(badge, protoLabel),
			colorize(lineColor+ansiBold, flow),
			colorize(ansiDim, meta),
		)

	case p.HasICMP:
		proto := " ICMP "
		if p.HasIPv6 {
			proto = "ICMPv6"
		}
		flow := fmt.Sprintf("%s -> %s", p.SrcIP(), p.DstIP())
		meta := fmt.Sprintf("type=%d code=%d id=%d seq=%d", p.ICMP.Type, p.ICMP.Code, p.ICMP.ID, p.ICMP.Seq)

		fmt.Printf("%s %s %s %s %s\n",
			num,
			ts,
			colorize(badgeICMP, proto),
			colorize(ansiYellow+ansiBold, flow),
			colorize(ansiDim, meta),
		)

	default:
		protoLabel := fmt.Sprintf(" %-4s ", p.LinkType)
		if p.HasEthernet && p.Ethernet.EtherType == layers.EtherTypeARP {
			protoLabel = " ARP  "
		}
		fmt.Printf("%s %s %s %s\n",
			num,
			ts,
			colorize(badgeARP, protoLabel),
			colorize(ansiGray, fmt.Sprintf("payload=%d bytes", len(p.Payload))),
		)
	}
}

// generateDemoPcap writes a realistic multi-protocol PCAP file (DNS query/response, HTTP GET/200, TLS ClientHello, ICMP)
// so users can test offline analysis immediately without root privileges.
func generateDemoPcap(path string) error {
	pw, err := capture.CreatePcapFile(path, capture.LinkTypeEthernet, 65535)
	if err != nil {
		return err
	}
	defer pw.Close()

	baseTime := time.Date(2026, 10, 14, 15, 30, 0, 0, time.UTC)

	// 1. UDP DNS Query for "example.com"
	dnsQuery := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	pkt1 := buildIPv4UDPPacket([4]byte{192, 168, 1, 10}, [4]byte{8, 8, 8, 8}, 54321, 53, dnsQuery)

	// 2. TCP HTTP GET Request
	httpReq := []byte("GET /status HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: GoPcap/1.0\r\n\r\n")
	pkt2 := buildIPv4TCPPacket([4]byte{192, 168, 1, 10}, [4]byte{93, 184, 216, 34}, 55000, 80, 1000, 1, layers.TCPFlagPSH|layers.TCPFlagACK, httpReq)

	// 3. TCP TLS 1.2 ClientHello with SNI "secure.example.com"
	tlsCH := buildSampleTLSClientHello("secure.example.com", "h2")
	pkt3 := buildIPv4TCPPacket([4]byte{192, 168, 1, 10}, [4]byte{93, 184, 216, 34}, 55001, 443, 2000, 1, layers.TCPFlagPSH|layers.TCPFlagACK, tlsCH)

	samples := [][]byte{pkt1, pkt2, pkt3}
	for i, data := range samples {
		if err := pw.WritePacket(capture.RawPacket{
			Info: capture.CaptureInfo{
				Timestamp:     baseTime.Add(time.Duration(i*10) * time.Millisecond),
				CaptureLength: len(data),
				Length:        len(data),
			},
			LinkType: capture.LinkTypeEthernet,
			Data:     data,
		}); err != nil {
			return err
		}
	}
	return nil
}

func buildIPv4UDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	eth[0], eth[5] = 0x00, 0x01
	eth[6], eth[11] = 0x00, 0x02
	binary.BigEndian.PutUint16(eth[12:14], uint16(layers.EtherTypeIPv4))

	udpLen := 8 + len(payload)
	ipTotal := 20 + udpLen
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotal))
	ip[8] = 64
	ip[9] = uint8(layers.IPProtocolUDP)
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))

	out := append(eth, ip...)
	out = append(out, udp...)
	return append(out, payload...)
}

func buildIPv4TCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], uint16(layers.EtherTypeIPv4))

	tcpLen := 20 + len(payload)
	ipTotal := 20 + tcpLen
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotal))
	ip[8] = 64
	ip[9] = uint8(layers.IPProtocolTCP)
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // 20 bytes header
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	out := append(eth, ip...)
	out = append(out, tcp...)
	return append(out, payload...)
}

func buildSampleTLSClientHello(sni, alpn string) []byte {
	sniBytes := []byte(sni)
	sniExt := make([]byte, 4+2+3+len(sniBytes))
	binary.BigEndian.PutUint16(sniExt[0:2], 0x0000) // ext type SNI
	binary.BigEndian.PutUint16(sniExt[2:4], uint16(2+3+len(sniBytes)))
	binary.BigEndian.PutUint16(sniExt[4:6], uint16(3+len(sniBytes)))
	sniExt[6] = 0 // host_name
	binary.BigEndian.PutUint16(sniExt[7:9], uint16(len(sniBytes)))
	copy(sniExt[9:], sniBytes)

	alpnBytes := []byte(alpn)
	alpnExt := make([]byte, 4+2+1+len(alpnBytes))
	binary.BigEndian.PutUint16(alpnExt[0:2], 0x0010) // ext type ALPN
	binary.BigEndian.PutUint16(alpnExt[2:4], uint16(2+1+len(alpnBytes)))
	binary.BigEndian.PutUint16(alpnExt[4:6], uint16(1+len(alpnBytes)))
	alpnExt[6] = uint8(len(alpnBytes))
	copy(alpnExt[7:], alpnBytes)

	exts := append(sniExt, alpnExt...)

	// ClientHello body: Version(2) + Random(32) + SessionID(1) + CipherSuites(4) + Comp(2) + ExtLen(2) + Exts
	chBody := make([]byte, 2+32+1+4+2+2+len(exts))
	binary.BigEndian.PutUint16(chBody[0:2], 0x0303) // TLS 1.2
	chBody[34] = 0                                  // SessionID len 0
	binary.BigEndian.PutUint16(chBody[35:37], 2)    // 1 cipher suite
	binary.BigEndian.PutUint16(chBody[37:39], 0x1301)
	chBody[39] = 1 // 1 compression method
	chBody[40] = 0
	binary.BigEndian.PutUint16(chBody[41:43], uint16(len(exts)))
	copy(chBody[43:], exts)

	hs := make([]byte, 4+len(chBody))
	hs[0] = 1 // ClientHello
	hs[1] = byte(len(chBody) >> 16)
	hs[2] = byte(len(chBody) >> 8)
	hs[3] = byte(len(chBody))
	copy(hs[4:], chBody)

	rec := make([]byte, 5+len(hs))
	rec[0] = 22 // Handshake
	binary.BigEndian.PutUint16(rec[1:3], 0x0301)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}
