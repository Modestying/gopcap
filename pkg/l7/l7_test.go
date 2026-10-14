package l7

import (
	"encoding/binary"
	"testing"
)

func TestParseDNSWithCompressionPointer(t *testing.T) {
	// Construct a DNS response with a question for "api.example.com" (offset 12)
	// and an answer using a compression pointer (0xC00C) to offset 12, returning 93.184.216.34
	pkt := []byte{
		0xab, 0xcd, // ID
		0x81, 0x80, // Flags: Standard query response, no error
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, 0x00, 0x00,
		// Question at offset 12: 3api7example3com0
		0x03, 'a', 'p', 'i',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Answer using pointer 0xC00C -> offset 12
		0xc0, 0x0c,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLENGTH 4
		93, 184, 216, 34,
	}

	msg, err := ParseDNS(pkt)
	if err != nil {
		t.Fatalf("ParseDNS failed: %v", err)
	}
	if !msg.IsResponse || len(msg.Questions) != 1 || len(msg.Answers) != 1 {
		t.Fatalf("unexpected DNS structure: %+v", msg)
	}
	if msg.Questions[0].Name != "api.example.com" {
		t.Errorf("expected question name api.example.com, got %q", msg.Questions[0].Name)
	}
	if msg.Answers[0].Name != "api.example.com" || msg.Answers[0].Value != "93.184.216.34" {
		t.Errorf("unexpected answer: %+v", msg.Answers[0])
	}
}

func TestParseHTTPRequestAndResponse(t *testing.T) {
	reqRaw := []byte("POST /v1/login HTTP/1.1\r\nHost: auth.example.org\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"user\":\"demo\"}")
	req, err := ParseHTTP(reqRaw)
	if err != nil {
		t.Fatalf("ParseHTTP request failed: %v", err)
	}
	if req.IsResponse || req.Method != "POST" || req.URI != "/v1/login" || req.Host != "auth.example.org" {
		t.Errorf("unexpected parsed HTTP request: %+v", req)
	}
	if req.ContentLength != 15 || string(req.BodyPreview) != "{\"user\":\"demo\"}" {
		t.Errorf("unexpected HTTP body: len=%d preview=%q", req.ContentLength, string(req.BodyPreview))
	}

	respRaw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK")
	resp, err := ParseHTTP(respRaw)
	if err != nil {
		t.Fatalf("ParseHTTP response failed: %v", err)
	}
	if !resp.IsResponse || resp.StatusCode != 200 || resp.StatusText != "OK" {
		t.Errorf("unexpected parsed HTTP response: %+v", resp)
	}
}

func TestParseTLSClientHelloSNI(t *testing.T) {
	sni := "gopcap.example.com"
	sniBytes := []byte(sni)

	ext := make([]byte, 4+2+3+len(sniBytes))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000)
	binary.BigEndian.PutUint16(ext[2:4], uint16(2+3+len(sniBytes)))
	binary.BigEndian.PutUint16(ext[4:6], uint16(3+len(sniBytes)))
	ext[6] = 0
	binary.BigEndian.PutUint16(ext[7:9], uint16(len(sniBytes)))
	copy(ext[9:], sniBytes)

	body := make([]byte, 2+32+1+4+2+2+len(ext))
	binary.BigEndian.PutUint16(body[0:2], 0x0303)
	binary.BigEndian.PutUint16(body[35:37], 2)
	binary.BigEndian.PutUint16(body[37:39], 0xc02f)
	body[39] = 1
	binary.BigEndian.PutUint16(body[41:43], uint16(len(ext)))
	copy(body[43:], ext)

	hs := make([]byte, 4+len(body))
	hs[0] = 1
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 22
	binary.BigEndian.PutUint16(rec[1:3], 0x0301)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)

	ch, err := ParseTLSClientHello(rec)
	if err != nil {
		t.Fatalf("ParseTLSClientHello failed: %v", err)
	}
	if ch.ServerName != sni {
		t.Errorf("expected SNI %q, got %q", sni, ch.ServerName)
	}
}
