package l7

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// HTTPMessage represents a parsed HTTP/1.x request or response extracted from a TCP stream.
type HTTPMessage struct {
	IsResponse    bool
	Method        string
	URI           string
	Version       string
	StatusCode    int
	StatusText    string
	Host          string
	UserAgent     string
	ContentType   string
	ContentLength int
	Headers       map[string]string
	BodyPreview   []byte
}

var (
	ErrNotHTTP       = errors.New("l7/http: payload is not an HTTP/1.x message")
	ErrIncompleteHdr = errors.New("l7/http: incomplete HTTP header")
)

var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
}

// IsLikelyHTTP performs a fast prefix check for HTTP/1.x requests or responses.
func IsLikelyHTTP(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	if bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return true
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// Summary returns a single-line summary of the HTTP request or response.
func (m *HTTPMessage) Summary() string {
	if m.IsResponse {
		return fmt.Sprintf("HTTP %s %d %s (type=%s len=%d)", m.Version, m.StatusCode, m.StatusText, m.ContentType, m.ContentLength)
	}
	host := m.Host
	if host == "" {
		host = "-"
	}
	return fmt.Sprintf("HTTP %s %s (Host: %s)", m.Method, m.URI, host)
}

// ParseHTTP parses an HTTP/1.x request or response from a TCP payload or reassembled stream buffer.
func ParseHTTP(data []byte) (*HTTPMessage, error) {
	if !IsLikelyHTTP(data) {
		return nil, ErrNotHTTP
	}

	hdrEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return nil, ErrIncompleteHdr
	}

	hdrBlock := string(data[:hdrEnd])
	body := data[hdrEnd+4:]

	lines := strings.Split(hdrBlock, "\r\n")
	if len(lines) == 0 {
		return nil, ErrNotHTTP
	}

	firstLine := lines[0]
	msg := &HTTPMessage{
		Headers: make(map[string]string, len(lines)-1),
	}

	if strings.HasPrefix(firstLine, "HTTP/1.") {
		// Response: HTTP/1.1 200 OK
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) < 2 {
			return nil, ErrNotHTTP
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, ErrNotHTTP
		}
		msg.IsResponse = true
		msg.Version = parts[0]
		msg.StatusCode = code
		if len(parts) == 3 {
			msg.StatusText = parts[2]
		}
	} else {
		// Request: GET /index.html HTTP/1.1
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
			return nil, ErrNotHTTP
		}
		msg.IsResponse = false
		msg.Method = parts[0]
		msg.URI = parts[1]
		msg.Version = parts[2]
	}

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:colon])
		v := strings.TrimSpace(line[colon+1:])
		lowerK := strings.ToLower(k)
		msg.Headers[lowerK] = v

		switch lowerK {
		case "host":
			msg.Host = v
		case "user-agent":
			msg.UserAgent = v
		case "content-type":
			msg.ContentType = v
		case "content-length":
			if cl, err := strconv.Atoi(v); err == nil {
				msg.ContentLength = cl
			}
		}
	}

	if len(body) > 0 {
		previewLen := len(body)
		if previewLen > 256 {
			previewLen = 256
		}
		msg.BodyPreview = body[:previewLen]
	}

	return msg, nil
}
