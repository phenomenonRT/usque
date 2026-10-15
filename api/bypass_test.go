package api

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// recordConn is a minimal net.Conn that records every Write call as a separate
// segment so tests can assert on how the stream was fragmented.
type recordConn struct {
	segments [][]byte
	closed   bool
}

func (c *recordConn) Write(b []byte) (int, error) {
	seg := make([]byte, len(b))
	copy(seg, b)
	c.segments = append(c.segments, seg)
	return len(b), nil
}

func (c *recordConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *recordConn) Close() error                     { c.closed = true; return nil }
func (c *recordConn) LocalAddr() net.Addr              { return nil }
func (c *recordConn) RemoteAddr() net.Addr             { return nil }
func (c *recordConn) SetDeadline(time.Time) error      { return nil }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }

func TestFragmentConnSplitsFirstWrites(t *testing.T) {
	rec := &recordConn{}
	conn := wrapTLSFragment(rec, &TLSFragmentConfig{Sizes: []int{1, 2}})

	payload := []byte("hello world")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write reported %d bytes, want %d", n, len(payload))
	}

	var got [][]byte
	got = append(got, rec.segments...)
	want := [][]byte{[]byte("h"), []byte("el"), []byte("lo world")}
	if len(got) != len(want) {
		t.Fatalf("got %d segments %q, want %d", len(got), got, len(want))
	}
	var joined bytes.Buffer
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("segment %d = %q, want %q", i, got[i], want[i])
		}
		joined.Write(got[i])
	}
	if !bytes.Equal(joined.Bytes(), payload) {
		t.Fatalf("reassembled stream = %q, want %q", joined.Bytes(), payload)
	}
}

func TestFragmentConnAccumulatesAcrossWrites(t *testing.T) {
	rec := &recordConn{}
	conn := wrapTLSFragment(rec, &TLSFragmentConfig{Sizes: []int{1}})

	// A 1-byte first write satisfies the plan; the stream then passes through.
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := conn.Write([]byte("bc")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	want := [][]byte{[]byte("a"), []byte("bc")}
	if len(rec.segments) != len(want) {
		t.Fatalf("got %d segments %q, want %d", len(rec.segments), rec.segments, len(want))
	}
	for i := range want {
		if !bytes.Equal(rec.segments[i], want[i]) {
			t.Fatalf("segment %d = %q, want %q", i, rec.segments[i], want[i])
		}
	}
}

func TestWrapTLSFragmentDisabled(t *testing.T) {
	rec := &recordConn{}
	if got := wrapTLSFragment(rec, nil); got != net.Conn(rec) {
		t.Fatalf("nil config should return the original conn")
	}
	if got := wrapTLSFragment(rec, &TLSFragmentConfig{}); got != net.Conn(rec) {
		t.Fatalf("empty sizes should return the original conn")
	}
}

func TestTLSFragmentConfigEnabled(t *testing.T) {
	var nilCfg *TLSFragmentConfig
	if nilCfg.Enabled() {
		t.Fatal("nil config must be disabled")
	}
	if (&TLSFragmentConfig{}).Enabled() {
		t.Fatal("zero config must be disabled")
	}
	if !DefaultTLSFragmentConfig().Enabled() {
		t.Fatal("default config must be enabled")
	}
}

// buildClientHello собирает минимальный, но корректный TLS ClientHello с одним
// расширением server_name, чтобы проверить разбор и точки разрыва.
func buildClientHello(sni string) []byte {
	host := []byte(sni)
	sn := make([]byte, 0, 5+len(host))
	sn = append(sn, byte((len(host)+3)>>8), byte(len(host)+3)) // список имён
	sn = append(sn, 0x00)                                      // host_name
	sn = append(sn, byte(len(host)>>8), byte(len(host)))
	sn = append(sn, host...)
	ext := []byte{0x00, 0x00, byte(len(sn) >> 8), byte(len(sn))}
	ext = append(ext, sn...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	payload := append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}
	return append(rec, payload...)
}

func TestClientHelloSNI(t *testing.T) {
	hello := buildClientHello("www.example.org")
	start, end, ok := clientHelloSNI(hello)
	if !ok {
		t.Fatal("clientHelloSNI did not parse a valid ClientHello")
	}
	if got := string(hello[start:end]); got != "www.example.org" {
		t.Fatalf("SNI = %q, want %q", got, "www.example.org")
	}

	if _, _, ok := clientHelloSNI(nil); ok {
		t.Fatal("clientHelloSNI must reject an empty buffer")
	}
	if _, _, ok := clientHelloSNI(hello[:10]); ok {
		t.Fatal("clientHelloSNI must reject a truncated ClientHello")
	}
	// No server_name extension at all.
	noSNI := buildClientHello("")
	if _, _, ok := clientHelloSNI(noSNI); ok {
		t.Fatal("clientHelloSNI must report no SNI when the name is empty")
	}
}

func TestFragmentConnSplitsInsideSNI(t *testing.T) {
	rec := &recordConn{}
	conn := wrapTLSFragment(rec, &TLSFragmentConfig{Auto: true})

	hello := buildClientHello("www.microsoft.com")
	start, end, ok := clientHelloSNI(hello)
	if !ok {
		t.Fatal("test ClientHello did not parse")
	}

	n, err := conn.Write(hello)
	if err != nil || n != len(hello) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(hello))
	}
	if len(rec.segments) != 3 {
		t.Fatalf("got %d segments, want 3", len(rec.segments))
	}
	// Имя сервера не должно встречаться ни в одном сегменте целиком.
	for i, seg := range rec.segments {
		if bytes.Contains(seg, []byte("www.microsoft.com")) {
			t.Fatalf("segment %d contains the whole SNI", i)
		}
	}
	// Каждая внутренняя граница попадает внутрь имени сервера.
	offset := 0
	for i := 0; i < len(rec.segments)-1; i++ {
		offset += len(rec.segments[i])
		if offset <= start || offset >= end {
			t.Fatalf("split at %d does not fall inside the SNI [%d, %d)", offset, start, end)
		}
	}
	if offset != len(rec.segments[0])+len(rec.segments[1]) {
		t.Fatalf("boundaries were counted wrong: %d", offset)
	}

	var joined []byte
	for _, s := range rec.segments {
		joined = append(joined, s...)
	}
	if !bytes.Equal(joined, hello) {
		t.Fatal("reassembled stream does not match the ClientHello")
	}
}

func TestFragmentConnWaitsForWholeRecord(t *testing.T) {
	rec := &recordConn{}
	conn := wrapTLSFragment(rec, &TLSFragmentConfig{Auto: true})

	hello := buildClientHello("example.org")
	cut := len(hello) / 3
	if _, err := conn.Write(hello[:cut]); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if len(rec.segments) != 0 {
		t.Fatalf("wrote %d segments before the record was complete", len(rec.segments))
	}
	if _, err := conn.Write(hello[cut:]); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if len(rec.segments) != 3 {
		t.Fatalf("got %d segments, want 3", len(rec.segments))
	}
}

func TestFragmentConnAutoPassesThroughNonTLS(t *testing.T) {
	rec := &recordConn{}
	conn := wrapTLSFragment(rec, &TLSFragmentConfig{Auto: true})

	first := []byte("GET / HTTP/1.1\r\n")
	if _, err := conn.Write(first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if len(rec.segments) != 1 || !bytes.Equal(rec.segments[0], first) {
		t.Fatalf("got %q, want a single passthrough write", rec.segments)
	}
	if _, err := conn.Write([]byte("Host: example.org\r\n")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if len(rec.segments) != 2 {
		t.Fatalf("got %d segments, want 2 passthrough writes", len(rec.segments))
	}
}

func TestFragmentConnAutoFallsBackWithoutSNI(t *testing.T) {
	rec := &recordConn{}
	conn := wrapTLSFragment(rec, &TLSFragmentConfig{Auto: true})

	hello := buildClientHello("")
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(rec.segments) != 2 || len(rec.segments[0]) != 1 {
		t.Fatalf("got %d segments (first %d bytes), want 2 with a 1-byte first segment",
			len(rec.segments), len(rec.segments[0]))
	}
}
