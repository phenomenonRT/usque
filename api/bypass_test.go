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
	for _, seg := range rec.segments {
		got = append(got, seg)
	}
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
		t.Fatal("empty sizes must be disabled")
	}
	if !DefaultTLSFragmentConfig().Enabled() {
		t.Fatal("default config must be enabled")
	}
}
