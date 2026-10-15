package internal

import (
	"testing"
	"time"
)

func TestDefaultQuicConfigIdleTimeoutAboveKeepalive(t *testing.T) {
	// The QUIC idle timeout must stay above the keepalive period, otherwise the
	// two race and the connection is dropped right when a keepalive would have
	// refreshed it (sporadic "no recent network activity" disconnects).
	for _, keepalive := range []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 2 * time.Minute} {
		cfg := DefaultQuicConfig(keepalive, 0)
		if cfg.MaxIdleTimeout <= keepalive {
			t.Fatalf("MaxIdleTimeout %s must exceed keepalive %s", cfg.MaxIdleTimeout, keepalive)
		}
	}
}

func TestDefaultQuicConfigInitialPacketSize(t *testing.T) {
	cfg := DefaultQuicConfig(30*time.Second, 1200)
	if cfg.InitialPacketSize != 1200 {
		t.Fatalf("InitialPacketSize = %d, want 1200", cfg.InitialPacketSize)
	}
	if !cfg.DisablePathMTUDiscovery {
		t.Fatal("DisablePathMTUDiscovery must be set when InitialPacketSize > 0")
	}

	cfg = DefaultQuicConfig(30*time.Second, 0)
	if cfg.InitialPacketSize != 0 {
		t.Fatalf("InitialPacketSize = %d, want 0", cfg.InitialPacketSize)
	}
	if cfg.DisablePathMTUDiscovery {
		t.Fatal("DisablePathMTUDiscovery must not be set when InitialPacketSize == 0")
	}
}
