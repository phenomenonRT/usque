package internal

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestTLSCurvesForName(t *testing.T) {
	cases := []struct {
		name string
		want []tls.CurveID
	}{
		{"", nil},
		{"auto", nil},
		{"AUTO", nil},
		{" default ", nil},
		{"p256", []tls.CurveID{tls.CurveP256}},
		{"P-256", []tls.CurveID{tls.CurveP256}},
		{"x25519", []tls.CurveID{tls.X25519}},
	}
	for _, tc := range cases {
		got, err := TLSCurvesForName(tc.name)
		if err != nil {
			t.Fatalf("TLSCurvesForName(%q) returned error: %v", tc.name, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("TLSCurvesForName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}

	if _, err := TLSCurvesForName("secp384r1"); err == nil {
		t.Fatal("TLSCurvesForName must reject an unknown profile")
	}
}

func TestAlternateCurveNameIsOpposite(t *testing.T) {
	// The alternate profile must always differ from the main one: the sweep
	// checks both, because the server may accept only one shape of ClientHello.
	for _, name := range []string{"auto", "p256", "x25519"} {
		alt := AlternateCurveName(name)
		if alt == "" {
			t.Fatalf("AlternateCurveName(%q) is empty", name)
		}
		curves, err := TLSCurvesForName(name)
		if err != nil {
			t.Fatalf("TLSCurvesForName(%q): %v", name, err)
		}
		altCurves, err := TLSCurvesForName(alt)
		if err != nil {
			t.Fatalf("TLSCurvesForName(%q): %v", alt, err)
		}
		if len(curves) > 0 && len(altCurves) > 0 && curves[0] == altCurves[0] {
			t.Fatalf("AlternateCurveName(%q) = %q, want a different profile", name, alt)
		}
		if name == "p256" && alt != "auto" {
			t.Fatalf("AlternateCurveName(p256) = %q, want auto", alt)
		}
	}

	if got := AlternateCurveName("nonsense"); got != "" {
		t.Fatalf("AlternateCurveName(nonsense) = %q, want an empty string", got)
	}
}

func TestBypassPoolSizesAreSane(t *testing.T) {
	// The sweep order and the OpenWrt route pinning depend on these constant
	// lists staying non-empty and aligned.
	if len(BypassEndpointsV4) == 0 || len(BypassEndpointsV6) == 0 {
		t.Fatal("endpoint pools must not be empty")
	}
	if len(BypassSNIs) == 0 || len(BypassQUICPorts) == 0 {
		t.Fatal("SNI and port pools must not be empty")
	}
	if BypassQUICPorts[0] != 443 {
		t.Fatalf("first QUIC port = %d, want 443", BypassQUICPorts[0])
	}
	if BypassInitialPacketSize < 1200 {
		t.Fatalf("BypassInitialPacketSize = %d, must be at least 1200 (RFC 9000)", BypassInitialPacketSize)
	}
	if BypassInitialPacketSize+BypassPacketSizeJitter > 1300 {
		t.Fatalf("initial packet size may grow to %d, want at most 1300",
			BypassInitialPacketSize+BypassPacketSizeJitter)
	}
}
