package cmd

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestCheckVerdictBothTransportsFailed(t *testing.T) {
	got := checkVerdict([]checkOutcome{
		{useHTTP2: false, sni: "a.example", port: 443},
		{useHTTP2: true, sni: "a.example", port: 443},
	})
	if len(got) == 0 || !strings.Contains(got[0], "ни UDP/QUIC, ни TCP") {
		t.Fatalf("verdict = %v, want a both-transports-failed conclusion", got)
	}
}

func TestCheckVerdictOnlyQUICFailed(t *testing.T) {
	got := checkVerdict([]checkOutcome{
		{useHTTP2: false, sni: "a.example", port: 443},
		{useHTTP2: false, sni: "a.example", port: 500},
	})
	if len(got) == 0 || !strings.Contains(got[0], "режет QUIC") {
		t.Fatalf("verdict = %v, want a QUIC-blocked conclusion", got)
	}
}

func TestCheckVerdictOnlyH2Failed(t *testing.T) {
	got := checkVerdict([]checkOutcome{
		{useHTTP2: true, sni: "a.example", port: 443},
	})
	if len(got) == 0 || !strings.Contains(got[0], "режет и HTTP/2") {
		t.Fatalf("verdict = %v, want an HTTP/2-blocked conclusion", got)
	}
}

func TestCheckVerdictHTTP2Works(t *testing.T) {
	got := checkVerdict([]checkOutcome{
		{useHTTP2: false, sni: "a.example", port: 443},
		{useHTTP2: true, sni: "a.example", port: 443, ok: true},
	})
	if len(got) == 0 || !strings.Contains(got[0], "HTTP/2") {
		t.Fatalf("verdict = %v, want an HTTP/2 hint", got)
	}
}

func TestCheckVerdictAlternativePort(t *testing.T) {
	got := checkVerdict([]checkOutcome{
		{useHTTP2: false, sni: "a.example", port: 443},
		{useHTTP2: false, sni: "a.example", port: 500, ok: true},
	})
	if len(got) != 1 || !strings.Contains(got[0], "порт 500") {
		t.Fatalf("verdict = %v, want a single port hint", got)
	}
}

func TestCheckVerdictAlternativeSNI(t *testing.T) {
	got := checkVerdict([]checkOutcome{
		{useHTTP2: false, sni: "consumer-masque.cloudflareclient.com", port: 443},
		{useHTTP2: false, sni: "www.microsoft.com", port: 443, ok: true},
	})
	if len(got) != 1 || !strings.Contains(got[0], "www.microsoft.com") {
		t.Fatalf("verdict = %v, want a single SNI hint", got)
	}
}

func TestCheckVerdictStandardCombination(t *testing.T) {
	// The first, plain combination works: nothing to explain.
	got := checkVerdict([]checkOutcome{
		{useHTTP2: false, sni: "a.example", port: 443, ok: true},
	})
	if len(got) != 0 {
		t.Fatalf("verdict = %v, want no hints", got)
	}
}

func TestCheckVerdictNothingTested(t *testing.T) {
	if got := checkVerdict(nil); got != nil {
		t.Fatalf("verdict = %v, want nil", got)
	}
}

func TestCollectOutcomesKeepsOrder(t *testing.T) {
	slots := []*checkOutcome{nil, {port: 500}, nil, {port: 1701}}
	got := collectOutcomes(slots)
	if len(got) != 2 || got[0].port != 500 || got[1].port != 1701 {
		t.Fatalf("collectOutcomes = %v, want [500 1701]", got)
	}
}

func TestOutcomeOfReadsCandidate(t *testing.T) {
	// A QUIC candidate keeps the SNI from its TLS config and the port from the
	// UDP endpoint; that is what the verdict logic keys on.
	cands := buildCandidates(candidateInput{
		SNIs:     []string{"www.example.org"},
		TLSBySNI: map[string]*tls.Config{"www.example.org": {ServerName: "www.example.org"}},
		QUICIPs:  []string{"192.0.2.1"},
		H2IPs:    []string{"192.0.2.1"},
		Ports:    []int{500},
		H2Ports:  []int{443},
	})
	if len(cands) != 2 {
		t.Fatalf("buildCandidates returned %d candidates, want 2", len(cands))
	}

	out := outcomeOf(cands[0], true)
	if out.useHTTP2 || out.port != 500 || out.sni != "www.example.org" || !out.ok {
		t.Fatalf("outcomeOf(quic) = %+v", out)
	}

	if !cands[1].UseHTTP2 {
		t.Fatalf("second candidate = %q, want HTTP/2", cands[1].Label)
	}
	if got := outcomeOf(cands[1], false); got.port != 443 || !got.useHTTP2 || got.ok {
		t.Fatalf("outcomeOf(http2) = %+v", got)
	}
}
