package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
)

func TestDedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"a", "", "b", "a", "c", "b", ""})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupeStrings = %v, want %v", got, want)
	}
}

func TestDedupeInts(t *testing.T) {
	got := dedupeInts([]int{443, 0, 500, 443, -1, 500, 1701})
	want := []int{443, 500, 1701}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupeInts = %v, want %v", got, want)
	}
}

func TestPrependInt(t *testing.T) {
	got := prependInt(443, []int{500, 443})
	want := []int{443, 500, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prependInt = %v, want %v", got, want)
	}
	// Callers combine prependInt with dedupeInts to drop the duplicate.
	if got := dedupeInts(prependInt(443, []int{500, 443})); !reflect.DeepEqual(got, []int{443, 500}) {
		t.Fatalf("dedupeInts(prependInt) = %v, want [443 500]", got)
	}
	if got := prependInt(0, []int{500}); !reflect.DeepEqual(got, []int{500}) {
		t.Fatalf("prependInt(0) = %v, want [500]", got)
	}
}

func TestPrefixEndpoint(t *testing.T) {
	got := prefixEndpoint("162.159.198.1", []string{"162.159.197.1"})
	want := []string{"162.159.198.1", "162.159.197.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixEndpoint = %v, want %v", got, want)
	}
	if got := prefixEndpoint("", []string{"a"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("prefixEndpoint empty base = %v, want [a]", got)
	}
}

func TestBypassSNIsDefaultPutsNeutralFirst(t *testing.T) {
	got := bypassSNIs(internal.ConnectSNI, false, nil, internal.BypassSNIs)
	if len(got) == 0 {
		t.Fatal("bypassSNIs returned no names")
	}
	// Names outside Cloudflare must be tried first: the server accepts any name
	// and TSPU blocks Cloudflare domains by SNI.
	if isCloudflareName(got[0]) {
		t.Fatalf("first SNI = %q, want a name outside Cloudflare", got[0])
	}
	// The config SNI must still be somewhere in the list.
	found := false
	for _, s := range got {
		if s == internal.ConnectSNI {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("%q is missing from %v", internal.ConnectSNI, got)
	}
	// The pool plus the config SNI must not contain duplicates.
	seen := make(map[string]struct{}, len(got))
	for _, s := range got {
		if _, ok := seen[s]; ok {
			t.Fatalf("duplicate SNI %q in %v", s, got)
		}
		seen[s] = struct{}{}
	}
}

func TestBypassSNIsUserOverride(t *testing.T) {
	got := bypassSNIs("example.com", true, nil, internal.BypassSNIs)
	want := []string{"example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bypassSNIs override = %v, want %v", got, want)
	}
}

func TestBypassSNIsExtraReplacesPool(t *testing.T) {
	// --bypass-sni must fully replace the built-in Cloudflare pool so a blocked
	// region can sweep only non-Cloudflare names.
	got := bypassSNIs(internal.ConnectSNI, false, []string{"www.example.org", "cdn.example.net"}, internal.BypassSNIs)
	want := []string{"www.example.org", "cdn.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bypassSNIs extra = %v, want %v", got, want)
	}

	// An explicit -s is kept first, then the extra names.
	got = bypassSNIs("pinned.example", true, []string{"www.example.org"}, internal.BypassSNIs)
	want = []string{"pinned.example", "www.example.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bypassSNIs pinned+extra = %v, want %v", got, want)
	}
}

func TestBypassSNIsIncludesNonCloudflare(t *testing.T) {
	// When a provider blocks Cloudflare domains by SNI, the sweep must still
	// contain names outside Cloudflare.
	for _, want := range []string{"www.microsoft.com", "www.apple.com", "www.bing.com"} {
		found := false
		for _, s := range internal.BypassSNIs {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("BypassSNIs is missing non-Cloudflare name %q: %v", want, internal.BypassSNIs)
		}
	}
}

func TestL4DefaultSNIPresentInPool(t *testing.T) {
	// buildL4Plan relies on this: the L4 default SNI must remain in the sweep,
	// otherwise a QUIC-only proxy could never use the transport it is built for.
	got := bypassSNIs(internal.L4ConnectSNI, false, nil, internal.BypassSNIs)
	found := false
	for _, s := range got {
		if s == internal.L4ConnectSNI {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("first L4 SNI %q is missing from %v", internal.L4ConnectSNI, got)
	}
}

func TestOrderSNIsForSweep(t *testing.T) {
	got := orderSNIsForSweep([]string{
		"consumer-masque.cloudflareclient.com",
		"www.example.org",
		"one.one.one.one",
		"cdn.example.net",
		"www.cloudflare.com",
	})
	want := []string{
		"www.example.org",
		"cdn.example.net",
		"consumer-masque.cloudflareclient.com",
		"one.one.one.one",
		"www.cloudflare.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderSNIsForSweep = %v, want %v", got, want)
	}
}

func TestBuildCandidatesBreadthFirst(t *testing.T) {
	in := candidateInput{
		SNIs:     []string{"neutral.example", "cf.example", "third.example"},
		TLSBySNI: map[string]*tls.Config{"neutral.example": {}, "cf.example": {}, "third.example": {}},
		QUICIPs:  []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		H2IPs:    []string{"192.0.2.11", "192.0.2.12", "192.0.2.13"},
		Ports:    []int{443, 500, 1701},
		H2Ports:  []int{443},
	}

	got := buildCandidates(in)
	if len(got) != 20 {
		t.Fatalf("got %d candidates, want 20", len(got))
	}

	// Every dimension must show up within the first few attempts: a blocked
	// combination costs a full timeout, so the sweep must not exhaust the port
	// list (or the SNI list) before touching the others.
	want := []string{
		"quic 192.0.2.1:443 sni=neutral.example",
		"h2 192.0.2.11:443 sni=neutral.example",
		"quic 192.0.2.1:500 sni=neutral.example",
		"quic 192.0.2.1:1701 sni=neutral.example",
		"h2 192.0.2.11:443 sni=cf.example",
		"quic 192.0.2.1:443 sni=cf.example",
		"h2 192.0.2.11:443 sni=third.example",
		"quic 192.0.2.1:443 sni=third.example",
	}
	for i, label := range want {
		if got[i].Label != label {
			t.Fatalf("candidate %d = %q, want %q", i, got[i].Label, label)
		}
	}

	// Alternative addresses must be reached before the address × SNI tail.
	if got[8].Label != "h2 192.0.2.12:443 sni=neutral.example" {
		t.Fatalf("candidate 8 = %q, want the next HTTP/2 address", got[8].Label)
	}

	seen := make(map[string]struct{}, len(got))
	for _, c := range got {
		if _, ok := seen[c.Label]; ok {
			t.Fatalf("duplicate candidate %q", c.Label)
		}
		seen[c.Label] = struct{}{}
	}
}

func TestBuildCandidatesCapsList(t *testing.T) {
	var ips []string
	for i := 0; i < 40; i++ {
		ips = append(ips, fmt.Sprintf("192.0.2.%d", i+1))
	}
	got := buildCandidates(candidateInput{
		SNIs:     []string{"a.example", "b.example"},
		TLSBySNI: map[string]*tls.Config{"a.example": {}, "b.example": {}},
		QUICIPs:  ips,
		H2IPs:    ips,
		Ports:    []int{443, 500},
		H2Ports:  []int{443},
	})
	if len(got) != maxBypassCandidates {
		t.Fatalf("got %d candidates, want the cap of %d", len(got), maxBypassCandidates)
	}
}

func TestBuildCandidatesPrefersHTTP2WhenAsked(t *testing.T) {
	in := candidateInput{
		SNIs:     []string{"neutral.example"},
		TLSBySNI: map[string]*tls.Config{"neutral.example": {}},
		QUICIPs:  []string{"192.0.2.1", "192.0.2.2"},
		H2IPs:    []string{"192.0.2.11", "192.0.2.12"},
		Ports:    []int{443},
		H2Ports:  []int{443},
		UseHTTP2: true,
	}
	got := buildCandidates(in)
	if len(got) == 0 || !got[0].UseHTTP2 {
		t.Fatalf("first candidate = %q, want HTTP/2", got[0].Label)
	}
}

func TestBuildCandidatesSkipsInvalidAddresses(t *testing.T) {
	got := buildCandidates(candidateInput{
		SNIs:     []string{"neutral.example"},
		TLSBySNI: map[string]*tls.Config{"neutral.example": {}},
		QUICIPs:  []string{"not-an-ip"},
		H2IPs:    []string{"not-an-ip"},
		Ports:    []int{443},
		H2Ports:  []int{443},
	})
	if len(got) != 0 {
		t.Fatalf("got %d candidates, want none", len(got))
	}
}

func TestBuildCandidatesWithoutSNIs(t *testing.T) {
	if got := buildCandidates(candidateInput{QUICIPs: []string{"192.0.2.1"}}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestIsCloudflareName(t *testing.T) {
	for _, s := range []string{"consumer-masque.cloudflareclient.com", "one.one.one.one", "www.cloudflare.com", "CLOUDFLARE-DNS.com."} {
		if !isCloudflareName(s) {
			t.Fatalf("isCloudflareName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"www.microsoft.com", "www.apple.com", "example.org"} {
		if isCloudflareName(s) {
			t.Fatalf("isCloudflareName(%q) = true, want false", s)
		}
	}
}

func TestPreferHTTP2(t *testing.T) {
	quic := api.TunnelCandidate{Label: "quic", UseHTTP2: false}
	h2 := api.TunnelCandidate{Label: "h2", UseHTTP2: true}
	got := preferHTTP2([]api.TunnelCandidate{quic, h2, quic, h2})
	if len(got) != 4 {
		t.Fatalf("preferHTTP2 changed length: %d", len(got))
	}
	for i, c := range got {
		wantH2 := i < 2
		if c.UseHTTP2 != wantH2 {
			t.Fatalf("preferHTTP2[%d].UseHTTP2 = %v, want %v", i, c.UseHTTP2, wantH2)
		}
	}
}

func TestBypassCIDRsCoverEndpoints(t *testing.T) {
	// Every pooled endpoint must fall inside a pinned CIDR so the OpenWrt
	// routing logic in usque.sh keeps it reachable outside the tunnel.
	checkCovered := func(t *testing.T, endpoints, cidrs []string) {
		t.Helper()
		nets := make([]*net.IPNet, 0, len(cidrs))
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatalf("bad CIDR %q: %v", c, err)
			}
			nets = append(nets, n)
		}
		for _, ep := range endpoints {
			ip := net.ParseIP(ep)
			if ip == nil {
				t.Fatalf("endpoint %q is not an IP", ep)
			}
			covered := false
			for _, n := range nets {
				if n.Contains(ip) {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("endpoint %q is not covered by %v", ep, cidrs)
			}
		}
	}
	checkCovered(t, internal.BypassEndpointsV4, internal.BypassCIDRsV4)
	checkCovered(t, internal.BypassEndpointsV6, internal.BypassCIDRsV6)
}
