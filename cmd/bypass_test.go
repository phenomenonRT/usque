package cmd

import (
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

func TestBypassSNIsDefaultStartsWithConfigSNI(t *testing.T) {
	got := bypassSNIs(internal.ConnectSNI, false, nil, internal.BypassSNIs)
	if len(got) == 0 || got[0] != internal.ConnectSNI {
		t.Fatalf("first SNI = %q, want %q", got[0], internal.ConnectSNI)
	}
	// The default pool plus the config SNI must not contain duplicates.
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

func TestL4DefaultSNIFirstInPool(t *testing.T) {
	// buildL4Plan relies on this: the L4 default SNI must come first so the
	// primary port sweep uses it.
	got := bypassSNIs(internal.L4ConnectSNI, false, nil, internal.BypassSNIs)
	if len(got) == 0 || got[0] != internal.L4ConnectSNI {
		t.Fatalf("first L4 SNI = %q, want %q", got[0], internal.L4ConnectSNI)
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
