package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
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

func TestBuildCandidatesVariantPhases(t *testing.T) {
	// Experiments that cost one attempt each (no SNI, the opposite TLS curve
	// profile, a fixed source port) must be tried on the primary address before
	// the sweep starts walking ports and addresses.
	got := buildCandidates(candidateInput{
		SNIs:         []string{"neutral.example"},
		TLSBySNI:     map[string]*tls.Config{"neutral.example": {}},
		TLSConfigAlt: &tls.Config{ServerName: "neutral.example"},
		AltCurve:     "p256",
		NoSNI:        &tls.Config{},
		QUICIPs:      []string{"192.0.2.1"},
		H2IPs:        []string{"192.0.2.11"},
		Ports:        []int{443, 500},
		H2Ports:      []int{443},
		SourcePorts:  []int{4500},
	})

	want := []string{
		"quic 192.0.2.1:443 sni=neutral.example",
		"h2 192.0.2.11:443 sni=neutral.example",
		"quic 192.0.2.1:443 без SNI",
		"h2 192.0.2.11:443 без SNI",
		"quic 192.0.2.1:443 sni=neutral.example curve=p256",
		"h2 192.0.2.11:443 sni=neutral.example curve=p256",
		"quic 192.0.2.1:443 sni=neutral.example sport=4500",
		"quic 192.0.2.1:500 sni=neutral.example",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %v", len(got), len(want), labelsOf(got))
	}
	for i, label := range want {
		if got[i].Label != label {
			t.Fatalf("candidate %d = %q, want %q", i, got[i].Label, label)
		}
	}

	// The name-less handshake must really have no SNI, and the fixed-source-port
	// attempt must carry its port.
	if got[2].TLSConfig.ServerName != "" || got[3].TLSConfig.ServerName != "" {
		t.Fatal("candidates must be built without a server name")
	}
	if got[6].LocalPort != 4500 {
		t.Fatalf("source port candidate LocalPort = %d, want 4500", got[6].LocalPort)
	}
	for i, c := range got {
		if i != 6 && c.LocalPort != 0 {
			t.Fatalf("candidate %d unexpectedly sets LocalPort = %d", i, c.LocalPort)
		}
	}
}

func TestBuildCandidatesWithoutVariantsStaysUnchanged(t *testing.T) {
	// Without the optional inputs the sweep must be exactly the classic one:
	// the phases above are skippable while the server keeps working with SNI.
	got := buildCandidates(candidateInput{
		SNIs:     []string{"neutral.example"},
		TLSBySNI: map[string]*tls.Config{"neutral.example": {}},
		QUICIPs:  []string{"192.0.2.1"},
		H2IPs:    []string{"192.0.2.11"},
		Ports:    []int{443, 500},
		H2Ports:  []int{443},
	})
	want := []string{
		"quic 192.0.2.1:443 sni=neutral.example",
		"h2 192.0.2.11:443 sni=neutral.example",
		"quic 192.0.2.1:500 sni=neutral.example",
	}
	if !reflect.DeepEqual(labelsOf(got), want) {
		t.Fatalf("labels = %v, want %v", labelsOf(got), want)
	}
}

func TestBuildCandidatesQUICOnly(t *testing.T) {
	// L4-прокси собирает список тем же кодом, но без HTTP/2: адресов TCP у него нет.
	got := buildCandidates(candidateInput{
		SNIs:     []string{"neutral.example", "cf.example"},
		TLSBySNI: map[string]*tls.Config{"neutral.example": {}, "cf.example": {}},
		QUICIPs:  []string{"192.0.2.1", "192.0.2.2"},
		Ports:    []int{443, 500},
	})
	for _, c := range got {
		if c.UseHTTP2 {
			t.Fatalf("candidate %q is HTTP/2, want QUIC only", c.Label)
		}
	}
	if len(got) == 0 {
		t.Fatal("no candidates built")
	}
}

func TestAppendWithinCapReservesRoomForIPv6(t *testing.T) {
	var base []api.TunnelCandidate
	for i := 0; i < maxBypassCandidates; i++ {
		base = append(base, api.TunnelCandidate{Label: fmt.Sprintf("v4-%d", i)})
	}
	extra := make([]api.TunnelCandidate, 0, 20)
	for i := 0; i < 20; i++ {
		extra = append(extra, api.TunnelCandidate{Label: fmt.Sprintf("v6-%d", i)})
	}

	got := appendWithinCap(base, extra)
	if len(got) != maxBypassCandidates {
		t.Fatalf("got %d candidates, want %d", len(got), maxBypassCandidates)
	}
	if got[len(got)-1].Label != "v6-15" {
		t.Fatalf("last candidate = %q, want the IPv6 tail to be kept", got[len(got)-1].Label)
	}
	v4 := 0
	for _, c := range got {
		if strings.HasPrefix(c.Label, "v4-") {
			v4++
		}
	}
	if want := maxBypassCandidates - maxBypassCandidates/4; v4 != want {
		t.Fatalf("kept %d IPv4 candidates, want %d", v4, want)
	}

	if got := appendWithinCap([]api.TunnelCandidate{{Label: "only"}}, nil); len(got) != 1 {
		t.Fatalf("appendWithinCap without a tail changed the list: %v", labelsOf(got))
	}
}

func TestPreferRememberedCandidate(t *testing.T) {
	list := []api.TunnelCandidate{{Label: "a"}, {Label: "b"}, {Label: "c"}}

	got, ok := preferRememberedCandidate(list, "c")
	if !ok {
		t.Fatal("remembered combination was not found")
	}
	if !reflect.DeepEqual(labelsOf(got), []string{"c", "a", "b"}) {
		t.Fatalf("order = %v, want [c a b]", labelsOf(got))
	}
	if !reflect.DeepEqual(labelsOf(list), []string{"a", "b", "c"}) {
		t.Fatalf("the input list was modified: %v", labelsOf(list))
	}

	// A stale file from another network must not break the sweep.
	got, ok = preferRememberedCandidate(list, "gone")
	if ok || !reflect.DeepEqual(labelsOf(got), []string{"a", "b", "c"}) {
		t.Fatalf("stale combination: ok=%v order=%v", ok, labelsOf(got))
	}
	if _, ok := preferRememberedCandidate(list, ""); ok {
		t.Fatal("an empty remembered label must be reported as not found")
	}

	// Already first: nothing to reorder.
	got, ok = preferRememberedCandidate(list, "a")
	if !ok || !reflect.DeepEqual(labelsOf(got), []string{"a", "b", "c"}) {
		t.Fatalf("first combination: ok=%v order=%v", ok, labelsOf(got))
	}
}

func TestBypassStateRoundTrip(t *testing.T) {
	path := t.TempDir() + "/config.json.bypass"
	if got := readBypassState(path); got != "" {
		t.Fatalf("readBypassState on a missing file = %q, want an empty string", got)
	}
	if err := writeBypassState(path, "quic 192.0.2.1:500 sni=www.microsoft.com"); err != nil {
		t.Fatalf("writeBypassState: %v", err)
	}
	if got := readBypassState(path); got != "quic 192.0.2.1:500 sni=www.microsoft.com" {
		t.Fatalf("readBypassState = %q", got)
	}
	if err := writeBypassState("", "x"); err != nil {
		t.Fatalf("writeBypassState with no path must be a no-op: %v", err)
	}
	if err := writeBypassState(path, ""); err != nil {
		t.Fatalf("writeBypassState with no label must be a no-op: %v", err)
	}
}

func TestBypassStatePath(t *testing.T) {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "test"}
		c.Flags().StringP("config", "c", "config.json", "")
		c.Flags().String("bypass-state", "", "")
		return c
	}

	c := newCmd()
	if got := bypassStatePath(c); got != "config.json"+bypassStateExt {
		t.Fatalf("default path = %q, want the config path plus %q", got, bypassStateExt)
	}

	// A custom path replaces the default one.
	if err := c.Flags().Set("bypass-state", "/etc/usque/warp.bypass"); err != nil {
		t.Fatal(err)
	}
	if got := bypassStatePath(c); got != "/etc/usque/warp.bypass" {
		t.Fatalf("custom path = %q", got)
	}

	// "-" (and its synonyms) turns remembering off completely.
	for _, off := range []string{"-", "off", "none", " OFF "} {
		c := newCmd()
		if err := c.Flags().Set("bypass-state", off); err != nil {
			t.Fatal(err)
		}
		if got := bypassStatePath(c); got != "" {
			t.Fatalf("bypass-state %q = %q, want an empty path", off, got)
		}
	}
}

func TestOnWinnerRemembersOnlyNewCombinations(t *testing.T) {
	path := t.TempDir() + "/config.json.bypass"
	plan := tunnelPlan{StatePath: path}

	onWinner := plan.OnWinner()
	if onWinner == nil {
		t.Fatal("OnWinner returned nil for a configured path")
	}
	onWinner("quic 192.0.2.1:443 sni=a.example")
	if got := readBypassState(path); got != "quic 192.0.2.1:443 sni=a.example" {
		t.Fatalf("remembered %q", got)
	}

	// The same combination must not rewrite the file (flash wears out), but a
	// new one must.
	onWinner("quic 192.0.2.1:443 sni=a.example")
	onWinner("h2 192.0.2.11:443 sni=b.example")
	if got := readBypassState(path); got != "h2 192.0.2.11:443 sni=b.example" {
		t.Fatalf("remembered %q", got)
	}

	onWinner("")
	if got := readBypassState(path); got != "h2 192.0.2.11:443 sni=b.example" {
		t.Fatalf("an empty label must be ignored, got %q", got)
	}

	if off := (tunnelPlan{}).OnWinner(); off != nil {
		t.Fatal("OnWinner must be nil when remembering is off")
	}
}

func TestDedupePorts(t *testing.T) {
	got := dedupePorts([]int{4500, 0, 443, 4500, 70000, -1, 500})
	want := []int{4500, 443, 500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupePorts = %v, want %v", got, want)
	}
}

// TestSweepCoversEveryWARPGNetwork проверяет главное свойство перебора адресов:
// лимит кандидатов обрывает список, поэтому каждая документированная сеть
// WARP/MASQUE должна попасть в проверку, а не остаться за пределами лимита.
// Именно так ломается наивный порядок «сначала один адрес, потом следующий»:
// до последних сетей перебор просто не доходит.
func TestSweepCoversEveryWARPGNetwork(t *testing.T) {
	tlsConfigs := func(snis []string) map[string]*tls.Config {
		out := make(map[string]*tls.Config, len(snis))
		for _, s := range snis {
			out[s] = &tls.Config{}
		}
		return out
	}

	got := buildCandidates(candidateInput{
		SNIs:     internal.BypassSNIs,
		TLSBySNI: tlsConfigs(internal.BypassSNIs),
		QUICIPs:  append([]string{"162.159.198.1"}, internal.BypassEndpointsV4...),
		H2IPs:    append([]string{"162.159.198.2"}, internal.BypassEndpointsV4...),
		Ports:    internal.BypassQUICPorts,
		H2Ports:  []int{internal.BypassH2Port},
	})
	if len(got) != maxBypassCandidates {
		t.Fatalf("got %d candidates, want the sweep to be full (%d)", len(got), maxBypassCandidates)
	}

	covered := map[string]bool{}
	for _, c := range got {
		var ip net.IP
		switch addr := c.Endpoint.(type) {
		case *net.UDPAddr:
			ip = addr.IP
		case *net.TCPAddr:
			ip = addr.IP
		}
		if ip == nil {
			continue
		}
		covered[ip.Mask(net.CIDRMask(24, 32)).String()+"/24"] = true
	}
	for _, cidr := range internal.BypassCIDRsV4 {
		if !covered[cidr] {
			t.Errorf("сеть %s не проверяется ни одной комбинацией: перебор заканчивается раньше", cidr)
		}
	}
}

func TestBypassEndpointPoolStartsWithEveryNetwork(t *testing.T) {
	// Порядок списка адресов — по одному представителю каждой сети в начале.
	// Иначе, как показано выше, до части сетей перебор может не дойти.
	want := len(internal.BypassCIDRsV4)
	if len(internal.BypassEndpointsV4) < want {
		t.Fatalf("в BypassEndpointsV4 адресов меньше, чем сетей в BypassCIDRsV4")
	}
	seen := map[string]bool{}
	for _, ip := range internal.BypassEndpointsV4[:want] {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("BypassEndpointsV4 contains an invalid address %q", ip)
		}
		seen[parsed.Mask(net.CIDRMask(24, 32)).String()+"/24"] = true
	}
	for _, cidr := range internal.BypassCIDRsV4 {
		if !seen[cidr] {
			t.Errorf("в первых %d адресах BypassEndpointsV4 нет адреса из %s", want, cidr)
		}
	}
}

func TestBypassIPv6PoolCoversItsNetworks(t *testing.T) {
	// У IPv6-хвоста перебора совсем мало места, поэтому каждая /48 должна быть
	// представлена в самом начале списка, а не где-то в глубине.
	want := len(internal.BypassCIDRsV6)
	if len(internal.BypassEndpointsV6) < want {
		t.Fatalf("в BypassEndpointsV6 адресов меньше, чем сетей в BypassCIDRsV6")
	}
	all := map[string]bool{}
	for _, ip := range internal.BypassEndpointsV6 {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("BypassEndpointsV6 contains an invalid address %q", ip)
		}
		if parsed.To4() != nil {
			t.Fatalf("BypassEndpointsV6 contains an IPv4 address %q", ip)
		}
		all[ipv6NetworkOf(parsed)] = true
	}
	head := map[string]bool{}
	for _, ip := range internal.BypassEndpointsV6[:want] {
		head[ipv6NetworkOf(net.ParseIP(ip))] = true
	}
	for _, cidr := range internal.BypassCIDRsV6 {
		if !all[cidr] {
			t.Errorf("в BypassEndpointsV6 нет адреса из %s", cidr)
		}
		if !head[cidr] {
			t.Errorf("в первых %d адресах BypassEndpointsV6 нет адреса из %s", want, cidr)
		}
	}
}

// ipv6NetworkOf возвращает /48-сеть адреса в виде, в котором её пишут CIDR-списки.
func ipv6NetworkOf(ip net.IP) string {
	masked := ip.Mask(net.CIDRMask(48, 128))
	return masked.String() + "/48"
}

func labelsOf(cands []api.TunnelCandidate) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Label)
	}
	return out
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
