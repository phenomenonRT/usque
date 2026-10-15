package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	defaultL4ConnectTimeout    = 15 * time.Second
	defaultL4ConnectRetryCount = 2
	// defaultL4CandidateTimeout bounds a single endpoint attempt while rotating.
	defaultL4CandidateTimeout = 4 * time.Second
)

// DNSResolver resolves a hostname for L4Proxy local DNS mode.
type DNSResolver interface {
	Resolve(ctx context.Context, name string) (net.IP, error)
}

// L4ProxyConfig configures a new L4Proxy.
type L4ProxyConfig struct {
	TLSConfig         *tls.Config
	QUICConfig        *quic.Config
	Endpoint          *net.UDPAddr
	DNSResolver       DNSResolver
	ResolveLocally    bool
	OnConnect         func(target string)
	OnDisconnect      func(target string)
	ConnectTimeout    time.Duration
	ConnectRetryCount int
	// Candidates, when non-empty, enables endpoint/SNI rotation (DPI bypass).
	// Every candidate must carry a *net.UDPAddr endpoint (L4 is HTTP/3 only).
	Candidates []TunnelCandidate
	// CandidateTimeout bounds a single candidate attempt during rotation.
	CandidateTimeout time.Duration
	// Parallel keeps that many candidate attempts in flight at once. Values
	// below two mean sequential attempts.
	Parallel int
}

// L4Proxy opens one HTTP/3 CONNECT stream for each proxied TCP connection.
type L4Proxy struct {
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	endpoint          *net.UDPAddr
	dnsResolver       DNSResolver
	resolveLocally    bool
	onConnect         func(target string)
	onDisconnect      func(target string)
	connectTimeout    time.Duration
	connectRetryCount int
	candidates        []TunnelCandidate
	candidateTimeout  time.Duration
	parallel          int
	candidateIdx      atomic.Uint32
	connMu            sync.Mutex
	client            *l4HTTP3Client
	dialFn            func(context.Context, string) (*l4TCPConn, error)
}

type l4HTTP3Client struct {
	udpConn    *net.UDPConn
	quicConn   *quic.Conn
	clientConn *http3.ClientConn
}

// NewL4Proxy creates an L4 proxy dialer from a configuration struct.
func NewL4Proxy(cfg L4ProxyConfig) (*L4Proxy, error) {
	if cfg.TLSConfig == nil && len(cfg.Candidates) == 0 {
		return nil, fmt.Errorf("missing TLS config")
	}
	if cfg.Endpoint == nil && len(cfg.Candidates) == 0 {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}
	if cfg.ResolveLocally && cfg.DNSResolver == nil {
		return nil, fmt.Errorf("missing DNS resolver")
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultL4ConnectTimeout
	}
	if cfg.ConnectRetryCount <= 0 {
		cfg.ConnectRetryCount = defaultL4ConnectRetryCount
	}
	for _, cand := range cfg.Candidates {
		if _, ok := cand.Endpoint.(*net.UDPAddr); !ok {
			return nil, fmt.Errorf("l4 candidate %q requires a UDP endpoint", cand.Label)
		}
	}
	if len(cfg.Candidates) > 0 && cfg.CandidateTimeout <= 0 {
		cfg.CandidateTimeout = defaultL4CandidateTimeout
	}

	proxy := &L4Proxy{
		tlsConfig:         cfg.TLSConfig,
		quicConfig:        cfg.QUICConfig,
		endpoint:          cfg.Endpoint,
		dnsResolver:       cfg.DNSResolver,
		resolveLocally:    cfg.ResolveLocally,
		onConnect:         cfg.OnConnect,
		onDisconnect:      cfg.OnDisconnect,
		connectTimeout:    cfg.ConnectTimeout,
		connectRetryCount: cfg.ConnectRetryCount,
		candidates:        cfg.Candidates,
		candidateTimeout:  cfg.CandidateTimeout,
		parallel:          cfg.Parallel,
	}
	proxy.dialFn = proxy.dial
	return proxy, nil
}

// dialCandidates returns the effective endpoint list. When no bypass candidates
// were configured, the single TLSConfig/Endpoint pair is used.
func (p *L4Proxy) dialCandidates() []TunnelCandidate {
	if len(p.candidates) > 0 {
		return p.candidates
	}
	if p.endpoint == nil || p.tlsConfig == nil {
		return nil
	}
	return []TunnelCandidate{{
		TLSConfig: p.tlsConfig,
		Endpoint:  p.endpoint,
		Label:     p.endpoint.String(),
	}}
}

// nextCandidateIdx returns a rotating index across the candidate list.
func (p *L4Proxy) nextCandidateIdx() uint32 {
	return p.candidateIdx.Add(1) - 1
}

// DialContext connects target over an L4 MASQUE HTTP/3 CONNECT stream.
func (p *L4Proxy) DialContext(ctx context.Context, target string) (net.Conn, error) {
	if p == nil || p.dialFn == nil {
		return nil, fmt.Errorf("missing dialer")
	}
	if p.endpoint == nil && len(p.candidates) == 0 {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}
	target, err := p.resolveTarget(ctx, target)
	if err != nil {
		return nil, err
	}

	timeout := p.connectTimeout
	if timeout <= 0 {
		timeout = defaultL4ConnectTimeout
	}
	attempts := p.connectRetryCount
	if attempts <= 0 {
		attempts = defaultL4ConnectRetryCount
	}
	dial := p.dialFn
	if dial == nil {
		dial = p.dial
	}

	var lastErr error
	for range attempts {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dial(dialCtx, target)
		cancel()
		if err == nil {
			if p.onConnect != nil {
				p.onConnect(target)
			}
			conn.onClose = func() {
				if p.onDisconnect != nil {
					p.onDisconnect(target)
				}
			}
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (p *L4Proxy) resolveTarget(ctx context.Context, target string) (string, error) {
	if !p.resolveLocally {
		return target, nil
	}
	if p.dnsResolver == nil {
		return "", fmt.Errorf("missing DNS resolver")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: %w", target, err)
	}
	if net.ParseIP(host) != nil {
		return target, nil
	}
	ip, err := p.dnsResolver.Resolve(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func (p *L4Proxy) dial(ctx context.Context, target string) (*l4TCPConn, error) {
	h3Client, err := p.getOrCreateClientConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := h3Client.clientConn.OpenRequestStream(ctx)
	if err != nil {
		if !shouldReconnectOnOpenStreamError(ctx, err) {
			return nil, err
		}
		// The cached HTTP/3 connection might be stale; reconnect once and retry.
		p.closeClientConnIfCurrent(h3Client)
		h3Client, err = p.getOrCreateClientConn(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = h3Client.clientConn.OpenRequestStream(ctx)
		if err != nil {
			if shouldReconnectOnOpenStreamError(ctx, err) {
				p.closeClientConnIfCurrent(h3Client)
			}
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+target, nil)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	req.Host = target
	if err := stream.SendRequestHeader(req); err != nil {
		_ = stream.Close()
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_ = stream.Close()
		return nil, fmt.Errorf("CONNECT rejected with status %d", response.StatusCode)
	}
	return &l4TCPConn{stream: stream, local: h3Client.udpConn.LocalAddr(), remote: l4Addr(target)}, nil
}

func shouldReconnectOnOpenStreamError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if ctx != nil && (errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return false
	}
	return true
}

func (p *L4Proxy) getOrCreateClientConn(ctx context.Context) (*l4HTTP3Client, error) {
	p.connMu.Lock()
	if p.client != nil {
		client := p.client
		p.connMu.Unlock()
		return client, nil
	}
	p.connMu.Unlock()

	candidates := p.dialCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}

	var (
		newClient *l4HTTP3Client
		err       error
	)
	if p.parallel > 1 && len(candidates) > 1 {
		newClient, err = p.dialCandidatesParallel(ctx, candidates)
	} else {
		newClient, err = p.dialCandidatesSequential(ctx, candidates)
	}
	if err != nil {
		return nil, err
	}

	p.connMu.Lock()
	if p.client != nil {
		current := p.client
		p.connMu.Unlock()
		closeL4HTTP3(newClient.udpConn, newClient.quicConn)
		return current, nil
	}
	p.client = newClient
	p.connMu.Unlock()

	return newClient, nil
}

// dialCandidatesSequential walks the candidates round-robin, one at a time.
func (p *L4Proxy) dialCandidatesSequential(ctx context.Context, candidates []TunnelCandidate) (*l4HTTP3Client, error) {
	var lastErr error
	for range candidates {
		cand := candidates[p.nextCandidateIdx()%uint32(len(candidates))]
		client, err := p.tryCandidate(ctx, cand)
		if err == nil {
			return client, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no connection candidates")
	}
	return nil, lastErr
}

// dialCandidatesParallel keeps p.parallel attempts in flight at once and stops
// as soon as one connects.
func (p *L4Proxy) dialCandidatesParallel(ctx context.Context, candidates []TunnelCandidate) (*l4HTTP3Client, error) {
	type result struct {
		client *l4HTTP3Client
		err    error
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	limit := p.parallel
	if limit > len(candidates) {
		limit = len(candidates)
	}

	results := make(chan result, limit)
	start := int(p.nextCandidateIdx())
	launched, inFlight := 0, 0

	launch := func() {
		cand := candidates[(start+launched)%len(candidates)]
		launched++
		inFlight++
		go func() {
			client, err := p.tryCandidate(runCtx, cand)
			results <- result{client: client, err: err}
		}()
	}

	for inFlight < limit {
		launch()
	}

	var lastErr error
	for inFlight > 0 {
		var res result
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res = <-results:
		}
		inFlight--

		if res.client != nil {
			cancel() // stop the attempts that are still running
			return res.client, nil
		}
		lastErr = res.err
		if launched < len(candidates) && ctx.Err() == nil {
			launch()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no connection candidates")
	}
	return nil, lastErr
}

// tryCandidate performs a single HTTP/3 connection attempt.
func (p *L4Proxy) tryCandidate(ctx context.Context, cand TunnelCandidate) (*l4HTTP3Client, error) {
	endpoint, ok := cand.Endpoint.(*net.UDPAddr)
	if !ok || endpoint == nil {
		return nil, fmt.Errorf("candidate %q is not a UDP endpoint", cand.Label)
	}

	attemptCtx := ctx
	var cancel context.CancelFunc
	if p.candidateTimeout > 0 {
		attemptCtx, cancel = context.WithTimeout(ctx, p.candidateTimeout)
	}
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	udpConn, err := listenUDPForEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	// without ConnectionIDLength set, backend occasionally throws PROTOCOL_VIOLATION
	// and that closes our connection
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	quicConn, err := qtr.Dial(attemptCtx, endpoint, cand.TLSConfig, p.quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}

	return &l4HTTP3Client{
		udpConn:    udpConn,
		quicConn:   quicConn,
		clientConn: (&http3.Transport{}).NewClientConn(quicConn),
	}, nil
}

func (p *L4Proxy) closeClientConnIfCurrent(expected *l4HTTP3Client) {
	if expected == nil {
		return
	}

	p.connMu.Lock()
	if p.client != expected {
		p.connMu.Unlock()
		return
	}
	p.client = nil
	p.connMu.Unlock()

	closeL4HTTP3(expected.udpConn, expected.quicConn)
}

func listenUDPForEndpoint(endpoint *net.UDPAddr) (*net.UDPConn, error) {
	if endpoint.IP.To4() == nil {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero})
	}
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
}

func closeL4HTTP3(udpConn *net.UDPConn, quicConn *quic.Conn) {
	if quicConn != nil {
		_ = quicConn.CloseWithError(0, "")
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

type l4TCPConn struct {
	stream  l4Stream
	local   net.Addr
	remote  net.Addr
	once    sync.Once
	onClose func()
}

type l4Stream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func (c *l4TCPConn) Read(b []byte) (int, error) {
	if c.stream == nil {
		return 0, net.ErrClosed
	}
	return c.stream.Read(b)
}

func (c *l4TCPConn) Write(b []byte) (int, error) {
	if c.stream == nil {
		return 0, net.ErrClosed
	}
	return c.stream.Write(b)
}

func (c *l4TCPConn) CloseWrite() error {
	if c.stream == nil {
		return nil
	}
	return c.stream.Close()
}
func (c *l4TCPConn) CloseRead() error {
	if c.stream == nil {
		return nil
	}
	c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return nil
}
func (c *l4TCPConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.CloseWrite()
		_ = c.CloseRead()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}
func (c *l4TCPConn) LocalAddr() net.Addr {
	if c.local == nil {
		return l4Addr("l4")
	}
	return c.local
}
func (c *l4TCPConn) RemoteAddr() net.Addr { return c.remote }
func (c *l4TCPConn) SetDeadline(t time.Time) error {
	if c.stream == nil {
		return nil
	}
	return c.stream.SetDeadline(t)
}
func (c *l4TCPConn) SetReadDeadline(t time.Time) error {
	if c.stream == nil {
		return nil
	}
	return c.stream.SetReadDeadline(t)
}
func (c *l4TCPConn) SetWriteDeadline(t time.Time) error {
	if c.stream == nil {
		return nil
	}
	return c.stream.SetWriteDeadline(t)
}

type l4Addr string

func (a l4Addr) Network() string { return "masque-l4-tcp" }
func (a l4Addr) String() string  { return string(a) }

type closeWriter interface {
	CloseWrite() error
}

// RelayTCP copies bytes in both directions and preserves TCP half-close.
func RelayTCP(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	relay := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}
	go relay(a, b)
	go relay(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
