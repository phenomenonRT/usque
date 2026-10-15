package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
	}()

	(*packetBufsPtr)[0] = pkt
	_, err := n.dev.Write(*packetBufsPtr, 0)
	return err
}

// Close closes the underlying TUN device and unblocks pending reads.
func (n *NetstackAdapter) Close() error {
	return n.dev.Close()
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// Close closes the underlying TUN device and unblocks pending reads.
func (w *WaterAdapter) Close() error {
	return w.iface.Close()
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// pumpShutdownGrace bounds how long the supervisor waits for both forwarding
// pumps to exit after an error before spawning a fresh pair. A device-side
// pump may still be parked in a blocking TUN read during this window; the
// readMu serializes any overlap with the next cycle's device reader.
const pumpShutdownGrace = 2 * time.Second

// CONNECT-IP context ID 0 is encoded as a one-byte QUIC varint. Reserving this
// byte before packets lets connect-ip-go send outbound datagrams in place.
const datagramContextIDHeadroom = 1

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          net.Addr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	UseHTTP2          bool
	// Candidates, when non-empty, enables client-side bypass: the supervisor
	// rotates through endpoint/SNI/transport combinations (SNI is carried in
	// each candidate's TLSConfig) until one connects, and remembers the winner
	// for subsequent reconnects. TLSConfig/Endpoint/UseHTTP2 are ignored then.
	Candidates []TunnelCandidate
	// Fragment optionally splits the TLS ClientHello into several TCP segments
	// (HTTP/2 candidates only) to evade DPI.
	Fragment *TLSFragmentConfig
	// ConnectTimeout bounds a single candidate attempt during rotation. Zero
	// means no per-candidate timeout (the parent context still applies).
	ConnectTimeout time.Duration
	// OnConnect is a path to an executable run after every successful tunnel
	// connect. It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnConnect string
	// OnDisconnect is a path to an executable run after every tunnel loss.
	// It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnDisconnect string
	// HookEnv is a set of USQUE_* environment variables layered on top of the
	// parent process env for OnConnect / OnDisconnect invocations. USQUE_EVENT
	// and USQUE_ENDPOINT are set by MaintainTunnel itself.
	HookEnv map[string]string
}

// cloneHookEnv returns a shallow copy of src so concurrent hook invocations
// do not share a map.
func cloneHookEnv(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes first.
// Returns ctx.Err() on cancellation and nil on normal completion.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// waitForTunnelError returns when either a forwarding pump reports an error
// or the tunnel context is cancelled.
func waitForTunnelError(ctx context.Context, errChan <-chan error) error {
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeTunnelDevice closes devices that expose Close. This is used only when
// the owning tunnel context is cancelled, not during ordinary reconnects.
func closeTunnelDevice(device TunnelDevice) {
	if device == nil {
		return
	}
	if closer, ok := device.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			log.Printf("Failed to close TUN device during shutdown: %v", err)
		}
	}
}

// validateEndpoint ensures the endpoint type matches the selected transport.
func validateEndpoint(endpoint net.Addr, useHTTP2 bool) {
	if useHTTP2 {
		if _, ok := endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/2 mode requires a *net.TCPAddr endpoint, got %T", endpoint)
		}
		return
	}
	if _, ok := endpoint.(*net.UDPAddr); !ok {
		log.Fatalf("MaintainTunnel: HTTP/3 mode requires a *net.UDPAddr endpoint, got %T", endpoint)
	}
}

// tunnelSession holds an established Connect-IP tunnel and its transports.
type tunnelSession struct {
	candidate TunnelCandidate
	udpConn   *net.UDPConn
	transport *http3.Transport
	ipConn    *connectip.Conn
	response  *http.Response
}

// close releases every transport owned by the session.
func (s *tunnelSession) close() {
	if s == nil {
		return
	}
	if s.ipConn != nil {
		_ = s.ipConn.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
}

// tunnelCandidates returns the effective candidate list. When no bypass
// candidates were configured, the single TLSConfig/Endpoint pair is used.
func tunnelCandidates(cfg MaintainTunnelConfig) []TunnelCandidate {
	if len(cfg.Candidates) > 0 {
		return cfg.Candidates
	}
	label := "config endpoint"
	if cfg.Endpoint != nil {
		label = cfg.Endpoint.String()
	}
	return []TunnelCandidate{{
		TLSConfig: cfg.TLSConfig,
		Endpoint:  cfg.Endpoint,
		UseHTTP2:  cfg.UseHTTP2,
		Label:     label,
	}}
}

// establishTunnel tries candidates round-robin starting at start until one
// yields a 200 Connect-IP response. It returns the session and the index of the
// winning candidate so the caller can prefer it on the next reconnect.
func establishTunnel(ctx context.Context, cfg MaintainTunnelConfig, cands []TunnelCandidate, start int) (*tunnelSession, int, error) {
	if len(cands) == 0 {
		return nil, 0, errors.New("no connection candidates configured")
	}

	var lastErr error
	for i := 0; i < len(cands); i++ {
		idx := (start + i) % len(cands)
		cand := cands[idx]

		attemptCtx := ctx
		var cancel context.CancelFunc
		if cfg.ConnectTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, cfg.ConnectTimeout)
		}

		log.Printf("Establishing MASQUE connection to %s (%s)", cand.Endpoint, cand.Label)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			attemptCtx,
			cand.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize),
			internal.ConnectURI,
			cand.Endpoint,
			cand.UseHTTP2,
			cfg.Fragment,
		)
		if cancel != nil {
			cancel()
		}

		if err != nil {
			lastErr = err
			log.Printf("Candidate %s failed: %v", cand.Label, err)
			closePartialConnection(ipConn, tr, udpConn)
			if ctx.Err() != nil {
				return nil, idx, ctx.Err()
			}
			continue
		}

		if rsp == nil || rsp.StatusCode != http.StatusOK {
			status := "no response"
			if rsp != nil {
				status = rsp.Status
			}
			lastErr = fmt.Errorf("candidate %s: unexpected status %s", cand.Label, status)
			log.Printf("Candidate %s rejected: %s", cand.Label, status)
			closePartialConnection(ipConn, tr, udpConn)
			if ctx.Err() != nil {
				return nil, idx, ctx.Err()
			}
			continue
		}

		return &tunnelSession{
			candidate: cand,
			udpConn:   udpConn,
			transport: tr,
			ipConn:    ipConn,
			response:  rsp,
		}, idx, nil
	}

	return nil, start, lastErr
}

// closePartialConnection closes whatever transports a failed attempt created.
func closePartialConnection(ipConn *connectip.Conn, tr *http3.Transport, udpConn *net.UDPConn) {
	if ipConn != nil {
		_ = ipConn.Close()
	}
	if tr != nil {
		_ = tr.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	candidates := tunnelCandidates(cfg)
	for _, cand := range candidates {
		validateEndpoint(cand.Endpoint, cand.UseHTTP2)
	}
	startIdx := 0

	// Cancellation must also interrupt blocking TUN reads, including the idle
	// wait before a connection is established. The concrete adapters close the
	// underlying device; ordinary reconnects leave it open.
	stopCloseDevice := context.AfterFunc(ctx, func() {
		closeTunnelDevice(cfg.Device)
	})
	// Ensure AfterFunc is cancelled before MaintainTunnel returns so it never
	// fires after the function has exited.
	defer stopCloseDevice()

	packetBufferPool := NewNetBuffer(cfg.MTU + datagramContextIDHeadroom)

	for {
		if ctx.Err() != nil {
			return
		}

		if !cfg.AlwaysReconnect {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")
			buf := packetBufferPool.Get()
			n, err := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
			if err != nil {
				packetBufferPool.Put(buf)
				log.Printf("Failed to read from TUN device while waiting for activity: %v", err)
				if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
					return
				}
				continue
			}
			packetBufferPool.Put(buf)
			log.Printf("Detected outbound activity (%d bytes). Reconnecting...", n)
		}

		session, winner, err := establishTunnel(ctx, cfg, candidates, startIdx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Failed to connect tunnel: %v", err)
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}
		startIdx = winner

		udpConn := session.udpConn
		tr := session.transport
		ipConn := session.ipConn

		log.Printf("Connected to MASQUE server via %s", session.candidate.Label)

		if cfg.OnConnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "connect"
			env["USQUE_ENDPOINT"] = session.candidate.Endpoint.String()
			RunHook(cfg.OnConnect, env)
		}

		errChan := make(chan error, 2)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var readMu sync.Mutex

		wg.Add(2)

		go func() {
			defer wg.Done()
			for {
				if pumpCtx.Err() != nil {
					return
				}
				buf := packetBufferPool.Get()
				readMu.Lock()
				n, err := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
				readMu.Unlock()
				if err != nil {
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %w", err)
					return
				}
				if pumpCtx.Err() != nil {
					packetBufferPool.Put(buf)
					return
				}
				icmp, err := ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)
				if err != nil {
					packetBufferPool.Put(buf)
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %w", err)
						return
					}
					log.Printf("Error writing to IP connection: %v, continuing...", err)
					continue
				}
				packetBufferPool.Put(buf)

				if len(icmp) > 0 {
					if err := cfg.Device.WritePacket(icmp); err != nil {
						if errors.As(err, new(*connectip.CloseError)) {
							errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %w", err)
							return
						}
						log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
					}
				}
			}
		}()

		go func() {
			defer wg.Done()
			for {
				packet, err := ipConn.ReadPacketZeroCopy(true)
				if err != nil {
					// In bypass mode the winning candidate picks the transport,
					// which may differ from the command-level flag.
					if session.candidate.UseHTTP2 {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %w", err)
						return
					}
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %w", err)
						return
					}
					log.Printf("Error reading from IP connection: %v, continuing...", err)
					continue
				}
				if err := cfg.Device.WritePacket(packet); err != nil {
					errChan <- fmt.Errorf("failed to write to TUN device: %w", err)
					return
				}
			}
		}()

		err = waitForTunnelError(ctx, errChan)
		if ctx.Err() != nil {
			log.Printf("Stopping tunnel: %v", ctx.Err())
		} else {
			log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
		}

		if ctx.Err() == nil && cfg.OnDisconnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "disconnect"
			env["USQUE_ENDPOINT"] = session.candidate.Endpoint.String()
			RunHook(cfg.OnDisconnect, env)
		}

		cancelPumps()
		_ = ipConn.Close()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(pumpShutdownGrace):
			log.Printf("Pump shutdown grace of %s expired; a stale TUN reader may still be parked (readMu will serialize next cycle)", pumpShutdownGrace)
		}

		if tr != nil {
			_ = tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
			return
		}
	}
}
