package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// stubConnectTunnel подменяет ConnectTunnel на время теста: настоящая попытка
// ходит в сеть, а здесь нужны только контексты, с которыми её запускают.
// Возвращаемое значение-сессия в тестах не используется, поэтому транспорт не
// создаётся.
func stubConnectTunnel(t *testing.T, fn func(lifetimeCtx, dialCtx context.Context, endpoint net.Addr) (*connectip.Conn, *http.Response, error)) {
	t.Helper()

	previous := connectCandidate
	connectCandidate = func(ctx context.Context, _ *tls.Config, _ *quic.Config, _ string, endpoint net.Addr, _ bool, _ *TLSFragmentConfig, opts ...ConnectOption) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
		ipConn, rsp, err := fn(ctx, applyConnectOptions(opts).dialCtx, endpoint)
		return nil, nil, ipConn, rsp, err
	}
	t.Cleanup(func() { connectCandidate = previous })
}

func okResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK"}
}

// TestParallelSweepKeepsWinnerContextAlive проверяет то, из-за чего туннель
// раньше переподключался по кругу: отмена контекста остальных попыток убивала
// победителя, потому что установленное соединение остаётся привязанным к своему
// контексту (поток HTTP/2 CONNECT).
func TestParallelSweepKeepsWinnerContextAlive(t *testing.T) {
	ctx := context.Background()

	winnerEndpoint := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	loserEndpoint := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1701}

	var winnerLifetime, winnerDial, loserDial context.Context
	loserAborted := make(chan struct{})

	stubConnectTunnel(t, func(lifetime, dial context.Context, endpoint net.Addr) (*connectip.Conn, *http.Response, error) {
		if endpoint.String() == winnerEndpoint.String() {
			winnerLifetime, winnerDial = lifetime, dial
			return &connectip.Conn{}, okResponse(), nil
		}

		loserDial = dial
		<-dial.Done()
		close(loserAborted)
		return nil, nil, context.Cause(dial)
	})

	cands := []TunnelCandidate{
		{Endpoint: loserEndpoint, Label: "loser"},
		{Endpoint: winnerEndpoint, Label: "winner"},
	}
	cfg := MaintainTunnelConfig{Parallel: 2, ConnectTimeout: time.Minute}

	sess, idx, err := establishTunnelParallel(ctx, cfg, cands, 0)
	if err != nil {
		t.Fatalf("establishTunnelParallel() error = %v, want the winner", err)
	}
	if sess == nil || idx != 1 {
		t.Fatalf("establishTunnelParallel() = %v, idx %d; want session of candidate 1", sess, idx)
	}

	select {
	case <-loserAborted:
	case <-time.After(5 * time.Second):
		t.Fatal("loser attempt was not aborted after the winner connected")
	}

	if winnerLifetime == nil || winnerDial == nil {
		t.Fatal("winner contexts were not recorded")
	}
	if winnerLifetime.Err() != nil {
		t.Fatalf("winner lifetime context is cancelled (%v): an established tunnel dies with it", winnerLifetime.Err())
	}
	if winnerDial.Err() == nil {
		t.Fatal("winner dial context is still alive, want it cancelled after establishment")
	}
	if loserDial == nil || loserDial.Err() == nil {
		t.Fatal("loser dial context is still alive, want the loser to be aborted")
	}
}

// TestAttemptTimeoutAbortsEstablishmentOnly проверяет, что таймаут попытки
// прерывает установку, но не трогает контекст времени жизни туннеля.
func TestAttemptTimeoutAbortsEstablishmentOnly(t *testing.T) {
	ctx := context.Background()
	endpoint := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	var lifetime, dial context.Context
	observed := make(chan struct{})

	stubConnectTunnel(t, func(l, d context.Context, _ net.Addr) (*connectip.Conn, *http.Response, error) {
		lifetime, dial = l, d
		<-d.Done()
		close(observed)
		return nil, nil, context.Cause(d)
	})

	cfg := MaintainTunnelConfig{ConnectTimeout: 30 * time.Millisecond}

	start := time.Now()
	sess, err := tryCandidate(ctx, nil, cfg, TunnelCandidate{Endpoint: endpoint, Label: "slow"})
	elapsed := time.Since(start)

	if sess != nil {
		t.Fatalf("tryCandidate() returned a session %v, want none", sess)
	}
	if err == nil {
		t.Fatal("tryCandidate() error = nil, want the timeout to abort the attempt")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("tryCandidate() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("tryCandidate() took %s, want the timeout to abort the establishment", elapsed)
	}

	<-observed
	if lifetime == nil || lifetime.Err() != nil {
		t.Fatalf("lifetime context = %v, want it untouched by the attempt timeout", lifetime)
	}
	if dial == nil || dial.Err() == nil {
		t.Fatal("dial context is still alive, want it cancelled by the timeout")
	}
}

// TestCloseTunnelSessionHandlesEmptySession проверяет, что закрытие сессии,
// которую никто не использовал (в том числе после гонки двух подключений),
// не падает.
func TestCloseTunnelSessionHandlesEmptySession(t *testing.T) {
	closeTunnelSession(nil)
	closeTunnelSession(&tunnelSession{})

	results := make(chan tunnelAttempt, 2)
	results <- tunnelAttempt{}
	results <- tunnelAttempt{session: &tunnelSession{}}
	close(results)

	done := make(chan struct{})
	go func() {
		drainLateAttempts(results, 2)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drainLateAttempts did not finish")
	}
}
