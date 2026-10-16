package api

import (
	"context"
	"sync"
	"testing"
	"time"
)

// testCloser фиксирует факт закрытия.
type testCloser struct {
	once   sync.Once
	closed chan struct{}
}

func newTestCloser() *testCloser {
	return &testCloser{closed: make(chan struct{})}
}

func (c *testCloser) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *testCloser) waitClosed(t *testing.T, what string) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: tracked resource was not closed", what)
	}
}

func (c *testCloser) waitOpen(t *testing.T, what string) {
	t.Helper()
	select {
	case <-c.closed:
		t.Fatalf("%s: tracked resource was closed", what)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestDialAborterClosesTrackedResources: отмена контекста закрывает ресурсы
// незавершённой установки, в том числе зарегистрированные уже после отмены.
func TestDialAborterClosesTrackedResources(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	abort := newDialAborter(ctx)

	before := newTestCloser()
	abort.track(before)

	cancel()

	after := newTestCloser()
	abort.track(after)

	before.waitClosed(t, "resource tracked before cancellation")
	after.waitClosed(t, "resource tracked after cancellation")

	if !abort.disarm() {
		t.Fatal("disarm() = false after the aborter fired, want true")
	}
}

// TestDialAborterDisarmDetachesFromContext: после успешной установки отмена не
// должна трогать ни уже зарегистрированные, ни новые ресурсы — иначе победитель
// перебора умирает вместе с отменой остальных попыток.
func TestDialAborterDisarmDetachesFromContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	abort := newDialAborter(ctx)

	tracked := newTestCloser()
	abort.track(tracked)

	if abort.disarm() {
		t.Fatal("disarm() = true before the context was cancelled, want false")
	}

	late := newTestCloser()
	abort.track(late)

	cancel()

	tracked.waitOpen(t, "resource tracked before disarm")
	late.waitOpen(t, "resource tracked after disarm")
}

// TestDialAborterOnCancelledContext: aborter, поставленный на уже отменённый
// контекст, закрывает всё зарегистрированное сразу.
func TestDialAborterOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	abort := newDialAborter(ctx)
	c := newTestCloser()
	abort.track(c)

	c.waitClosed(t, "resource tracked on a cancelled context")
	if !abort.disarm() {
		t.Fatal("disarm() = false after the context was already cancelled, want true")
	}
}

// TestNilDialAborterIsNoop: без контекста прерывания (нитка без обхода) aborter
// отсутствует и ни на что не влияет.
func TestNilDialAborterIsNoop(t *testing.T) {
	var abort *dialAborter

	c := newTestCloser()
	abort.track(c)

	if abort.disarm() {
		t.Fatal("disarm() on a nil aborter = true, want false")
	}
	c.waitOpen(t, "resource tracked on a nil aborter")
}
