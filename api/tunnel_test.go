package api

import (
	"context"
	"errors"
	"testing"
)

type testTunnelDevice struct {
	closed bool
}

func (d *testTunnelDevice) ReadPacket([]byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (d *testTunnelDevice) WritePacket([]byte) error {
	return nil
}

func (d *testTunnelDevice) Close() error {
	d.closed = true
	return nil
}

func TestWaitForTunnelErrorReturnsReportedError(t *testing.T) {
	want := errors.New("pump failed")
	errChan := make(chan error, 1)
	errChan <- want

	if got := waitForTunnelError(context.Background(), errChan); !errors.Is(got, want) {
		t.Fatalf("waitForTunnelError() = %v, want %v", got, want)
	}
}

func TestWaitForTunnelErrorReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := waitForTunnelError(ctx, make(chan error)); !errors.Is(got, context.Canceled) {
		t.Fatalf("waitForTunnelError() = %v, want %v", got, context.Canceled)
	}
}

func TestCloseTunnelDeviceClosesClosableDevice(t *testing.T) {
	device := &testTunnelDevice{}

	closeTunnelDevice(device)

	if !device.closed {
		t.Fatal("closeTunnelDevice() did not close the device")
	}
}

func TestCloseTunnelDeviceAcceptsDeviceWithoutClose(t *testing.T) {
	type nonClosableDevice struct{}
	device := nonClosableDevice{}

	// A device without Close is not closed by this helper.
	closeTunnelDevice(deviceAdapter{TunnelDevice: device})
}

type deviceAdapter struct {
	TunnelDevice
}
