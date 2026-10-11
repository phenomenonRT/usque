package api

import (
	"errors"
	"testing"
)

func TestIsRetryableHTTP3ConnectFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "remote protocol violation while reading response",
			err:  errors.New("connect-ip: failed to read response: http3: parsing frame failed: PROTOCOL_VIOLATION (remote)"),
			want: true,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "protocol violation without response read failure",
			err:  errors.New("http3: PROTOCOL_VIOLATION (remote)"),
			want: false,
		},
		{
			name: "response read timeout",
			err:  errors.New("failed to read response: context deadline exceeded"),
			want: false,
		},
		{
			name: "unrelated connection error",
			err:  errors.New("connection refused"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableHTTP3ConnectFailure(tt.err); got != tt.want {
				t.Fatalf("isRetryableHTTP3ConnectFailure(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
