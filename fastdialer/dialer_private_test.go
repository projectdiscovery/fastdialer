package fastdialer

import (
	"context"
	"net"
	"testing"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

func TestDial(t *testing.T) {
	t.Run("ZTLSWithConfig", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to start listener: %v", err)
		}
		defer func() { _ = listener.Close() }()

		serverAddr := listener.Addr().String()

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}

				// hold conn w/o completing handshake
				time.Sleep(5 * time.Second)
				_ = conn.Close()
			}
		}()

		options := DefaultOptions
		options.DialerTimeout = 100 * time.Millisecond

		dialer, err := NewDialer(options)
		if err != nil {
			t.Fatalf("Failed to create dialer: %v", err)
		}
		defer dialer.Close()

		ztlsConfig := &ztls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		}

		_, err = dialer.DialZTLSWithConfig(context.Background(), "tcp", serverAddr, ztlsConfig)
		if err == nil {
			t.Fatal("Expected an error due to timeout, got nil")
		}
	})

	t.Run("TLSWithConfigFallback", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to start listener: %v", err)
		}
		defer func() { _ = listener.Close() }()

		serverAddr := listener.Addr().String()

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				time.Sleep(5 * time.Second)
				_ = conn.Close()
			}
		}()

		options := DefaultOptions
		options.DialerTimeout = 100 * time.Millisecond
		options.DisableZtlsFallback = false

		dialer, err := NewDialer(options)
		if err != nil {
			t.Fatalf("Failed to create dialer: %v", err)
		}
		defer dialer.Close()

		_, err = dialer.DialTLSWithConfig(context.Background(), "tcp", serverAddr, DefaultTLSConfig)

		if err == nil {
			t.Fatal("Expected an error due to timeout, got nil")
		}
	})
}
