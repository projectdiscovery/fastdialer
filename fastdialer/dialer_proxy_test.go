package fastdialer

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"golang.org/x/net/proxy"
)

type trackingProxyDialer struct {
	mu          sync.Mutex
	dialedAddrs []string
	underlying  *net.Dialer
}

func (m *trackingProxyDialer) Dial(network, addr string) (net.Conn, error) {
	m.mu.Lock()
	m.dialedAddrs = append(m.dialedAddrs, addr)
	m.mu.Unlock()
	return m.underlying.Dial(network, addr)
}

type trackingContextProxyDialer struct {
	mu          sync.Mutex
	dialedAddrs []string
	contextUsed bool
	underlying  *net.Dialer
}

func (m *trackingContextProxyDialer) Dial(network, addr string) (net.Conn, error) {
	m.mu.Lock()
	m.dialedAddrs = append(m.dialedAddrs, addr)
	m.mu.Unlock()
	return m.underlying.Dial(network, addr)
}

func (m *trackingContextProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	m.mu.Lock()
	m.dialedAddrs = append(m.dialedAddrs, addr)
	m.contextUsed = true
	m.mu.Unlock()
	return m.underlying.DialContext(ctx, network, addr)
}

type blockingProxyDialer struct {
	delay time.Duration
}

func (b *blockingProxyDialer) Dial(network, addr string) (net.Conn, error) {
	time.Sleep(b.delay)
	return nil, io.EOF
}

func TestProxyDialerPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tracker := &trackingProxyDialer{underlying: &net.Dialer{}}
	var pd proxy.Dialer = tracker

	opts := DefaultOptions
	opts.ProxyDialer = &pd

	fd, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("could not create dialer: %v", err)
	}
	defer fd.Close()

	conn, err := fd.Dial(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.Close()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.dialedAddrs) == 0 {
		t.Fatalf("expected proxy dialer to be invoked, but dialedAddrs was empty")
	}
}

func TestProxyDialerTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	tracker := &trackingProxyDialer{underlying: &net.Dialer{}}
	var pd proxy.Dialer = tracker

	opts := DefaultOptions
	opts.ProxyDialer = &pd

	fd, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("could not create dialer: %v", err)
	}
	defer fd.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := fd.DialTLSWithConfig(context.Background(), "tcp", srv.Listener.Addr().String(), tlsConfig)
	if err != nil {
		t.Fatalf("dial TLS failed: %v", err)
	}
	_ = conn.Close()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.dialedAddrs) == 0 {
		t.Fatalf("expected proxy dialer to be invoked for TLS, but dialedAddrs was empty")
	}
}

func TestProxyDialerImpersonatedTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	tracker := &trackingProxyDialer{underlying: &net.Dialer{}}
	var pd proxy.Dialer = tracker

	opts := DefaultOptions
	opts.ProxyDialer = &pd

	fd, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("could not create dialer: %v", err)
	}
	defer fd.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", srv.Listener.Addr().String(), tlsConfig, impersonate.Chrome, nil)
	if err != nil {
		t.Fatalf("dial impersonated TLS failed: %v", err)
	}
	_ = conn.Close()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.dialedAddrs) == 0 {
		t.Fatalf("expected proxy dialer to be invoked for impersonated TLS, but dialedAddrs was empty")
	}
}

func TestProxyDialerContextDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tracker := &trackingContextProxyDialer{underlying: &net.Dialer{}}
	var pd proxy.Dialer = tracker

	opts := DefaultOptions
	opts.ProxyDialer = &pd

	fd, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("could not create dialer: %v", err)
	}
	defer fd.Close()

	conn, err := fd.Dial(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.Close()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if !tracker.contextUsed {
		t.Fatalf("expected ContextDialer.DialContext to be used")
	}
}

func TestProxyDialerTimeout(t *testing.T) {
	blocker := &blockingProxyDialer{delay: 300 * time.Millisecond}
	var pd proxy.Dialer = blocker

	opts := DefaultOptions
	opts.ProxyDialer = &pd
	opts.DialerTimeout = 50 * time.Millisecond

	fd, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("could not create dialer: %v", err)
	}
	defer fd.Close()

	_, err = fd.Dial(context.Background(), "tcp", "1.1.1.1:80")
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout after 50ms") {
		t.Fatalf("expected error containing 'timeout after 50ms', got %v", err)
	}
}
