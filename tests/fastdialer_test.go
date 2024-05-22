package tests

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"
)

func TestFastDialerIP(t *testing.T) {
	// leak test
	defer func() {
		goleak.VerifyNone(t, goleak.Pretty())
	}()

	opts := fastdialer.DefaultOptions
	opts.DialerTimeout = time.Duration(5) * time.Second
	fd, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)
	defer fd.Close()

	t.Run("Dial TCP IP", func(t *testing.T) {
		t.Parallel()
		// scanme.sh ip
		conn, err := fd.Dial(context.TODO(), "tcp", "128.199.158.128:80")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Dial UDP IP", func(t *testing.T) {
		t.Parallel()
		// scanme.sh ip
		conn, err := fd.Dial(context.TODO(), "udp", "128.199.158.128:53")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Dial TCP IP with TLS", func(t *testing.T) {
		t.Parallel()
		// scanme.sh ip
		conn, err := fd.Dial(context.TODO(), "tcp", "128.199.158.128:443")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})
}

func TestFastDialerDomains(t *testing.T) {
	// leak test
	defer func() {
		goleak.VerifyNone(t, goleak.Pretty())
	}()

	opts := fastdialer.DefaultOptions
	opts.DialerTimeout = time.Duration(5) * time.Second
	fd, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)
	defer fd.Close()

	t.Run("Dial TCP Domain", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.Dial(context.TODO(), "tcp", "scanme.sh:80")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Dial UDP Domain", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.Dial(context.TODO(), "udp", "scanme.sh:53")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Dial TCP Domain with TLS", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.DialTLS(context.TODO(), "tcp", "scanme.sh:443")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})
}

func TestFastDialerDomainMultiIP(t *testing.T) {
	// leak test
	defer func() {
		goleak.VerifyNone(t, goleak.Pretty())
	}()

	// domain that has multiple ips like projectdiscovery.io
	opts := fastdialer.DefaultOptions
	opts.DialerTimeout = time.Duration(5) * time.Second
	fd, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)
	defer fd.Close()

	t.Run("Dial TCP Domain", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.Dial(context.TODO(), "tcp", "projectdiscovery.io:80")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Dial TCP Filtered", func(t *testing.T) {
		t.Parallel()
		// this is blocked by firewall
		conn, err := fd.Dial(context.TODO(), "tcp", "projectdiscovery.io:53")
		// this will fail because of firewall but we expect this to happen fast
		// and timeout should not be stacked
		require.NotNil(t, err)
		require.Nil(t, conn)
	})

	t.Run("Dial TCP Domain with TLS", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.DialTLS(context.TODO(), "tcp", "projectdiscovery.io:443")
		require.Nil(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	})
}

func TestFastDialerDomainsInvalid(t *testing.T) {
	// leak test
	defer func() {
		goleak.VerifyNone(t, goleak.Pretty())
	}()

	opts := fastdialer.DefaultOptions
	opts.DialerTimeout = time.Duration(5) * time.Second
	fd, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)
	defer fd.Close()

	t.Run("Dial TCP Invalid Domain", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.Dial(context.TODO(), "tcp", "invalid.invalid:80")
		require.NotNil(t, err)
		require.Nil(t, conn)
	})

	t.Run("Dial TCP Invalid Domain with TLS", func(t *testing.T) {
		t.Parallel()
		conn, err := fd.DialTLS(context.TODO(), "tcp", "invalid.invalid:443")
		require.NotNil(t, err)
		require.Nil(t, conn)
	})
}

func TestFastDialerNConcurrent(t *testing.T) {
	// leak test
	defer func() {
		goleak.VerifyNone(t, goleak.Pretty())
	}()

	opts := fastdialer.DefaultOptions
	opts.DialerTimeout = time.Duration(5) * time.Second
	fd, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)
	defer fd.Close()

	wg := &sync.WaitGroup{}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// scanme.sh ip
			conn, _ := fd.Dial(context.TODO(), "tcp", "scanme.sh:80")
			if conn != nil {
				_ = conn.Close()
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _ := fd.DialTLS(context.TODO(), "tcp", "scanme.sh:443")
			if conn != nil {
				_ = conn.Close()
			}
		}()
	}

	wg.Wait()
}

func TestFastDialerHTTP(t *testing.T) {
	// sending and receiving using fastdialer connection
	opts := fastdialer.DefaultOptions
	dialer, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.Dial,
		},
	}

	resp, err := client.Get("http://scanme.sh")
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.Equal(t, resp.StatusCode, http.StatusOK)
}

func TestFastDialerHTTPS(t *testing.T) {
	// sending and receiving using fastdialer connection
	opts := fastdialer.DefaultOptions
	dialer, err := fastdialer.NewDialer(opts)
	require.Nil(t, err)
	defer dialer.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Get("https://hackerone.com/")
	require.Nil(t, err)
	require.NotNil(t, resp)
	// require.Equal(t, resp.StatusCode, http.StatusOK)
}
