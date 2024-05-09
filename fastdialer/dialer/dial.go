package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	errorutil "github.com/projectdiscovery/utils/errors"
	ptrutil "github.com/projectdiscovery/utils/ptr"
	utls "github.com/refraction-networking/utls"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/proxy"
)

// SimpleDialer only supports dialing to a network address it does not support higher level protocols like TLS
type SimpleDialer interface {
	// Dial connects to the address on the named network.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// DialWrapper is a interface that implements higher level logic for dialing
// while taking a SimpleDialer as the base dialer
type DialWrapper interface {
	// Dial connects to the address on the named network.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	// DialTLS connects to the address on the named network using TLS.
	// If ztlsFallback is true, it will fallback to ZTLS if the handshake fails.
	DialTLS(ctx context.Context, network, address string, config *tls.Config, ztlsFallback bool) (net.Conn, error)
	// DialZTLS connects to the address on the named network using ZTLS.
	DialZTLS(ctx context.Context, network, address string, config *ztls.Config) (net.Conn, error)
	// DialTLSAndImpersonate connects to the address on the named network using TLS and impersonates with given data
	DialTLSAndImpersonate(ctx context.Context, network, address string, config *tls.Config, strategy impersonate.Strategy, identify *impersonate.Identity) (net.Conn, error)
	// WithProxyDialer dials with a proxy dialer. (does not suppport TLS or ZTLS)
	WithProxyDialer(ctx context.Context, proxyDialer proxy.Dialer, network, address string) (net.Conn, error)
}

type dialerX struct {
	nd *net.Dialer
}

func NewDialerX(nd *net.Dialer) DialWrapper {
	return &dialerX{nd: nd}
}

// Dial connects to the address on the named network.
func (d *dialerX) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return d.nd.Dial(network, address)
}

// DialTLS connects to the address on the named network using TLS.
// If ztlsFallback is true, it will fallback to ZTLS if the handshake fails.
func (d *dialerX) DialTLS(ctx context.Context, network, address string, config *tls.Config, ztlsFallback bool) (net.Conn, error) {
	// fallback to ztls  in case of handshake error with chrome ciphers
	// ztls fallback can either be disabled by setting env variable DISABLE_ZTLS_FALLBACK=true or by setting DisableZtlsFallback=true in options
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !(d.options.DisableZtlsFallback && disableZTLSFallback) {

	}
	var ztlsconfigCopy *ztls.Config
	if opts.shouldUseZTLS {
		ztlsconfigCopy = opts.ztlsconfig.Clone()
	} else {
		if opts.tlsconfig == nil {
			opts.tlsconfig = &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			}
		}
		ztlsconfigCopy, err = AsZTLSConfig(opts.tlsconfig)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not convert tls config to ztls config")
		}
	}
	ztlsconfigCopy.CipherSuites = ztls.ChromeCiphers
	conn, err = ztls.DialWithDialer(d.dialer, opts.network, hostPort, ztlsconfigCopy)
	err = errorutil.WrapfWithNil(err, "ztls fallback failed")
}

// DialTLSAndImpersonate connects to the address on the named network using TLS and impersonates with given data
func (d *dialerX) DialTLSAndImpersonate(ctx context.Context, network, address string, config *tls.Config, strategy *impersonate.Strategy, identify *impersonate.Identity) (net.Conn, error) {
	// clone existing tls config
	uTLSConfig := &utls.Config{
		InsecureSkipVerify: tlsconfigCopy.InsecureSkipVerify,
		ServerName:         tlsconfigCopy.ServerName,
		MinVersion:         tlsconfigCopy.MinVersion,
		MaxVersion:         tlsconfigCopy.MaxVersion,
		CipherSuites:       tlsconfigCopy.CipherSuites,
	}

	var uTLSConn *utls.UConn
	if opts.imperStrategy == impersonate.Random {
		uTLSConn = utls.UClient(nativeConn, uTLSConfig, utls.HelloRandomized)
	} else if opts.imperStrategy == impersonate.Custom {
		uTLSConn = utls.UClient(nativeConn, uTLSConfig, utls.HelloCustom)
		clientHelloSpec := utls.ClientHelloSpec(ptrutil.Safe(opts.impersonateIdentity))
		if err := uTLSConn.ApplyPreset(&clientHelloSpec); err != nil {
			return nil, err
		}
	}
	if err := uTLSConn.Handshake(); err != nil {
		return nil, err
	}
}

// DialZTLS connects to the address on the named network using ZTLS.
func (d *dialerX) DialZTLS(ctx context.Context, network, address string, config *ztls.Config) (net.Conn, error) {
}

// WithProxyDialer dials with a proxy dialer. (does not suppport TLS or ZTLS)
func (d *dialerX) WithProxyDialer(ctx context.Context, proxyDialer proxy.Dialer, network, address string) (net.Conn, error) {
	dialer := *d.proxyDialer
	// timeout not working for socks5 proxy dialer
	// tying to handle it here
	connectionCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err = dialer.Dial(opts.network, hostPort)
		if err != nil {
			errCh <- err
			return
		}
		connectionCh <- conn
	}()
	// using timer as time.After is not recovered gy GC
	dialerTime := time.NewTimer(d.options.DialerTimeout)
	defer dialerTime.Stop()
	select {
	case <-dialerTime.C:
		return nil, fmt.Errorf("timeout after %v", d.options.DialerTimeout)
	case conn = <-connectionCh:
	case err = <-errCh:
	}
}

// // dialtcp
// func (d *Dialer) dialtcp(ctx context.Context, network, address string) (net.Conn, error) {
// 	return d.dialer.DialContext(ctx, network, address)
// }

// // dialtls
// func (d *Dialer) dialtls(_ context.Context, network, address string, config *tls.Config) (net.Conn, error) {
// 	return tls.DialWithDialer(d.dialer, network, address, config)
// }

// // dialztls
// func (d *Dialer) dialztls(ctx context.Context, network, address string, config *ztls.Config) (net.Conn, error) {
// 	return ztls.DialWithDialer(d.dialer, network, address, config)
// }
