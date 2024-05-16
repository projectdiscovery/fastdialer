package dialer

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	ctxutil "github.com/projectdiscovery/utils/context"
	"github.com/projectdiscovery/utils/errkit"
	ptrutil "github.com/projectdiscovery/utils/ptr"
	utls "github.com/refraction-networking/utls"
	ztls "github.com/zmap/zcrypto/tls"
)

var (
	// ErrRetryWithZTLS is a error that indicates to retry with ZTLS
	ErrRetryWithZTLS = errkit.New("retry with ztls")
)

// ConnWrapper is a interface that implements higher level logic for a simple net.Conn
// like tls, ztls, proxy connections
type ConnWrapper interface {
	// DialTLS connects to the address on the named network using TLS.
	// If ztlsFallback is true, it will fallback to ZTLS if the handshake fails.
	DialTLS(ctx context.Context, network, address string, config *tls.Config, ztlsFallback bool) (net.Conn, error)
	// DialZTLS connects to the address on the named network using ZTLS.
	DialZTLS(ctx context.Context, network, address string, config *ztls.Config) (net.Conn, error)
	// DialTLSAndImpersonate connects to the address on the named network using TLS and impersonates with given data
	DialTLSAndImpersonate(ctx context.Context, network, address string, config *tls.Config, strategy impersonate.Strategy, identify *impersonate.Identity) (net.Conn, error)
}

type connWrap struct {
	nd net.Conn
}

// NewConnWrap creates a new connection wrapper
// that allows escalating layer 4 connections to higher level
// tls, ztls, or proxy connections
func NewConnWrap(nd net.Conn) ConnWrapper {
	return &connWrap{nd: nd}
}

// DialTLS connects to the address on the named network using TLS.
// If ztlsFallback is true, it will fallback to ZTLS if the handshake fails.
func (d *connWrap) DialTLS(ctx context.Context, network, address string, config *tls.Config, ztlsFallback bool) (conn net.Conn, err error) {
	// when errored close underlying tcp
	defer func() {
		if err != nil {
			_ = d.nd.Close()
		}
	}()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if config == nil {
		config = getDefaultTLSConfig()
	}
	// todo: check if config verification is needed
	tlsConn := tls.Client(d.nd, config)
	err = tlsConn.HandshakeContext(ctx)
	if err == nil {
		return tlsConn, nil
	}
	if errkit.IsDeadlineErr(err) || errkit.IsNetworkTemporaryErr(err) {
		return nil, errkit.Wrap(err, "tls handshake timeout")
	}
	return nil, ErrRetryWithZTLS
}

// DialTLSAndImpersonate connects to the address on the named network using TLS and impersonates with given data
func (d *connWrap) DialTLSAndImpersonate(ctx context.Context, network, address string, config *tls.Config, strategy impersonate.Strategy, identify *impersonate.Identity) (conn net.Conn, err error) {
	// when errored close underlying tcp
	defer func() {
		if err != nil {
			_ = d.nd.Close()
		}
	}()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// clone existing tls config
	uTLSConfig := &utls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		ServerName:         config.ServerName,
		MinVersion:         config.MinVersion,
		MaxVersion:         config.MaxVersion,
		CipherSuites:       config.CipherSuites,
	}

	var uTLSConn *utls.UConn
	if strategy == impersonate.Random {
		uTLSConn = utls.UClient(d.nd, uTLSConfig, utls.HelloRandomized)
	} else if strategy == impersonate.Custom {
		uTLSConn = utls.UClient(d.nd, uTLSConfig, utls.HelloCustom)
		clientHelloSpec := utls.ClientHelloSpec(ptrutil.Safe(identify))
		if err := uTLSConn.ApplyPreset(&clientHelloSpec); err != nil {
			return nil, err
		}
	}
	if err := uTLSConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uTLSConn, nil
}

// DialZTLS connects to the address on the named network using ZTLS.
func (d *connWrap) DialZTLS(ctx context.Context, network, address string, config *ztls.Config) (conn net.Conn, err error) {
	// when errored close underlying tcp
	defer func() {
		if err != nil {
			_ = d.nd.Close()
		}
	}()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if config == nil {
		config = AsZTLSConfig(getDefaultTLSConfig())
		config.CipherSuites = ztls.ChromeCiphers // for reliable fallback
	}

	ztlsConn := ztls.Client(d.nd, config)
	return ctxutil.ExecFuncWithTwoReturns(ctx, func() (net.Conn, error) {
		if err := ztlsConn.Handshake(); err != nil {
			// intentionally marshalled error to replace cause
			return nil, errkit.New("ztls handshake failure: %v", err)
		}
		return ztlsConn, nil
	})
}

// getDefaultTLSConfig returns a default tls config
func getDefaultTLSConfig() *tls.Config {
	return &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}
}

func AsZTLSConfig(tlsConfig *tls.Config) *ztls.Config {
	if tlsConfig == nil {
		tlsConfig = getDefaultTLSConfig()
	}
	ztlsConfig := &ztls.Config{
		NextProtos:             tlsConfig.NextProtos,
		ServerName:             tlsConfig.ServerName,
		ClientAuth:             ztls.ClientAuthType(tlsConfig.ClientAuth),
		InsecureSkipVerify:     tlsConfig.InsecureSkipVerify,
		CipherSuites:           tlsConfig.CipherSuites,
		SessionTicketsDisabled: tlsConfig.SessionTicketsDisabled,
		MinVersion:             tlsConfig.MinVersion,
		MaxVersion:             tlsConfig.MaxVersion,
	}
	return ztlsConfig
}
