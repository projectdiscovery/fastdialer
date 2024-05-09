package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	errorutil "github.com/projectdiscovery/utils/errors"
	ptrutil "github.com/projectdiscovery/utils/ptr"
	utls "github.com/refraction-networking/utls"
	ztls "github.com/zmap/zcrypto/tls"
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
func (d *connWrap) DialTLS(ctx context.Context, network, address string, config *tls.Config, ztlsFallback bool) (net.Conn, error) {
	// todo: check if config verification is needed
	tlsConn := tls.Client(d.nd, config)
	err := tlsConn.HandshakeContext(ctx)
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || !ztlsFallback {
		return tlsConn, nil
	}
	// fallback with chrome ciphers by default

}

// DialTLSAndImpersonate connects to the address on the named network using TLS and impersonates with given data
func (d *connWrap) DialTLSAndImpersonate(ctx context.Context, network, address string, config *tls.Config, strategy impersonate.Strategy, identify *impersonate.Identity) (net.Conn, error) {
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
func (d *connWrap) DialZTLS(ctx context.Context, network, address string, config *ztls.Config) (net.Conn, error) {
	ztlsConn := ztls.Client(d.nd, config)
	// use execWithReturn to inject context
	if err := ztlsConn.Handshake(); err != nil {
		return nil, err
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
