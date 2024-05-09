package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	iputil "github.com/projectdiscovery/utils/ip"
	ztls "github.com/zmap/zcrypto/tls"
)

func (d *Dialer) dial(ctx context.Context, network, address string, shouldUseTLS, shouldUseZTLS bool, tlsconfig *tls.Config, ztlsconfig *ztls.Config, impersonateStrategy impersonate.Strategy, impersonateIdentity *impersonate.Identity) (conn net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var hostname, port, fixedIP string

	if strings.HasPrefix(address, "[") {
		closeBracketIndex := strings.Index(address, "]")
		if closeBracketIndex == -1 {
			return nil, MalformedIP6Error
		}
		hostname = address[:closeBracketIndex+1]
		if len(address) < closeBracketIndex+2 {
			return nil, NoPortSpecifiedError
		}
		port = address[closeBracketIndex+2:]
	} else {
		addressParts := strings.SplitN(address, ":", 3)
		numberOfParts := len(addressParts)

		if numberOfParts >= 2 {
			// ip|host:port
			hostname = addressParts[0]
			port = addressParts[1]
			// ip|host:port:ip => curl --resolve ip:port:ip
			if numberOfParts > 2 {
				fixedIP = addressParts[2]
			}
			// check if the ip is within the context
			if ctxIP := ctx.Value(IP); ctxIP != nil {
				fixedIP = fmt.Sprint(ctxIP)
			}
		} else {
			// no port => error
			return nil, NoPortSpecifiedError
		}
	}

	// check if data is in cache
	hostname = asAscii(hostname)
	data, err := d.GetDNSData(hostname)
	if err != nil {
		// otherwise attempt to retrieve it
		data, err = d.dnsclient.Resolve(hostname)
	}
	if data == nil {
		return nil, ResolveHostError
	}

	if err != nil || len(data.A)+len(data.AAAA) == 0 {
		return nil, NoAddressFoundError
	}

	var numInvalidIPS int
	var IPS []string
	// use fixed ip as first
	if fixedIP != "" {
		IPS = append(IPS, fixedIP)
	} else {
		IPS = append(IPS, append(data.A, data.AAAA...)...)
	}

	// Dial to the IPs finally.
	for _, ip := range IPS {
		// check if we have allow/deny list
		if !d.networkpolicy.Validate(ip) {
			if d.options.OnInvalidTarget != nil {
				d.options.OnInvalidTarget(hostname, ip, port)
			}
			numInvalidIPS++
			continue
		}
		if d.options.OnBeforeDial != nil {
			d.options.OnBeforeDial(hostname, ip, port)
		}
		conn, err = d.dialIP(ctx, &ipDialOpts{
			hostname:            hostname,
			ip:                  ip,
			port:                port,
			network:             network,
			shouldUseTLS:        shouldUseTLS,
			shouldUseZTLS:       shouldUseZTLS,
			imperStrategy:       impersonateStrategy,
			impersonateIdentity: impersonateIdentity,
			tlsconfig:           tlsconfig,
			ztlsconfig:          ztlsconfig,
		})
		break
	}

	if conn == nil {
		if numInvalidIPS == len(IPS) {
			return nil, NoAddressAllowedError
		}
		return nil, CouldNotConnectError
	}

	if err != nil {
		return nil, err
	}

	return
}

type ipDialOpts struct {
	hostname            string
	ip                  string
	port                string
	network             string
	shouldUseTLS        bool
	shouldUseZTLS       bool
	imperStrategy       impersonate.Strategy
	impersonateIdentity *impersonate.Identity
	tlsconfig           *tls.Config
	ztlsconfig          *ztls.Config
}

// func dialIP dials to given ip
func (d *Dialer) dialIP(ctx context.Context, opts *ipDialOpts) (conn net.Conn, err error) {
	// hostPort
	hostPort := net.JoinHostPort(opts.ip, opts.port)

	switch {
	case opts.shouldUseTLS:
		// tls config
		tlsconfigCopy := opts.tlsconfig.Clone()
		switch {
		case d.options.SNIName != "":
			tlsconfigCopy.ServerName = d.options.SNIName
		case ctx.Value(SniName) != nil:
			sniName := ctx.Value(SniName).(string)
			tlsconfigCopy.ServerName = sniName
		case !iputil.IsIP(opts.hostname):
			tlsconfigCopy.ServerName = opts.hostname
		}

		// impersonation by using ciphers
		if opts.imperStrategy == impersonate.None {
			// no impersonation with ztls fallback
			conn, err = d.dialerX.DialTLS(ctx, opts.network, hostPort, tlsconfigCopy, true)
		} else {
			// impersonation
			conn, err = d.dialerX.DialTLSAndImpersonate(ctx, opts.network, hostPort, tlsconfigCopy, opts.imperStrategy, opts.impersonateIdentity)
		}

	case opts.shouldUseZTLS:
		ztlsconfigCopy := opts.ztlsconfig.Clone()
		switch {
		case d.options.SNIName != "":
			ztlsconfigCopy.ServerName = d.options.SNIName
		case ctx.Value(SniName) != nil:
			sniName := ctx.Value(SniName).(string)
			ztlsconfigCopy.ServerName = sniName
		case !iputil.IsIP(opts.hostname):
			ztlsconfigCopy.ServerName = opts.hostname
		}
		conn, err = d.dialerX.DialZTLS(ctx, opts.network, hostPort, ztlsconfigCopy)

	case d.proxyDialer != nil:
		conn, err = d.dialerX.WithProxyDialer(ctx, *d.proxyDialer, opts.network, hostPort)

	default:
		conn, err = d.dialer.DialContext(ctx, opts.network, hostPort)
	}

	if err == nil {
		if d.options.WithDialerHistory && d.dialerHistory != nil {
			setErr := d.dialerHistory.Set(opts.hostname, []byte(opts.ip))
			if setErr != nil {
				return nil, setErr
			}
		}
		if d.options.OnDialCallback != nil {
			d.options.OnDialCallback(opts.hostname, opts.ip)
		}
		if d.options.WithTLSData && opts.shouldUseTLS {
			if connTLS, ok := conn.(*tls.Conn); ok {
				var data bytes.Buffer
				connState := connTLS.ConnectionState()
				err := json.NewEncoder(&data).Encode(cryptoutil.TLSGrab(&connState))
				if err != nil {
					return nil, err
				}
				setErr := d.dialerTLSData.Set(opts.hostname, data.Bytes())
				if setErr != nil {
					return nil, setErr
				}
			}
		}
	}
	return conn, err
}
