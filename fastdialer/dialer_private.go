package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"

	"github.com/projectdiscovery/fastdialer/fastdialer/dialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	iputil "github.com/projectdiscovery/utils/ip"
	ztls "github.com/zmap/zcrypto/tls"
)

type dialOptions struct {
	network             string
	address             string
	shouldUseTLS        bool
	shouldUseZTLS       bool
	tlsconfig           *tls.Config
	ztlsconfig          *ztls.Config
	impersonateStrategy impersonate.Strategy
	impersonateIdentity *impersonate.Identity
}

func (d *Dialer) dial(ctx context.Context, opts *dialOptions) (conn net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var hostname, port, fixedIP string

	// parse the address
	hostname, port, fixedIP, err = parseAddress(ctx, opts.address)
	if err != nil {
		return nil, err
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

	var tmp []string
	// use fixed ip as first
	if fixedIP != "" {
		tmp = append(tmp, fixedIP)
	} else {
		tmp = append(tmp, append(data.A, data.AAAA...)...)
	}

	// remove all ips blocked by network policy
	IPS := []string{}
	for _, ip := range tmp {
		// check if we have allow/deny list
		if !d.networkpolicy.Validate(ip) {
			if d.options.OnInvalidTarget != nil {
				d.options.OnInvalidTarget(hostname, ip, port)
			}
			continue
		}
		if d.options.OnBeforeDial != nil {
			d.options.OnBeforeDial(hostname, ip, port)
		}
		IPS = append(IPS, ip)
	}

	if len(IPS) == 0 {
		return nil, NoAddressAllowedError
	}

	// get layer 4 connection and escalate it as per requirements
	nativeConn, ip, err := d.getLayer4Conn(ctx, opts.network, hostname, port, IPS)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		err = CouldNotConnectError
	}

	// escalate it to required layer using dialIP
	return d.escalateConnection(ctx, nativeConn, &ipDialOpts{
		hostname:            hostname,
		ip:                  ip,
		port:                port,
		network:             opts.network,
		shouldUseTLS:        opts.shouldUseTLS,
		shouldUseZTLS:       opts.shouldUseZTLS,
		imperStrategy:       opts.impersonateStrategy,
		impersonateIdentity: opts.impersonateIdentity,
		tlsconfig:           opts.tlsconfig,
		ztlsconfig:          opts.ztlsconfig,
	})
}

// getLayer4Conn return a layer 4 connection for given address
func (d *Dialer) getLayer4Conn(ctx context.Context, network, hostname string, port string, ips []string) (net.Conn, string, error) {
	if hostname == "" || iputil.IsIP(hostname) {
		// no need to use handler at all if given input is ip
		for _, ip := range ips {
			conn, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, ip, nil
			}
		}
		return nil, "", CouldNotConnectError
	}

	// == implement handler here ====
	return nil, "", nil
	// // if this is a domain then use handler to perform singleflight on first call
	// // and use predective prefetching of tcp layer calls
	// dh := getDialHandler(ctx, d, hostname, port)
	// // firstFlight happens parallelly
	// if dh.IsFirstFlight() {
	// 	nativeConn, err := dh.dialFirst(ctx, ips)
	// 	if err != nil {
	// 		return nil, "", err
	// 	}
	// 	return nativeConn, "", nil
	// }

	// return dh.getConn(ctx, ips)
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

// escalateConnection escalates given layer4 connection to required layer
func (d *Dialer) escalateConnection(ctx context.Context, layer4Conn net.Conn, opts *ipDialOpts) (conn net.Conn, err error) {
	// hostPort
	hostPort := net.JoinHostPort(opts.ip, opts.port)
	// wrap the connection
	dialWrap := dialer.NewConnWrap(layer4Conn)

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
			conn, err = dialWrap.DialTLS(ctx, opts.network, hostPort, tlsconfigCopy, true)
		} else {
			// impersonation
			conn, err = dialWrap.DialTLSAndImpersonate(ctx, opts.network, hostPort, tlsconfigCopy, opts.imperStrategy, opts.impersonateIdentity)
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
		conn, err = dialWrap.DialZTLS(ctx, opts.network, hostPort, ztlsconfigCopy)

	case d.proxyDialer != nil:
		conn, err = dialWrap.WithProxyDialer(ctx, *d.proxyDialer, opts.network, hostPort)

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
