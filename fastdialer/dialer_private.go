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
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
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
	return d.escalateConnection(ctx, nativeConn, &escalateLayerOpts{
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
func (d *Dialer) getLayer4Conn(ctx context.Context, network, hostname string, port string, ips []string) (conn net.Conn, ip string, err error) {
	if hostname == "" || iputil.IsIP(hostname) || len(ips) == 1 {
		// no need to use handler at all if given input is ip
		// or only one ip is available
		for _, ip := range ips {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			d.acquire()
			conn, err := d.simpleDialer.Dial(ctx, network, net.JoinHostPort(ip, port))
			conn = d.releaseWithHook(conn)
			if err == nil {
				return conn, ip, nil
			}
		}
		return nil, "", CouldNotConnectError
	}

	// == implement handler here ====
	//  this will use a cached version or create new and cache it
	l4Handler, err := d.getDialHandler(ctx,  hostname, network, port, ips)
	if err != nil {
		return nil, "", err
	}
	return l4Handler.getConn(ctx)
}

// escalateLayerOpts contains options for escalating layer 4 connection
type escalateLayerOpts struct {
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
func (d *Dialer) escalateConnection(ctx context.Context, layer4Conn net.Conn, opts *escalateLayerOpts) (conn net.Conn, err error) {
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
			conn, err = dialWrap.DialTLS(ctx, opts.network, hostPort, tlsconfigCopy, !(d.options.DisableZtlsFallback || disableZTLSFallback))
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
	default:
		// layer 4 connection are already established so just return it
		conn = layer4Conn
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

func (d *Dialer) acquire() {
	if d.sg == nil {
		return
	}
	d.sg.Add()
}

// trackConn adds
func (d *Dialer) releaseWithHook(conn net.Conn) net.Conn {
	if d.sg == nil {
		return conn
	}
	if conn == nil {
		d.sg.Done()
		return nil
	}
	x := dialer.NetConnTrace{
		Conn: conn,
	}
	x.CloseCallback = func() error {
		d.sg.Done()
		return nil
	}
	return &x
}
