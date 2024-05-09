package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"

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

	defer func() {
		if conn == nil {
			err = CouldNotConnectError
		}
	}()

	if hostname == "" || iputil.IsIP(hostname) {
		// no need to use handler at all if given input is ip
		for _, ip := range IPS {
			conn, err = d.dialIP(ctx, &ipDialOpts{
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
			if err == nil {
				return
			}
		}
		return
	}

	// if this is a domain then use handler to perform singleflight on first call
	// and use predective prefetching of tcp layer calls
	dh := newDialHandler(ctx, d, hostname, port, IPS)
	return dh.getConn(ctx)

	// // dialQueue contains info about the ips to dial
	// dialQueue := []*ipDialOpts{}

	// for _, ip := range IPS {

	// 	dialQueue = append(dialQueue, &ipDialOpts{
	// 		hostname:            hostname,
	// 		ip:                  ip,
	// 		port:                port,
	// 		network:             network,
	// 		shouldUseTLS:        shouldUseTLS,
	// 		shouldUseZTLS:       shouldUseZTLS,
	// 		imperStrategy:       impersonateStrategy,
	// 		impersonateIdentity: impersonateIdentity,
	// 		tlsconfig:           tlsconfig,
	// 		ztlsconfig:          ztlsconfig,
	// 	})
	// }

	// // check if handler exists in cache
	// if h, err := d.ConnCache.GetIFPresent(address); !errors.Is(err, gcache.KeyNotFoundError) && h != nil {
	// 	return h.getConn(ctx, dialQueue[0])
	// }

	// select {
	// case <-ctx.Done():
	// 	return nil, ctx.Err()

	// case <-d.group.DoChan(address, func() (interface{}, error) {
	// 	// Dial to the IPs finally.
	// 	for _, ip := range IPS {
	// 		// check if we have allow/deny list
	// 		if !d.networkpolicy.Validate(ip) {
	// 			if d.options.OnInvalidTarget != nil {
	// 				d.options.OnInvalidTarget(hostname, ip, port)
	// 			}
	// 			numInvalidIPS++
	// 			continue
	// 		}
	// 		if d.options.OnBeforeDial != nil {
	// 			d.options.OnBeforeDial(hostname, ip, port)
	// 		}
	// 		conn, err = d.dialIP(ctx, &ipDialOpts{
	// 			hostname:            hostname,
	// 			ip:                  ip,
	// 			port:                port,
	// 			network:             network,
	// 			shouldUseTLS:        shouldUseTLS,
	// 			shouldUseZTLS:       shouldUseZTLS,
	// 			imperStrategy:       impersonateStrategy,
	// 			impersonateIdentity: impersonateIdentity,
	// 			tlsconfig:           tlsconfig,
	// 			ztlsconfig:          ztlsconfig,
	// 		})
	// 	}
	// 	return conn, err
	// }):

	// }

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
