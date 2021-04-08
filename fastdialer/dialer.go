package fastdialer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/ipranger"
	retryabledns "github.com/projectdiscovery/retryabledns"
	"github.com/yl2chen/cidranger"
)

// Dialer structure containing data information
type Dialer struct {
	options       *Options
	dnsclient     *retryabledns.Client
	hm            *hybrid.HybridMap
	dialerHistory *hybrid.HybridMap
	dialer        *net.Dialer
	ranger        *ipranger.IPRanger
}

// NewDialer instance
func NewDialer(options Options) (*Dialer, error) {
	var resolvers []string
	// Add system resolvers as the first to be tried
	if options.ResolversFile {
		systemResolvers, err := loadResolverFile()
		if err == nil && len(systemResolvers) > 0 {
			resolvers = systemResolvers
		}
	}
	resolvers = append(resolvers, options.BaseResolvers...)
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	dialerHistory, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		DualStack: true,
	}

	// load hardcoded values from host file
	if options.HostsFile {
		// nolint:errcheck // if they cannot be loaded it's not a hard failure
		loadHostsFile(hm)
	}
	dnsclient := retryabledns.New(resolvers, options.MaxRetries)

	var ranger ipranger.IPRanger
	// Populate blacklist if necessary
	if len(options.BlacklistHosts) > 0 {
		ranger.RangerExclude = cidranger.NewPCTrieRanger()
		for _, blacklistHost := range options.BlacklistHosts {
			ranger.Exclude(blacklistHost)
		}
	}

	// Populate whitelist if necessary
	if len(options.WhitelistHosts) > 0 {
		ranger.Ranger = cidranger.NewPCTrieRanger()
		for _, whitelistHost := range options.WhitelistHosts {
			ranger.Add(whitelistHost)
		}
	}

	return &Dialer{dnsclient: dnsclient, hm: hm, dialerHistory: dialerHistory, dialer: dialer, options: &options, ranger: &ranger}, nil
}

// Dial function compatible with net/http
func (d *Dialer) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = d.dial(ctx, network, address, false)
	return
}

// DialTLS with encrypted connection
func (d *Dialer) DialTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = d.dial(ctx, network, address, true)
	return
}

func (d *Dialer) dial(ctx context.Context, network, address string, shouldUseTLS bool) (conn net.Conn, err error) {
	separator := strings.LastIndex(address, ":")

	// check if data is in cache
	hostname := address[:separator]
	data, err := d.GetDNSData(hostname)
	if err != nil {
		// otherwise attempt to retrieve it
		data, err = d.dnsclient.Resolve(hostname)
	}
	if data == nil {
		return nil, errors.New("could not resolve host")
	}

	if err != nil || len(data.A)+len(data.AAAA) == 0 {
		return nil, &NoAddressFoundError{}
	}

	// Dial to the IPs finally.
	for _, ip := range append(data.A, data.AAAA...) {
		// if we have blacklisted hosts, check if the ip is blocked
		if d.ranger.TotalExcludeIps > 0 && d.ranger.IsExcluded(ip) {
			continue
		}
		// if we have whitelisted hosts, check if ip is allowed
		if d.ranger.TotalIps > 0 && !d.ranger.Contains(ip) {
			continue
		}

		if shouldUseTLS {
			conn, err = tls.DialWithDialer(d.dialer, network, ip+address[separator:], &tls.Config{InsecureSkipVerify: true})
		} else {
			conn, err = d.dialer.DialContext(ctx, network, ip+address[separator:])
		}
		if err == nil {
			setErr := d.dialerHistory.Set(hostname, []byte(ip))
			if setErr != nil {
				return nil, err
			}
			break
		}
	}
	if conn == nil {
		return nil, &NoAddressFoundError{}
	}
	return
}

// Close instance and cleanups
func (d *Dialer) Close() {
	d.hm.Close()
	d.dialerHistory.Close()
}

// GetDialedIP returns the ip dialed by the HTTP client
func (d *Dialer) GetDialedIP(hostname string) string {
	v, ok := d.dialerHistory.Get(hostname)
	if ok {
		return string(v)
	}

	return ""
}

// GetDNSDataFromCache cached by the resolver
func (d *Dialer) GetDNSDataFromCache(hostname string) (*retryabledns.DNSData, error) {
	var data retryabledns.DNSData
	dataBytes, ok := d.hm.Get(hostname)
	if !ok {
		return nil, errors.New("no data found")
	}

	err := data.Unmarshal(dataBytes)
	return &data, err
}

// GetDNSData for the given hostname
func (d *Dialer) GetDNSData(hostname string) (*retryabledns.DNSData, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.To4() != nil {
			return &retryabledns.DNSData{A: []string{hostname}}, nil
		}
		if ip.To16() != nil {
			return &retryabledns.DNSData{AAAA: []string{hostname}}, nil
		}
	}
	var (
		data *retryabledns.DNSData
		err  error
	)
	data, err = d.GetDNSDataFromCache(hostname)
	if err != nil {
		data, err = d.dnsclient.Resolve(hostname)
		if d.options.EnableFallback {
			data, err = d.dnsclient.ResolveWithSyscall(hostname)
		}
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, errors.New("could not resolve host")
		}
		b, _ := data.Marshal()
		err = d.hm.Set(hostname, b)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return data, nil
}
