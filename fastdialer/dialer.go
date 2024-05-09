package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"

	"github.com/Mzack9999/gcache"
	gounit "github.com/docker/go-units"
	"github.com/projectdiscovery/fastdialer/fastdialer/dialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/fastdialer/fastdialer/metafiles"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/networkpolicy"
	retryabledns "github.com/projectdiscovery/retryabledns"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	"github.com/projectdiscovery/utils/env"

	simpleflight "github.com/projectdiscovery/utils/memoize/simpleflight"
	"github.com/zmap/zcrypto/encoding/asn1"
	ztls "github.com/zmap/zcrypto/tls"
)

// option to disable ztls fallback in case of handshake error
// reads from env variable DISABLE_ZTLS_FALLBACK
var (
	disableZTLSFallback = env.GetEnvOrDefault("DISABLE_ZTLS_FALLBACK", false)
	MaxDNSCacheSize     int64
	MaxDNSItems         = 1024
)

func init() {
	// enable permissive parsing for ztls, so that it can allow permissive parsing for X509 certificates
	asn1.AllowPermissiveParsing = true
	maxCacheSize := env.GetEnvOrDefault("MAX_DNS_CACHE_SIZE", "10mb")
	maxDnsCacheSize, err := gounit.FromHumanSize(maxCacheSize)
	if err != nil {
		panic(err)
	}
	MaxDNSCacheSize = maxDnsCacheSize
	MaxDNSItems = env.GetEnvOrDefault("MAX_DNS_ITEMS", 1024)
}

// Dialer structure containing data information
type Dialer struct {
	options   *Options
	dnsclient *retryabledns.Client
	// memory typed cache
	mDnsCache gcache.Cache[string, *retryabledns.DNSData]
	// memory/disk untyped ([]byte) cache
	hmDnsCache    *hybrid.HybridMap
	hostsFileData *hybrid.HybridMap
	dialerHistory *hybrid.HybridMap
	dialerTLSData *hybrid.HybridMap
	simpleDialer  dialer.SimpleDialer
	networkpolicy *networkpolicy.NetworkPolicy

	// optimizations
	group          simpleflight.Group[string]
	l4HandlerCache gcache.Cache[string, *l4ConnHandler]
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
	var err error
	var dialerHistory *hybrid.HybridMap
	if options.WithDialerHistory {
		// we need to use disk to store all the dialed ips
		dialerHistoryCacheOptions := hybrid.DefaultDiskOptions
		dialerHistoryCacheOptions.DBType = getHMAPDBType(options)
		dialerHistory, err = hybrid.New(dialerHistoryCacheOptions)
		if err != nil {
			return nil, err
		}
	}
	// when loading in memory set max size to 10 MB
	var (
		hmDnsCache *hybrid.HybridMap
		dnsCache   gcache.Cache[string, *retryabledns.DNSData]
	)
	options.CacheType = Memory
	if options.CacheType == Memory {
		dnsCache = gcache.New[string, *retryabledns.DNSData](MaxDNSItems).Build()
	} else {
		hmDnsCache, err = hybrid.New(hybrid.DefaultHybridOptions)
		if err != nil {
			return nil, err
		}
	}

	var dialerTLSData *hybrid.HybridMap
	if options.WithTLSData {
		dialerTLSData, err = hybrid.New(hybrid.DefaultDiskOptions)
		if err != nil {
			return nil, err
		}
	}

	var netDialer *net.Dialer
	if options.Dialer != nil {
		netDialer = options.Dialer
	} else {
		netDialer = &net.Dialer{
			Timeout:   options.DialerTimeout,
			KeepAlive: options.DialerKeepAlive,
			DualStack: true,
		}
	}

	var hostsFileData *hybrid.HybridMap
	// load hardcoded values from host file
	if options.HostsFile {
		var err error
		if options.CacheType == Memory {
			hostsFileData, err = metafiles.GetHostsFileDnsData(metafiles.InMemory)
		} else {
			hostsFileData, err = metafiles.GetHostsFileDnsData(metafiles.Hybrid)
		}
		if options.Logger != nil && err != nil {
			options.Logger.Printf("could not load hosts file: %s\n", err)
		}
	}
	dnsclient, err := retryabledns.New(resolvers, options.MaxRetries)
	if err != nil {
		return nil, err
	}

	var npOptions networkpolicy.Options
	if options.WithNetworkPolicyOptions != nil {
		npOptions = *options.WithNetworkPolicyOptions
	}

	// Populate deny list if necessary
	npOptions.DenyList = append(npOptions.DenyList, options.Deny...)
	// Populate allow list if necessary
	npOptions.AllowList = append(npOptions.AllowList, options.Allow...)

	npOptions.AllowPortList = append(npOptions.AllowPortList, options.AllowPortList...)
	npOptions.DenyPortList = append(npOptions.DenyPortList, options.DenyPortList...)

	npOptions.AllowSchemeList = append(npOptions.AllowSchemeList, options.AllowSchemeList...)
	npOptions.DenySchemeList = append(npOptions.DenySchemeList, options.DenySchemeList...)

	np, err := networkpolicy.New(npOptions)
	if err != nil {
		return nil, err
	}
	if options.Dialer.Timeout == 0 {
		// use defaults just in case if not set
		options.Dialer.Timeout = DefaultOptions.DialerTimeout
	}

	dx := &Dialer{
		dnsclient:     dnsclient,
		mDnsCache:     dnsCache,
		hmDnsCache:    hmDnsCache,
		hostsFileData: hostsFileData,
		dialerHistory: dialerHistory,
		dialerTLSData: dialerTLSData,
		simpleDialer:  dialer.NewSimpleDialer(netDialer, options.ProxyDialer, options.DialerTimeout),
		options:       &options,
		networkpolicy: np,
		group:         simpleflight.Group[string]{},
	}
	dx.l4HandlerCache = gcache.New[string, *l4ConnHandler](options.MaxL4HandlerPoolSize).
		LRU().
		Expiration(options.L4CacheExpiration).
		EvictedFunc(func(key string, value *l4ConnHandler) {
			dx.group.Forget(key)
			value.Close()
		}).
		Build()
	return dx, nil
}

// Dial function compatible with net/http
func (d *Dialer) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        false,
		shouldUseZTLS:       false,
		tlsconfig:           nil,
		ztlsconfig:          nil,
		impersonateStrategy: impersonate.None,
		impersonateIdentity: nil,
	})
}

// DialTLS with encrypted connection
func (d *Dialer) DialTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if d.options.WithZTLS {
		return d.DialZTLSWithConfig(ctx, network, address, &ztls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	}
	return d.DialTLSWithConfig(ctx, network, address, &tls.Config{Renegotiation: tls.RenegotiateOnceAsClient, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
}

// DialZTLS with encrypted connection using ztls
func (d *Dialer) DialZTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = d.DialZTLSWithConfig(ctx, network, address, &ztls.Config{InsecureSkipVerify: true})
	return
}

// DialTLS with encrypted connection
func (d *Dialer) DialTLSWithConfig(ctx context.Context, network, address string, config *tls.Config) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        true,
		shouldUseZTLS:       false,
		tlsconfig:           config,
		ztlsconfig:          nil,
		impersonateStrategy: impersonate.None,
		impersonateIdentity: nil,
	})
}

// DialTLSWithConfigImpersonate dials tls with impersonation
func (d *Dialer) DialTLSWithConfigImpersonate(ctx context.Context, network, address string, config *tls.Config, impersonate impersonate.Strategy, identity *impersonate.Identity) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        true,
		shouldUseZTLS:       false,
		tlsconfig:           config,
		ztlsconfig:          nil,
		impersonateStrategy: impersonate,
		impersonateIdentity: identity,
	})
}

// DialZTLSWithConfig dials ztls with config
func (d *Dialer) DialZTLSWithConfig(ctx context.Context, network, address string, config *ztls.Config) (conn net.Conn, err error) {
	// ztls doesn't support tls13
	if IsTLS13(config) {
		stdTLSConfig, err := AsTLSConfig(config)
		if err != nil {
			return nil, err
		}
		return d.dial(ctx, &dialOptions{
			network:             network,
			address:             address,
			shouldUseTLS:        true,
			shouldUseZTLS:       false,
			tlsconfig:           stdTLSConfig,
			ztlsconfig:          nil,
			impersonateStrategy: impersonate.None,
			impersonateIdentity: nil,
		})
	}
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        false,
		shouldUseZTLS:       true,
		tlsconfig:           nil,
		ztlsconfig:          config,
		impersonateStrategy: impersonate.None,
		impersonateIdentity: nil,
	})
}

// GetDialedIP returns the ip dialed by the HTTP client
func (d *Dialer) GetDialedIP(hostname string) string {
	if !d.options.WithDialerHistory || d.dialerHistory == nil {
		return ""
	}
	hostname = asAscii(hostname)
	v, ok := d.dialerHistory.Get(hostname)
	if ok {
		return string(v)
	}

	return ""
}

// GetTLSData returns the tls data for a hostname
func (d *Dialer) GetTLSData(hostname string) (*cryptoutil.TLSData, error) {
	hostname = asAscii(hostname)
	if !d.options.WithTLSData {
		return nil, NoTLSHistoryError
	}
	v, ok := d.dialerTLSData.Get(hostname)
	if !ok {
		return nil, NoTLSDataError
	}

	var tlsData cryptoutil.TLSData
	err := json.NewDecoder(bytes.NewReader(v)).Decode(&tlsData)
	if err != nil {
		return nil, err
	}

	return &tlsData, nil
}

// GetDNSDataFromCache cached by the resolver
func (d *Dialer) GetDNSDataFromCache(hostname string) (*retryabledns.DNSData, error) {
	hostname = asAscii(hostname)
	var data retryabledns.DNSData
	var dataBytes []byte
	var ok bool
	if d.hostsFileData != nil {
		dataBytes, ok = d.hostsFileData.Get(hostname)
	}
	if !ok {
		if d.mDnsCache != nil {
			return d.mDnsCache.GetIFPresent(hostname)
		}

		dataBytes, ok = d.hmDnsCache.Get(hostname)
		if !ok {
			return nil, NoDNSDataError
		}
	}
	err := data.Unmarshal(dataBytes)
	return &data, err
}

// GetDNSData for the given hostname
func (d *Dialer) GetDNSData(hostname string) (*retryabledns.DNSData, error) {
	hostname = asAscii(hostname)
	// support http://[::1] http://[::1]:8080
	// https://datatracker.ietf.org/doc/html/rfc2732
	// It defines a syntax
	// for IPv6 addresses and allows the use of "[" and "]" within a URI
	// explicitly for this reserved purpose.
	if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
		ipv6host := hostname[1:strings.LastIndex(hostname, "]")]
		if ip := net.ParseIP(ipv6host); ip != nil {
			if ip.To16() != nil {
				return &retryabledns.DNSData{AAAA: []string{ip.To16().String()}}, nil
			}
		}
	}
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
		if err != nil && d.options.EnableFallback {
			data, err = d.dnsclient.ResolveWithSyscall(hostname)
		}
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, ResolveHostError
		}
		if len(data.A)+len(data.AAAA) > 0 {
			if d.mDnsCache != nil {
				err := d.mDnsCache.Set(hostname, data)
				if err != nil {
					return nil, err
				}
			}

			if d.hmDnsCache != nil {
				b, err := data.Marshal()
				if err != nil {
					return nil, err
				}
				err = d.hmDnsCache.Set(hostname, b)
				if err != nil {
					return nil, err
				}
			}

		}
		return data, nil
	}
	return data, nil
}

// Close instance and cleanups
func (d *Dialer) Close() {
	if d.mDnsCache != nil {
		d.mDnsCache.Purge()
	}
	if d.hmDnsCache != nil {
		d.hmDnsCache.Close()
	}
	if d.options.WithDialerHistory && d.dialerHistory != nil {
		d.dialerHistory.Close()
	}
	if d.options.WithTLSData {
		d.dialerTLSData.Close()
	}
	if d.l4HandlerCache != nil {
		d.l4HandlerCache.Purge()
	}
	if d.dnsclient != nil {
		d.dnsclient.Close()
	}
	// donot close hosts file as it is meant to be shared
}
