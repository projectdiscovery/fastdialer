package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Mzack9999/gcache"
	gounit "github.com/docker/go-units"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/fastdialer/fastdialer/metafiles"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/networkpolicy"
	retryabledns "github.com/projectdiscovery/retryabledns"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	ptrutil "github.com/projectdiscovery/utils/ptr"
	utls "github.com/refraction-networking/utls"
	"github.com/zmap/zcrypto/encoding/asn1"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/proxy"
)

// option to disable ztls fallback in case of handshake error
// reads from env variable DISABLE_ZTLS_FALLBACK
var (
	disableZTLSFallback = false
	MaxDNSCacheSize     int64
	MaxDNSItems         = 1024
)

func init() {
	// enable permissive parsing for ztls, so that it can allow permissive parsing for X509 certificates
	asn1.AllowPermissiveParsing = true
	disableZTLSFallback = env.GetEnvOrDefault("DISABLE_ZTLS_FALLBACK", false)
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
	dialer        *net.Dialer
	proxyDialer   *proxy.Dialer
	networkpolicy *networkpolicy.NetworkPolicy
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

	var dialer *net.Dialer
	if options.Dialer != nil {
		dialer = options.Dialer
	} else {
		dialer = &net.Dialer{
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

	return &Dialer{
		dnsclient:     dnsclient,
		mDnsCache:     dnsCache,
		hmDnsCache:    hmDnsCache,
		hostsFileData: hostsFileData,
		dialerHistory: dialerHistory,
		dialerTLSData: dialerTLSData,
		dialer:        dialer,
		proxyDialer:   options.ProxyDialer,
		options:       &options,
		networkpolicy: np,
	}, nil
}

// Dial function compatible with net/http
func (d *Dialer) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = d.dial(ctx, network, address, false, false, nil, nil, impersonate.None, nil)
	return
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
	conn, err = d.dial(ctx, network, address, true, false, config, nil, impersonate.None, nil)
	return
}

// DialTLSWithConfigImpersonate dials tls with impersonation
func (d *Dialer) DialTLSWithConfigImpersonate(ctx context.Context, network, address string, config *tls.Config, impersonate impersonate.Strategy, identity *impersonate.Identity) (conn net.Conn, err error) {
	conn, err = d.dial(ctx, network, address, true, false, config, nil, impersonate, identity)
	return
}

// DialZTLSWithConfig dials ztls with config
func (d *Dialer) DialZTLSWithConfig(ctx context.Context, network, address string, config *ztls.Config) (conn net.Conn, err error) {
	// ztls doesn't support tls13
	if IsTLS13(config) {
		stdTLSConfig, err := AsTLSConfig(config)
		if err != nil {
			return nil, err
		}
		return d.dial(ctx, network, address, true, false, stdTLSConfig, nil, impersonate.None, nil)
	}
	return d.dial(ctx, network, address, false, true, nil, config, impersonate.None, nil)
}

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
		hostPort := net.JoinHostPort(ip, port)
		if shouldUseTLS {
			tlsconfigCopy := tlsconfig.Clone()
			switch {
			case d.options.SNIName != "":
				tlsconfigCopy.ServerName = d.options.SNIName
			case ctx.Value(SniName) != nil:
				sniName := ctx.Value(SniName).(string)
				tlsconfigCopy.ServerName = sniName
			case !iputil.IsIP(hostname):
				tlsconfigCopy.ServerName = hostname
			}
			if impersonateStrategy == impersonate.None {
				conn, err = tls.DialWithDialer(d.dialer, network, hostPort, tlsconfigCopy)
			} else {
				nativeConn, err := d.dialer.DialContext(ctx, network, hostPort)
				if err != nil {
					return nativeConn, err
				}
				// clone existing tls config
				uTLSConfig := &utls.Config{
					InsecureSkipVerify: tlsconfigCopy.InsecureSkipVerify,
					ServerName:         tlsconfigCopy.ServerName,
					MinVersion:         tlsconfigCopy.MinVersion,
					MaxVersion:         tlsconfigCopy.MaxVersion,
					CipherSuites:       tlsconfigCopy.CipherSuites,
				}
				var uTLSConn *utls.UConn
				if impersonateStrategy == impersonate.Random {
					uTLSConn = utls.UClient(nativeConn, uTLSConfig, utls.HelloRandomized)
				} else if impersonateStrategy == impersonate.Custom {
					uTLSConn = utls.UClient(nativeConn, uTLSConfig, utls.HelloCustom)
					clientHelloSpec := utls.ClientHelloSpec(ptrutil.Safe(impersonateIdentity))
					if err := uTLSConn.ApplyPreset(&clientHelloSpec); err != nil {
						return nil, err
					}
				}
				if err := uTLSConn.Handshake(); err != nil {
					return nil, err
				}
				conn = uTLSConn
			}
		} else if shouldUseZTLS {
			ztlsconfigCopy := ztlsconfig.Clone()
			switch {
			case d.options.SNIName != "":
				ztlsconfigCopy.ServerName = d.options.SNIName
			case ctx.Value(SniName) != nil:
				sniName := ctx.Value(SniName).(string)
				ztlsconfigCopy.ServerName = sniName
			case !iputil.IsIP(hostname):
				ztlsconfigCopy.ServerName = hostname
			}
			conn, err = ztls.DialWithDialer(d.dialer, network, hostPort, ztlsconfigCopy)
		} else {
			if d.proxyDialer != nil {
				dialer := *d.proxyDialer
				// timeout not working for socks5 proxy dialer
				// tying to handle it here
				connectionCh := make(chan net.Conn, 1)
				errCh := make(chan error, 1)
				go func() {
					conn, err = dialer.Dial(network, hostPort)
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
			} else {
				conn, err = d.dialer.DialContext(ctx, network, hostPort)
			}
		}
		// fallback to ztls  in case of handshake error with chrome ciphers
		// ztls fallback can either be disabled by setting env variable DISABLE_ZTLS_FALLBACK=true or by setting DisableZtlsFallback=true in options
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !(d.options.DisableZtlsFallback && disableZTLSFallback) {
			var ztlsconfigCopy *ztls.Config
			if shouldUseZTLS {
				ztlsconfigCopy = ztlsconfig.Clone()
			} else {
				if tlsconfig == nil {
					tlsconfig = &tls.Config{
						Renegotiation:      tls.RenegotiateOnceAsClient,
						MinVersion:         tls.VersionTLS10,
						InsecureSkipVerify: true,
					}
				}
				ztlsconfigCopy, err = AsZTLSConfig(tlsconfig)
				if err != nil {
					return nil, errorutil.NewWithErr(err).Msgf("could not convert tls config to ztls config")
				}
			}
			ztlsconfigCopy.CipherSuites = ztls.ChromeCiphers
			conn, err = ztls.DialWithDialer(d.dialer, network, hostPort, ztlsconfigCopy)
			err = errorutil.WrapfWithNil(err, "ztls fallback failed")
		}
		if err == nil {
			if d.options.WithDialerHistory && d.dialerHistory != nil {
				setErr := d.dialerHistory.Set(hostname, []byte(ip))
				if setErr != nil {
					return nil, setErr
				}
			}
			if d.options.OnDialCallback != nil {
				d.options.OnDialCallback(hostname, ip)
			}
			if d.options.WithTLSData && shouldUseTLS {
				if connTLS, ok := conn.(*tls.Conn); ok {
					var data bytes.Buffer
					connState := connTLS.ConnectionState()
					err := json.NewEncoder(&data).Encode(cryptoutil.TLSGrab(&connState))
					if err != nil {
						return nil, err
					}
					setErr := d.dialerTLSData.Set(hostname, data.Bytes())
					if setErr != nil {
						return nil, setErr
					}
				}
			}
			break
		}
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
	// donot close hosts file as it is meant to be shared
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
				b, _ := data.Marshal()
				if err != nil {
					return nil, err
				}
				err := d.hmDnsCache.Set(hostname, b)
				if err != nil {
					return nil, err
				}
			}

		}
		return data, nil
	}
	return data, nil
}

func getHMAPDBType(options Options) hybrid.DBType {
	switch options.DiskDbType {
	case Pogreb:
		return hybrid.PogrebDB
	default:
		return hybrid.LevelDB
	}
}
