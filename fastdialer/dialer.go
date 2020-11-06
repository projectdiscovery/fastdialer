package fastdialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/dnsclient"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

// Dialer structure containing data information
type Dialer struct {
	dnsclient     *dnsclient.Client
	hm            *hybrid.HybridMap
	dialerHistory *hybrid.HybridMap
	dialer        *net.Dialer
}

// NewDialer instance
func NewDialer(options Options) (*Dialer, error) {
	dnsclient, err := dnsclient.New(options.BaseResolvers, options.MaxRetries)
	if err != nil {
		return nil, err
	}
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

	return &Dialer{dnsclient: dnsclient, hm: hm, dialerHistory: dialerHistory, dialer: dialer}, nil
}

// Dial function compatible with net/http
func (d *Dialer) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	separator := strings.LastIndex(address, ":")

	// check if data is in cache
	hostname := address[:separator]
	data, err := d.GetDNSData(hostname)
	if err != nil {
		// otherwise attempt to retrieve it
		data, err = d.dnsclient.Resolve(hostname)
	}

	if err != nil || len(data.IP4s)+len(data.IP6s) == 0 {
		return nil, &NoAddressFoundError{}
	}

	// Dial to the IPs finally.
	for _, ip := range append(data.IP4s, data.IP6s...) {
		conn, err = d.dialer.DialContext(ctx, network, ip+address[separator:])
		if err == nil {
			setErr := d.dialerHistory.Set(hostname, []byte(ip))
			if setErr != nil {
				return nil, err
			}
			break
		}
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
func (d *Dialer) GetDNSDataFromCache(hostname string) (*dnsclient.DNSData, error) {
	var data dnsclient.DNSData
	dataBytes, ok := d.hm.Get(hostname)
	if !ok {
		return nil, fmt.Errorf("No data found")
	}

	err := data.Unmarshal(dataBytes)
	return &data, err
}

// GetDNSData for the given hostname
func (d *Dialer) GetDNSData(hostname string) (*dnsclient.DNSData, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.To4() != nil {
			return &dnsclient.DNSData{IP4s: []string{hostname}}, nil
		}
		if ip.To16() != nil {
			return &dnsclient.DNSData{IP6s: []string{hostname}}, nil
		}
	}
	var (
		data *dnsclient.DNSData
		err  error
	)
	data, err = d.GetDNSDataFromCache(hostname)
	if err != nil {
		data, err = d.dnsclient.Resolve(hostname)
		if err != nil {
			return nil, err
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
