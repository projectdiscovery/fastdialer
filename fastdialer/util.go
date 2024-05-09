package fastdialer

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/projectdiscovery/hmap/store/hybrid"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/idna"
)

func AsTLSConfig(ztlsConfig *ztls.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		NextProtos:             ztlsConfig.NextProtos,
		ServerName:             ztlsConfig.ServerName,
		ClientAuth:             tls.ClientAuthType(ztlsConfig.ClientAuth),
		InsecureSkipVerify:     ztlsConfig.InsecureSkipVerify,
		CipherSuites:           ztlsConfig.CipherSuites,
		SessionTicketsDisabled: ztlsConfig.SessionTicketsDisabled,
		MinVersion:             ztlsConfig.MinVersion,
		MaxVersion:             ztlsConfig.MaxVersion,
	}
	return tlsConfig, nil
}

func AsZTLSConfig(tlsConfig *tls.Config) (*ztls.Config, error) {
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
	return ztlsConfig, nil
}

func IsTLS13(config interface{}) bool {
	switch c := config.(type) {
	case *tls.Config:
		return c.MinVersion == tls.VersionTLS13
	case *ztls.Config:
		return c.MinVersion == tls.VersionTLS13
	}

	return false
}

func asAscii(hostname string) string {
	hostnameAscii, _ := idna.ToASCII(hostname)
	return hostnameAscii
}

func getHMAPDBType(options Options) hybrid.DBType {
	switch options.DiskDbType {
	case Pogreb:
		return hybrid.PogrebDB
	default:
		return hybrid.LevelDB
	}
}

// parseAddress parses the address and returns the hostname, port and fixedIP
func parseAddress(ctx context.Context, address string) (hostname, port, fixedIP string, err error) {
	if strings.HasPrefix(address, "[") {
		closeBracketIndex := strings.Index(address, "]")
		if closeBracketIndex == -1 {
			return "", "", "", MalformedIP6Error
		}
		hostname = address[:closeBracketIndex+1]
		if len(address) < closeBracketIndex+2 {
			return "", "", "", NoPortSpecifiedError
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
			return "", "", "", NoPortSpecifiedError
		}
	}
	return
}
