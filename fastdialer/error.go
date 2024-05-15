package fastdialer

import "github.com/projectdiscovery/utils/errkit"

var (
	CouldNotConnectError  = errkit.New("could not connect to any address found for host")
	NoAddressFoundError   = errkit.New("no address found for host")
	NoAddressAllowedError = errkit.New("denied address found for host")
	NoPortSpecifiedError  = errkit.New("port was not specified")
	MalformedIP6Error     = errkit.New("malformed IPv6 address")
	ResolveHostError      = errkit.New("could not resolve host")
	NoTLSHistoryError     = errkit.New("no tls data history available")
	NoTLSDataError        = errkit.New("no tls data found for the key")
	NoDNSDataError        = errkit.New("no data found")
	AsciiConversionError  = errkit.New("could not convert hostname to ASCII")
)
