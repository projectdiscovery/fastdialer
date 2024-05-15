package dialer

import (
	"context"
	"net"
	"time"

	ctxUtil "github.com/projectdiscovery/utils/context"
	"github.com/projectdiscovery/utils/errkit"
	"golang.org/x/net/proxy"
)

// SimpleDialer is plain dialer without any additional features
// it abstracts the use of proxy dialer
type SimpleDialer interface {
	// Dial dials to the address on the named network.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// simpleDialer is a simple dialer without any additional features
type simpleDialer struct {
	// stdlib dialer
	nd *net.Dialer
	// proxy dialer
	pd proxy.Dialer
	// timeout for dialing
	timeout time.Duration
}

func NewSimpleDialer(nd *net.Dialer, pd proxy.Dialer, timeout time.Duration) SimpleDialer {
	return &simpleDialer{nd: nd, pd: pd}
}

func (d *simpleDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if d.pd != nil {
		ctx, cancel := context.WithTimeoutCause(ctx, d.timeout, errkit.New("dialer timeout"))
		defer cancel()
		return ctxUtil.ExecFuncWithTwoReturns(ctx, func() (net.Conn, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return d.pd.Dial(network, address)
		})
	}
	return d.nd.DialContext(ctx, network, address)
}
