package fastdialer

import (
	"context"
	"net"
)

// dialHandler handles dial requests to a particular address
type dialHandler struct {
	// fastdialer instance to use for dialing
	fd *Dialer
}

func newDialHandler(ctx context.Context, fd *Dialer, hostname, port string, ips []string) *dialHandler {
	return &dialHandler{fd: fd}
}

func (d *dialHandler) getConn(ctx context.Context) (net.Conn, error) {

}


