package dialer

import (
	"net"
	"time"
)

var _ net.Conn = &NetConnTrace{}

// NetConnTrace is a net.Conn implementation that allows tracing
// via callbacks
type NetConnTrace struct {
	net.Conn

	// Callbacks
	ReadCallback  func([]byte) (int, error)
	WriteCallback func([]byte) (int, error)
	CloseCallback func() error
}

func (c *NetConnTrace) Read(b []byte) (int, error) {
	if c.ReadCallback != nil {
		return c.ReadCallback(b)
	}
	return c.Conn.Read(b)
}

func (c *NetConnTrace) Write(b []byte) (int, error) {
	if c.WriteCallback != nil {
		return c.WriteCallback(b)
	}
	return c.Conn.Write(b)
}

func (c *NetConnTrace) Close() error {
	if c.CloseCallback != nil {
		return c.CloseCallback()
	}
	return c.Conn.Close()
}

func (c *NetConnTrace) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *NetConnTrace) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *NetConnTrace) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *NetConnTrace) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *NetConnTrace) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
