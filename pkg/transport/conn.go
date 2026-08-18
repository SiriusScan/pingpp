package transport

import (
	"context"
	"net"
	"sync"
)

// CountDial records a network operation that does not go through DialTCP/DialUDP
// (for example ICMP echo or a library that owns its own dialer). Call this
// before the real I/O so MaxNetworkOps still describes scan activity.
// CountDial does not acquire the host-concurrency permit; wrap the real I/O
// with HostLimiter.Acquire (or use DialTCP/DialUDP).
func CountDial(ctx context.Context) error {
	return recordDial(ctx)
}

// AddObservedBytes records payload volume for I/O that is not on a wrapped conn
// (ICMP echo libraries). It does not count a dial.
func AddObservedBytes(ctx context.Context, read, sent int64) {
	if m := ContextMeter(ctx); m != nil {
		m.AddBytes(read, sent)
	}
}

type releaseConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func wrapRelease(c net.Conn, release func()) net.Conn {
	if release == nil {
		return c
	}
	if c == nil {
		release()
		return nil
	}
	rc := &releaseConn{Conn: c, release: release}
	if pc, ok := c.(net.PacketConn); ok {
		return &releasePacketConn{releaseConn: rc, packet: pc}
	}
	return rc
}

func (c *releaseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type releasePacketConn struct {
	*releaseConn
	packet net.PacketConn
}

func (c *releasePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(b)
}

func (c *releasePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(b, addr)
}

// WrapConn counts payload bytes on Read/Write against the scan meter.
// DialTCP and DialUDP wrap automatically; use this when a library dials
// internally and only exposes the resulting net.Conn.
//
// UDP connections keep the net.PacketConn shape so libraries such as miekg/dns
// still treat them as datagram sockets rather than length-prefixed TCP.
func WrapConn(ctx context.Context, c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	m := ContextMeter(ctx)
	if m == nil {
		return c
	}
	switch c.(type) {
	case *meteredConn, *meteredPacketConn:
		return c
	}
	if pc, ok := c.(net.PacketConn); ok {
		return &meteredPacketConn{Conn: c, packet: pc, meter: m}
	}
	return &meteredConn{Conn: c, meter: m}
}

type meteredConn struct {
	net.Conn
	meter *Meter
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.meter.AddBytes(int64(n), 0)
	}
	return n, err
}

func (c *meteredConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.meter.AddBytes(0, int64(n))
	}
	return n, err
}

type meteredPacketConn struct {
	net.Conn
	packet net.PacketConn
	meter  *Meter
}

func (c *meteredPacketConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.meter.AddBytes(int64(n), 0)
	}
	return n, err
}

func (c *meteredPacketConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.meter.AddBytes(0, int64(n))
	}
	return n, err
}

func (c *meteredPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.packet.ReadFrom(b)
	if n > 0 {
		c.meter.AddBytes(int64(n), 0)
	}
	return n, addr, err
}

func (c *meteredPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.packet.WriteTo(b, addr)
	if n > 0 {
		c.meter.AddBytes(0, int64(n))
	}
	return n, err
}
